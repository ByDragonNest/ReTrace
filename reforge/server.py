"""FastAPI app wiring the MCP host, the agent loop, the approval gate and the SPA."""
import asyncio
import json
import logging
import os
import re
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Response, Request, UploadFile, File
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, RedirectResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import agent, audit, config, execution, model_gateway, observability, support_bundle, static_analysis, llm, bindiff, report_export, workspace
from . import route_policy
from .identity import Permission
from . import artifacts as artifacts_mod
from . import artifact_overview as overview_mod
from . import heuristics
from . import string_signal
from .workspace import UnsafePathError
from .knowledge import get_kb
from .mcp_host import MCPHost
from .session import SessionStore
from .tool_registry import ToolRegistry

class _RingLogHandler(logging.Handler):
    """Keeps the last N operational log lines in memory for the support bundle.

    In memory rather than read back off disk: the log file may be rotated, redirected to a
    collector, or not exist at all, and a support bundle that works only when logging happens to
    be configured one way is a support bundle that fails when you need it.
    """

    def __init__(self, capacity: int = 500):
        super().__init__()
        self.capacity = capacity
        self._lines: list = []

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._lines.append(self.format(record))
            if len(self._lines) > self.capacity:
                del self._lines[:-self.capacity]
        except Exception:                    # a logging handler must never raise
            pass

    def lines(self) -> list:
        return list(self._lines)


_RECENT_LOGS = _RingLogHandler()

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)
def _resolve_web_root() -> Path:
    """Locate the SPA, tolerating both supported layouts.

    - installed wheel / checkout : <package>/web   (the SPA ships inside the package)
    - pre-P0-S4 layout           : <repo>/web      (kept so an old checkout still runs)

    StaticFiles(check_dir=True) raises at construction when the directory is missing, so an
    install that cannot find the SPA used to fail at import with a Starlette RuntimeError that
    said nothing about the cause. Fail with an actionable message instead.
    """
    for candidate in (Path(__file__).resolve().parent / "web",
                      Path(__file__).resolve().parent.parent / "web"):
        if (candidate / "index.html").is_file():
            return candidate
    raise RuntimeError(
        "ReTrace web assets not found. Expected index.html in either "
        f"{Path(__file__).resolve().parent / 'web'} or "
        f"{Path(__file__).resolve().parent.parent / 'web'}. "
        "Install from a checkout with `pip install -e .`, or run from the repository root."
    )


_RECENT_LOGS.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s | %(message)s"))
logging.getLogger().addHandler(_RECENT_LOGS)
logging.getLogger().addFilter(observability.CorrelationFilter())
if getattr(config, "LOG_FORMAT", "text") == "json":
    for _h in logging.getLogger().handlers:
        if _h is not _RECENT_LOGS:
            _h.setFormatter(observability.JSONFormatter())

WEB = _resolve_web_root()

from . import __version__ as _pkg_version

store = SessionStore()
host: MCPHost | None = None
registry: ToolRegistry | None = None


def _require_host() -> MCPHost:
    """The MCP host, or 503. Handlers used to dereference the global directly, which is an
    AttributeError - a 500 with a stack trace - in the window before the lifespan has built it."""
    if host is None:
        raise HTTPException(503, "MCP host is not started yet")
    return host


def _require_registry() -> ToolRegistry:
    if registry is None:
        raise HTTPException(503, "tool registry is not built yet")
    return registry
enabled_servers: set = set()


def _try_project_procmon_summary(session, artifact_id: str, tool: str, result: dict) -> dict | None:
    """If a Procmon parse returned JSON, project aggregate runtime nodes into the Evidence Graph."""
    if not result or result.get("is_error") or "procmon" not in (tool or "").lower():
        return None
    text = result.get("text", "") if isinstance(result, dict) else str(result)
    if not text.strip().startswith("{"):
        return None
    try:
        from . import evidence_graph as _eg
        summary = json.loads(text)
        g = _eg.for_session(session)
        g.project_procmon_summary(artifact_id, summary)
        for a in getattr(session, "artifacts", []) or []:
            if a.get("id") == artifact_id:
                a["parsed"] = True
                a["parsed_by"] = tool
                a["parse_summary"] = {
                    "events_loaded": summary.get("events_loaded"),
                    "events_matched": summary.get("events_matched", summary.get("events_loaded")),
                    "total_events_seen": summary.get("total_events_seen"),
                    "top_operations": summary.get("top_operations", [])[:8],
                }
                break
        session.persist()
        return summary
    except Exception as exc:  # noqa: BLE001
        logging.getLogger("reforge").warning("Procmon graph projection failed: %s", exc)
        return None


def _load_enabled() -> set:
    configured = set(config.load_server_config())
    state = {}
    if config.SERVERS_STATE_FILE.is_file():
        try:
            state = json.loads(config.SERVERS_STATE_FILE.read_text(encoding="utf-8"))
        except Exception:
            state = {}
    return {n for n in configured if state.get(n, True)}   # default: enabled


def _save_enabled() -> None:
    configured = list(config.load_server_config())
    state = {n: (n in enabled_servers) for n in configured}
    config.SERVERS_STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global host, registry, enabled_servers
    host = MCPHost(config.load_server_config())
    enabled_servers = _load_enabled()
    await host.connect_all(enabled=enabled_servers)
    registry = ToolRegistry(host)
    try:
        from .job_manager import manager as _jm
        _jm.set_persist_dir(str(config.JOBS_DIR))
        restored = _jm.load_persisted()
        if restored:
            logging.getLogger("reforge").info("Restored %d job(s) from disk", restored)
    except Exception as exc:
        logging.getLogger("reforge").warning("Job persistence unavailable: %s", exc)
    try:
        kb = get_kb()
        logging.getLogger("reforge").info(
            "Methodology KB: %d documents, %d chunks", len(kb.sources), len(kb.chunks))
    except Exception as exc:
        logging.getLogger("reforge").warning("Knowledge base unavailable: %s", exc)
    logging.getLogger("reforge").info(
        "MCP host ready: %d tools, errors=%s", len(host.tools), host.errors)
    _log = logging.getLogger("reforge")
    # The security posture is reported in full at every start. An operator must be able to see,
    # without reading any file, exactly what this instance will and will not do unattended.
    _log.info("Profile: %s | safety=%s (approval gate %s) | workspace=%s | external paths=%s",
              config.DEPLOYMENT_PROFILE, config.SAFETY_MODE,
              "ON" if config.REQUIRE_APPROVAL else "OFF",
              config.WORKSPACE_DIR, config.ALLOW_OUTSIDE_WORKSPACE)
    _exec = execution.describe(config)
    _log.info("Execution: best isolation=%s | dynamic execution %s",
              _exec["best_isolation"],
              "PERMITTED UNISOLATED" if _exec["unisolated_execution_permitted"]
              else ("allowed" if _exec["dynamic_execution_allowed"] else "REFUSED"))
    if _exec["unisolated_execution_permitted"]:
        _log.warning("Code from an analysed sample will run in THIS process with YOUR privileges. "
                     "There is no isolation. Set allow_unisolated_execution=false to refuse it.")
    _log.info("Model egress: profile=%s | provider=%s | %s",
              config.OPERATING_PROFILE, config.LLM_PROVIDER,
              {"offline_deterministic": "no model is called at all",
               "local_only": "nothing leaves this host",
               "hybrid": "raw bytes and decompiled code stay local",
               "frontier": "cloud permitted; every request is classified, redacted and recorded",
               }.get(config.OPERATING_PROFILE, "unknown profile"))
    if config.SAFETY_MODE == "autonomous":
        _log.warning("safety_mode=autonomous - risky actions run WITHOUT approval. "
                     "This was explicitly configured; it is not the default.")
    if config.ALLOW_OUTSIDE_WORKSPACE:
        _log.warning("allow_outside_workspace=true - files outside %s can be analyzed, and path "
                     "confinement degrades to an incomplete deny-list.", config.WORKSPACE_DIR)
    if config.AUTH_REQUIRED:
        if config.AUTH_TRUST_LOCALHOST:
            _log.warning("auth_trust_localhost=true - ANY local process reaches the API "
                         "unauthenticated. Intended for single-user workstations only.")
        # The bootstrap link is the only way to learn an auto-generated token, so it is printed
        # once here and nowhere else. Visiting it exchanges the token for an HttpOnly cookie and
        # redirects to a clean URL, so the secret does not persist in the address bar or history.
        _log.info("Auth enabled. Open this link ONCE to authenticate this browser:\n"
                  "    http://%s:%s/?token=%s", config.HOST, config.PORT, config.AUTH_TOKEN)
    else:
        _log.warning("AUTH DISABLED - the /api endpoints are open to anyone who can reach them.")
    if config.RETENTION_DAYS:
        try:
            from . import db as _db

            swept = _db.sweep_expired()
            if swept.get("marked"):
                _log.warning("Retention: %d project(s) past %d days are now hidden and "
                             "recoverable. They are not erased until purge_expired() is run.",
                             swept["marked"], config.RETENTION_DAYS)
        except Exception as exc:              # noqa: BLE001 - never block startup on retention
            _log.error("retention sweep failed: %s", exc)

    drift = config.legacy_drift()
    if drift:
        _log.warning(
            "reforge/config.py still carries legacy values that are NOT active: %s. "
            "Settings now live in %s; edit them there or via the Settings UI.",
            ", ".join(f"{k}={v['in_config_py']!r} (active: {v['active']!r})"
                      for k, v in drift.items()),
            config.SETTINGS_FILE)
    yield
    await host.aclose()


API_VERSION = "v1"
API_PREFIX = f"/api/{API_VERSION}"

app = FastAPI(
    title="ReTrace API",
    version=_pkg_version,
    description=(
        "Evidence-first Application Security Testing for binaries.\n\n"
        f"The versioned prefix `{API_PREFIX}` is canonical. The unversioned `/api/...` paths are "
        "kept as a compatibility alias for existing clients and the bundled SPA, and will be "
        "removed in a future major version - see docs/ROADMAP.md."
    ),
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------- uniform error model
class APIError(Exception):
    """An error with a machine-readable code.

    Handlers previously raised bare HTTPException with a human sentence as the detail, in two
    languages, so a client had no way to react to an error other than by matching prose. Every
    error now answers with the same envelope and a stable `code`.
    """

    def __init__(self, code: str, message: str, status: int = 400, **context):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
        self.context = context


def _error_body(code: str, message: str, status: int, **context) -> dict:
    body = {"error": {"code": code, "message": message, "status": status}}
    if context:
        body["error"]["context"] = context
    return body


# Status -> stable code, for the HTTPExceptions raised across the existing handlers.
_CODE_FOR_STATUS = {
    400: "bad_request", 401: "unauthorized", 403: "forbidden", 404: "not_found",
    409: "conflict", 413: "payload_too_large", 422: "validation_error",
    500: "internal_error", 502: "upstream_error", 503: "unavailable", 507: "insufficient_storage",
}


if config.CORS_ALLOW_ORIGINS:
    # Not installed by default: with no CORS headers a browser already refuses to *read* a
    # cross-origin reply, which is the correct posture for a bundled same-origin SPA. Adding a
    # permissive policy "so it works" is how that protection gets thrown away.
    from fastapi.middleware.cors import CORSMiddleware

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(config.CORS_ALLOW_ORIGINS),
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["X-Reforge-Token", "Content-Type"],
    )


@app.exception_handler(APIError)
async def _api_error_handler(_request: Request, exc: APIError):
    return JSONResponse(_error_body(exc.code, exc.message, exc.status, **exc.context),
                        status_code=exc.status)


@app.exception_handler(HTTPException)
async def _http_error_handler(_request: Request, exc: HTTPException):
    code = _CODE_FOR_STATUS.get(exc.status_code, "error")
    detail = exc.detail if isinstance(exc.detail, str) else json.dumps(exc.detail, default=str)
    return JSONResponse(_error_body(code, detail, exc.status_code),
                        status_code=exc.status_code, headers=getattr(exc, "headers", None))


@app.exception_handler(RequestValidationError)
async def _validation_error_handler(_request: Request, exc: RequestValidationError):
    return JSONResponse(
        _error_body("validation_error", "the request body or parameters are invalid", 422,
                    fields=[{"loc": [str(p) for p in e.get("loc", [])], "msg": e.get("msg", "")}
                            for e in exc.errors()[:20]]),
        status_code=422)


@app.middleware("http")
async def _version_prefix(request: Request, call_next):
    """Serve the canonical `/api/v1/...` paths from the existing unversioned handlers.

    Rewriting here rather than re-registering ~70 routes keeps one implementation of each
    endpoint: the alternative is two route tables that drift. The response carries the API version
    so a client can tell what answered it.
    """
    path = request.url.path
    if path.startswith(API_PREFIX + "/") or path == API_PREFIX:
        rewritten = "/api" + path[len(API_PREFIX):]
        request.scope["path"] = rewritten
        request.scope["raw_path"] = rewritten.encode("utf-8")
    response = await call_next(request)
    if path.startswith("/api"):
        response.headers["X-API-Version"] = API_VERSION
    return response

from . import auth as _auth

_LOOPBACK = _auth.LOOPBACK


# ---------------------------------------------------------------- cross-origin + rate limiting
_STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}


def _same_origin(request: Request, origin: str) -> bool:
    """Whether `origin` is this server's own origin, compared on scheme+host+port."""
    from urllib.parse import urlparse

    try:
        parsed = urlparse(origin)
    except ValueError:
        return False
    if not parsed.scheme or not parsed.netloc:
        return False
    host_header = request.headers.get("host") or ""
    # Compare against the Host the client actually used, not a configured name: behind a tunnel or
    # a reverse proxy the configured HOST is not what the browser sees.
    return parsed.netloc.lower() == host_header.lower()


def _origin_allowed(request: Request) -> bool:
    """Reject a state-changing API call that a *different* site caused the browser to make.

    This is the control for the drive-by in docs/threat-model.md T-5. A page the analyst visits can
    issue `POST multipart/form-data` at http://127.0.0.1:8000/api/... - that is a "simple" request,
    so there is no preflight to refuse it, and with loopback trusted no credential is needed. The
    attacker cannot read the reply, but the write happens.

    A browser always attaches `Origin` to such a request, so comparing it to our own origin stops
    it. `Sec-Fetch-Site` is checked too where present (a second, independent signal). A request
    with no `Origin` at all is allowed: that is curl, the CLI and every non-browser client, none of
    which can be driven by a web page.
    """
    if request.method not in _STATE_CHANGING:
        return True
    origin = request.headers.get("origin")
    if origin and not _same_origin(request, origin):
        if origin in (getattr(config, "CORS_ALLOW_ORIGINS", None) or []):
            return True
        return False
    site = (request.headers.get("sec-fetch-site") or "").lower()
    if site and site not in ("same-origin", "same-site", "none"):
        return False
    return True


class _RateLimiter:
    """Fixed-window counter per client. Deliberately simple and in-process.

In-process is the whole deployment, so there is nothing to share it with: what this closes is
    a runaway script or a hostile page hammering the API on one machine. Bucketing by minute keeps
    the state to one integer per client and cannot leak memory across a long run.
    """

    def __init__(self):
        self._window = 0
        self._hits: dict = {}

    def allow(self, client: str, limit: int) -> bool:
        if limit <= 0:
            return True
        now_window = int(time.time() // 60)
        if now_window != self._window:
            self._window = now_window
            self._hits.clear()
        count = self._hits.get(client, 0) + 1
        self._hits[client] = count
        return count <= limit


_rate_limiter = _RateLimiter()


@app.middleware("http")
async def _request_policy(request: Request, call_next):
    """Cross-origin and rate policy, applied before authentication."""
    if request.url.path.startswith("/api"):
        if not _origin_allowed(request):
            return JSONResponse(
                _error_body("cross_origin_denied",
                            "This request was initiated by another site. State-changing API calls "
                            "must come from the ReTrace UI itself.", 403,
                            origin=request.headers.get("origin", "")),
                status_code=403)
        client = (request.client.host if request.client else "") or "unknown"
        limit = int(getattr(config, "RATE_LIMIT_PER_MINUTE", 0) or 0)
        if not _rate_limiter.allow(client, limit):
            return JSONResponse(
                _error_body("rate_limited",
                            f"More than {limit} API requests in a minute from this client.", 429),
                status_code=429,
                )
    return await call_next(request)


# ---------------------------------------------------------------------------- identity / authz
def principal_of(request: Request):
    """Who is calling. Resolved once per request by the auth middleware."""
    from .identity import ANONYMOUS

    return getattr(request.state, "principal", None) or ANONYMOUS


def require(request: Request, permission, project_id: str = ""):
    """Enforce a permission, answering 403 with the uniform envelope and auditing the refusal.

    Refusals are audited as well as grants. "Who tried and was stopped" is exactly what an
    investigation needs, and recording only successes makes the trail a record of what went right.
    """
    from . import audit
    from .identity import AccessDenied
    from .identity import require as _require

    actor = principal_of(request)
    try:
        _require(actor, permission, project_id or None)
    except AccessDenied as exc:
        audit.record("authz.denied", principal=actor, project_id=project_id,
                     outcome="denied", permission=permission.value,
                     path=request.url.path, method=request.method)
        raise APIError("forbidden", str(exc), status=403,
                       permission=permission.value) from None
    return actor


def require_project(request: Request, pid: str, permission):
    """Permission check plus project visibility, for a route that names a project.

    Both are needed: holding `project:read` says you may read projects, not that you may read
    *this* one. A caller who cannot see a project is told 404, not 403 - answering 403 would
    confirm the project exists to someone with no right to know that.
    """
    from . import audit
    from .session import can_access

    actor = require(request, permission, pid)
    session = store.get(pid)
    if session is None:
        raise APIError("not_found", "project not found", status=404)
    if not can_access(actor, session):
        audit.record("authz.denied", principal=actor, project_id=pid, outcome="denied",
                     permission=permission.value, reason="not a member of this project")
        raise APIError("not_found", "project not found", status=404)
    return actor, session


def _matched_route(request: Request):
    """The route template this request will be dispatched to, resolved before dispatch."""
    return _match(request)[0]


def _match(request: Request):
    """(route, path_params) for this request, resolved before dispatch.

    Starlette records the matched route on the scope only *during* dispatch, which is after the
    middleware has had to decide. Matching here against the same ordered route table gives the
    same answer the router will reach, and hands back the captured path parameters - which is how
    the middleware knows which project a request is about without each handler telling it.
    """
    from starlette.routing import Match

    for route in app.router.routes:
        match, child = route.matches(request.scope)
        if match is not Match.NONE:
            return route, (child or {}).get("path_params", {}) or {}
    return None, {}


#: Path parameters that name a project. `session_id` is the same thing under an older name.
_PROJECT_PARAMS = ("pid", "session_id", "project_id")


def _project_id_of(path_params: dict) -> str:
    for key in _PROJECT_PARAMS:
        value = path_params.get(key)
        if value:
            return str(value)
    return ""


@app.middleware("http")
async def _observe(request: Request, call_next):
    """Correlation id, timing and counters for every request.

    Outermost middleware so it sees the real outcome, including requests the policy and auth
    middlewares refuse — a deployment refusing half its traffic is exactly what the metrics should
    show, and a filter that only counts what got through would hide it.
    """
    correlation_id = request.headers.get("X-Correlation-Id") or observability.new_correlation_id()
    observability.set_context(correlation_id=correlation_id)
    started = time.perf_counter()
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        return response
    finally:
        elapsed = time.perf_counter() - started
        route = getattr(_matched_route(request), "path", request.url.path)
        observability.METRICS.increment(
            "retrace_http_requests_total", help="HTTP requests by route, method and status.",
            route=route, method=request.method, status=str(status))
        observability.METRICS.observe(
            "retrace_http_request_seconds", elapsed,
            help="HTTP request duration in seconds.", route=route)
        try:
            response.headers["X-Correlation-Id"] = correlation_id
        except (NameError, AttributeError):
            pass


@app.middleware("http")
async def _route_policy(request: Request, call_next):
    """Default-deny authorization for every API route.

    A route with no entry in `route_policy.ROUTE_PERMISSIONS` is refused. That is the point: an
    endpoint added without deciding who may call it fails loudly in development instead of
    shipping open. Per-project checks stay in the handlers - this answers "may this principal do
    this kind of thing at all", not "may they do it to this project".
    """
    path = request.url.path
    if not path.startswith("/api") or request.method in ("OPTIONS", "HEAD"):
        return await call_next(request)

    route, path_params = _match(request)
    template = getattr(route, "path", "") if route else ""
    declared, policy = route_policy.lookup(request.method, template)

    if not declared:
        logging.getLogger("reforge").error(
            "DEFAULT DENY: %s %s (template %r) has no entry in route_policy.ROUTE_PERMISSIONS. "
            "Declare it there - every API route must state who may call it.",
            request.method, path, template)
        return JSONResponse(
            _error_body("route_not_authorized",
                        "This endpoint has no declared authorization policy and is refused.",
                        403),
            status_code=403)

    if policy != route_policy.PUBLIC:
        actor = principal_of(request)
        try:
            permission = Permission(policy)
        except ValueError:                      # a typo in the table must not fail open
            logging.getLogger("reforge").error(
                "route_policy declares unknown permission %r for %s %s", policy,
                request.method, template)
            return JSONResponse(
                _error_body("route_not_authorized",
                            "This endpoint's authorization policy is invalid and is refused.",
                            403),
                status_code=403)
        if not actor.can(permission):
            audit.record("authz.denied", principal=actor, outcome="denied",
                         permission=permission.value, path=path, method=request.method)
            return JSONResponse(
                _error_body("forbidden",
                            f"{actor.subject or 'anonymous'} lacks {permission.value}", 403,
                            permission=permission.value),
                status_code=403)

        # Ownership, centrally. Holding `project:read` says you may read projects, not that you
        # may read *this* one - and 29 routes read or wrote a project with only the permission
        # check behind them. Doing this per handler is what left those 29 behind, so it is done
        # here, once, for every route whose path names a project.
        project_id = _project_id_of(path_params)
        if project_id:
            from .session import can_access

            session = store.get(project_id)
            if session is not None and not can_access(actor, session):
                audit.record("authz.denied", principal=actor, project_id=project_id,
                             outcome="denied", permission=permission.value,
                             reason="not a member of this project",
                             path=path, method=request.method)
                # 404, not 403: answering 403 confirms the project exists to someone with no
                # right to know that.
                return JSONResponse(
                    _error_body("not_found", "project not found", 404), status_code=404)
            observability.set_context(project=project_id)
        observability.set_context(actor=actor.subject or "-")
    return await call_next(request)


@app.middleware("http")
async def _auth_guard(request: Request, call_next):
    """Centralized auth for the API.

    The credential is taken from the `X-Reforge-Token` header (automation) or the `reforge_token`
    cookie set by the bootstrap link (browser). It is deliberately NOT read from the query string
    any more: a token in a URL ends up in access logs, shell history, browser history and Referer
    headers. `GET /` still accepts `?token=` once, to exchange it for the cookie.

    Static assets stay open; the SPA itself is not a secret.
    """
    tok = (request.headers.get("X-Reforge-Token")
           or request.cookies.get("reforge_token") or "")
    client = (request.client.host if request.client else "") or ""
    allowed = _auth.authorize(
        request.url.path, request.method, client,
        token_provided=tok, token_expected=config.AUTH_TOKEN,
        auth_required=config.AUTH_REQUIRED, trust_localhost=config.AUTH_TRUST_LOCALHOST)
    if allowed and request.url.path.startswith("/api"):
        from . import identity_providers as _idp
        from .identity import ANONYMOUS

        try:
            request.state.principal = _idp.resolve(request, config)
        except _idp.AuthenticationError as exc:
            return JSONResponse(_error_body("unauthorized", str(exc), 401), status_code=401)
        except _idp.IdentityProviderUnavailable as exc:
            # 503, not 401: the credential may be perfectly good and we simply cannot check it.
            # Answering 401 would tell an operator their users' logins broke when the IdP is down.
            return JSONResponse(
                _error_body("identity_provider_unavailable", str(exc), 503), status_code=503)
        if request.state.principal is ANONYMOUS or request.state.principal.is_anonymous():
            # The shared token got them through the door; it does not say who they are. On a
            # profile that requires an identity provider, that is not enough.
            if config.IDENTITY_PROVIDER != "local" or config.DEPLOYMENT_PROFILE != "workstation":
                return JSONResponse(
                    _error_body("unauthenticated",
                                "This deployment requires an authenticated identity. Present a "
                                "bearer token from the configured identity provider.", 401),
                    status_code=401)

    if not allowed:
        return JSONResponse(
            _error_body("unauthorized",
                        "Missing or invalid credential. Open the bootstrap link printed at "
                        "startup once to authenticate this browser, or send the X-Reforge-Token "
                        "header.", 401),
            status_code=401)
    return await call_next(request)


class MessageIn(BaseModel):
    session_id: str
    text: str
    mode: str | None = None        # auto | static | dynamic
    llm_route: str | None = "api"  # api/cloud for chat by default; local-assist uses local endpoint


class ApproveIn(BaseModel):
    session_id: str
    approval_id: str
    decision: str  # "approve" | "deny"


class LocalAssistIn(BaseModel):
    session_id: str
    kind: str                         # strings | imports | evidence | graph | node
    question: str | None = None
    context: dict | list | str | None = None


def _compact_json(obj, limit: int = 6500) -> str:
    try:
        text = json.dumps(obj, ensure_ascii=False, indent=2, default=str)
    except Exception:
        text = str(obj)
    if len(text) <= limit:
        return text
    return text[:limit] + "\n...[truncated]"


def _local_assist_prompt(kind: str, question: str, context: str) -> tuple[str, str]:
    system = (
        "You are a local assistant for vulnerability research on benign software. "
        "Answer only with operational observations based on the provided context. "
        "Do not invent evidence, do not ask for more data, do not generate exploits. "
        "Output at most 220 words, short bullets, no raw JSON."
    )
    recipes = {
        "strings": (
            "Analyze only the extracted string groups present in the context. "
            "Every observation must cite a real string in backticks and its group. "
            "Do not talk about APIs, imports or findings unless they appear as strings in the context. "
            "If there is no strong link to the Evidence Graph or a callsite, say so explicitly. "
            "If the operator asks for reclassification, use applicable REASSIGN lines before the summary."
        ),
        "imports": (
            "Analyze imports/APIs. Group by attack surface, explain why it matters "
            "and point out the callsites or data-flow to look for next."
        ),
        "evidence": (
            "Analyze technical evidence. Distinguish facts, gaps, and useful links to "
            "findings, sinks, sources or runtime."
        ),
        "graph": (
            "Analyze the summarized Evidence Graph. Prioritize nodes, chains and next "
            "checks without repeating the whole graph."
        ),
        "node": (
            "Analyze an Evidence Graph node. Explain context, important relationships, "
            "why it matters and next checks."
        ),
    }
    fmt = (
        "If you need to reclassify, put lines first in this format: REASSIGN: <full string> => <category>\n"
        "Then use:\n"
        "## Strings reading\n- max 3 bullets, each with `string`, group and meaning\n"
        "## Evidence Graph link\n- max 3 bullets, each with `string` and the node/relationship to look for\n"
        "## False positives\n- max 2 bullets, only if useful"
        if kind == "strings" else
        "## Summary\n- max 2 bullets\n## Signals\n- max 4 bullets\n## Next steps\n- max 3 bullets"
    )
    user = (
        f"Task: {recipes.get(kind, recipes['graph'])}\n"
        f"Operator question: {question or 'Provide an operational summary.'}\n\n"
        f"Required format:\n{fmt}\n\n"
        f"Compact context:\n{context}"
    )
    return system, user


@app.get("/api/status")
async def status():
    servers = {}
    for name in config.load_server_config():
        connected = any(t.server == name for t in host.tools.values())
        servers[name] = {
            "connected": connected,
            "enabled": name in enabled_servers,
            "tool_count": sum(1 for t in host.tools.values() if t.server == name),
            "error": host.errors.get(name),
        }
    health = host.health()
    for name in servers:
        servers[name].update(health.get(name, {}))
    reachable, llm_error = await llm.local_reachable()
    # An SDK that is not installed trumps everything the probe can say: the server may be fine
    # and the model pulled, and no turn will ever reach it.
    llm_error = llm.provider_problem() or llm_error
    return {
        "provider": config.LLM_PROVIDER,
        "llm_available": config.LLM_PROVIDER != "none",
        # None = not applicable (no provider, or a cloud one that is not probed from here)
        "llm_reachable": reachable,
        "llm_error": llm_error,
        "llm_base_url": config.LOCAL_BASE_URL if config.LLM_PROVIDER == "local" else "",
        "model": config.active_model(),
        "total_tools": len(host.tools),
        "safety_mode": config.SAFETY_MODE,
        "deployment_profile": config.DEPLOYMENT_PROFILE,
        "require_approval": config.REQUIRE_APPROVAL,
        "execution": execution.describe(config),
        "operating_profile": config.OPERATING_PROFILE,
        "lang": config.UI_LANG,
        "auth_required": config.AUTH_REQUIRED,
        "knowledge": {"docs": len(get_kb().sources), "chunks": len(get_kb().chunks)},
        "servers": servers,
    }


@app.get("/api/servers")
async def list_servers():
    """Per-server status + the tools each one exposes (name + one-line description)."""
    return host.server_status(config.load_server_config(), enabled_servers)


class ServerToggleIn(BaseModel):
    enabled: bool


@app.post("/api/servers/{name}")
async def toggle_server(name: str, body: ServerToggleIn, request: Request):
    actor = require(request, Permission.SERVER_MANAGE)
    audit.record("server.toggle", principal=actor, server=name, enabled=body.enabled)
    configured = config.load_server_config()
    if name not in configured:
        raise HTTPException(404, "unknown MCP server")
    mcp = _require_host()
    if body.enabled:
        enabled_servers.add(name)
        connected = await mcp.connect_one(name)
    else:
        enabled_servers.discard(name)
        await mcp.disconnect_one(name)
        connected = False
    _require_registry().rebuild()
    _save_enabled()
    return {"name": name, "enabled": body.enabled, "connected": connected,
            "error": mcp.errors.get(name),
            "tool_count": sum(1 for t in mcp.tools.values() if t.server == name)}


class TargetIn(BaseModel):
    path: str


@app.post("/api/projects/{pid}/target")
async def set_target(pid: str, body: TargetIn):
    session = store.get(pid)
    if not session:
        raise HTTPException(404, "project not found")
    try:
        resolved = workspace.safe_resolve(body.path)
    except UnsafePathError as exc:
        raise HTTPException(400, f"invalid path: {exc}")
    session.target_path = str(resolved)
    session.static_done = False
    session.persist()
    await agent._ensure_static(session)        # always-on static analysis, even with no LLM
    return {"ok": True, "target": session.target_path,
            "findings": session.findings, "static_done": session.static_done}


@app.post("/api/projects/{pid}/upload")
async def upload_sample(pid: str, request: Request, file: UploadFile = File(...)):
    actor, _s = require_project(request, pid, Permission.ARTIFACT_UPLOAD)
    """Import a binary into the project under the same upload policy as any other artifact.

    This used to be its own inline `while True: out.write(chunk)` loop with no size limit, no
    quota, no free-space check and no cleanup - a second, unguarded way into the same directory.
    It now shares the single enforced path, so a limit cannot be bypassed by choosing an endpoint.
    """
    session = store.get(pid)
    if not session:
        raise HTTPException(404, "project not found")
    try:
        rec = await asyncio.to_thread(
            artifacts_mod.store_stream, pid, file.filename or "sample.bin", file.file,
            1 << 20, _declared_upload_size(request))
    except artifacts_mod.UploadRejected as exc:
        raise HTTPException(exc.status, str(exc))
    return {"ok": True, "path": rec["path"], "name": rec["name"], "size": rec["size"],
            "sha256": rec["sha256"], "type": rec["type"],
            "original_name": rec["original_name"], "type_mismatch": rec["type_mismatch"]}


def _declared_upload_size(request: Request) -> int | None:
    """The client's Content-Length, used only to refuse early.

    It is a hint from an untrusted client, never a substitute for counting the bytes that actually
    arrive - `_stream_to_temp` enforces the real limit as they come in.
    """
    raw = request.headers.get("content-length")
    try:
        return int(raw) if raw is not None else None
    except ValueError:
        return None


@app.post("/api/projects/{pid}/artifacts")
async def upload_artifact(pid: str, request: Request, file: UploadFile = File(...)):
    actor, _s = require_project(request, pid, Permission.ARTIFACT_UPLOAD)
    """Upload a generic artifact (Procmon XML, pcap, logs, dumps, …) into the project.

    The file is stored safely, type-detected, and registered on the session. Returns the artifact
    record (including the detected type and suggested MCP routing) so the UI/agent can parse it.
    """
    session = store.get(pid)
    if not session:
        raise HTTPException(404, "project not found")
    # Stream to disk in chunks so a multi-hundred-MB Procmon XML is never fully held in RAM,
    # under the size/count/quota/free-space policy in artifacts.check_can_accept.
    declared = _declared_upload_size(request)
    try:
        rec = await asyncio.to_thread(
            artifacts_mod.store_stream, pid, file.filename or "artifact.bin", file.file,
            1 << 20, declared)
    except artifacts_mod.UploadRejected as exc:
        raise HTTPException(exc.status, str(exc))
    # Offline static overview: for small files run it immediately so the Artifacts panel shows an
    # at-a-glance summary (Procmon event counts, PCAP talkers, PE capabilities, …) with no LLM and
    # no live MCP server. Large files defer to an explicit "Analyze" action to bound CPU/time.
    if overview_mod.should_auto_run(rec):
        rec["overview"] = await asyncio.to_thread(overview_mod.build_overview, rec)
        rec["overview_status"] = "done"
        # Offline heuristic behavioral analysis (deterministic, no LLM) for trace/binary types.
        rec["heuristics"] = await asyncio.to_thread(heuristics.analyze, rec)
        rec["heuristics_status"] = "error" if rec["heuristics"].get("error") else "done"
    else:
        rec["overview_status"] = "deferred"   # too large for auto; user triggers it
        rec["heuristics_status"] = "deferred"
    artifacts_mod.register(session, rec)
    # Leave a trace in the conversation so the agent KNOWS a file was uploaded and how to load it.
    # Without this, the model has no idea the artifact exists and tries to guess a path.
    routing = rec.get("routing") or {}
    hint = (f" To analyse it, call parse_artifact(artifact_id=\"{rec['id']}\")."
            if routing.get("server") and routing.get("tool")
            else f" Use read_artifact(artifact_id=\"{rec['id']}\") to inspect it.")
    try:
        session.messages.append({"role": "user", "content":
            (f"[SYSTEM] The operator uploaded an artifact: id={rec['id']}, "
             f"name={rec['name']}, type={rec['type']}, size={rec['size']} bytes.{hint} "
             "Do not guess paths on disk: use the artifact meta-tools.")})
        session.persist()
    except Exception:
        pass
    return {"ok": True, "artifact": rec}


@app.get("/api/projects/{pid}/artifacts")
async def list_artifacts(pid: str):
    """List artifacts registered on the project."""
    session = store.get(pid)
    if not session:
        raise HTTPException(404, "project not found")
    return {"artifacts": getattr(session, "artifacts", [])}


@app.post("/api/projects/{pid}/artifacts/{aid}/overview")
async def artifact_overview(pid: str, aid: str):
    """Compute (or recompute) the offline static overview for an artifact.

    Offline and bounded: no LLM, no live MCP server, the file is never executed. Used for large
    artifacts whose overview was deferred at upload, or to refresh a stale one.
    """
    session = store.get(pid)
    if not session:
        raise HTTPException(404, "project not found")
    rec = artifacts_mod.get(session, aid)
    if not rec:
        raise HTTPException(404, "artifact not found")
    ov = await asyncio.to_thread(overview_mod.build_overview, rec)
    rec["overview"] = ov
    rec["overview_status"] = "error" if ov.get("error") else "done"
    # Recompute the offline heuristic analysis as well (deferred large files land here).
    he = await asyncio.to_thread(heuristics.analyze, rec)
    rec["heuristics"] = he
    rec["heuristics_status"] = "error" if he.get("error") else "done"
    session.persist()
    return {"ok": not ov.get("error"), "artifact_id": aid, "overview": ov,
            "overview_status": rec["overview_status"],
            "heuristics": he, "heuristics_status": rec["heuristics_status"]}


@app.get("/api/projects/{pid}/raw-export")
async def raw_export(pid: str, request: Request, download: int = 0):
    actor, _sess = require_project(request, pid, Permission.RAW_EXPORT)
    audit.record("raw.export", principal=actor, project_id=pid, download=bool(download))
    """Full Markdown dump of everything detected/used/done in this investigation.

    Offline and deterministic — no LLM is called. Intended to be pasted into any LLM to generate a
    report, or archived. With download=1 it is served as a .md attachment.
    """
    session = store.get(pid)
    if not session:
        raise HTTPException(404, "project not found")
    from . import raw_export as _raw
    md = await asyncio.to_thread(_raw.build_markdown, session)
    if download:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", (getattr(session, "name", None) or pid))
        return Response(content=md, media_type="text/markdown",
                        headers={"Content-Disposition": f'attachment; filename="reforge_{safe}.md"'})
    return {"ok": True, "markdown": md, "bytes": len(md)}


class ArtifactParseIn(BaseModel):
    tool: str | None = None        # override qualified tool, e.g. "procmon__procmon_load_xml"
    args: dict | None = None       # extra args merged into the call (e.g. process_name filter)


@app.post("/api/projects/{pid}/artifacts/{aid}/parse")
async def parse_artifact(pid: str, aid: str, body: ArtifactParseIn | None = None):
    """Resolve an artifact to its on-disk path and hand it to the appropriate MCP tool.

    This is the bridge that fixes "Procmon says 0 events": the uploaded file's real path is
    injected into the MCP tool's path argument (default routing comes from the detected type).
    """
    session = store.get(pid)
    if not session:
        raise HTTPException(404, "project not found")
    rec = artifacts_mod.get(session, aid)
    if not rec:
        raise HTTPException(404, "artifact not found")
    try:
        resolved = artifacts_mod.resolve_path(session, aid)
    except (KeyError, UnsafePathError) as exc:
        raise HTTPException(400, f"invalid artifact path: {exc}")

    routing = rec.get("routing") or {}
    body = body or ArtifactParseIn()
    if body.tool:
        qualified = body.tool
        path_arg = (body.args or {}).get("__path_arg") or "path"
    elif routing.get("server") and routing.get("tool"):
        qualified = f"{routing['server']}{'__'}{routing['tool']}"
        path_arg = routing.get("path_arg", "path")
    else:
        raise HTTPException(400, "no MCP tool suggested for this artifact type; "
                                 "specify 'tool' explicitly")

    if host is None:
        raise HTTPException(503, "MCP host is not started yet")
    call_args = {path_arg: resolved}
    for k, v in (body.args or {}).items():
        if not k.startswith("__"):
            call_args[k] = v
    result = await host.call(qualified, call_args)
    graph_summary = _try_project_procmon_summary(session, aid, qualified, result)
    return {"ok": not result.get("is_error", False),
            "artifact_id": aid, "tool": qualified, "path": resolved,
            "result": result, "graph_projected": bool(graph_summary),
            "graph_summary": graph_summary}


class DiffIn(BaseModel):
    path_a: str
    path_b: str


@app.post("/api/diff")
async def binary_diff(body: DiffIn):
    try:
        pa = str(workspace.safe_resolve(body.path_a))
        pb = str(workspace.safe_resolve(body.path_b))
    except UnsafePathError as exc:
        raise HTTPException(400, f"invalid path: {exc}")
    res = await asyncio.to_thread(bindiff.diff, pa, pb)
    return res


class ReportExportIn(BaseModel):
    markdown: str
    fmt: str                       # html | pdf | docx
    name: str | None = None


@app.post("/api/report/export")
async def report_export_endpoint(body: ReportExportIn, request: Request):
    actor = require(request, Permission.REPORT_EXPORT)
    audit.record("report.export", principal=actor,
                 fmt=getattr(body, "fmt", "") or getattr(body, "format", ""))
    name = (body.name or "report").strip().replace(" ", "_") or "report"
    fmt = body.fmt.lower()
    title = f"ReTrace Report — {body.name or ''}".strip(" —")
    media = {
        "html": "text/html; charset=utf-8",
        "pdf": "application/pdf",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    }.get(fmt)
    if not media:
        raise HTTPException(400, "unsupported format (html|pdf|docx)")

    if fmt == "html":
        data, err = report_export.to_html(body.markdown, title).encode("utf-8"), ""
    elif fmt == "pdf":
        data, err = await asyncio.to_thread(report_export.to_pdf, body.markdown, title)
    else:
        from . import report_docx
        data, err = await asyncio.to_thread(report_docx.to_docx, body.markdown, title)
    if err:
        raise HTTPException(503, err)
    return Response(content=data, media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="{name}.{fmt}"'})


@app.get("/api/report/template")
async def report_template(fmt: str = "md"):
    """Download a blank report template (md or docx), same structure as the generated report."""
    from . import report_pt
    md = report_pt.template(lang=config.UI_LANG)
    fname = "template_report"
    if fmt == "docx":
        from . import report_docx
        data, err = await asyncio.to_thread(report_docx.to_docx, md, "Template PT")
        if err:
            raise HTTPException(503, err)
        return Response(content=data,
                        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        headers={"Content-Disposition": f'attachment; filename="{fname}.docx"'})
    return Response(content=md, media_type="text/markdown; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{fname}.md"'})


class AnalyzeIn(BaseModel):
    file_path: str


@app.post("/api/analyze")
async def analyze(body: AnalyzeIn):
    """Offline static triage — works with no LLM and no MCP servers."""
    try:
        resolved = str(workspace.safe_resolve(body.file_path))
    except UnsafePathError as exc:
        raise HTTPException(400, f"invalid path: {exc}")
    return static_analysis.analyze(resolved)


class SettingsIn(BaseModel):
    provider: str | None = None            # auto | anthropic | local | none
    anthropic_model: str | None = None
    anthropic_api_key: str | None = None
    local_model: str | None = None
    local_base_url: str | None = None
    require_approval: bool | None = None   # legacy toggle; can only tighten (see config.apply_runtime)
    safety_mode: str | None = None         # safe | assisted | autonomous
    deployment_profile: str | None = None  # workstation | team
    persist: bool = False                  # save to STATE_ROOT/settings.json (secrets -> secrets store)


@app.post("/api/local-assist")
async def local_assist(body: LocalAssistIn):
    """Short, local-only LLM helper for UI sections.

    Used by Strings, Imports, Evidence and the Evidence Graph. It intentionally avoids
    the agent/tool loop and sends only compact context to prevent context bloat.
    """
    session = store.get(body.session_id)
    if not session:
        raise HTTPException(404, "project not found")
    local = llm.get_llm("local")
    if not local.available:
        raise HTTPException(503, "local LLM is not configured")
    ctx = _compact_json(body.context, 6500)
    system, user = _local_assist_prompt((body.kind or "graph").lower(), body.question or "", ctx)
    try:
        text = await local.complete(system, [], user)
        usage = getattr(local, "last_usage", None)
        if usage:
            try:
                from . import llm_cost
                session.add_llm_usage(llm_cost.usage_entry("local", config.LOCAL_MODEL, usage, None))
                session.persist()
            except Exception:
                pass
        out = {"ok": True, "provider": "local", "model": config.LOCAL_MODEL,
               "text": (text or "").strip()[:2400]}
        # For the Strings tab, the model emits `REASSIGN: <string> => <category>` lines. Apply them
        # SERVER-SIDE so the move actually happens and is persisted (survives reload, honoured by
        # graph/report/exports), not just reflected in the live browser map.
        if (body.kind or "").lower() == "strings":
            try:
                res = string_signal.apply_reassignments(session, text or "")
                out["reassignments"] = res
            except Exception as exc:  # noqa: BLE001 - reassignment must never break the assist reply
                out["reassignments"] = {"applied": [], "skipped": [], "error": str(exc)}
        return out
    except Exception as exc:
        raise HTTPException(502, f"local LLM error: {exc}")


@app.get("/api/settings")
async def get_settings(request: Request):
    require(request, Permission.SETTINGS_READ)
    return config.current_settings()


@app.post("/api/settings")
async def update_settings(body: SettingsIn, request: Request):
    actor = require(request, Permission.SETTINGS_WRITE)
    audit.record("settings.write", principal=actor,
                 changed=sorted(k for k, v in body.model_dump().items()
                                if v is not None and k != "anthropic_api_key"),
                 safety_mode=body.safety_mode, persist=body.persist)
    try:
        config.apply_runtime(
            provider=body.provider, anthropic_model=body.anthropic_model,
            anthropic_api_key=body.anthropic_api_key, local_model=body.local_model,
            local_base_url=body.local_base_url, require_approval=body.require_approval,
            safety_mode=body.safety_mode, deployment_profile=body.deployment_profile)
    except Exception as exc:        # validation rejected the change; keep the running settings
        raise HTTPException(400, f"invalid settings: {exc}")
    llm.reset()
    if body.persist:
        vals = {k: v for k, v in {
            "provider": body.provider, "anthropic_model": body.anthropic_model,
            "anthropic_api_key": body.anthropic_api_key, "local_model": body.local_model,
            "local_base_url": body.local_base_url, "safety_mode": body.safety_mode,
            "deployment_profile": body.deployment_profile}.items() if v is not None}
        try:
            config.persist_settings(vals)
        except Exception as exc:
            return {**config.current_settings(), "persist_error": str(exc)}
    return config.current_settings()


@app.get("/api/whoami")
async def whoami(request: Request):
    """Who the server thinks you are, and what you may do. Never returns a credential."""
    actor = principal_of(request)
    return {
        **actor.describe(),
        "permissions": sorted(p.value for p in actor.global_permissions()),
        "deployment_profile": config.DEPLOYMENT_PROFILE,
        "identity_provider": config.IDENTITY_PROVIDER,
    }


@app.get("/api/support-bundle")
async def support_bundle_endpoint(request: Request):
    """A diagnostic bundle an operator can send without review.

    Carries versions, posture, masked configuration, metrics and the audit chain's integrity -
    and deliberately no sample, finding, evidence, project name or credential. See
    reforge/support_bundle.py for what is excluded and why.
    """
    actor = require(request, Permission.AUDIT_READ)
    payload = support_bundle.build(recent_logs=_RECENT_LOGS.lines())
    audit.record("support_bundle.export", principal=actor, bytes=len(payload))
    return Response(
        payload, media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="retrace-support-bundle.zip"'})


@app.get("/api/metrics")
async def metrics(request: Request, fmt: str = "json"):
    """Technical metrics. `fmt=prometheus` for the text exposition format.

    In-process: a workstation install must not need a metrics backend to be observable. The same
    numbers scrape into one when there is a fleet.
    """
    require(request, Permission.PROJECT_READ)
    if fmt == "prometheus":
        return Response(observability.METRICS.prometheus(), media_type="text/plain; version=0.0.4")
    return {"metrics": observability.METRICS.snapshot(),
            "sli": observability.service_level_indicators()}


@app.get("/api/retention")
async def retention_status(request: Request):
    """What retention would remove, without removing it."""
    require(request, Permission.AUDIT_READ)
    from . import db as _db

    return {"retention_days": config.RETENTION_DAYS,
            "enabled": bool(config.RETENTION_DAYS),
            "pending_purge": _db.purge_expired(confirm=False)}


@app.post("/api/retention/purge")
async def retention_purge(request: Request, grace_days: int = 30, confirm: bool = False):
    """Permanently remove projects soft-deleted longer than `grace_days` ago.

    `confirm=false` (the default) reports what would go and touches nothing. Irreversible
    destruction of customer findings takes two steps, and the first shows you the list.
    """
    actor = require(request, Permission.PROJECT_DELETE)
    from . import db as _db

    result = _db.purge_expired(grace_days=grace_days, confirm=confirm)
    if confirm:
        audit.record("retention.purge", principal=actor, outcome="ok",
                     purged=result["purged"], grace_days=grace_days,
                     project_ids=[p["id"] for p in result["projects"]])
    return result


@app.get("/api/egress")
async def egress_ledger(request: Request, limit: int = 200):
    """What has left this machine: every model request, its data class, provider and model.

    The question a customer under NDA actually asks is "did any of our binary reach a third
    party". This is the answer, and it is readable by anyone who can read the project rather than
    only by an administrator - an analyst must be able to check what their own work sent.
    """
    require(request, Permission.PROJECT_READ)
    return {"profile": config.OPERATING_PROFILE,
            "summary": model_gateway.summary(),
            "entries": model_gateway.ledger(limit=min(limit, 1000))}


@app.get("/api/audit")
async def audit_log(request: Request, limit: int = 200, action: str = "", project_id: str = ""):
    """The audit trail, newest first, with the integrity of its hash chain."""
    require(request, Permission.AUDIT_READ)
    return {"entries": audit.read(limit=min(limit, 1000), action=action, project_id=project_id),
            "integrity": audit.verify()}


@app.post("/api/sessions")
async def new_session():
    return {"session_id": store.create().id}


class ProjectIn(BaseModel):
    name: str


def _transcript(session) -> list:
    items, pending = [], {}
    for m in session.messages:
        role = m.get("role")
        if role == "user":
            c = m.get("content", "")
            if c == agent._NUDGE or c == agent._COMPLETION_CHECK or c.startswith("[Automatic static analysis"):
                continue
            items.append({"t": "user", "text": c})
        elif role == "assistant":
            if m.get("text"):
                items.append({"t": "assistant", "text": m["text"]})
            for tc in m.get("tool_calls", []):
                it = {"t": "tool", "tool": tc["name"], "args": tc.get("input", {}),
                      "result": None, "error": False}
                items.append(it)
                pending[tc["id"]] = it
        elif role == "tool":
            for res in m.get("results", []):
                hit = pending.get(res["id"])
                if hit:
                    hit["result"] = (res.get("content") or "")[:4000]
                    hit["error"] = bool(res.get("is_error"))
    return items


@app.get("/api/projects")
async def list_projects(request: Request):
    actor = require(request, Permission.PROJECT_READ)
    return {"projects": store.list_projects_for(actor)}


@app.post("/api/projects")
async def create_project(body: ProjectIn, request: Request):
    actor = require(request, Permission.PROJECT_CREATE)
    # The creator owns it. Ownership is what makes `can_access` mean anything: without it every
    # project is visible to every caller who holds project:read, which is the model being replaced.
    s = store.create(name=body.name.strip() or None, owner=actor.subject)
    audit.record("project.create", principal=actor, project_id=s.id, name=s.name)
    return {"id": s.id, "name": s.name, "owner": s.owner}


@app.get("/api/projects/{pid}")
async def load_project(pid: str, request: Request):
    require_project(request, pid, Permission.PROJECT_READ)
    s = store.get(pid)
    if not s:
        raise HTTPException(404, "project not found")
    return {"id": s.id, "name": s.name, "target_path": s.target_path, "mode": getattr(s, "mode", "auto"),
            # Whether a turn is running right now. The SPA re-reads this whenever its event stream
            # (re)connects, so a restart mid-turn cannot leave the composer disabled.
            "busy": bool(getattr(s, "busy", False)),
            "findings": s.findings, "evidence": getattr(s, "evidence", []),
            "static_strings": getattr(s, "static_strings", []),
            "static_imports": getattr(s, "static_imports", []),
            "string_overrides": dict(getattr(s, "string_overrides", {}) or {}),
            "llm_usage": getattr(s, "llm_usage", []),
            "usage_summary": s.usage_summary() if hasattr(s, "usage_summary") else {},
            # The static pass already computes all of the below and stores it on the session; it
            # simply was not reachable from the UI, so the target profile, the mitigation audit and
            # the attack surface could never be displayed. Additive — no existing key changed.
            "target_profile": getattr(s, "target_profile", None),
            "attack_surface": getattr(s, "attack_surface", {}),
            "artifacts": getattr(s, "artifacts", []),
            "static_done": bool(getattr(s, "static_done", False)),
            "report_generated": bool(getattr(s, "report_generated", False)),
            "transcript": _transcript(s)}


@app.get("/api/projects/{pid}/assessment")
async def project_assessment(pid: str):
    """Deterministic assessment snapshot: target profile, risk posture, finding buckets,
    attack surface, coverage, workflow phase and recommended next actions.

    One call instead of eight, and entirely offline: every number is derived from state the
    session already holds. No LLM, no network, no subprocess.
    """
    s = store.get(pid)
    if not s:
        raise HTTPException(404, "project not found")
    from . import assessment as _assess
    return _assess.snapshot(s)


@app.get("/api/projects/{pid}/usage")
async def project_usage(pid: str):
    s = store.get(pid)
    if not s:
        raise HTTPException(404, "project not found")
    return {"usage": getattr(s, "llm_usage", []),
            "summary": s.usage_summary() if hasattr(s, "usage_summary") else {}}


@app.get("/api/projects/{pid}/strings")
async def get_strings(pid: str):
    s = store.get(pid)
    if not s:
        raise HTTPException(404, "project not found")
    overrides = dict(getattr(s, "string_overrides", {}) or {})
    return {"strings": getattr(s, "static_strings", []),
            "overrides": overrides,
            "counts": string_signal.grouped_overview(s)["counts"]}


class StringReassignIn(BaseModel):
    # Either provide explicit pairs, or raw LLM text containing REASSIGN lines.
    pairs: list | None = None          # [["<string>", "<category>"], ...]
    text: str | None = None
    clear: bool = False                # when true, drop overrides for the given strings (or all)
    strings: list | None = None        # strings to clear when clear=true (None/empty => clear all)


@app.post("/api/projects/{pid}/strings/reassign")
async def reassign_strings(pid: str, body: StringReassignIn):
    """Apply or clear high-signal string category overrides, persisted on the session.

    This is the authoritative move: it validates each reassignment (allowed category + the string
    must exist) and writes session.string_overrides so the change survives reload and is visible to
    every consumer, not just the live UI. LLM/user input is untrusted; invalid moves are skipped.
    """
    s = store.get(pid)
    if not s:
        raise HTTPException(404, "project not found")

    if body.clear:
        overrides = dict(getattr(s, "string_overrides", {}) or {})
        targets = body.strings if body.strings else list(overrides.keys())
        cleared = [k for k in targets if overrides.pop(k, None) is not None]
        s.string_overrides = overrides
        s.persist()
        return {"ok": True, "cleared": cleared, "override_count": len(overrides)}

    payload = body.pairs if body.pairs else (body.text or "")
    # Normalize [["s","cat"]] pairs into tuples; ignore malformed rows.
    if isinstance(payload, list):
        payload = [(p[0], p[1]) for p in payload if isinstance(p, (list, tuple)) and len(p) >= 2]
    res = string_signal.apply_reassignments(s, payload)
    return {"ok": True, **res}


class StringReclassifyIn(BaseModel):
    query: str | None = ""        # optional filter: only reclassify strings matching this text
    limit: int | None = 160       # max strings submitted to the model in one pass


@app.post("/api/projects/{pid}/strings/reclassify")
async def reclassify_strings(pid: str, body: StringReclassifyIn | None = None):
    """Authoritative LLM reclassification of high-signal strings — it ACTUALLY moves them.

    Forces the local LLM into strict JSON output (not optional REASSIGN lines), validates every move
    against the corpus + allowed categories, and PERSISTS the result to session.string_overrides.
    Returns what was moved, what was skipped (and why-able via counts), and the raw model JSON.
    """
    s = store.get(pid)
    if not s:
        raise HTTPException(404, "project not found")
    if not getattr(s, "static_strings", None):
        raise HTTPException(400, "No strings to analyze: set the target first.")
    local = llm.get_llm("local")
    if not local.available:
        raise HTTPException(503, "Local LLM not configured (Settings → local model).")
    body = body or StringReclassifyIn()
    try:
        res = await string_signal.llm_reclassify(s, local, query=body.query or "",
                                                 limit=int(body.limit or 160))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(502, f"local LLM error: {exc}")
    # Record token usage like the other local-assist paths.
    usage = getattr(local, "last_usage", None)
    if usage:
        try:
            from . import llm_cost
            s.add_llm_usage(llm_cost.usage_entry("local", config.LOCAL_MODEL, usage, None))
            s.persist()
        except Exception:
            pass
    return {"ok": True, **res, "overrides": dict(getattr(s, "string_overrides", {}) or {})}
async def get_imports(pid: str):
    s = store.get(pid)
    if not s:
        raise HTTPException(404, "project not found")
    return {"imports": getattr(s, "static_imports", [])}


@app.get("/api/projects/{pid}/evidence")
async def list_evidence(pid: str):
    s = store.get(pid)
    if not s:
        raise HTTPException(404, "project not found")
    return {"evidence": getattr(s, "evidence", [])}


@app.get("/api/tools")
async def list_tools(q: str = "", phase: str = "", server: str = "", risk_class: str = ""):
    """Search the tool catalog with hybrid retrieval. Returns tool metadata + risk/cost/tags."""
    from .tool_registry import ToolRegistry as _TR
    reg = _TR(_require_host())
    if q:
        qualifieds = reg.search(q, 20, server=server or None,
                                risk_classes=[risk_class] if risk_class else None,
                                phase=phase or None)
        summary = reg.metadata_summary()
        qs = set(qualifieds)
        return {"tools": [t for t in summary if t["qualified"] in qs]}
    return {"tools": reg.metadata_summary()}


@app.get("/api/projects/{pid}/toollog")
async def tool_log(pid: str):
    s = store.get(pid)
    if not s:
        raise HTTPException(404, "project not found")
    return {"log": getattr(s, "investigation_log", [])}


@app.delete("/api/projects/{pid}")
async def delete_project(pid: str, request: Request):
    actor, session = require_project(request, pid, Permission.PROJECT_DELETE)
    audit.record("project.delete", principal=actor, project_id=pid,
                 name=getattr(session, "name", ""),
                 findings=len(getattr(session, "findings", []) or []))
    return {"deleted": store.delete(pid)}


@app.post("/api/message")
async def message(body: MessageIn, request: Request):
    require_project(request, body.session_id, Permission.ANALYSIS_RUN)
    session = store.get(body.session_id)
    if not session:
        raise HTTPException(404, "session not found")
    if session.busy:
        raise HTTPException(409, "session busy")
    if body.mode in ("auto", "static", "dynamic"):
        session.mode = body.mode
    session.task = asyncio.create_task(agent.run_turn(session, _require_host(), _require_registry(),
                                                      body.text, llm_route=body.llm_route or "api"))
    return {"ok": True}


class StopIn(BaseModel):
    session_id: str


@app.post("/api/stop")
async def stop(body: StopIn):
    session = store.get(body.session_id)
    if not session:
        raise HTTPException(404, "session not found")
    t = session.task
    cancelled = t is not None and not t.done()
    if t is not None and cancelled:
        t.cancel()
    session.busy = False
    await session.emit("stopped")
    await session.emit("status", text="Ready", busy=False)
    await session.emit("done")
    return {"stopped": cancelled}


@app.post("/api/approve")
async def approve(body: ApproveIn, request: Request):
    actor = require(request, Permission.APPROVAL_GRANT, body.session_id)
    audit.record("approval." + ("grant" if body.decision == "approve" else "deny"),
                 principal=actor, project_id=body.session_id,
                 approval_id=body.approval_id, decision=body.decision)
    session = store.get(body.session_id)
    if not session:
        raise HTTPException(404, "session not found")
    ok = session.resolve_approval(body.approval_id, body.decision == "approve")
    return {"ok": ok}


@app.get("/api/stream/{session_id}")
async def stream(session_id: str):
    session = store.get(session_id)
    if not session:
        raise HTTPException(404, "session not found")

    async def gen():
        q = session.subscribe()
        try:
            while True:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=15.0)
                except asyncio.TimeoutError:
                    # Keeps proxies and browsers from closing an idle stream; not an event.
                    yield ": keepalive\n\n"
                    continue
                yield f"data: {json.dumps(event, default=str)}\n\n"
        finally:
            session.unsubscribe(q)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache"})


@app.post("/api/report/{session_id}")
async def make_report(session_id: str):
    session = store.get(session_id)
    if not session:
        raise HTTPException(404, "session not found")
    from . import report_pt, findings as _fx
    md = await report_pt.generate(session, lang=config.UI_LANG)
    session.report_generated = True
    session.persist()
    return JSONResponse({"markdown": md, "warnings": _fx.validate(session),
                         "usage_summary": session.usage_summary() if hasattr(session, "usage_summary") else {}})


@app.get("/api/projects/{pid}/workflow")
async def get_workflow(pid: str):
    s = store.get(pid)
    if not s:
        raise HTTPException(404, "project not found")
    from . import workflow as _wf
    return _wf.guidance(s)


class PhaseIn(BaseModel):
    phase: str | None = None        # phase key, or 'auto'/None to unpin


@app.post("/api/projects/{pid}/workflow")
async def set_workflow(pid: str, body: PhaseIn):
    s = store.get(pid)
    if not s:
        raise HTTPException(404, "project not found")
    from . import workflow as _wf
    if not _wf.set_phase(s, body.phase or ""):
        raise HTTPException(400, "unknown workflow phase")
    s.persist()
    return _wf.guidance(s)


@app.get("/api/report/{session_id}/validate")
async def validate_report(session_id: str):
    session = store.get(session_id)
    if not session:
        raise HTTPException(404, "session not found")
    from . import findings as _fx
    return {"warnings": _fx.validate(session)}


# ---------------------------------------------------------------------------
# Evidence Graph / Finding Validator / Source-to-Sink / Playbook / Job system
# ---------------------------------------------------------------------------
@app.get("/api/projects/{pid}/graph")
async def get_graph(pid: str):
    """The project's Evidence Graph, synced from the current session state."""
    s = store.get(pid)
    if not s:
        raise HTTPException(404, "project not found")
    from . import evidence_graph as _eg
    g = _eg.for_session(s)
    g.sync_from_session(s)
    return g.to_json()


@app.get("/api/projects/{pid}/graph/summary")
async def get_graph_summary(pid: str):
    """Dashboard summary for the Evidence Graph: node/edge counts, findings and artifacts."""
    s = store.get(pid)
    if not s:
        raise HTTPException(404, "project not found")
    from . import evidence_graph as _eg
    g = _eg.for_session(s)
    g.sync_from_session(s)
    return {"stats": g.stats(), "summary": g.summary()}


@app.get("/api/graph/neo4j/status")
async def neo4j_status():
    """Whether the optional Neo4j backend is enabled, installed, and reachable."""
    from . import neo4j_sync
    return await asyncio.to_thread(neo4j_sync.status)


@app.post("/api/projects/{pid}/graph/neo4j/sync")
async def neo4j_sync_project(pid: str):
    """Mirror this project's evidence graph into Neo4j (opt-in). SQLite stays the source of truth.

    If Neo4j isn't enabled/installed/reachable, returns ok=False plus a ready-to-run Cypher script
    so the analyst can still load the graph into Neo4j Browser manually.
    """
    s = store.get(pid)
    if not s:
        raise HTTPException(404, "project not found")
    from . import evidence_graph as _eg
    from . import neo4j_sync
    g = _eg.for_session(s)
    g.sync_from_session(s)
    payload = g.to_json()
    try:
        res = await asyncio.to_thread(neo4j_sync.sync_graph, pid, payload)
        res["match_cypher"] = neo4j_sync.project_match_cypher(pid)
        res["browser_url"] = neo4j_sync._browser_url(getattr(config, "NEO4J_URI", ""))
        return res
    except RuntimeError as exc:
        # Graceful fallback: hand back the Cypher script + the reason sync wasn't possible.
        cypher = neo4j_sync.to_cypher(pid, payload)
        return {"ok": False, "reason": str(exc), "fallback": "cypher",
                "cypher": cypher, "status": neo4j_sync.status()}


@app.get("/api/projects/{pid}/graph/neo4j/cypher")
async def neo4j_cypher(pid: str):
    """Download a standalone Cypher script that rebuilds this project's graph in any Neo4j."""
    s = store.get(pid)
    if not s:
        raise HTTPException(404, "project not found")
    from . import evidence_graph as _eg
    from . import neo4j_sync
    g = _eg.for_session(s)
    g.sync_from_session(s)
    cypher = neo4j_sync.to_cypher(pid, g.to_json())
    return Response(content=cypher, media_type="text/plain",
                    headers={"Content-Disposition": f'attachment; filename="reforge_{pid}.cypher"'})


@app.get("/api/projects/{pid}/graph/node/{node_id:path}")
async def get_graph_node(pid: str, node_id: str):
    """One graph node plus incoming/outgoing relations for a side-panel dossier."""
    s = store.get(pid)
    if not s:
        raise HTTPException(404, "project not found")
    from . import evidence_graph as _eg
    g = _eg.for_session(s)
    g.sync_from_session(s)
    node = g.get_node(node_id)
    if not node:
        raise HTTPException(404, "node not found")
    return node


@app.get("/api/projects/{pid}/graph/neighborhood/{node_id:path}")
async def get_graph_neighborhood(pid: str, node_id: str, depth: int = 1):
    """Bounded subgraph around a node for 'show neighbors' and investigation paths."""
    s = store.get(pid)
    if not s:
        raise HTTPException(404, "project not found")
    from . import evidence_graph as _eg
    g = _eg.for_session(s)
    g.sync_from_session(s)
    if not g.get_node(node_id):
        raise HTTPException(404, "node not found")
    return g.neighborhood(node_id, depth=depth)


@app.get("/api/projects/{pid}/graph/runtime")
async def get_graph_runtime(pid: str):
    """Runtime/Procmon graph projection only: artifact/process/op/touched-object nodes."""
    s = store.get(pid)
    if not s:
        raise HTTPException(404, "project not found")
    from . import evidence_graph as _eg
    g = _eg.for_session(s)
    g.sync_from_session(s)
    j = g.to_json()
    runtime_types = {"artifact", "process", "procmon_op", "file_path",
                     "registry_key", "network_endpoint", "dynamic_event"}
    ids = {n["id"] for n in j["nodes"] if n["type"] in runtime_types}
    return {"nodes": [n for n in j["nodes"] if n["id"] in ids],
            "edges": [e for e in j["edges"] if e["src"] in ids and e["dst"] in ids],
            "summary": j.get("summary", {})}


@app.get("/api/projects/{pid}/graph/unvalidated-sinks")
async def graph_unvalidated_sinks(pid: str):
    s = store.get(pid)
    if not s:
        raise HTTPException(404, "project not found")
    from . import evidence_graph as _eg
    g = _eg.for_session(s)
    g.sync_from_session(s)
    return {"sinks": g.unvalidated_sinks()}


@app.get("/api/projects/{pid}/graph/weak-findings")
async def graph_weak_findings(pid: str, min_evidence: int = 2):
    s = store.get(pid)
    if not s:
        raise HTTPException(404, "project not found")
    from . import evidence_graph as _eg
    g = _eg.for_session(s)
    g.sync_from_session(s)
    return {"findings": g.findings_lacking_evidence(min_evidence=min_evidence)}


@app.get("/api/projects/{pid}/validate-findings")
async def validate_findings(pid: str):
    """Deterministic (non-LLM) validation of every finding in the project."""
    s = store.get(pid)
    if not s:
        raise HTTPException(404, "project not found")
    from . import finding_validator as _fv
    return _fv.validate_session(s)


@app.get("/api/projects/{pid}/source-to-sink")
async def source_to_sink(pid: str):
    """Candidate source\u2192sink chains derived from the binary's sinks and sources."""
    s = store.get(pid)
    if not s:
        raise HTTPException(404, "project not found")
    from . import source_to_sink as _s2s
    return {"chains": _s2s.from_session(s)}


class GraphDiffIn(BaseModel):
    session_a: str
    session_b: str


@app.post("/api/graph/diff")
async def graph_diff_endpoint(body: GraphDiffIn):
    """Compare the Evidence Graph of two projects/versions (A=previous, B=new)."""
    sa, sb = store.get(body.session_a), store.get(body.session_b)
    if not sa or not sb:
        raise HTTPException(404, "one of the two projects does not exist")
    from . import evidence_graph as _eg, graph_diff as _gd
    ga = _eg.for_session(sa); ga.sync_from_session(sa)
    gb = _eg.for_session(sb); gb.sync_from_session(sb)
    d = _gd.diff_objects(ga, gb)
    d["highlights"] = _gd.security_highlights(d)
    return d


@app.get("/api/projects/{pid}/export/sarif")
async def export_sarif(pid: str):
    """Export the project's findings as SARIF 2.1.0."""
    s = store.get(pid)
    if not s:
        raise HTTPException(404, "project not found")
    from . import sbom_sarif as _ss
    return JSONResponse(_ss.to_sarif(s))


@app.get("/api/projects/{pid}/export/cyclonedx")
async def export_cyclonedx(pid: str, online: bool = False):
    """Export a CycloneDX 1.5 SBOM of the third-party components.
    With `?online=true` it enriches each component with candidate CVEs via NVD (best-effort)."""
    s = store.get(pid)
    if not s:
        raise HTTPException(404, "project not found")
    from . import sbom_sarif as _ss
    key = getattr(config, "NVD_API_KEY", "")
    return JSONResponse(_ss.cyclonedx_from_session(s, online=online, api_key=key))


@app.get("/api/playbooks")
async def list_playbooks():
    from . import playbook as _pb
    return {"playbooks": _pb.list_summaries(), "modules": sorted(_pb.VALID_MODULES)}


@app.get("/api/playbooks/for-module/{module}")
async def playbooks_for_module(module: str):
    """Playbook attached to a specific UI module (drives the per-module Run launcher)."""
    from . import playbook as _pb
    return {"module": module, "playbooks": _pb.for_module(module)}


class PlaybookSaveIn(BaseModel):
    id: str | None = None
    name: str
    description: str | None = ""
    safety_mode: str = "safe"
    requires_dynamic: bool = False
    steps: list = []
    expected_outputs: list | None = None
    modules: list | None = None
    system_prompt: str | None = None


@app.post("/api/playbooks/custom")
async def create_custom_playbook(body: PlaybookSaveIn):
    """Create/update a custom playbook (saved to playbooks/custom/, validated, never executable code)."""
    from . import playbook as _pb
    payload = {k: v for k, v in body.model_dump().items() if v is not None}
    try:
        rec = _pb.save_custom(payload)
    except ValueError as exc:
        raise HTTPException(400, f"invalid playbook: {exc}")
    return {"ok": True, "playbook": {k: v for k, v in rec.items() if not k.startswith("_")},
            "custom": True}


@app.delete("/api/playbooks/custom/{playbook_id}")
async def delete_custom_playbook(playbook_id: str):
    """Delete a custom playbook. Bundled playbooks cannot be deleted."""
    from . import playbook as _pb
    if not _pb.delete_custom(playbook_id):
        raise HTTPException(404, "custom playbook not found (bundled playbooks cannot be deleted)")
    return {"ok": True, "deleted": playbook_id}


class PlaybookRunIn(BaseModel):
    session_id: str
    playbook_id: str


@app.post("/api/playbooks/run")
async def run_playbook(body: PlaybookRunIn):
    """Start a playbook as a guided message to the agent (honouring the safety mode)."""
    s = store.get(body.session_id)
    if not s:
        raise HTTPException(404, "session not found")
    from . import playbook as _pb
    pb = _pb.get(body.playbook_id)
    if not pb:
        raise HTTPException(404, "playbook not found")
    if pb.get("requires_dynamic") and config.SAFETY_MODE == "safe":
        raise HTTPException(400, "This playbook requires dynamic actions: use "
                                 "'assisted' or 'autonomous' mode.")
    if s.busy:
        raise HTTPException(409, "session busy")
    steps = ", ".join(pb.get("steps", []))
    task = (f"Run the playbook \u201c{pb['name']}\u201d. Suggested steps, in order: {steps}. "
            f"{pb.get('system_prompt', '')}")
    s.task = asyncio.create_task(agent.run_turn(s, _require_host(), _require_registry(), task, llm_route="api"))
    return {"ok": True, "playbook": pb["id"], "steps": pb.get("steps", [])}


@app.get("/api/jobs")
async def list_jobs():
    from .job_manager import manager as _jm
    return {"jobs": _jm.list()}


@app.get("/api/jobs/{job_id}")
async def get_job(job_id: str):
    from .job_manager import manager as _jm
    j = _jm.get(job_id)
    if not j:
        raise HTTPException(404, "job not found")
    return j.to_dict()


class JobIn(BaseModel):
    session_id: str
    kind: str


@app.post("/api/jobs")
async def submit_job(body: JobIn):
    """Start a job (static analysis, source_to_sink, report_generation, ...)."""
    s = store.get(body.session_id)
    if not s:
        raise HTTPException(404, "session not found")
    from . import jobs as _jobs
    _jobs.ensure_registered(store, host, registry)
    from .job_manager import manager as _jm
    job = _jm.submit(body.kind, {"session_id": body.session_id})
    return job.to_dict()


@app.post("/api/jobs/{job_id}/cancel")
async def cancel_job(job_id: str):
    from .job_manager import manager as _jm
    return {"cancelled": _jm.cancel(job_id)}


# How long a bootstrapped browser session stays authenticated before the link must be used again.
_SESSION_MAX_AGE = 12 * 3600


def _set_session_cookie(response, request: Request) -> None:
    """Attach the session credential: HttpOnly, SameSite=Strict, expiring.

    HttpOnly because no page script needs to read it and an XSS should not be able to exfiltrate
    it; SameSite=Strict so it never rides a cross-site request; Secure only over HTTPS, since
    setting it on plain http would make the cookie silently undeliverable for local use.
    """
    response.set_cookie(
        "reforge_token", config.AUTH_TOKEN,
        httponly=True,
        samesite="strict",
        secure=request.url.scheme == "https",
        max_age=_SESSION_MAX_AGE,
        path="/",
    )


@app.get("/")
async def index(request: Request):
    """Serve the SPA, and exchange a bootstrap ?token= for a session cookie.

    The token used to be left in the URL and stored in a JS-readable cookie. That put a long-lived
    credential into the address bar, browser history and any Referer header, and exposed it to any
    script running on the page. It is now swapped for an HttpOnly, SameSite=Strict cookie and the
    browser is redirected to a clean URL, so the secret appears exactly once, in one request.
    """
    tok = request.query_params.get("token")
    if tok and config.AUTH_TOKEN and secrets.compare_digest(tok, config.AUTH_TOKEN):
        redirect: Response = RedirectResponse(url="/", status_code=303)
        _set_session_cookie(redirect, request)
        return redirect

    resp: Response = FileResponse(WEB / "index.html")
    resp.headers["Cache-Control"] = "no-cache, must-revalidate"
    # Hand the browser a credential of its own, but ONLY if this request would have been allowed
    # to call the API. Reaching this line does not mean the caller is authorised: the middleware
    # deliberately lets every non-/api path through so the SPA and its assets load for anyone, so
    # issuing the cookie here unconditionally would give the session credential to any client that
    # can fetch "/" - which is everyone. The check below asks the same question the middleware
    # asks of an API call, and only then issues it.
    #
    # The point of issuing it at all: the SPA carries no token, so when loopback is not trusted it
    # had no credential whatsoever - the page loaded and every /api call 401'd. With the cookie as
    # the durable credential, tightening `auth_trust_localhost` later cannot break an open tab.
    if config.AUTH_REQUIRED and config.AUTH_TOKEN and not request.cookies.get("reforge_token"):
        would_be_allowed = _auth.authorize(
            "/api/status", "GET", (request.client.host if request.client else "") or "",
            token_provided=request.headers.get("X-Reforge-Token") or "",
            token_expected=config.AUTH_TOKEN,
            auth_required=config.AUTH_REQUIRED,
            trust_localhost=config.AUTH_TRUST_LOCALHOST)
        if would_be_allowed:
            _set_session_cookie(resp, request)
    return resp


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    """No icon is shipped; answer 204 instead of letting this 404 on every page load."""
    return Response(status_code=204)


# SPA assets served with no-cache so frontend changes are always picked up (avoids the
# "old cached app.js" trap). Each file gets its own explicit route — no path ever comes from the
# request — so the StaticFiles mount below still handles everything else.
_SPA_ASSETS = {
    "app.js": "application/javascript",
    "assessment.js": "application/javascript",
    "palette.js": "application/javascript",
    "styles.css": "text/css",
}


_NO_CACHE = "no-cache, must-revalidate"


def _register_spa_assets() -> None:
    for name, media in _SPA_ASSETS.items():
        def _serve(_name: str = name, _media: str = media):
            async def handler(request: Request):
                path = WEB / _name
                resp = FileResponse(path, media_type=_media, stat_result=os.stat(path),
                                    headers={"Cache-Control": _NO_CACHE})
                # `no-cache` means "revalidate before use", not "never cache" - but a plain
                # FileResponse never answers the revalidation, so every reload re-sent the whole
                # bundle (~440 KB) even when nothing had changed. Answer it with 304 on a
                # matching ETag; an edited file gets a new tag and is sent in full.
                client_tag = request.headers.get("if-none-match", "").strip().removeprefix("W/")
                if client_tag and client_tag == resp.headers.get("etag"):
                    return Response(status_code=304, headers={
                        "ETag": resp.headers["etag"], "Cache-Control": _NO_CACHE})
                return resp
            return handler
        app.get(f"/{name}")(_serve())


_register_spa_assets()


@app.api_route("/api/{rest:path}",
               methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"],
               include_in_schema=False)
async def _unknown_api_route(rest: str, request: Request):
    """Uniform 404 for an unmatched API path.

    Registered last, after every real route, so it can only catch what nothing else claimed.
    Without it these requests fell through to the SPA's StaticFiles mount and came back as its
    plain-text "Not Found" - outside the error contract, and misleading for an API client.
    """
    raise APIError("not_found", f"no API route for {request.method} {request.url.path}",
                   status=404, api_version=API_VERSION)


app.mount("/", StaticFiles(directory=WEB), name="web")
