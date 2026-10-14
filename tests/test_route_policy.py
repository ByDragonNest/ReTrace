"""Default-deny authorization for every API route (slice P2-S8).

Slice P2-S1 put permission checks on eleven routes by hand, leaving ~50 unguarded - including
`POST /api/projects/{pid}/target`, which chooses the binary to analyse. The specific holes
mattered less than the shape of the problem: **a route added later was unguarded by default and
nothing caught it.**
"""
from __future__ import annotations

import pytest

from reforge import config, route_policy
from reforge.identity import Permission, Principal, Role
from reforge.server import app


# --------------------------------------------------------------------------- the table
def test_every_api_route_declares_who_may_call_it():
    """The test that keeps the table honest. A new route fails here until it is declared."""
    missing = route_policy.undeclared(app.router.routes)
    assert not missing, (
        "these API routes have no entry in route_policy.ROUTE_PERMISSIONS and are therefore "
        f"refused at runtime; declare them: {sorted(missing)}"
    )


def test_the_table_declares_no_route_that_does_not_exist():
    """A stale entry is a permission nobody is enforcing and a reader being misled."""
    live = set()
    for route in app.router.routes:
        path = getattr(route, "path", "")
        if not path.startswith("/api"):
            continue
        for method in (getattr(route, "methods", set()) or set()):
            live.add((method, path))
    stale = [key for key in route_policy.ROUTE_PERMISSIONS if key not in live]
    assert not stale, f"entries for routes that no longer exist: {sorted(stale)}"


def test_every_declared_policy_is_a_real_permission():
    for key, policy in route_policy.ROUTE_PERMISSIONS.items():
        if policy == route_policy.PUBLIC:
            continue
        Permission(policy)                      # raises ValueError on a typo


def test_only_a_short_explicit_list_is_public():
    """Public must stay the exception. Growth here is the policy quietly dissolving."""
    public = sorted(k for k, v in route_policy.ROUTE_PERMISSIONS.items()
                    if v == route_policy.PUBLIC)
    non_catchall = [k for k in public if "{rest:path}" not in k[1]]
    assert len(non_catchall) <= 4, f"too many public routes: {non_catchall}"
    for method, path in non_catchall:
        assert path in ("/api/status", "/api/whoami"), f"{path} should not be public"


def test_state_changing_routes_are_never_public():
    for (method, path), policy in route_policy.ROUTE_PERMISSIONS.items():
        if method in ("POST", "PUT", "PATCH", "DELETE") and "{rest:path}" not in path:
            assert policy != route_policy.PUBLIC, f"{method} {path} is public"


def test_an_undeclared_route_defaults_to_denied():
    declared, policy = route_policy.lookup("GET", "/api/something-new")
    assert declared is False and policy is None


# --------------------------------------------------------------------------- enforcement
@pytest.fixture()
def api(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    monkeypatch.setattr(config, "WORKSPACE_DIR", tmp_path)
    monkeypatch.setattr(config, "STATE_ROOT", tmp_path)
    with TestClient(app) as c:
        c.headers.update({"X-Reforge-Token": config.AUTH_TOKEN})
        yield c


class _As:
    """Run a block as a given principal, leaving the rest of the stack real."""

    def __init__(self, role, subject="bob"):
        self.principal = Principal(subject=subject, roles=frozenset({role}) if role else frozenset())

    def __enter__(self):
        from reforge import server
        self._original = server.principal_of
        server.principal_of = lambda request: self.principal
        return self.principal

    def __exit__(self, *exc):
        from reforge import server
        server.principal_of = self._original


@pytest.mark.parametrize("method,path,permission", [
    ("POST", "/api/projects/p1/target", "analysis:run"),
    ("POST", "/api/message", "analysis:run"),
    ("GET", "/api/projects/p1/evidence", "project:read"),
    ("GET", "/api/projects/p1/export/sarif", "report:export"),
    ("GET", "/api/projects/p1/raw-export", "raw:export"),
    ("POST", "/api/settings", "settings:write"),
    ("GET", "/api/audit", "audit:read"),
])
def test_a_principal_without_the_permission_is_refused(api, method, path, permission):
    """These were all reachable by anyone holding the shared token before this slice."""
    with _As(None):                              # authenticated, no roles at all
        r = api.request(method, path, json={})
        assert r.status_code == 403, f"{method} {path} answered {r.status_code}"
        body = r.json()["error"]
        assert body["code"] in ("forbidden", "route_not_authorized")
        if body["code"] == "forbidden":
            assert body["context"]["permission"] == permission


def test_a_read_only_principal_can_read_but_not_run(api):
    with _As(Role.READ_ONLY):
        assert api.get("/api/projects").status_code == 200
        assert api.post("/api/projects/p1/target", json={"path": "/tmp/x"}).status_code == 403
        assert api.post("/api/projects", json={"name": "x"}).status_code == 403


def test_an_analyst_can_run_but_not_administer(api):
    with _As(Role.ANALYST):
        assert api.get("/api/settings").status_code == 200       # settings:read
        assert api.post("/api/settings", json={}).status_code == 403
        assert api.post("/api/servers/ghidra", json={"enabled": False}).status_code == 403
        assert api.get("/api/audit").status_code == 403


def test_status_and_whoami_answer_for_any_authenticated_caller(api):
    with _As(None):
        assert api.get("/api/status").status_code == 200
        assert api.get("/api/whoami").status_code == 200


def test_an_unknown_api_path_is_still_a_clean_404_not_a_403(api):
    """"No such route" must not become "forbidden": it helps nobody and confuses the authorised."""
    with _As(Role.ANALYST):
        r = api.get("/api/definitely-not-a-route")
        assert r.status_code == 404
        assert r.json()["error"]["code"] == "not_found"


def test_a_route_missing_from_the_table_is_refused_at_runtime(api, monkeypatch):
    """The default-deny behaviour itself, exercised rather than assumed."""
    original = dict(route_policy.ROUTE_PERMISSIONS)
    route_policy.ROUTE_PERMISSIONS.pop(("GET", "/api/status"), None)
    try:
        with _As(Role.ADMINISTRATOR):
            r = api.get("/api/status")
            assert r.status_code == 403
            assert r.json()["error"]["code"] == "route_not_authorized"
    finally:
        route_policy.ROUTE_PERMISSIONS.clear()
        route_policy.ROUTE_PERMISSIONS.update(original)


def test_a_typo_in_the_table_fails_closed(api):
    """A misspelled permission must refuse, not wave the request through."""
    original = route_policy.ROUTE_PERMISSIONS[("GET", "/api/tools")]
    route_policy.ROUTE_PERMISSIONS[("GET", "/api/tools")] = "projekt:read"
    try:
        with _As(Role.ADMINISTRATOR):
            r = api.get("/api/tools")
            assert r.status_code == 403
            assert r.json()["error"]["code"] == "route_not_authorized"
    finally:
        route_policy.ROUTE_PERMISSIONS[("GET", "/api/tools")] = original


def test_the_administrator_reaches_every_declared_route_type(api):
    """The gate must not be a wall: the role that holds everything must pass it."""
    with _As(Role.ADMINISTRATOR):
        for path in ("/api/status", "/api/whoami", "/api/projects", "/api/settings",
                     "/api/tools", "/api/servers", "/api/audit", "/api/playbooks"):
            assert api.get(path).status_code == 200, path
