"""A support bundle an operator can actually send (slice P2-S6, prompt §12).

The bundle exists so a customer can get help without handing over a binary they are under NDA to
protect. That makes what it *excludes* the design, not an afterthought:

* **No customer content.** No samples, no findings, no evidence, no decompiled code, no strings,
  no project names. Not redacted — absent.
* **No secrets.** Configuration is included because a misconfiguration is usually the problem, but
  every credential-shaped value is masked, and the masking is asserted by test rather than hoped
  for.
* **No audit entries' detail.** The audit trail records who did what *to which project*; the
  bundle carries the chain's integrity verdict and counts, not the entries.

What it does carry: versions, the resolved security posture, metrics and SLIs, the MCP server
catalogue and manifest state, recent operational log lines (scrubbed), and the environment facts
that explain most problems.
"""
from __future__ import annotations

import io
import json
import platform
import sys
import time
import zipfile
from typing import Any, Dict, List

#: Config keys whose value is never included, whatever it looks like.
_NEVER_INCLUDE = {
    "anthropic_api_key", "nvd_api_key", "neo4j_password", "auth_token", "local_api_key",
    "oidc_audience",
}
_SECRET_SHAPED = ("key", "token", "secret", "password", "credential")


def _safe_config() -> Dict[str, Any]:
    """The resolved settings, with every credential-shaped value masked or dropped."""
    from . import config

    try:
        values = config.SETTINGS.model_dump(mode="json")
    except Exception:
        values = {}
    out: Dict[str, Any] = {}
    for key, value in sorted(values.items()):
        low = key.lower()
        if low in _NEVER_INCLUDE:
            continue
        if any(marker in low for marker in _SECRET_SHAPED):
            out[key] = "«present»" if value else "«not set»"
            continue
        out[key] = value
    # Whether a credential exists is diagnostic; its value never is.
    out["_has_anthropic_key"] = bool(getattr(config, "ANTHROPIC_API_KEY", ""))
    out["_has_auth_token"] = bool(getattr(config, "AUTH_TOKEN", ""))
    return out


def _posture() -> Dict[str, Any]:
    from . import config, execution

    return {
        "deployment_profile": config.DEPLOYMENT_PROFILE,
        "safety_mode": config.SAFETY_MODE,
        "approval_gate": config.REQUIRE_APPROVAL,
        "operating_profile": config.OPERATING_PROFILE,
        "identity_provider": config.IDENTITY_PROVIDER,
        "auth_required": config.AUTH_REQUIRED,
        "auth_trust_localhost": config.AUTH_TRUST_LOCALHOST,
        "allow_outside_workspace": config.ALLOW_OUTSIDE_WORKSPACE,
        "external_roots_count": len(getattr(config, "EXTERNAL_ROOTS", []) or []),
        "unmanifested_risk_floor": config.UNMANIFESTED_RISK_FLOOR,
        "execution": execution.describe(config),
    }


def _servers() -> Dict[str, Any]:
    """Which MCP servers are configured and whether each has a manifest. No paths, no arguments:
    a command line can carry a sample path, and a sample path can carry a customer name."""
    from . import config, mcp_manifest

    try:
        configured = config.load_server_config()
    except Exception:
        configured = {}
    registry = mcp_manifest.registry()
    return {
        "configured": sorted(configured),
        "manifested": registry.servers(),
        "manifest_errors": registry.errors,
        "unmanifested": sorted(set(configured) - set(registry.servers())),
    }


def _audit_integrity() -> Dict[str, Any]:
    """The chain's verdict and counts. Never the entries: they name projects."""
    from . import audit

    try:
        return audit.verify()
    except Exception as exc:                 # noqa: BLE001
        return {"ok": None, "error": f"{type(exc).__name__}: {exc}"}


def _environment() -> Dict[str, Any]:
    from . import __version__

    return {
        "retrace_version": __version__,
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def _dependencies() -> Dict[str, str]:
    """Installed versions of what we actually import. Half of all problems are a version."""
    import importlib.metadata as md

    out = {}
    for name in ("fastapi", "starlette", "uvicorn", "pydantic", "mcp", "pefile", "anthropic",
                 "openai", "pyjwt", "httpx", "pyyaml", "python-multipart"):
        try:
            out[name] = md.version(name)
        except md.PackageNotFoundError:
            out[name] = "not installed"
    return out


def build(recent_logs: List[str] | None = None) -> bytes:
    """The bundle, as zip bytes. Deterministic order so two bundles can be diffed."""
    from . import observability

    sections = {
        "environment.json": _environment(),
        "dependencies.json": _dependencies(),
        "security-posture.json": _posture(),
        "configuration.json": _safe_config(),
        "mcp-servers.json": _servers(),
        "metrics.json": observability.METRICS.snapshot(),
        "sli.json": observability.service_level_indicators(),
        "audit-integrity.json": _audit_integrity(),
    }

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("README.txt", _readme())
        for name, payload in sections.items():
            archive.writestr(name, json.dumps(payload, indent=2, sort_keys=True, default=str))
        if recent_logs:
            # Two passes. `scrub()` removes what a pattern can find - symbol names, hex dumps.
            # Project names it cannot: a project is called whatever the analyst called it, and
            # what they called it is usually the customer. Those are removed by name, which means
            # looking them up. (A test caught "acme-corp" surviving the first pass.)
            identifiers = _project_identifiers()
            scrubbed = "\n".join(
                observability.scrub_identifiers(observability.scrub(line), identifiers)
                for line in recent_logs)
            archive.writestr("recent-logs.txt", scrubbed)
    return buffer.getvalue()


def _project_identifiers() -> List[str]:
    """Project names and ids, collected only so they can be removed. Never written out."""
    try:
        from .session import SessionStore

        return [value for row in SessionStore().list_projects()
                for value in (row.get("name"), row.get("id")) if value]
    except Exception:                        # noqa: BLE001 - a bundle must build regardless
        return []


def _readme() -> str:
    return (
        "ReTrace support bundle\n"
        "======================\n\n"
        "What this contains: versions, the resolved security posture, configuration with every\n"
        "credential masked, the MCP server and manifest state, metrics and SLIs, the audit\n"
        "chain's integrity verdict, and recent operational log lines.\n\n"
        "What this does NOT contain, by design:\n"
        "  - any analysed sample, or any part of one\n"
        "  - findings, evidence, decompiled code, extracted strings\n"
        "  - project names or identifiers\n"
        "  - any API key, access token or password\n"
        "  - audit entries (only the chain's integrity verdict and counts)\n\n"
        "The bundle is meant to be sendable without review. If you find anything in it that\n"
        "should not leave your organisation, that is a bug - please report it.\n"
    )
