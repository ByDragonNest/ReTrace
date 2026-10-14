"""Declarative permission for every API route, enforced default-deny (slice P2-S8).

Slice P2-S1 put permission checks on eleven routes by hand. That left ~50 unguarded — including
`POST /api/projects/{pid}/target`, which chooses the binary to analyse, and `GET
/api/projects/{pid}/evidence`. Worse than the specific holes: **a route added later was unguarded
by default, and nothing caught it.** Per-route checks written by hand are a policy you have to
remember; this is a policy you have to opt out of.

Two properties:

* **Default deny.** A route with no entry here is refused, not allowed. Adding an endpoint without
  deciding who may call it now breaks it loudly in development instead of shipping it open.
* **Declared in one place.** The whole authorization surface is this table, reviewable in one
  screen, rather than spread across 1,400 lines of handlers where "which routes can an analyst
  reach" is answerable only by reading all of them.

This is the coarse gate: *may this principal do this kind of thing at all*. Routes that name a
project still call `require_project()` for the per-project check — holding `project:read` says you
may read projects, not that you may read *that* one.
"""
from __future__ import annotations

from typing import Dict, Optional, Tuple

from .identity import Permission

#: Any authenticated caller, including one whose identity provider granted them no roles. Reserved
#: for endpoints that must answer before the UI can decide what to show.
PUBLIC = "public"

Policy = Optional[str]

#: (METHOD, path template as registered) -> Permission.value, or PUBLIC.
ROUTE_PERMISSIONS: Dict[Tuple[str, str], Policy] = {
    # --- must answer before the UI can render anything -----------------------------------
    ("GET", "/api/status"): PUBLIC,
    ("GET", "/api/whoami"): PUBLIC,
    # The catch-all that produces the uniform 404. Refusing it would turn "no such route" into
    # "forbidden", which tells an unauthorised caller less but confuses an authorised one more.
    ("GET", "/api/{rest:path}"): PUBLIC,
    ("POST", "/api/{rest:path}"): PUBLIC,
    ("PUT", "/api/{rest:path}"): PUBLIC,
    ("PATCH", "/api/{rest:path}"): PUBLIC,
    ("DELETE", "/api/{rest:path}"): PUBLIC,

    # --- reading ---------------------------------------------------------------------------
    ("GET", "/api/projects"): Permission.PROJECT_READ.value,
    ("GET", "/api/projects/{pid}"): Permission.PROJECT_READ.value,
    ("GET", "/api/projects/{pid}/artifacts"): Permission.PROJECT_READ.value,
    ("GET", "/api/projects/{pid}/assessment"): Permission.PROJECT_READ.value,
    ("GET", "/api/projects/{pid}/evidence"): Permission.PROJECT_READ.value,
    ("GET", "/api/projects/{pid}/graph"): Permission.PROJECT_READ.value,
    ("GET", "/api/projects/{pid}/graph/summary"): Permission.PROJECT_READ.value,
    ("GET", "/api/projects/{pid}/graph/runtime"): Permission.PROJECT_READ.value,
    ("GET", "/api/projects/{pid}/graph/node/{node_id:path}"): Permission.PROJECT_READ.value,
    ("GET", "/api/projects/{pid}/graph/neighborhood/{node_id:path}"): Permission.PROJECT_READ.value,
    ("GET", "/api/projects/{pid}/graph/unvalidated-sinks"): Permission.PROJECT_READ.value,
    ("GET", "/api/projects/{pid}/graph/weak-findings"): Permission.PROJECT_READ.value,
    ("GET", "/api/projects/{pid}/graph/neo4j/cypher"): Permission.PROJECT_READ.value,
    ("GET", "/api/projects/{pid}/source-to-sink"): Permission.PROJECT_READ.value,
    ("GET", "/api/projects/{pid}/strings"): Permission.PROJECT_READ.value,
    ("GET", "/api/projects/{pid}/toollog"): Permission.PROJECT_READ.value,
    ("GET", "/api/projects/{pid}/usage"): Permission.PROJECT_READ.value,
    ("GET", "/api/projects/{pid}/validate-findings"): Permission.PROJECT_READ.value,
    ("GET", "/api/projects/{pid}/workflow"): Permission.PROJECT_READ.value,
    ("GET", "/api/stream/{session_id}"): Permission.PROJECT_READ.value,
    ("GET", "/api/jobs"): Permission.PROJECT_READ.value,
    ("GET", "/api/jobs/{job_id}"): Permission.PROJECT_READ.value,
    ("GET", "/api/playbooks"): Permission.PROJECT_READ.value,
    ("GET", "/api/playbooks/for-module/{module}"): Permission.PROJECT_READ.value,
    ("GET", "/api/report/template"): Permission.PROJECT_READ.value,
    ("GET", "/api/servers"): Permission.PROJECT_READ.value,
    ("GET", "/api/tools"): Permission.PROJECT_READ.value,
    ("GET", "/api/graph/neo4j/status"): Permission.PROJECT_READ.value,

    # --- creating and owning ---------------------------------------------------------------
    ("POST", "/api/projects"): Permission.PROJECT_CREATE.value,
    ("DELETE", "/api/projects/{pid}"): Permission.PROJECT_DELETE.value,
    ("POST", "/api/sessions"): Permission.PROJECT_CREATE.value,

    # --- running analysis -------------------------------------------------------------------
    # `target` chooses which binary is analysed. It was unguarded.
    ("POST", "/api/projects/{pid}/target"): Permission.ANALYSIS_RUN.value,
    ("POST", "/api/message"): Permission.ANALYSIS_RUN.value,
    ("POST", "/api/analyze"): Permission.ANALYSIS_RUN.value,
    ("POST", "/api/local-assist"): Permission.ANALYSIS_RUN.value,
    ("POST", "/api/stop"): Permission.ANALYSIS_RUN.value,
    ("POST", "/api/diff"): Permission.ANALYSIS_RUN.value,
    ("POST", "/api/graph/diff"): Permission.ANALYSIS_RUN.value,
    ("POST", "/api/jobs"): Permission.ANALYSIS_RUN.value,
    ("POST", "/api/jobs/{job_id}/cancel"): Permission.ANALYSIS_RUN.value,
    ("POST", "/api/playbooks/run"): Permission.ANALYSIS_RUN.value,
    ("POST", "/api/projects/{pid}/artifacts/{aid}/overview"): Permission.ANALYSIS_RUN.value,
    ("POST", "/api/projects/{pid}/artifacts/{aid}/parse"): Permission.ANALYSIS_RUN.value,
    ("POST", "/api/projects/{pid}/strings/reclassify"): Permission.ANALYSIS_RUN.value,
    ("POST", "/api/projects/{pid}/graph/neo4j/sync"): Permission.ANALYSIS_RUN.value,
    ("POST", "/api/report/{session_id}"): Permission.ANALYSIS_RUN.value,

    # --- changing stored analysis -----------------------------------------------------------
    ("POST", "/api/projects/{pid}/workflow"): Permission.PROJECT_WRITE.value,
    ("POST", "/api/projects/{pid}/strings/reassign"): Permission.PROJECT_WRITE.value,
    ("POST", "/api/playbooks/custom"): Permission.PROJECT_WRITE.value,
    ("DELETE", "/api/playbooks/custom/{playbook_id}"): Permission.PROJECT_WRITE.value,

    # --- bringing data in ---------------------------------------------------------------------
    ("POST", "/api/projects/{pid}/upload"): Permission.ARTIFACT_UPLOAD.value,
    ("POST", "/api/projects/{pid}/artifacts"): Permission.ARTIFACT_UPLOAD.value,

    # --- taking data out ----------------------------------------------------------------------
    ("POST", "/api/report/export"): Permission.REPORT_EXPORT.value,
    ("GET", "/api/report/{session_id}/validate"): Permission.REPORT_EXPORT.value,
    ("GET", "/api/projects/{pid}/export/sarif"): Permission.REPORT_EXPORT.value,
    ("GET", "/api/projects/{pid}/export/cyclonedx"): Permission.REPORT_EXPORT.value,
    ("GET", "/api/projects/{pid}/raw-export"): Permission.RAW_EXPORT.value,

    # --- authorising a gated tool call --------------------------------------------------------
    ("POST", "/api/approve"): Permission.APPROVAL_GRANT.value,

    # --- administration -------------------------------------------------------------------------
    ("GET", "/api/settings"): Permission.SETTINGS_READ.value,
    ("POST", "/api/settings"): Permission.SETTINGS_WRITE.value,
    ("POST", "/api/servers/{name}"): Permission.SERVER_MANAGE.value,
    ("GET", "/api/audit"): Permission.AUDIT_READ.value,
    # Readable by anyone who can read projects, not only an administrator: an analyst must be able
    # to check what their own work sent off the machine.
    ("GET", "/api/egress"): Permission.PROJECT_READ.value,
    ("GET", "/api/metrics"): Permission.PROJECT_READ.value,
    ("GET", "/api/retention"): Permission.AUDIT_READ.value,
    ("POST", "/api/retention/purge"): Permission.PROJECT_DELETE.value,
    ("GET", "/api/support-bundle"): Permission.AUDIT_READ.value,
}


def lookup(method: str, path_template: str) -> Tuple[bool, Policy]:
    """(declared, policy). `declared=False` means default-deny applies."""
    key = (method.upper(), path_template)
    if key in ROUTE_PERMISSIONS:
        return True, ROUTE_PERMISSIONS[key]
    return False, None


def undeclared(routes) -> list:
    """API route/method pairs with no entry. Used by the test that keeps this table honest."""
    missing = []
    for route in routes:
        path = getattr(route, "path", "")
        if not path.startswith("/api"):
            continue
        for method in sorted(getattr(route, "methods", set()) or []):
            if method in ("HEAD", "OPTIONS"):
                continue
            if (method, path) not in ROUTE_PERMISSIONS:
                missing.append((method, path))
    return missing
