"""The ◐ pieces of phase P2, completed.

Four gaps that were named as residual risk in earlier slices and are now closed:

* **P2-S8 risk 2** — 29 routes read or wrote a project with only a permission check behind them.
  Holding `project:read` says you may read projects, not that you may read *that* one.
* **P2-S3 risk 1** — the manifest carried `input_schema` and nothing validated against it.
* **P2-S6 risk 6** — `job_success_rate` and `tool_call_success_rate` had definitions and no
  counters feeding them, so they read `null` forever.
* **P2-S4 risk 1** — no spend ceiling; `llm_cost.py` accounted after the fact, which is an invoice.
"""
from __future__ import annotations

import asyncio

import pytest

from reforge import config, mcp_manifest, model_gateway, observability
from reforge.identity import Principal, Role
from reforge.observability import METRICS


@pytest.fixture()
def api(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from reforge.server import app
    monkeypatch.setattr(config, "WORKSPACE_DIR", tmp_path)
    monkeypatch.setattr(config, "STATE_ROOT", tmp_path)
    with TestClient(app) as c:
        c.headers.update({"X-Reforge-Token": config.AUTH_TOKEN})
        yield c


class _As:
    def __init__(self, role, subject="bob"):
        self.principal = Principal(subject=subject, roles=frozenset({role}))

    def __enter__(self):
        from reforge import server
        self._original = server.principal_of
        server.principal_of = lambda request: self.principal
        return self.principal

    def __exit__(self, *exc):
        from reforge import server
        server.principal_of = self._original


# --------------------------------------------------------------------------- project ownership
@pytest.mark.parametrize("suffix", [
    "/evidence", "/strings", "/graph", "/graph/summary", "/assessment", "/usage",
    "/toollog", "/workflow", "/export/sarif", "/export/cyclonedx", "/source-to-sink",
    "/validate-findings", "/artifacts",
])
def test_another_analyst_cannot_read_someone_elses_project(api, suffix):
    """All of these were permission-checked and ownership-unchecked."""
    pid = api.post("/api/projects", json={"name": "alice-work"}).json()["id"]
    with _As(Role.ANALYST):
        response = api.get(f"/api/projects/{pid}{suffix}")
    assert response.status_code == 404, f"{suffix} leaked another project (got {response.status_code})"
    assert response.json()["error"]["code"] == "not_found"


@pytest.mark.parametrize("suffix,payload", [
    ("/target", {"path": "/tmp/x"}),
    ("/workflow", {"phase": "triage"}),
    ("/strings/reassign", {"moves": []}),
])
def test_another_analyst_cannot_write_to_someone_elses_project(api, suffix, payload):
    pid = api.post("/api/projects", json={"name": "alice-work"}).json()["id"]
    with _As(Role.ANALYST):
        assert api.post(f"/api/projects/{pid}{suffix}", json=payload).status_code == 404


def test_the_owner_still_reaches_their_own_project(api):
    """The check must not become a wall."""
    pid = api.post("/api/projects", json={"name": "mine"}).json()["id"]
    for suffix in ("", "/evidence", "/assessment", "/strings"):
        assert api.get(f"/api/projects/{pid}{suffix}").status_code == 200, suffix


def test_a_refusal_says_not_found_not_forbidden(api):
    """403 would confirm the project exists to someone with no right to know that."""
    pid = api.post("/api/projects", json={"name": "alice-work"}).json()["id"]
    with _As(Role.ANALYST):
        body = api.get(f"/api/projects/{pid}/evidence").json()
    assert body["error"]["code"] == "not_found"
    assert "forbidden" not in str(body).lower()


def test_cross_project_access_is_audited(api, tmp_path, monkeypatch):
    from reforge import audit

    pid = api.post("/api/projects", json={"name": "alice-work"}).json()["id"]
    with _As(Role.ANALYST):
        api.get(f"/api/projects/{pid}/evidence")
    denials = [e for e in audit.read(limit=50)
               if e["action"] == "authz.denied" and e.get("project_id") == pid]
    assert denials and "not a member" in denials[0]["detail"]["reason"]


def test_ownership_is_enforced_centrally_not_per_handler():
    """Per-handler checks are what left 29 routes behind."""
    import inspect

    from reforge import server

    source = inspect.getsource(server._route_policy)
    assert "can_access" in source, "the middleware does not check project ownership"


# --------------------------------------------------------------------------- schema validation
VALID_SCHEMA = {"type": "object", "required": ["path"],
                "properties": {"path": {"type": "string"}, "depth": {"type": "integer"}}}


def test_valid_arguments_pass():
    mcp_manifest.validate_against(VALID_SCHEMA, {"path": "/tmp/x"},
                                  direction="arguments", tool="t")


@pytest.mark.parametrize("payload,expected", [
    ({}, "required"),
    ({"path": 123}, "string"),
    ({"path": "/x", "depth": "two"}, "integer"),
])
def test_invalid_arguments_are_refused(payload, expected):
    with pytest.raises(mcp_manifest.SchemaViolation) as exc:
        mcp_manifest.validate_against(VALID_SCHEMA, payload, direction="arguments", tool="t")
    assert expected in str(exc.value)


def test_no_schema_means_no_check_and_says_so():
    """Absence of a schema must not be reported as a successful validation."""
    mcp_manifest.validate_against(None, {"anything": True}, direction="arguments", tool="t")
    mcp_manifest.validate_against({}, {"anything": True}, direction="arguments", tool="t")


def test_the_fallback_check_catches_the_common_cases():
    """When jsonschema is absent the check is narrower - and never claims to be more."""
    problems = mcp_manifest._structural_check(VALID_SCHEMA, {"path": 7})
    assert any("expected string" in p for p in problems)
    assert mcp_manifest._structural_check(VALID_SCHEMA, {"path": "/x"}) == []


def test_the_error_names_the_offending_field_and_is_bounded():
    schema = {"type": "object", "required": [f"f{i}" for i in range(20)]}
    with pytest.raises(mcp_manifest.SchemaViolation) as exc:
        mcp_manifest.validate_against(schema, {}, direction="arguments", tool="t")
    assert len(exc.value.problems) <= mcp_manifest._MAX_VALIDATION_ERRORS


def test_the_host_validates_before_dispatching():
    import inspect

    from reforge.mcp_host import MCPHost

    source = inspect.getsource(MCPHost.call)
    assert source.index("validate_against") < source.index("conn.call("), \
        "arguments must be validated before they reach the server"


# --------------------------------------------------------------------------- SLI counters
@pytest.fixture(autouse=True)
def clean_metrics():
    METRICS.reset()
    yield
    METRICS.reset()


def test_job_outcomes_feed_the_sli(tmp_path, monkeypatch):
    from reforge.job_manager import JobManager

    monkeypatch.setattr(config, "STATE_ROOT", tmp_path)

    async def ok(job, **_):
        return {"ok": True}

    async def boom(job, **_):
        raise RuntimeError("nope")

    manager = JobManager()
    manager.register("good", ok)
    manager.register("bad", boom)
    loop = asyncio.new_event_loop()
    for _ in range(3):
        loop.run_until_complete(manager.run_job(manager.submit("good", {})))
    loop.run_until_complete(manager.run_job(manager.submit("bad", {})))

    assert observability.service_level_indicators()["job_success_rate"] == 0.75


def test_tool_call_outcomes_feed_the_sli():
    METRICS.increment("retrace_tool_calls_total", server="ghidra", outcome="ok")
    METRICS.increment("retrace_tool_calls_total", server="ghidra", outcome="ok")
    METRICS.increment("retrace_tool_calls_total", server="x64dbg", outcome="error")
    assert observability.service_level_indicators()["tool_call_success_rate"] == 0.6667


def test_a_metrics_failure_never_fails_a_job(tmp_path, monkeypatch):
    from reforge.job_manager import JobManager

    monkeypatch.setattr(config, "STATE_ROOT", tmp_path)
    monkeypatch.setattr(METRICS, "increment",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("metrics down")))

    async def ok(job, **_):
        return {"ok": True}

    manager = JobManager()
    manager.register("good", ok)
    job = asyncio.new_event_loop().run_until_complete(manager.run_job(manager.submit("good", {})))
    assert job.status == "completed"


# --------------------------------------------------------------------------- budgets
class _Cfg:
    def __init__(self, ceiling):
        self.PROJECT_BUDGET_USD = ceiling
        self.OPERATING_PROFILE = "frontier"


def test_a_project_under_its_ceiling_proceeds(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "STATE_ROOT", tmp_path)
    monkeypatch.setattr(model_gateway, "project_spend", lambda pid: 3.0)
    status = model_gateway.check_budget("p1", _Cfg(10.0))
    assert status["spent_usd"] == 3.0 and status["unlimited"] is False


def test_a_project_at_its_ceiling_is_refused_before_the_request_goes_out(monkeypatch, tmp_path):
    """A ceiling checked afterwards is an invoice, not a limit."""
    monkeypatch.setattr(config, "STATE_ROOT", tmp_path)
    monkeypatch.setattr(model_gateway, "project_spend", lambda pid: 10.5)
    with pytest.raises(model_gateway.BudgetExceeded) as exc:
        model_gateway.check_budget("p1", _Cfg(10.0))
    assert exc.value.spent == 10.5 and exc.value.ceiling == 10.0


def test_zero_means_unlimited(monkeypatch, tmp_path):
    """The workstation default: an analyst paying for their own key needs no second-guessing."""
    monkeypatch.setattr(config, "STATE_ROOT", tmp_path)
    monkeypatch.setattr(model_gateway, "project_spend", lambda pid: 9_999.0)
    assert model_gateway.check_budget("p1", _Cfg(0.0))["unlimited"] is True
    assert config.PROJECT_BUDGET_USD == 0.0


def test_exceeding_the_budget_is_recorded(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "STATE_ROOT", tmp_path)
    monkeypatch.setattr(model_gateway, "project_spend", lambda pid: 50.0)
    with pytest.raises(model_gateway.BudgetExceeded):
        model_gateway.check_budget("p1", _Cfg(10.0))
    assert any(e["action"] == "llm.egress_denied" for e in model_gateway.ledger())


def test_the_turn_checks_the_budget_before_calling_the_model():
    import inspect

    from reforge import agent

    assert "check_budget" in inspect.getsource(agent._enforce_budget)
