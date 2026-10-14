"""Deterministic assessment snapshot (reforge/assessment.py).

The dashboard is only trustworthy if these numbers are. Every test here asserts that a value is
derived from real session state — and, just as importantly, that nothing is invented when the
state is empty.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from reforge import assessment as A                                  # noqa: E402
from reforge.session import Session                                  # noqa: E402


def _target(s, **profile):
    s.target_path = "/tmp/demo.exe"
    s.static_done = True
    s.target_profile = {"file": "demo.exe", "format": "PE", "arch": "x64", **profile}
    return s


# ----------------------------- classification -----------------------------
def test_hardening_is_not_a_vulnerability():
    f = {"title": "Missing mitigation: DEP", "severity": "MEDIUM", "status": "CONFIRMED",
         "vuln_type": "hardening"}
    assert A.classify(f) == "hardening"


def test_isolated_sink_is_informational_not_a_vulnerability():
    """A dangerous API in the import table with nothing else around it is attack surface."""
    f = {"title": "exec sink present (CreateProcessA)", "severity": "LOW", "status": "HYPOTHESIS",
         "vuln_type": "exec", "evidence_bundle": {"isolated_only": True}}
    assert A.classify(f) == "informational"


def test_indicator_status_is_informational():
    f = {"title": "High-entropy resource section", "severity": "INFO", "status": "INDICATOR"}
    assert A.classify(f) == "informational"


def test_rejected_finding_is_its_own_bucket():
    f = {"title": "X", "severity": "HIGH", "status": "REJECTED", "vuln_type": "mem_copy"}
    assert A.classify(f) == "rejected"


def test_real_defect_is_a_vulnerability():
    f = {"title": "Stack overflow in parse_packet", "severity": "HIGH", "status": "HYPOTHESIS",
         "vuln_type": "mem_copy", "location": "0x401234"}
    assert A.classify(f) == "vulnerability"


def test_bucket_splits_all_four_kinds():
    found = [
        {"title": "a", "severity": "HIGH", "status": "HYPOTHESIS", "vuln_type": "mem_copy"},
        {"title": "b", "severity": "MEDIUM", "status": "CONFIRMED", "vuln_type": "hardening"},
        {"title": "c", "severity": "INFO", "status": "INDICATOR"},
        {"title": "d", "severity": "HIGH", "status": "REJECTED", "vuln_type": "exec"},
    ]
    b = A.bucket(found)
    assert len(b["vulnerabilities"]) == 1
    assert len(b["hardening"]) == 1
    assert len(b["informational"]) == 1
    assert len(b["rejected"]) == 1


# ----------------------------- risk -----------------------------
def test_risk_unknown_before_static_analysis():
    """"We have not looked" must not render the same as "we looked and found nothing"."""
    r = A.risk([], [], analyzed=False)
    assert r["band"] == "UNKNOWN"


def test_risk_none_after_clean_static_analysis():
    r = A.risk([], [], analyzed=True)
    assert r["band"] == "NONE"


def test_risk_band_is_the_highest_confirmed_severity():
    vulns = [
        {"title": "a", "severity": "CRITICAL", "status": "HYPOTHESIS", "vuln_type": "exec"},
        {"title": "b", "severity": "HIGH", "status": "confirmed_dynamic", "vuln_type": "mem_copy"},
    ]
    r = A.risk(vulns, [], analyzed=True)
    assert r["band"] == "HIGH"          # the CRITICAL one is unconfirmed, so it does not set the band
    assert r["confirmed"] is True


def test_unconfirmed_claims_are_demoted_one_band():
    """An LLM or heuristic claiming CRITICAL with no evidence must not drive the headline number."""
    vulns = [{"title": "a", "severity": "CRITICAL", "status": "HYPOTHESIS", "vuln_type": "exec"}]
    r = A.risk(vulns, [], analyzed=True)
    assert r["band"] == "HIGH"
    assert r["confirmed"] is False
    assert "one band lower" in r["basis"]


def test_hardening_never_raises_the_risk_band():
    hardening = [{"title": "Missing mitigation: DEP", "severity": "CRITICAL",
                  "status": "CONFIRMED", "vuln_type": "hardening"}]
    r = A.risk([], hardening, analyzed=True)
    assert r["band"] == "NONE"
    assert r["amplifiers"] == ["Missing mitigation: DEP"]


def test_risk_basis_is_always_explained():
    for args in (([], [], True), ([], [], False),
                 ([{"title": "a", "severity": "LOW", "status": "CONFIRMED", "vuln_type": "file"}], [], True)):
        assert A.risk(*args)["basis"].strip()


# ----------------------------- attack surface -----------------------------
def test_attack_surface_is_empty_without_static_analysis():
    s = Session("p", "demo")
    surf = A.attack_surface(s)
    assert surf["available"] is False
    assert surf["sinks"] == [] and surf["sources"] == [] and surf["source_groups"] == []


def test_attack_surface_ranks_sinks_by_worst_case():
    s = Session("p", "demo")
    s.attack_surface = {
        "sinks": {"file": ["CreateFileA"], "exec": ["CreateProcessA", "system"]},
        "sources": {"recv": "network (socket)", "GetCommandLineA": "command-line arguments"},
    }
    surf = A.attack_surface(s)
    assert surf["available"] is True
    # ordered by the worst case if the sink turns out to be reachable
    assert surf["sinks"][0]["klass"] == "exec"
    assert surf["sinks"][0]["potential_severity"] == "CRITICAL"
    assert surf["sinks"][0]["priority"] == "high"
    assert surf["sinks"][0]["cwe"] == "CWE-78"
    assert surf["sinks"][0]["count"] == 2
    # the explanation comes from reforge.sinks, never re-worded here
    from reforge.sinks import _PLAIN
    assert surf["sinks"][0]["why"] == _PLAIN["exec"]


def test_input_sources_are_grouped_by_origin():
    s = Session("p", "demo")
    s.attack_surface = {"sinks": {}, "sources": {"recv": "network (socket)",
                                                 "recvfrom": "network (socket)",
                                                 "ReadFile": "file"}}
    surf = A.attack_surface(s)
    groups = {g["origin"]: g for g in surf["source_groups"]}
    assert groups["network (socket)"]["count"] == 2
    assert groups["network (socket)"]["symbols"] == ["recv", "recvfrom"]
    assert groups["file"]["symbols"] == ["ReadFile"]


def test_attack_surface_has_no_behavioural_capability_taxonomy():
    """Removed with the malware vocabulary: the surface is sinks and sources, nothing else."""
    s = Session("p", "demo")
    s.attack_surface = {"capabilities": {"keylog": ["SetWindowsHookExA"]}, "sinks": {}, "sources": {}}
    surf = A.attack_surface(s)
    assert "categories" not in surf
    assert surf["available"] is False, "a leftover capability map must not resurrect the surface"


# ----------------------------- coverage -----------------------------
def test_coverage_ratios_are_none_without_a_denominator():
    s = Session("p", "demo")
    cov = A.coverage(s, A.bucket([]))
    assert cov["evidence_backed_pct"] is None
    assert cov["confirmed_pct"] is None


def test_coverage_counts_real_records():
    s = _target(Session("p", "demo"))
    s.add_finding({"title": "a", "severity": "HIGH", "status": "confirmed_dynamic",
                   "vuln_type": "mem_copy", "evidence_refs": ["E-0001"]})
    s.add_finding({"title": "b", "severity": "HIGH", "status": "HYPOTHESIS", "vuln_type": "exec"})
    cov = A.coverage(s, A.bucket(s.findings))
    assert cov["findings_total"] == 2
    assert cov["evidence_backed"] == 1 and cov["evidence_backed_pct"] == 50
    assert cov["dynamically_confirmed"] == 1
    assert cov["static_done"] is True


# ----------------------------- next actions -----------------------------
def test_next_action_without_a_target_is_to_load_one():
    s = Session("p", "demo")
    snap = A.snapshot(s)
    assert [a["key"] for a in snap["next_actions"]] == ["load_target"]


def test_next_action_after_target_but_before_static_is_to_run_static():
    s = Session("p", "demo")
    s.target_path = "/tmp/demo.exe"
    snap = A.snapshot(s)
    assert [a["key"] for a in snap["next_actions"]] == ["run_static"]


def test_high_severity_candidates_are_the_top_recommendation():
    s = _target(Session("p", "demo"))
    s.add_finding({"title": "a", "severity": "CRITICAL", "status": "HYPOTHESIS",
                   "vuln_type": "mem_copy", "location": "0x1"})
    actions = A.snapshot(s)["next_actions"]
    assert actions[0]["key"] == "validate_high"
    assert actions[0]["priority"] == "p0"
    assert actions[0]["count"] == 1


def test_recommendations_carry_their_count_and_never_fabricate():
    """Each action must be backed by a real count; nothing is emitted on an untouched project."""
    s = _target(Session("p", "demo"))
    for a in A.snapshot(s)["next_actions"]:
        assert a["count"] is None or a["count"] > 0
    # no findings, no artifacts, no report -> only the generic "add artifacts" style suggestions
    assert "validate_high" not in [a["key"] for a in A.snapshot(s)["next_actions"]]


def test_sink_tracing_is_suggested_only_while_no_vulnerability_exists():
    s = _target(Session("p", "demo"))
    s.attack_surface = {"capabilities": {}, "sinks": {"exec": ["CreateProcessA"]}, "sources": {}}
    assert "trace_sinks" in [a["key"] for a in A.snapshot(s)["next_actions"]]
    s.add_finding({"title": "real bug", "severity": "HIGH", "status": "HYPOTHESIS",
                   "vuln_type": "exec", "location": "0x1"})
    assert "trace_sinks" not in [a["key"] for a in A.snapshot(s)["next_actions"]]


# ----------------------------- snapshot shape -----------------------------
def test_snapshot_is_complete_and_json_safe_on_an_empty_project():
    import json
    snap = A.snapshot(Session("p", "demo"))
    for key in ("target", "risk", "counts", "attack_surface", "coverage", "workflow",
                "next_actions", "activity"):
        assert key in snap, f"missing key: {key}"
    json.dumps(snap)                       # must survive the API serializer


def test_snapshot_reports_the_deterministic_workflow_phase():
    s = _target(Session("p", "demo"))
    snap = A.snapshot(s)
    assert snap["workflow"]["phase"] in [p["key"] for p in snap["workflow"]["phases"]]
    assert snap["coverage"]["phases_total"] == len(snap["workflow"]["phases"])


def test_activity_is_newest_first_and_bounded():
    s = _target(Session("p", "demo"))
    for i in range(30):
        s.log_tool(f"tool_{i}", {}, "ok", False, None)
    act = A.activity(s, limit=5)
    assert len(act) == 5
    assert act[0]["tool"] == "tool_29"


def test_snapshot_never_invents_a_target_profile():
    snap = A.snapshot(Session("p", "demo"))
    assert snap["target"]["loaded"] is False
    assert snap["target"].get("sha256") is None


# ----------------------- API surface -----------------------
def test_assessment_endpoint_and_project_payload():
    """The dashboard needs the target profile and attack surface through the API; both used to be
    computed, stored on the session, and then unreachable from the client."""
    import logging
    logging.disable(logging.CRITICAL)
    from fastapi.testclient import TestClient
    from reforge.server import app, store
    from reforge import config

    headers = {"X-Reforge-Token": config.AUTH_TOKEN}
    with TestClient(app) as c:
        pid = c.post("/api/projects", json={"name": "assessment-api-test"},
                     headers=headers).json()["id"]
        try:
            payload = c.get(f"/api/projects/{pid}", headers=headers).json()
            for key in ("target_profile", "attack_surface", "artifacts",
                        "static_done", "report_generated"):
                assert key in payload, f"project payload is missing {key}"
            # existing keys must survive untouched
            for key in ("findings", "evidence", "static_strings", "static_imports",
                        "transcript"):
                assert key in payload, f"project payload lost {key}"

            r = c.get(f"/api/projects/{pid}/assessment", headers=headers)
            assert r.status_code == 200
            snap = r.json()
            assert snap["risk"]["band"] == "UNKNOWN"
            assert snap["target"]["loaded"] is False

            assert c.get("/api/projects/does-not-exist/assessment",
                         headers=headers).status_code == 404
            # IOC extraction is gone: neither the payload key nor the endpoint remain
            assert "static_iocs" not in payload
            assert c.get(f"/api/projects/{pid}/iocs", headers=headers).status_code == 404
        finally:
            store.delete(pid)
    logging.disable(logging.NOTSET)


def test_approval_event_carries_risk_metadata():
    """The approval card can only ask for informed consent if the event says what is at stake."""
    import asyncio
    from reforge.session import Session

    s = Session("p", "demo")
    loop = asyncio.new_event_loop()

    async def scenario():
        task = asyncio.ensure_future(s.request_approval(
            "x64dbg__MemoryWrite", {"address": "0x401000"}, "write_or_patch requires approval",
            risk_class="write_or_patch", consequence="Modifies state.", risk_level="HIGH"))
        evt = await s.events.get()
        for aid in list(s.pending):
            s.resolve_approval(aid, False)
        await task
        return evt

    try:
        evt = loop.run_until_complete(scenario())
    finally:
        loop.close()

    assert evt["kind"] == "awaiting_approval"
    assert evt["risk_class"] == "write_or_patch"
    assert evt["risk_level"] == "HIGH"
    assert evt["consequence"]


def test_policy_describes_every_risk_class():
    from reforge import policy
    for rc in ("safe_read", "sensitive_read", "dynamic_execution", "write_or_patch", "network"):
        assert policy.consequence(rc), f"no consequence text for {rc}"
        assert policy.risk_level(rc) in ("HIGH", "MEDIUM", "LOW")
    # state-changing classes must never be presented as low risk
    assert policy.risk_level("write_or_patch") == "HIGH"
    assert policy.risk_level("dynamic_execution") == "HIGH"
