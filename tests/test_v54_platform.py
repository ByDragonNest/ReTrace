"""Test dei moduli v5.4: Evidence Graph, Finding Validator, source→sink, playbook, job manager."""
import asyncio

import pytest

from reforge import (evidence_graph as eg, finding_validator as fv,
                     source_to_sink as s2s, playbook as pb, job_manager as jm)


# --------------------------- Evidence Graph --------------------------------
def _graph():
    g = eg.EvidenceGraph(":memory:")
    b = g.add_binary({"file": "BimGrp24.exe", "sha256": "abc", "arch": "x86"})
    g.add_import(b, "CreateProcessA")
    g.add_import(b, "strcpy")
    sk = g.add_sink("CreateProcessA")
    src = g.add_source("argv")
    g.link_source_to_sink(src, sk)
    g.add_evidence("E-0001", {"source": "ghidra"})
    g.add_finding("F-0001", {"title": "USP", "severity": "HIGH",
                             "status": "hypothesis", "location": "0x401200"})
    g.link_evidence_to_finding("evidence:E-0001", "finding:F-0001")
    fn = g.add_function(b, "0x401200", "FUN_401200")
    g.link_finding_to_function("finding:F-0001", fn)
    return g


def test_graph_creation_and_stats():
    g = _graph()
    s = g.stats()
    assert s["binary"] == 1 and s["import"] == 2 and s["finding"] == 1
    assert s["edges"] >= 5


def test_graph_finding_with_evidence():
    g = _graph()
    f = g.get_finding_with_evidence("finding:F-0001")
    assert f["evidence"][0]["id"] == "evidence:E-0001"
    assert f["functions"][0]["label"] == "FUN_401200"


def test_graph_unvalidated_sinks_and_weak_findings():
    g = _graph()
    assert any(n["label"] == "CreateProcessA" for n in g.unvalidated_sinks())
    weak = g.findings_lacking_evidence(min_evidence=2)
    assert weak and weak[0]["evidence_count"] == 1


def test_graph_mark_sink_validated():
    g = _graph()
    g.mark_sink_validated("CreateProcessA", True)
    assert not any(n["label"] == "CreateProcessA" for n in g.unvalidated_sinks())


def test_graph_export_json():
    g = _graph()
    j = g.to_json()
    assert set(j.keys()) >= {"nodes", "edges", "stats"}
    assert any(n["type"] == "finding" for n in j["nodes"])


def test_graph_idempotent_sync():
    class Sess:
        id = "tx"
        target_profile = {"file": "x.exe", "sha256": "z"}
        static_imports = ["CreateProcessA", "strcpy"]
        evidence = [{"id": "E-0001", "source": "ghidra"}]
        findings = [{"id": "F-0001", "title": "t", "severity": "HIGH",
                     "status": "hypothesis", "location": "0x401200",
                     "evidence_refs": ["E-0001"]}]
    g = eg.EvidenceGraph(":memory:")
    a = g.sync_from_session(Sess())
    b = g.sync_from_session(Sess())
    assert a == b  # idempotente


# --------------------------- Finding Validator -----------------------------
def test_validator_import_only_stays_hypothesis():
    r = fv.validate_finding({"id": "F-1", "severity": "HIGH", "status": "hypothesis",
                             "location": "0x401200", "evidence": "import table"})
    assert r["status"] == fv.HYPOTHESIS
    assert r["confidence"] <= 0.30
    assert "Missing source-to-sink evidence" in r["warnings"]


def test_validator_dynamic_confirmed():
    r = fv.validate_finding({"id": "F-2", "severity": "CRITICAL", "status": "confirmed_dynamic",
                             "location": "0x4015af", "recommendation": "fix",
                             "evidence": "osservato a runtime in x64dbg, breakpoint, source→sink",
                             "evidence_refs": ["E-1", "E-2"]})
    assert r["status"] == fv.CONFIRMED
    assert r["exportable_as_confirmed"] is True


def test_validator_no_evidence_id_blocks_confirmed():
    r = fv.validate_finding({"id": "F-3", "severity": "HIGH", "status": "confirmed_dynamic",
                             "location": "0x401200",
                             "evidence": "runtime breakpoint source sink"})
    assert r["status"] != fv.CONFIRMED  # senza evidence ID non è esportabile come confermato


def test_validator_session_summary():
    class S:
        findings = [{"id": "F-1", "severity": "LOW", "status": "hypothesis",
                     "location": "0x1", "evidence": "x"}]
    out = fv.validate_session(S())
    assert out["summary"]["total"] == 1


# --------------------------- source → sink ---------------------------------
def test_s2s_candidate_chains():
    ch = s2s.build_candidate_chains(["argv[1]"], ["CreateProcessA"])
    assert ch and ch[0]["sink"] == "CreateProcessA"
    assert ch[0]["argument"] == "lpCommandLine"
    assert 0 < ch[0]["confidence"] < 1


def test_s2s_confirm_raises_confidence():
    ch = s2s.build_candidate_chains(["argv[1]"], ["CreateProcessA"])[0]
    before = ch["confidence"]
    after = s2s.confirm_chain(ch, "E-0009")
    assert after["confirmed_dynamic"] is True
    assert after["confidence"] > before
    assert "E-0009" in after["evidence_refs"]


def test_s2s_refine_adds_callsite():
    ch = s2s.build_candidate_chains(["argv[1]"], ["strcpy"])[0]
    ref = s2s.refine_chain(ch, function="FUN_401200", callsite="0x4012af")
    assert ref["callsite"] == "0x4012af"
    assert ref["confidence"] >= ch["confidence"]


# --------------------------- playbook --------------------------------------
def test_playbook_loading():
    pbs = pb.load_all()
    ids = {k for k in pbs if k != "_errors"}
    assert {"vulnerability_audit", "vuln_triage", "report_only"} <= ids
    assert "malware_triage" not in ids        # replaced by vuln_triage (benign-target lens)
    assert "_errors" not in pbs or not pbs["_errors"]


def test_playbook_required_fields():
    va = pb.get("vulnerability_audit")
    assert va["safety_mode"] in pb.VALID_SAFETY
    assert isinstance(va["steps"], list) and va["steps"]


def test_playbook_summaries_hide_prompt():
    for s in pb.list_summaries():
        assert "system_prompt" not in s


# --------------------------- job manager -----------------------------------
def test_job_state_transitions():
    j = jm.Job("static_analysis", {})
    assert j.status == jm.QUEUED
    assert j.set_status(jm.RUNNING) is True
    assert j.set_status(jm.COMPLETED) is True
    assert j.set_status(jm.RUNNING) is False  # transizione non consentita da completed


def test_job_run_success():
    mgr = jm.JobManager()

    async def handler(job, **kw):
        return {"ok": True, "echo": kw.get("x")}

    mgr.register("echo", handler)
    job = mgr.submit("echo", {"x": 42})
    asyncio.run(mgr.run_job(job))
    assert job.status == jm.COMPLETED
    assert job.output == {"ok": True, "echo": 42}
    assert job.duration is not None


def test_job_run_failure():
    mgr = jm.JobManager()

    async def boom(job, **kw):
        raise RuntimeError("kaboom")

    mgr.register("boom", boom)
    job = mgr.submit("boom", {})
    asyncio.run(mgr.run_job(job))
    assert job.status == jm.FAILED
    assert "kaboom" in job.error


def test_job_unknown_kind_fails_fast():
    mgr = jm.JobManager()
    job = mgr.submit("nonexistent", {})
    assert job.status == jm.FAILED
    # The message moved to English in slice P2-S10; the contract is that the error names the
    # unknown kind, not that it is phrased a particular way.
    assert "No handler" in job.error and "nonexistent" in job.error
