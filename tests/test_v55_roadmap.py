"""Test dei moduli v5.5: graph diff, record_chain, SARIF, CycloneDX, persistenza job."""
import asyncio
import tempfile

from reforge import (evidence_graph as eg, graph_diff as gd,
                     sbom_sarif as ss, job_manager as jm)


# --------------------------- graph diff ------------------------------------
def _two_graphs():
    a = eg.EvidenceGraph(":memory:")
    ba = a.add_binary({"file": "v1.exe", "sha256": "a"})
    a.add_import(ba, "strcpy")
    a.add_finding("F-1", {"title": "BO", "severity": "HIGH", "status": "hypothesis"})
    b = eg.EvidenceGraph(":memory:")
    bb = b.add_binary({"file": "v2.exe", "sha256": "b"})
    b.add_import(bb, "strcpy")
    b.add_import(bb, "CreateProcessA")
    b.add_sink("CreateProcessA")
    b.add_finding("F-1", {"title": "BO", "severity": "HIGH", "status": "confirmed_dynamic"})
    b.add_finding("F-2", {"title": "Cmd inj", "severity": "CRITICAL", "status": "confirmed_dynamic"})
    return a, b


def test_diff_detects_added_and_removed():
    a, b = _two_graphs()
    d = gd.diff_objects(a, b)
    assert d["summary"]["new_sinks"] == 1
    assert d["summary"]["new_findings"] == 1
    assert d["summary"]["nodes_added"] >= 3


def test_diff_detects_status_change():
    a, b = _two_graphs()
    d = gd.diff_objects(a, b)
    changed = [c for c in d["changed"] if c["type"] == "finding"]
    assert changed and "status" in changed[0]["changes"]
    assert changed[0]["changes"]["status"]["to"] == "confirmed_dynamic"


def test_diff_highlights():
    a, b = _two_graphs()
    hl = gd.security_highlights(gd.diff_objects(a, b))
    assert any("CreateProcessA" in h for h in hl)
    assert any("confirmed_dynamic" in h for h in hl)


def test_diff_identical_graphs_empty():
    a, _ = _two_graphs()
    d = gd.diff_objects(a, a)
    assert d["summary"]["nodes_added"] == 0
    assert d["summary"]["nodes_removed"] == 0
    assert gd.security_highlights(d) == []


# --------------------------- record_chain (dataflow) -----------------------
def test_record_chain_persists_edge():
    g = eg.EvidenceGraph(":memory:")
    bid = g.add_binary({"file": "x", "sha256": "z"})
    g.record_chain(bid, {"source": "argv[1]", "sink": "CreateProcessA",
                         "function": "FUN_401200", "callsite": "0x4012AF",
                         "argument": "lpCommandLine", "confidence": 0.72})
    chains = g.chains()
    assert chains and chains[0]["callsite"] == "0x4012AF"
    assert chains[0]["argument"] == "lpCommandLine"
    # l'arco SOURCE_FLOWS_TO_SINK deve esistere
    assert g.query_edges("SOURCE_FLOWS_TO_SINK")


def test_record_chain_creates_function_link():
    g = eg.EvidenceGraph(":memory:")
    bid = g.add_binary({"file": "x", "sha256": "z"})
    g.record_chain(bid, {"source": "recv", "sink": "system",
                         "function": "FUN_402000", "callsite": "0x402010"})
    assert g.query_edges("FUNCTION_CALLS_IMPORT")
    assert g.stats()["function"] == 1


# --------------------------- SARIF -----------------------------------------
class _Sess:
    target_profile = {"file": "BimGrp24.exe"}
    target_path = None
    findings = [
        {"id": "F-1", "title": "Cmd inj", "severity": "CRITICAL", "status": "confirmed_dynamic",
         "cwe": "CWE-78", "location": "0x4012af", "description": "desc", "evidence_refs": ["E-1"]},
        {"id": "F-2", "title": "FP", "severity": "LOW", "status": "rejected",
         "location": "0x10", "description": "x"},
    ]


def test_sarif_structure_and_levels():
    sar = ss.to_sarif(_Sess())
    assert sar["version"] == "2.1.0"
    run = sar["runs"][0]
    # il finding REJECTED è escluso
    assert len(run["results"]) == 1
    assert run["results"][0]["level"] == "error"
    assert run["tool"]["driver"]["rules"][0]["id"] == "CWE-78"


def test_sarif_security_severity():
    sar = ss.to_sarif(_Sess())
    rule = sar["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["properties"]["security-severity"] == "9.5"


# --------------------------- CycloneDX -------------------------------------
def test_cyclonedx_structure():
    cdx = ss.to_cyclonedx([{"library": "zlib", "version": "1.2.11", "keyword": "zlib"},
                           {"library": "OpenSSL", "version": "1.0.1"}], binary_name="x.exe")
    assert cdx["bomFormat"] == "CycloneDX"
    assert cdx["specVersion"] == "1.5"
    assert len(cdx["components"]) == 2
    assert cdx["components"][0]["bom-ref"].startswith("pkg:generic/zlib@")


def test_cyclonedx_from_session_fallback():
    class S:
        target_profile = {"file": "x.exe"}
        target_path = None
        findings = [{"vuln_type": "third_party_component",
                     "title": "Libreria di terze parti: zlib 1.2.8"}]
    cdx = ss.cyclonedx_from_session(S())
    names = [c["name"] for c in cdx["components"]]
    assert "zlib" in names


# --------------------------- job persistence -------------------------------
def test_job_persistence_roundtrip():
    td = tempfile.mkdtemp()
    m = jm.JobManager(persist_dir=td)

    async def h(job, **kw):
        return {"ok": True}

    m.register("t", h)
    job = m.submit("t", {})
    asyncio.run(m.run_job(job))
    assert job.status == jm.COMPLETED

    m2 = jm.JobManager(persist_dir=td)
    n = m2.load_persisted()
    assert n == 1
    assert m2.get(job.id).status == jm.COMPLETED


def test_job_persistence_marks_interrupted():
    td = tempfile.mkdtemp()
    m = jm.JobManager(persist_dir=td)
    # job creato ma mai eseguito (resta queued su disco)
    job = jm.Job("x", {})
    m._jobs[job.id] = job
    m._save(job)

    m2 = jm.JobManager(persist_dir=td)
    m2.load_persisted()
    j = m2.get(job.id)
    assert j.status == jm.FAILED
    # The reason must say it was the restart, not the job: an operator reading the job list
    # should not go looking for a bug in the analysis.
    assert "restart" in (j.error or "").lower()
