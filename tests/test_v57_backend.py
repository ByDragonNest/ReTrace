"""Backend tests for the v5.7 fixes.

Run in-process with FastAPI's TestClient (no live uvicorn). Covers:
  * centralized severity/confidence/CVSS normalization (report crash fix)
  * artifact upload / registry / type detection / id->path resolution / path-traversal safety
  * Procmon XML parsing on a real-shape sample (event count > 0)
  * x64dbg process-state oracle (timeout/no_event != terminated; terminated only with evidence)
  * intent-based tool loading (procmon_import / dynamic_analysis / report_generation / fallback)

These tests avoid network and the real MCP servers; MCP interaction is exercised via the parser
logic directly and via a fake host where needed.
"""
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from reforge import severity as S          # noqa: E402
from reforge import artifacts as A         # noqa: E402
from reforge import dbg_state as D         # noqa: E402
from reforge import intent as I            # noqa: E402
from reforge import workspace              # noqa: E402


# --------------------------------------------------------------------------- severity / report
@pytest.mark.parametrize("val,expect", [
    ("high", "HIGH"), ("HIGH", "HIGH"), ("alta", "HIGH"),
    ("critical", "CRITICAL"), ("media", "MEDIUM"), ("low", "LOW"),
    ("info", "INFO"), ("none", "INFO"), ("unknown", "INFO"),
    (8.1, "HIGH"), (9.8, "CRITICAL"), ("0.8", "HIGH"),
    (None, "INFO"), ("", "INFO"), ("garbage", "INFO"),
])
def test_norm_severity(val, expect):
    assert S.norm_severity(val) == expect


@pytest.mark.parametrize("val", ["high", "medium", "80%", "0.8", 80, None, "critical", "", "garbage"])
def test_norm_confidence_never_raises(val):
    out = S.norm_confidence(val)
    assert 0.0 <= out <= 1.0


@pytest.mark.parametrize("val", ["high", "8.1", "critical", None, "", "garbage"])
def test_cvss_score_never_raises(val):
    out = S.cvss_score(val)
    assert 0.0 <= out <= 10.0


def test_report_does_not_crash_on_label_strings():
    """The exact prompt bug: confidence/cvss/severity carrying labels must not crash the report."""
    import asyncio
    from reforge import config
    config.REPORT_USE_LLM_ENRICHMENT = False           # force the static path
    from reforge import report_pt
    from reforge.session import Session
    s = Session(name="crash")
    s.findings = [{"title": "BO", "severity": "high", "confidence": "high", "cvss": "high",
                   "status": "suspicious", "description": "d" * 60, "location": "sub_401000",
                   "evidence": "E-0001"}]
    s.target_profile = {"file": "BimGrp24.exe"}
    md = asyncio.new_event_loop().run_until_complete(report_pt.generate(s))
    assert isinstance(md, str) and len(md) > 100


def test_report_is_static_even_with_provider_on():
    import asyncio
    from reforge import config
    config.REPORT_USE_LLM_ENRICHMENT = False
    config.LLM_PROVIDER = "local"                       # provider "on" but enrichment off
    from reforge import report_pt
    from reforge.session import Session
    s = Session(name="static")
    s.findings = [{"title": "x", "severity": "medium", "status": "hypothesis",
                   "description": "y" * 50, "location": "sub_1"}]
    md = asyncio.new_event_loop().run_until_complete(report_pt.generate(s))
    assert "ReTrace" in md


# --------------------------------------------------------------------------- artifacts
PROCMON_SAMPLE = """<?xml version="1.0" encoding="UTF-8"?>
<procmon>
<processlist></processlist>
<eventlist>
<event>
<ProcessIndex>682</ProcessIndex>
<Time_of_Day>12:50:41,8963591</Time_of_Day>
<Process_Name>BimGrp24.exe</Process_Name>
<PID>352</PID>
<Operation>Process Start</Operation>
<Path></Path>
<Result>SUCCESS</Result>
<Detail>Parent PID: 9524</Detail>
</event>
<event>
<ProcessIndex>683</ProcessIndex>
<Time_of_Day>12:50:41,9000000</Time_of_Day>
<Process_Name>BimGrp24.exe</Process_Name>
<PID>352</PID>
<Operation>Load Image</Operation>
<Path>C:\\Windows\\System32\\ntdll.dll</Path>
<Result>SUCCESS</Result>
<Detail>Image Base: 0x77000000</Detail>
</event>
</eventlist></procmon>
"""


def test_detect_procmon_xml(tmp_path):
    p = tmp_path / "BimGrp.XML"
    p.write_text(PROCMON_SAMPLE, encoding="utf-8")
    assert A.detect_type(p, "BimGrp.XML") == A.TYPE_PROCMON_XML


def test_detect_types(tmp_path):
    (tmp_path / "a.json").write_text('{"x":1}', encoding="utf-8")
    (tmp_path / "b.txt").write_text("hello world plain text", encoding="utf-8")
    pe = tmp_path / "c.bin"; pe.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)
    assert A.detect_type(tmp_path / "a.json") == A.TYPE_JSON
    assert A.detect_type(tmp_path / "b.txt") == A.TYPE_TEXT
    assert A.detect_type(pe) == A.TYPE_PE


def test_artifact_store_register_resolve(tmp_path, monkeypatch):
    from reforge import config
    monkeypatch.setattr(config, "WORKSPACE_DIR", tmp_path)
    from reforge.session import Session
    s = Session(name="art")
    rec = A.store_upload(s.id, "BimGrp.XML", PROCMON_SAMPLE.encode("utf-8"))
    assert rec["type"] == A.TYPE_PROCMON_XML
    assert rec["routing"]["server"] == "procmon"
    A.register(s, rec)
    assert len(s.artifacts) == 1
    resolved = A.resolve_path(s, rec["id"])
    assert resolved.endswith(rec["name"])
    assert Path(resolved).is_file()


def test_artifact_resolution_rejects_traversal(tmp_path, monkeypatch):
    from reforge import config
    monkeypatch.setattr(config, "WORKSPACE_DIR", tmp_path)
    monkeypatch.setattr(config, "ALLOW_OUTSIDE_WORKSPACE", False)
    from reforge.session import Session
    s = Session(name="trav")
    rec = A.store_upload(s.id, "ok.xml", b"<procmon></procmon>")
    rec["path"] = "/etc/passwd"                          # tamper the stored path
    A.register(s, rec)
    with pytest.raises(workspace.UnsafePathError):
        A.resolve_path(s, rec["id"])


def test_procmon_parser_counts_events(tmp_path):
    """The actual Procmon MCP parser must return >0 events for a real-shape XML (not '0 events')."""
    spec = importlib.util.spec_from_file_location(
        "procmon_srv", str(ROOT / "servers" / "procmon_mcp.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    fn = getattr(m.procmon_load_xml, "fn", m.procmon_load_xml)
    p = tmp_path / "s.xml"; p.write_text(PROCMON_SAMPLE, encoding="utf-8")
    import json
    out = json.loads(fn(str(p)))
    assert out["events_loaded"] == 2
    assert out["total_events_seen"] == 2
    assert out["top_processes"][0][0] == "BimGrp24.exe"


# --------------------------------------------------------------------------- x64dbg state oracle
def test_timeout_is_not_terminated():
    v = D.classify_state(isdebugging_result={"is_error": True, "timeout": True, "text": "timeout"})
    assert v["state"] == D.RUNNING


def test_no_event_is_not_terminated():
    v = D.classify_state(isdebugging_result={"is_error": False, "text": "(no output)"})
    assert v["state"] == D.RUNNING
    v2 = D.classify_state(last_text="")
    assert v2["state"] != D.TERMINATED


def test_terminated_requires_strong_evidence():
    v = D.classify_state(isdebugging_result={"text": '{"isDebugging": false}'})
    assert v["state"] == D.TERMINATED
    v2 = D.classify_state(last_text="The process has exited with exit code 0")
    assert v2["state"] == D.TERMINATED


def test_terminated_confirmed_high_on_second_negative():
    v = D.classify_state(isdebugging_result={"text": "false"}, consecutive_negative=1)
    assert v["state"] == D.TERMINATED and v["confidence"] == "high"


def test_alive_markers_keep_running():
    assert D.classify_state(last_text="Breakpoint hit at 0x401000")["state"] == D.RUNNING
    assert D.classify_state(isdebugging_result={"text": "true"})["state"] == D.RUNNING


# --------------------------------------------------------------------------- intent loading
def test_intent_procmon_from_artifact():
    d = I.detect("", artifact_types=["procmon_xml"])
    assert d["intent"] == I.PROCMON_IMPORT


def test_intent_procmon_from_message():
    assert I.detect("importa il log procmon")["intent"] == I.PROCMON_IMPORT


def test_intent_dynamic_analysis():
    assert I.detect("metti un breakpoint in x64dbg")["intent"] == I.DYNAMIC_ANALYSIS
    assert I.detect("fai partire il processo e ispeziona i registri")["intent"] == I.DYNAMIC_ANALYSIS


def test_intent_report_generation():
    assert I.detect("genera il report PT in docx")["intent"] == I.REPORT_GENERATION
    # report intent loads no MCP tools (deterministic report)
    assert I.detect("genera il report")["queries"] == []


def test_intent_fallback_general():
    assert I.detect("ciao, da dove partiamo?")["intent"] == I.GENERAL


# --------------------------------------------------------------------------- artifact meta-tools
def test_summarize_for_llm_is_bounded(tmp_path, monkeypatch):
    from reforge import config
    monkeypatch.setattr(config, "WORKSPACE_DIR", tmp_path)
    from reforge.session import Session
    s = Session(name="sum")
    big = ("<procmon>" + "x" * 50000 + "</procmon>").encode("utf-8")
    rec = A.store_upload(s.id, "big.xml", big)
    A.register(s, rec)
    out = A.summarize_for_llm(rec, max_chars=1000)
    # The content peek must be truncated, not the whole 50k file.
    assert len(out) < 4000
    assert rec["id"] in out


def test_read_artifact_handler(tmp_path, monkeypatch):
    import asyncio
    from reforge import config
    monkeypatch.setattr(config, "WORKSPACE_DIR", tmp_path)
    from reforge.session import Session
    from reforge import agent
    from reforge.llm import ToolCall

    s = Session(name="rd")
    rec = A.store_upload(s.id, "BimGrp.XML", PROCMON_SAMPLE.encode("utf-8"))
    A.register(s, rec)

    # list_artifacts
    tc = ToolCall(id="1", name="list_artifacts", input={})
    out = asyncio.new_event_loop().run_until_complete(agent._dispatch(s, None, None, tc))
    assert rec["id"] in out["content"] and not out["is_error"]

    # read_artifact returns the bounded summary
    tc2 = ToolCall(id="2", name="read_artifact", input={"artifact_id": rec["id"]})
    out2 = asyncio.new_event_loop().run_until_complete(agent._dispatch(s, None, None, tc2))
    assert "Process_Name" in out2["content"] or "BimGrp24" in out2["content"]
    assert not out2["is_error"]

    # unknown id -> error, not crash
    tc3 = ToolCall(id="3", name="read_artifact", input={"artifact_id": "A-doesnotexist"})
    out3 = asyncio.new_event_loop().run_until_complete(agent._dispatch(s, None, None, tc3))
    assert out3["is_error"]


def test_store_stream_writes_full_file(tmp_path, monkeypatch):
    """Streaming upload must persist the whole file and detect its type (no in-memory full copy)."""
    import io
    from reforge import config
    monkeypatch.setattr(config, "WORKSPACE_DIR", tmp_path)
    from reforge.session import Session
    s = Session(name="stream")
    payload = PROCMON_SAMPLE.encode("utf-8")
    rec = A.store_stream(s.id, "BimGrp.XML", io.BytesIO(payload))
    assert rec["size"] == len(payload)
    assert rec["type"] == A.TYPE_PROCMON_XML
    assert Path(rec["path"]).read_bytes() == payload


def test_parse_artifact_bridges_path_to_mcp(tmp_path, monkeypatch):
    """parse_artifact must resolve the artifact path and pass it to the MCP tool's path arg."""
    import asyncio
    from reforge import config
    monkeypatch.setattr(config, "WORKSPACE_DIR", tmp_path)
    from reforge.session import Session
    from reforge import agent
    from reforge.llm import ToolCall

    s = Session(name="pa")
    rec = A.store_stream(s.id, "BimGrp.XML",
                         __import__("io").BytesIO(PROCMON_SAMPLE.encode("utf-8")))
    A.register(s, rec)

    captured = {}

    class FakeHost:
        tools = {"procmon__procmon_load_xml": object()}
        async def call(self, qualified, call_args):
            captured["qualified"] = qualified
            captured["args"] = call_args
            return {"is_error": False, "text": '{"events_loaded": 2}'}

    class FakeRegistry:
        def search(self, *a, **k): return []

    tc = ToolCall(id="1", name="parse_artifact", input={"artifact_id": rec["id"],
                                                        "process_name": "BimGrp24.exe"})
    out = asyncio.new_event_loop().run_until_complete(
        agent._dispatch(s, FakeHost(), FakeRegistry(), tc))
    assert not out["is_error"]
    assert captured["qualified"] == "procmon__procmon_load_xml"
    # The resolved real path was passed, not a path guessed from the conversation.
    # Since slice P0-S3 the stored name is generated from the artifact id and the DETECTED type,
    # never from the uploader-supplied filename, so this asserts the resolution rather than the
    # old name: a filename is attacker-controlled and must not reach the filesystem verbatim.
    assert captured["args"]["path"] == A.resolve_path(s, rec["id"])
    assert captured["args"]["path"].endswith(rec["name"])
    assert "BimGrp" not in captured["args"]["path"]
    assert Path(captured["args"]["path"]).is_file()
    assert captured["args"]["process_name"] == "BimGrp24.exe"


def test_parse_artifact_errors_when_server_not_connected(tmp_path, monkeypatch):
    import asyncio
    from reforge import config
    monkeypatch.setattr(config, "WORKSPACE_DIR", tmp_path)
    from reforge.session import Session
    from reforge import agent
    from reforge.llm import ToolCall

    s = Session(name="pa2")
    rec = A.store_stream(s.id, "x.xml", __import__("io").BytesIO(PROCMON_SAMPLE.encode("utf-8")))
    A.register(s, rec)

    class FakeHost:
        tools = {}  # procmon server NOT connected
        async def call(self, *a, **k): return {"is_error": False, "text": ""}

    class FakeRegistry:
        def search(self, *a, **k): return []

    tc = ToolCall(id="1", name="parse_artifact", input={"artifact_id": rec["id"]})
    out = asyncio.new_event_loop().run_until_complete(
        agent._dispatch(s, FakeHost(), FakeRegistry(), tc))
    assert out["is_error"]
    assert "is not available" in out["content"] or "does not appear to be connected" in out["content"]


# --------------------------------------------------------------------------- graph projection (v5.8)
def test_graph_projects_artifacts(tmp_path, monkeypatch):
    from reforge import config
    monkeypatch.setattr(config, "WORKSPACE_DIR", tmp_path)
    from reforge.session import Session
    from reforge import evidence_graph as eg
    s = Session(name="g")
    rec = A.store_stream(s.id, "BimGrp.XML", __import__("io").BytesIO(PROCMON_SAMPLE.encode("utf-8")))
    A.register(s, rec)
    g = eg.for_session(s)
    g.sync_from_session(s)
    j = g.to_json()
    art = [n for n in j["nodes"] if n["type"] == "artifact"]
    assert len(art) == 1 and art[0]["id"].endswith(rec["id"])


def test_graph_projects_procmon_summary_antinoise(tmp_path):
    from reforge import evidence_graph as eg
    g = eg.EvidenceGraph(str(tmp_path / "g.sqlite"))
    summary = {
        "top_processes": [["BimGrp24.exe", 150664]],
        "top_operations": [["RegQueryValue", 1240], ["CreateFile", 830]],
        "top_file_paths": [["C:\\BIM\\Input.txt", 50]],
        "top_registry_paths": [["HKLM\\Software\\BIM", 8]],
        "top_network": [],
    }
    g.project_procmon_summary("A-x", summary)
    j = g.to_json()
    types = {}
    for n in j["nodes"]:
        types[n["type"]] = types.get(n["type"], 0) + 1
    # Aggregated nodes only — NOT one node per event.
    assert types.get("process") == 1
    assert types.get("procmon_op") == 2
    assert types.get("file_path") == 1
    assert types.get("registry_key") == 1
    # total nodes stays tiny despite 150k events
    assert len(j["nodes"]) < 10


def test_procmon_load_summary_has_path_breakdown(tmp_path):
    """The enriched load summary must include file/registry breakdowns for graph projection."""
    import importlib.util, json as _json
    spec = importlib.util.spec_from_file_location(
        "procmon_srv2", str(ROOT / "servers" / "procmon_mcp.py"))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    fn = getattr(m.procmon_load_xml, "fn", m.procmon_load_xml)
    p = tmp_path / "s.xml"
    # sample includes a Load Image with a C:\ path
    p.write_text(PROCMON_SAMPLE, encoding="utf-8")
    out = _json.loads(fn(str(p)))
    assert "top_file_paths" in out and "top_registry_paths" in out and "top_network" in out
