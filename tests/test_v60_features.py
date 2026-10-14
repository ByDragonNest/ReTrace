"""Tests for the v6.0 feature block:

  * artifact_overview: offline per-type static overview (Procmon XML, PCAP, JSON), bounded + tolerant
  * playbook: data-driven module mapping + custom playbook CRUD (validation, save, shadow, delete)
  * neo4j_sync: status/Cypher export with no driver; sync via an injected fake driver

These avoid live services: PCAP/Procmon are built as fixtures; Neo4j is mocked.
"""
import struct
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from reforge import artifact_overview as OV     # noqa: E402
from reforge import artifacts as A              # noqa: E402
from reforge import playbook as PB              # noqa: E402


# --------------------------------------------------------------------------- artifact overview
PROCMON_XML = """<?xml version="1.0" encoding="UTF-8"?>
<procmon><eventlist>
<event><Process_Name>evil.exe</Process_Name><Operation>WriteFile</Operation>
  <Path>C:\\Temp\\a.bin</Path><Result>SUCCESS</Result></event>
<event><Process_Name>evil.exe</Process_Name><Operation>RegSetValue</Operation>
  <Path>HKLM\\Software\\Run</Path><Result>SUCCESS</Result></event>
<event><Process_Name>evil.exe</Process_Name><Operation>TCP Connect</Operation>
  <Path>10.0.0.1:443</Path><Result>SUCCESS</Result></event>
</eventlist></procmon>"""


def test_overview_procmon(tmp_path):
    p = tmp_path / "x.xml"
    p.write_text(PROCMON_XML, encoding="utf-8")
    ov = OV.build_overview({"path": str(p), "type": A.TYPE_PROCMON_XML, "size": len(PROCMON_XML)})
    assert ov["kind"] == "procmon"
    assert ov["events"] == 3
    kinds = dict(ov["events_by_kind"])
    assert kinds.get("file") == 1 and kinds.get("registry") == 1 and kinds.get("network") == 1
    assert ov["top_network"][0][0] == "10.0.0.1:443"


def test_overview_procmon_malformed_does_not_raise(tmp_path):
    p = tmp_path / "bad.xml"
    p.write_text("<procmon><eventlist><event><Operation>X", encoding="utf-8")  # truncated
    ov = OV.build_overview({"path": str(p), "type": A.TYPE_PROCMON_XML, "size": 30})
    assert ov["kind"] == "procmon"
    assert "error" in ov                          # captured, not raised


def _make_pcap(path: Path):
    gh = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)  # link type 1 = ethernet
    eth = b"\x11" * 6 + b"\x22" * 6 + b"\x08\x00"
    ip = bytes([0x45, 0, 0, 40]) + b"\x00" * 5 + bytes([6]) + b"\x00\x00" + \
        bytes([1, 2, 3, 4]) + bytes([5, 6, 7, 8])
    tcp = struct.pack(">HH", 50000, 443) + b"\x00" * 16
    pkt = eth + ip + tcp
    rec = struct.pack("<IIII", 0, 0, len(pkt), len(pkt))
    path.write_bytes(gh + rec + pkt)


def test_overview_pcap_offline(tmp_path):
    p = tmp_path / "t.pcap"
    _make_pcap(p)
    ov = OV.build_overview({"path": str(p), "type": A.TYPE_PCAP, "size": p.stat().st_size})
    assert ov["kind"] == "pcap"
    assert ov["packets"] == 1
    assert ov["link_type"] == "ETHERNET"
    assert ("1.2.3.4", 1) in ov["top_talkers"]
    assert (443, 1) in ov["top_ports"]
    assert dict(ov["l3_protocols"]).get("TCP") == 1


def test_overview_json(tmp_path):
    p = tmp_path / "x.json"
    p.write_text('{"a":1,"b":2,"c":3}', encoding="utf-8")
    ov = OV.build_overview({"path": str(p), "type": A.TYPE_JSON, "size": 19})
    assert ov["kind"] == "json"
    assert set(ov["json_keys"]) == {"a", "b", "c"}


def test_overview_missing_file():
    ov = OV.build_overview({"path": "/no/such/file", "type": A.TYPE_PROCMON_XML, "size": 1})
    assert "error" in ov


def test_should_auto_run_threshold():
    assert OV.should_auto_run({"size": 1024}) is True
    assert OV.should_auto_run({"size": OV.DEFAULT_AUTO_LIMIT + 1}) is False


# --------------------------------------------------------------------------- playbook modules
def test_bundled_playbooks_have_modules():
    summ = {s["id"]: s for s in PB.list_summaries()}
    assert "procmon_runtime_investigation" in summ
    assert "runtime" in summ["procmon_runtime_investigation"]["modules"]


def test_for_module_filters():
    ids = {s["id"] for s in PB.for_module("strings")}
    assert "source_to_sink_audit" in ids
    # a module no playbook targets returns empty, never errors
    assert PB.for_module("nonexistent-module") == []


def test_validate_payload_rejects_bad():
    errs = PB.validate_payload({"name": "x", "steps": [], "safety_mode": "safe"})
    assert any("steps" in e for e in errs)
    errs2 = PB.validate_payload({"id": "BAD ID!", "name": "x", "steps": ["a"], "safety_mode": "safe"})
    assert any("id" in e for e in errs2)
    errs3 = PB.validate_payload({"name": "x", "steps": ["a"], "safety_mode": "nope"})
    assert any("safety_mode" in e for e in errs3)
    errs4 = PB.validate_payload({"name": "x", "steps": ["a"], "safety_mode": "safe", "modules": ["bogus"]})
    assert any("modules" in e for e in errs4)


def test_custom_playbook_crud(tmp_path, monkeypatch):
    # Redirect the custom dir to a temp location so we don't touch the real one.
    monkeypatch.setattr(PB, "CUSTOM_DIR", tmp_path / "custom")
    pb = {"name": "My Net Triage", "steps": ["recon", "review"], "safety_mode": "safe",
          "modules": ["strings", "imports"], "description": "test"}
    rec = PB.save_custom(pb)
    assert rec["_custom"] is True
    assert rec["id"] == "my_net_triage"
    # appears in the module mapping
    assert "my_net_triage" in {s["id"] for s in PB.for_module("strings")}
    # delete
    assert PB.delete_custom("my_net_triage") is True
    assert "my_net_triage" not in {s["id"] for s in PB.list_summaries()}


def test_custom_cannot_delete_bundled():
    # Bundled playbooks live outside CUSTOM_DIR, so delete_custom returns False.
    assert PB.delete_custom("malware_triage") is False


# --------------------------------------------------------------------------- neo4j
def test_neo4j_status_no_driver(monkeypatch):
    from reforge import neo4j_sync as N
    monkeypatch.setattr(N, "driver_available", lambda: False)
    st = N.status()
    assert st["driver_installed"] is False
    assert st["reachable"] is None


def test_neo4j_cypher_export():
    from reforge import neo4j_sync as N
    g = {"nodes": [{"id": "a", "type": "binary", "label": "x"},
                   {"id": "b", "type": "dangerous_sink", "label": "y", "properties": {"deep": {"k": 1}}}],
         "edges": [{"source": "a", "target": "b", "type": "flows_to", "properties": {"c": 0.8}}]}
    cy = N.to_cypher("P1", g)
    assert "MATCH (n:ReforgeNode {project_id:" not in cy.split("\n")[0]  # comment first
    assert ":ReforgeNode:`Binary`" in cy
    assert ":ReforgeNode:`DangerousSink`" in cy
    assert "FLOWS_TO" in cy
    assert '"{\\"k\\": 1}"' in cy or "deep" in cy  # nested dict flattened to JSON string


def test_neo4j_sync_with_fake_driver(monkeypatch):
    from reforge import neo4j_sync as N
    from reforge import config
    calls = []

    class FakeSession:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def run(self, q, **kw): calls.append(q.strip().split("\n")[0]); return None

    class FakeDriver:
        def session(self, database=None): return FakeSession()
        def close(self): pass

    fake = types.ModuleType("neo4j")
    fake.GraphDatabase = types.SimpleNamespace(driver=lambda *a, **k: FakeDriver())
    monkeypatch.setitem(sys.modules, "neo4j", fake)
    monkeypatch.setattr(config, "NEO4J_ENABLED", True)

    g = {"nodes": [{"id": "a", "type": "binary", "label": "x"}],
         "edges": [{"source": "a", "target": "a", "type": "self"}]}
    res = N.sync_graph("P1", g)
    assert res["ok"] and res["nodes"] == 1 and res["edges"] == 1
    assert any("DETACH DELETE" in c for c in calls)        # scoped wipe ran
    assert any("MERGE (n:ReforgeNode" in c for c in calls)


def test_neo4j_sync_disabled_raises(monkeypatch):
    from reforge import neo4j_sync as N
    from reforge import config
    monkeypatch.setattr(config, "NEO4J_ENABLED", False)
    with pytest.raises(RuntimeError):
        N.sync_graph("P1", {"nodes": [], "edges": []})
