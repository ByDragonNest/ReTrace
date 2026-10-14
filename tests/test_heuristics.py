"""Tests for the offline heuristic VULNERABILITY engine (heuristics.py) and raw export.

ReTrace analyses benign software for vulnerabilities (NOT malware). The heuristic engine surfaces
vulnerability-relevant behaviours in a runtime/network trace, mapped to CWE, deterministically and
offline. These tests build representative traces of a benign program and assert the right CWE
findings fire.
"""
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from reforge import heuristics as H        # noqa: E402
from reforge import artifacts as A         # noqa: E402
from reforge import raw_export as RAW      # noqa: E402


# A benign program trace exhibiting vulnerability-relevant behaviours.
VULN_PROCMON = """<?xml version="1.0"?><procmon><eventlist>
<event><Process_Name>app.exe</Process_Name><Operation>Load Image</Operation><Path>C:\\Program Files\\App\\helper.dll</Path><Result>NAME NOT FOUND</Result></event>
<event><Process_Name>app.exe</Process_Name><Operation>Load Image</Operation><Path>C:\\Users\\v\\AppData\\Local\\Temp\\helper.dll</Path><Result>SUCCESS</Result></event>
<event><Process_Name>app.exe</Process_Name><Operation>WriteFile</Operation><Path>C:\\ProgramData\\App\\session_token.dat</Path><Result>SUCCESS</Result></event>
<event><Process_Name>app.exe</Process_Name><Operation>ReadFile</Operation><Path>C:\\Users\\Public\\App\\settings.ini</Path><Result>SUCCESS</Result></event>
<event><Process_Name>app.exe</Process_Name><Operation>Process Create</Operation><Path>C:\\Windows\\System32\\cmd.exe</Path><Result>SUCCESS</Result><Detail>cmd.exe /c update.bat</Detail></event>
</eventlist></procmon>"""


def _ids(res):
    return {f["id"] for f in res["findings"]}


def test_procmon_detects_vulnerability_surface(tmp_path):
    p = tmp_path / "v.xml"
    p.write_text(VULN_PROCMON, encoding="utf-8")
    res = H.analyze({"path": str(p), "type": A.TYPE_PROCMON_XML})
    ids = _ids(res)
    # DLL search-order hijack (both the NAME NOT FOUND probe and the writable-dir load)
    assert "procmon.dll_hijack.search" in ids
    assert "procmon.dll_hijack.writable" in ids
    # secret written to disk
    assert "procmon.sensitive.secret_on_disk" in ids
    # untrusted config from a user-writable location
    assert "procmon.untrusted_input.config" in ids
    # command-execution sink
    assert "procmon.command.spawn" in ids
    # every finding carries a CWE (NOT ATT&CK) and evidence
    for f in res["findings"]:
        assert f["cwe"] and all(c.startswith("CWE-") for c in f["cwe"])
        assert f["evidence"]
    # no malware-framed ids leaked back in
    assert not any("c2" in i or "ransom" in i or "dropper" in i or "persistence" in i for i in ids)


def test_procmon_clean_trace_no_findings(tmp_path):
    clean = ('<?xml version="1.0"?><procmon><eventlist>'
             '<event><Process_Name>app.exe</Process_Name><Operation>ReadFile</Operation>'
             '<Path>C:\\Program Files\\App\\data.txt</Path><Result>SUCCESS</Result></event>'
             '</eventlist></procmon>')
    p = tmp_path / "c.xml"
    p.write_text(clean, encoding="utf-8")
    res = H.analyze({"path": str(p), "type": A.TYPE_PROCMON_XML})
    assert res["findings"] == []
    assert res["severity"] == "info"


def test_procmon_malformed_no_raise(tmp_path):
    p = tmp_path / "bad.xml"
    p.write_text("<procmon><eventlist><event><Operation>X", encoding="utf-8")
    res = H.analyze({"path": str(p), "type": A.TYPE_PROCMON_XML})
    assert "error" in res
    assert res["findings"] == []


def _build_pcap(path, packets):
    gh = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    body = b""
    for pkt in packets:
        body += struct.pack("<IIII", 0, 0, len(pkt), len(pkt)) + pkt
    path.write_bytes(gh + body)


def _eth_ip_tcp(dst, dport, payload=b""):
    eth = b"\x11" * 6 + b"\x22" * 6 + b"\x08\x00"
    tcp = struct.pack(">HHIIBBHHH", 55000, dport, 0, 0, 0x50, 0x18, 8192, 0, 0) + payload
    ip = bytes([0x45, 0, 0, 20 + len(tcp)]) + b"\x00" * 5 + bytes([6]) + b"\x00\x00" + \
        bytes([10, 0, 0, 2]) + bytes(dst)
    return eth + ip + tcp


def test_pcap_detects_cleartext_and_credentials(tmp_path):
    pkts = [
        _eth_ip_tcp([93, 184, 216, 34], 80,
                    b"GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNz\r\n\r\n"),
        _eth_ip_tcp([10, 0, 0, 5], 21),
    ]
    p = tmp_path / "v.pcap"
    _build_pcap(p, pkts)
    res = H.analyze({"path": str(p), "type": A.TYPE_PCAP})
    ids = _ids(res)
    assert "pcap.cleartext.http_auth" in ids        # CWE-522 credential exposure
    assert "pcap.cleartext.transport" in ids        # CWE-319 cleartext transport
    for f in res["findings"]:
        assert all(c.startswith("CWE-") for c in f["cwe"])


def test_pcap_https_only_no_cleartext_finding(tmp_path):
    pkts = [_eth_ip_tcp([93, 184, 216, 34], 443) for _ in range(5)]
    p = tmp_path / "tls.pcap"
    _build_pcap(p, pkts)
    res = H.analyze({"path": str(p), "type": A.TYPE_PCAP})
    assert "pcap.cleartext.transport" not in _ids(res)


def test_attack_surface_is_cwe_tagged_sinks_not_behavioural_capabilities():
    """The attack surface is expressed as CWE-tagged dangerous sinks and untrusted input sources.

    The old Windows-API -> behavioural-capability map (process injection / persistence / keylogging
    / anti-debug / host recon) answered "is this malicious", which is not ReTrace's question. It was
    removed; this asserts the vulnerability-oriented model that replaced it.
    """
    from reforge import sinks
    inv = sinks.inventory(["CreateProcessA", "LoadLibraryA", "system", "strcpy", "recv"])
    assert inv["sinks"], "no sinks classified"
    assert "exec" in inv["sinks"] and "mem_copy" in inv["sinks"]
    assert all(f.get("cwe") for f in inv["findings"]), "every sink finding must carry a CWE"
    # untrusted input sources are inventoried separately from the sinks they may reach
    assert "recv" in inv["sources"]


def test_static_analysis_has_no_capability_taxonomy():
    from reforge import static_analysis as sa
    for gone in ("_capability_findings", "CAPABILITIES", "API_MAP", "_iocs"):
        assert not hasattr(sa, gone), f"{gone} should have been removed"


# --------------------------------------------------------------------------- raw export
class _FakeSession:
    id = "proj1"
    name = "Audit Demo"
    target_path = "C:\\app.exe"
    target_profile = {"format": "PE32", "arch": "x86", "sha256": "abc", "import_count": 12}
    findings = [{"title": "Stack buffer overflow", "severity": "high", "description": "strcpy senza bound",
                 "evidence": ["0x401000: strcpy(dst, argv[1])"]}]
    static_strings = ["C:\\App\\config.ini", "SELECT * FROM users"]
    static_imports = ["strcpy", "CreateProcessA"]
    static_iocs = {"sink_indicators": ["strcpy", "cmd.exe"]}
    string_overrides = {}
    investigation_log = [{"ts": "t1", "kind": "tool", "summary": "ran procmon"}]
    llm_usage = []

    def __init__(self):
        self.artifacts = [{
            "id": "A-1", "name": "trace.xml", "type": A.TYPE_PROCMON_XML, "size": 100,
            "overview": {"headline": "events", "top_processes": [["app.exe", 5]]},
            "heuristics": {"headline": "2 high", "findings": [
                {"id": "procmon.dll_hijack.writable", "title": "DLL da dir scrivibile",
                 "severity": "high", "confidence": 0.8, "cwe": ["CWE-427"],
                 "summary": "hijack", "evidence": ["app.exe: Load Image temp\\x.dll"], "count": 1}]},
        }]


def test_raw_export_uses_cwe(monkeypatch):
    import reforge.evidence_graph as eg

    class _G:
        def sync_from_session(self, s): pass
        def to_json(self): return {"nodes": [{"id": "n1", "type": "finding", "label": "x"}],
                                   "edges": []}
    monkeypatch.setattr(eg, "for_session", lambda s: _G())

    md = RAW.build_markdown(_FakeSession())
    assert "CWE-427" in md
    assert "**CWE:**" in md
    assert "ATT&CK" not in md            # malware framing must be gone
    assert "Stack buffer overflow" in md
