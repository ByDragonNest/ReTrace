"""Test dei moduli v5.6: arricchimento xref Ghidra, CVE in CycloneDX, parsing callsite."""
import asyncio

from reforge import xref_enrich as xe, sbom_sarif as ss


# --------------------------- parsing callsite ------------------------------
def test_parse_callsites_prefers_ghidra_names():
    sites = xe._parse_callsites(
        "Reference at 0x4012af in FUN_401200\n"
        "xref 0x401300 sub_401290\n"
        "call 0x401400 from CreateProcessHandler")
    assert sites[0] == {"function": "FUN_401200", "callsite": "0x4012af"}
    assert sites[1] == {"function": "sub_401290", "callsite": "0x401300"}
    # parola di servizio scartata, nome reale tenuto
    assert sites[2]["function"] == "CreateProcessHandler"


def test_parse_callsites_dedup_and_cap():
    text = "\n".join(["xref 0x401000 FUN_401000"] * 10)
    sites = xe._parse_callsites(text, max_sites=5)
    assert len(sites) == 1  # dedotto per (func, addr)


def test_parse_callsites_empty():
    assert xe._parse_callsites("nessun indirizzo qui") == []


# --------------------------- tool discovery --------------------------------
class _TI:
    def __init__(self, server, name):
        self.server = server
        self.name = name
        self.qualified = f"{server}__{name}"


class _Host:
    def __init__(self, tools, reply="Reference at 0x4012af in FUN_401200"):
        self._tools = tools
        self._reply = reply
        self.calls = []

    def catalog(self):
        return self._tools

    async def call(self, q, args):
        self.calls.append((q, args))
        return {"text": self._reply, "is_error": False}


def test_find_xref_tool_prefers_ghidra():
    host = _Host([_TI("x64dbg", "get_xrefs"), _TI("ghidra", "find_references")])
    assert xe._find_xref_tool(host) == "ghidra__find_references"


def test_find_xref_tool_none_when_absent():
    host = _Host([_TI("ghidra", "decompile"), _TI("x64dbg", "run")])
    assert xe._find_xref_tool(host) is None


# --------------------------- enrich flow -----------------------------------
class _Sess:
    id = "tx9"
    target_profile = {"file": "BimGrp24.exe", "sha256": "z"}
    target_path = None
    static_imports = ["CreateProcessA", "recv"]


def test_enrich_with_host_localizes_chains():
    host = _Host([_TI("ghidra", "get_xrefs")])
    r = asyncio.run(xe.enrich_chains(_Sess(), host))
    assert r["xref_tool"] == "ghidra__get_xrefs"
    assert r["total"] >= 1
    assert r["localized"] >= 1
    ch = r["chains"][0]
    assert ch["function"] == "FUN_401200"
    assert ch["callsite"] == "0x4012af"
    # ogni sink interrogato una sola volta (CreateProcessA), non per ogni catena
    sinks_queried = {a.get("name") for _, a in host.calls}
    assert "CreateProcessA" in sinks_queried


def test_enrich_without_host_degrades():
    """With no Ghidra server, enrichment localizes nothing and says so - it does not fail.

    The assertion is on the *behaviour*, not on the sentence: an earlier version matched the word
    "nessuno", which pinned the test to Italian copy and broke the moment the product became
    English-only. `xref_tool` must name no tool; which words say that is the UI's business.
    """
    r = asyncio.run(xe.enrich_chains(_Sess(), None))
    assert r["localized"] == 0
    assert "none" in r["xref_tool"].lower()
    assert "ghidra_" not in r["xref_tool"], "no tool should be named when none was available"
    assert r["total"] >= 1  # the candidate chains are still there


# --------------------------- CycloneDX + CVE -------------------------------
def test_cyclonedx_offline_no_vulnerabilities():
    cdx = ss.to_cyclonedx([{"library": "zlib", "version": "1.2.11", "keyword": "zlib"}],
                          binary_name="x", online=False)
    assert "vulnerabilities" not in cdx


def test_cyclonedx_with_supplied_cves():
    cdx = ss.to_cyclonedx([{"library": "OpenSSL", "version": "1.0.1",
                            "cves": [{"id": "CVE-2014-0160", "severity": "HIGH"}]}],
                          binary_name="x")
    assert len(cdx["vulnerabilities"]) == 1
    v = cdx["vulnerabilities"][0]
    assert v["id"] == "CVE-2014-0160"
    assert v["ratings"][0]["severity"] == "high"
    assert v["affects"][0]["ref"].startswith("pkg:generic/openssl@")


def test_cdx_sev_mapping():
    assert ss._cdx_sev("9.8") == "critical"
    assert ss._cdx_sev("7.0") == "high"
    assert ss._cdx_sev("4.5") == "medium"
    assert ss._cdx_sev("HIGH") == "high"
    assert ss._cdx_sev("garbage") == "unknown"
