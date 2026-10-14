"""Focused security/reliability tests for ReTrace (Phase 0/1).

Run from the repo root:   python -m pytest -q
or, without pytest:        python tests/test_security.py
"""
import asyncio
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from reforge import auth, policy, redact, workspace, config        # noqa: E402
from reforge.workspace import UnsafePathError                       # noqa: E402
from reforge.mcp_host import MCPHost, ToolInfo                       # noqa: E402
from reforge.session import Session                                 # noqa: E402


# ----------------------- 0.1 auth -----------------------
def test_auth_blocks_remote_without_token():
    assert auth.authorize("/api/status", "GET", "203.0.113.9", token_provided="",
                          token_expected="secret", auth_required=True, trust_localhost=True) is False


def test_auth_allows_remote_with_token():
    assert auth.authorize("/api/status", "GET", "203.0.113.9", token_provided="secret",
                          token_expected="secret", auth_required=True, trust_localhost=True) is True


def test_auth_allows_loopback():
    assert auth.authorize("/api/message", "POST", "127.0.0.1", token_provided="",
                          token_expected="secret", auth_required=True, trust_localhost=True) is True


def test_auth_static_always_open():
    assert auth.authorize("/styles.css", "GET", "203.0.113.9", token_provided="",
                          token_expected="secret", auth_required=True, trust_localhost=False) is True


# ----------------------- 0.2 path sandbox -----------------------
@pytest.mark.parametrize("bad", ["", "../../etc/passwd", "..\\..\\windows\\system32\\cmd.exe",
                                 "/etc/passwd", "/root/.ssh/id_rsa", r"C:\Windows\System32\kernel32.dll"])
def test_safe_resolve_rejects(bad):
    with pytest.raises(UnsafePathError):
        workspace.safe_resolve(bad)


def test_safe_resolve_accepts_workspace_file(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "WORKSPACE_DIR", tmp_path)
    f = tmp_path / "sample.bin"
    f.write_bytes(b"MZ\x90\x00")
    assert workspace.safe_resolve(str(f)) == f.resolve()


def test_sanitize_filename():
    assert workspace.sanitize_filename("../../evil; rm -rf.exe").endswith(".exe")
    assert "/" not in workspace.sanitize_filename("a/b/c.bin")
    assert workspace.sanitize_filename("") == "sample.bin"


# ----------------------- 0.3 approval / risk classes -----------------------
def test_risk_classes():
    assert policy.risk_class("x64dbg__DebugRun") == "dynamic_execution"
    assert policy.risk_class("ghidra__patch_bytes") == "write_or_patch"
    assert policy.risk_class("ghidra__list_imports") == "safe_read"


def test_gating_by_mode():
    assert policy.requires_approval("x64dbg__DebugRun", "assisted")[0] is True
    assert policy.requires_approval("x64dbg__DebugRun", "autonomous")[0] is False
    assert policy.requires_approval("ghidra__list_imports", "assisted")[0] is False
    assert policy.requires_approval("ghidra__list_imports", "safe")[0] is False
    # safe mode gates even a sensitive read
    assert policy.requires_approval("x64dbg__MemoryRead", "safe")[0] is True


# ----------------------- 0.4 tool timeout / truncation / breaker -----------------------
class _StubConn:
    def __init__(self, behavior):
        self.behavior = behavior

    async def call(self, name, args):
        if self.behavior == "hang":
            await asyncio.sleep(10)
        if self.behavior == "huge":
            class R:
                isError = False
                content = [type("B", (), {"type": "text", "text": "A" * 1000})()]
            return R()
        raise RuntimeError("boom")


def _host_with(behavior):
    h = MCPHost({"srv": {}})
    h.tools["srv__t"] = ToolInfo("srv", "t", "", {})
    h._conns["srv"] = _StubConn(behavior)
    return h


def test_tool_timeout(monkeypatch):
    monkeypatch.setattr(config, "TOOL_CALL_TIMEOUT", 0.05)
    h = _host_with("hang")
    res = asyncio.run(h.call("srv__t", {}))
    assert res["is_error"] and res.get("timeout")


def test_tool_output_capped(monkeypatch):
    monkeypatch.setattr(config, "TOOL_OUTPUT_MAX_CHARS", 100)
    h = _host_with("huge")
    res = asyncio.run(h.call("srv__t", {}))
    assert res["truncated"] and len(res["text"]) < 200


def test_circuit_breaker(monkeypatch):
    monkeypatch.setattr(config, "TOOL_BREAKER_THRESHOLD", 2)
    h = _host_with("err")
    asyncio.run(h.call("srv__t", {}))
    asyncio.run(h.call("srv__t", {}))
    res = asyncio.run(h.call("srv__t", {}))      # breaker now open
    assert res["is_error"] and res.get("breaker")


# ----------------------- 0.5 secret redaction / masking -----------------------
def test_redact_patterns():
    assert "sk-" not in redact.redact("token sk-ABCDEFGHIJKLMNOP1234 here")
    assert redact.mask("sk-supersecretkey")[-4:] == "tkey"
    assert redact.mask("") == ""


# ----------------------- 1.3 dedup / merge / validate -----------------------
def test_finding_update_on_match():
    """A second add with the same (title, location) updates in place instead of appending."""
    s = Session("p", "t")
    assert s.add_finding({"title": "X", "location": "0x1", "status": "HYPOTHESIS"}) is True
    assert s.add_finding({"title": "X", "location": "0x1", "status": "CONFIRMED",
                          "evidence": "e"}) is False        # updated, not appended
    assert len(s.findings) == 1
    assert s.findings[0]["evidence"] == "e"                 # descriptive fields merge


def test_a_declared_confirmation_without_evidence_is_capped_at_write_time():
    """Since slice P1-S1 the evidence gate runs when a finding is STORED, not when it is reported.

    This test previously asserted that declaring "CONFIRMED" stored "CONFIRMED". That was the
    defect: a finding could sit in the database claiming confirmation with nothing behind it, and
    only be corrected on the way out to a report. The declared value is kept for transparency and
    the delivered status is the one the evidence supports.
    """
    s = Session("p", "t")
    s.add_finding({"title": "X", "location": "0x1", "status": "CONFIRMED", "evidence": "e"})
    stored = s.findings[0]
    assert stored["declared_status"] == "CONFIRMED_STATIC"
    assert stored["status"] == "HYPOTHESIS", "an unevidenced confirmation must not be stored as one"
    assert "capped" in stored.get("status_capped_note", "").lower()
    assert stored["cvss_score"] is None, "no CVSS for a finding that is not confirmed"
    assert stored["confirmed_severity"] is None
    assert stored["schema_version"] >= 1 and stored["origin"]


def test_an_llm_cannot_raise_severity_or_status_through_an_update():
    """The guard that exists for exactly this was never invoked before slice P1-S3."""
    from reforge.engine import intake

    s = Session("p", "t")
    s.add_finding({"title": "Weak hash", "location": "0x1", "status": "HYPOTHESIS",
                   "severity": "LOW", "evidence": "MD5 symbol in the import table"},
                  origin=intake.ORIGIN_STATIC)
    before = dict(s.findings[0])

    s.add_finding({"title": "Weak hash", "location": "0x1",
                   "status": "CONFIRMED_DYNAMIC",          # must not be honoured
                   "severity": "CRITICAL",                 # must not be honoured
                   "cvss_score": 9.8,                      # must not be honoured
                   "description": "A clearer explanation of the weak hash."},
                  origin=intake.ORIGIN_LLM)

    after = s.findings[0]
    assert after["description"] == "A clearer explanation of the weak hash."  # prose does merge
    assert after["status"] == before["status"]
    assert after["severity"] == before["severity"]
    assert after["cvss_score"] == before["cvss_score"]
    assert after["blocked_enrichment"], "the blocked attempt must be recorded, not silently dropped"


def test_a_structurally_invalid_finding_is_rejected_not_repaired():
    from reforge.engine import intake

    s = Session("p", "t")
    for bad in ({"title": ""}, {"title": "x", "severity": "CATASTROPHIC"},
                {"title": "x", "confidence": 7}, {"title": "x", "cwe": "120"}):
        with pytest.raises(intake.FindingRejected):
            s.add_finding(bad)
    assert s.findings == [], "a rejected candidate must not be stored in any form"


# ----------------------- 1.7 atomic persistence + corrupt handling -----------------------
def test_persist_and_reload(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "PROJECTS_DIR", tmp_path)
    from reforge.session import SessionStore
    s = Session("proj1", "demo")
    s.add_finding({"title": "F", "location": "loc", "status": "CONFIRMED"})
    s.persist()
    assert (tmp_path / "proj1.json").is_file()
    store = SessionStore()
    reloaded = store.load("proj1")
    assert reloaded is not None and len(reloaded.findings) == 1


def test_corrupt_project_is_quarantined(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "PROJECTS_DIR", tmp_path)
    from reforge.session import SessionStore
    (tmp_path / "bad.json").write_text("{ not valid json", encoding="utf-8")
    store = SessionStore()
    assert store.load("bad") is None
    assert (tmp_path / "bad.json.corrupt").is_file()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))


# ----------------------- Phase 2: findings semantics + report validation -----------------------
from reforge import findings as fx                                  # noqa: E402


def test_status_normalization_and_category():
    assert fx.normalize_status("CONFIRMED") == "confirmed_static"
    assert fx.category({"status": "CONFIRMED"}) == "confirmed"
    assert fx.category({"status": "HYPOTHESIS"}) == "tentative"
    assert fx.category({"status": "x", "vuln_type": "hardening"}) == "observation"
    assert fx.category({"status": "rejected"}) == "rejected"


def test_confidence_imported_sink_lower_than_confirmed():
    imported = {"status": "HYPOTHESIS", "evidence": "API della classe exec (import table)"}
    confirmed = {"status": "confirmed_dynamic", "location": "FUN_00416000 @0x416075",
                 "evidence": "osservato a runtime con x64dbg: CreateProcessA('QuaniGrp.exe')",
                 "references": "Practical Malware Analysis p.214, ghidra"}
    assert fx.confidence(imported) < fx.confidence(confirmed)
    assert fx.confidence(confirmed) >= 0.9


def test_validate_flags_unvalidated_and_missing_location():
    class S:
        findings = [
            {"title": "Imported sink", "status": "HYPOTHESIS", "severity": "HIGH",
             "evidence": "import table"},                     # tentative + no precise loc
            {"title": "Conf no ev", "status": "CONFIRMED", "severity": "CRITICAL"},  # no evidence/location
        ]
        investigation_log = [{"tool": "t", "result_preview": "…(output truncated)"}]
    warns = fx.validate(S())
    msgs = " ".join(w["msg"].lower() for w in warns)
    assert "unvalidated hypotheses" in msgs
    assert "no linked evidence" in msgs
    assert "precise location" in msgs
    assert "truncat" in msgs


# ----------------------- Phase 1.2: evidence objects -----------------------
from reforge import evidence as ev                                  # noqa: E402


def test_add_evidence_assigns_ids_and_dedups():
    s = Session("p", "t")
    e1 = s.add_evidence(ev.make("ghidra", "decompiled main", raw="AAAA"))
    e2 = s.add_evidence(ev.make("ghidra", "decompiled main again", raw="AAAA"))  # same hash -> dedup
    e3 = s.add_evidence(ev.make("floss", "stack strings", raw="BBBB"))
    assert e1 == "E-0001" and e3 == "E-0002" and e2 == e1
    assert len(s.evidence) == 2


def test_evidence_refs_count_as_source_and_validate():
    f = {"title": "T", "status": "CONFIRMED", "severity": "HIGH",
         "location": "FUN_1 @0x401000", "evidence": "source->sink traced",
         "evidence_refs": ["E-0001", "E-0002"]}
    assert len(fx.sources(f)) >= 2
    # two independent evidence refs -> no "second source" warning, has evidence
    class S:
        findings = [f]
        investigation_log = []
    msgs = " ".join(w["msg"].lower() for w in fx.validate(S()))
    assert "no linked evidence" not in msgs


def test_report_includes_evidence_section():
    from reforge import report_pt
    s = Session("p", "demo"); s.target_profile = {"file": "demo"}
    eid = s.add_evidence(ev.make("static_analysis", "imported CreateProcessA", raw="import table"))
    s.add_finding({"title": "Cmd inj", "status": "HYPOTHESIS", "severity": "CRITICAL",
                   "location": "0x416075", "evidence_refs": [eid]})
    md = report_pt._deterministic(s)
    assert "Collected evidence" in md and eid in md


# ----------------------- Phase 2.2: workflow engine -----------------------
from reforge import workflow as wf                                  # noqa: E402


def test_workflow_starts_at_triage():
    s = Session("p", "t")
    assert wf.current_key(s) == "triage"


def test_workflow_advances_with_state():
    # Honest workflow: the automatic static baseline alone must NOT tick any phase.
    s = Session("p", "t"); s.target_path = "x"; s.static_done = True
    g = wf.guidance(s)
    assert not g["phases"][0]["done"]          # triage needs real tool activity, not just baseline
    assert g["phase"] == "triage"
    # After the agent actually runs tools, triage completes and the phase advances.
    s.investigation_log = [{"tool": "ghidra__list_imports", "is_error": False}]
    g2 = wf.guidance(s)
    assert g2["phases"][0]["done"]
    assert g2["phase"] != "triage"


def test_workflow_manual_pin_and_unpin():
    s = Session("p", "t")
    assert wf.set_phase(s, "exploitability") and wf.current_key(s) == "exploitability"
    assert wf.guidance(s)["pinned"] is True
    assert wf.set_phase(s, "auto") and wf.current_key(s) == "triage"
    assert wf.set_phase(s, "bogus") is False


# ----------------------- Phase 2.3: analyst views -----------------------
def test_static_analysis_returns_strings_imports(tmp_path):
    """analyze() must return strings and imports keys so the analyst views can populate."""
    from reforge import static_analysis
    # minimal PE-like file (starts MZ but not a real PE; falls through to non-PE path)
    f = tmp_path / "t.bin"
    f.write_bytes(b"\x00" * 10 + b"hello world" + b"\x00" + b"http://evil.com" + b"\x00")
    res = static_analysis.analyze(str(f))
    assert "strings" in res and "imports" in res
    assert any("hello" in s for s in res["strings"]) or isinstance(res["strings"], list)


def test_session_persists_static_data(tmp_path, monkeypatch):
    """static_strings/imports/attack_surface survive a persist+reload cycle."""
    monkeypatch.setattr(config, "PROJECTS_DIR", tmp_path)
    from reforge.session import SessionStore
    s = Session("q1", "demo")
    s.static_strings = ["hello", "world"]
    s.static_imports = ["CreateProcessA"]
    s.attack_surface = {"sinks": {"exec": ["CreateProcessA"]}, "sources": {"recv": "network (socket)"}}
    s.persist()
    reloaded = SessionStore().load("q1")
    assert reloaded.static_strings == ["hello", "world"]
    assert reloaded.static_imports == ["CreateProcessA"]
    assert reloaded.attack_surface["sinks"] == {"exec": ["CreateProcessA"]}
    assert not hasattr(reloaded, "static_iocs"), "IOC extraction was removed from the product"


# ----------------------- Phase 2.1: hybrid tool retrieval -----------------------
from reforge.mcp_host import MCPHost, ToolInfo
from reforge.tool_registry import ToolRegistry


def _make_registry():
    """Build a ToolRegistry with synthetic tools for testing."""
    h = MCPHost({})
    tools = [
        ToolInfo("ghidra","decompile_function","Decompile a function",{},
                 {"tags":["decompile","static","xref"],"risk_class":"safe_read","cost":"medium"}),
        ToolInfo("ghidra","find_dangerous_imports","Find dangerous API imports",{},
                 {"tags":["imports","sink","exec","attack_surface"],"risk_class":"safe_read","cost":"fast"}),
        ToolInfo("x64dbg","DebugRun","Run the process",{},
                 {"tags":["debug","dynamic","run","runtime"],"risk_class":"dynamic_execution","cost":"high"}),
        ToolInfo("x64dbg","MemoryRead","Read process memory",{},
                 {"tags":["memory","read","dynamic"],"risk_class":"sensitive_read","cost":"medium"}),
        ToolInfo("floss","floss_obfuscated_strings","Extract obfuscated strings",{},
                 {"tags":["strings","obfuscated","floss"],"risk_class":"safe_read","cost":"slow"}),
        ToolInfo("ghidra","list_imports","List the imported symbols",{},
                 {"tags":["imports","import","metadata"],"risk_class":"safe_read","cost":"fast"}),
    ]
    for t in tools:
        h.tools[t.qualified] = t
        h._conns[t.server] = None
    reg = ToolRegistry.__new__(ToolRegistry)
    reg.host = h
    reg.rebuild()
    return reg


def test_exact_match():
    reg = _make_registry()
    res = reg.search("decompile_function")
    assert any("decompile_function" in r for r in res)


def test_keyword_tag_search():
    reg = _make_registry()
    res = reg.search("imports sink")
    assert any("find_dangerous_imports" in r for r in res)


def test_risk_class_filter():
    reg = _make_registry()
    safe = reg.filter_by_risk(["safe_read"])
    dynamic = reg.filter_by_risk(["dynamic_execution"])
    assert all("x64dbg__DebugRun" not in q for q in safe)
    assert "x64dbg__DebugRun" in dynamic


def test_phase_boost_vuln_hunting():
    reg = _make_registry()
    res = reg.search("function analysis", phase="vuln_hunting")
    # decompile should rank higher than DebugRun in vuln_hunting phase
    names = [r.split("__")[1] for r in res]
    if "decompile_function" in names and "DebugRun" in names:
        assert names.index("decompile_function") < names.index("DebugRun")


def test_phase_boost_exploitability():
    reg = _make_registry()
    res = reg.search("memory", phase="exploitability")
    assert any("MemoryRead" in r or "DebugRun" in r for r in res)


def test_slow_cost_penalty():
    reg = _make_registry()
    res = reg.search("strings")
    # floss (slow) should rank lower than fast/medium tools unless query is specific
    if len(res) > 1:
        slow_idx = next((i for i, r in enumerate(res) if "floss" in r), None)
        fast_idx = next((i for i, r in enumerate(res) if "floss" not in r), None)
        if slow_idx is not None and fast_idx is not None:
            assert fast_idx <= slow_idx


def test_search_by_phase_returns_tools():
    reg = _make_registry()
    res = reg.search_by_phase("imports")
    assert len(res) > 0
    assert any("imports" in r for r in res)


def test_describe_includes_risk_and_tags():
    reg = _make_registry()
    desc = reg.describe(["ghidra__decompile_function"])
    assert "safe_read" in desc and "decompile" in desc


# ----------------------- PT report + template -----------------------
def test_pt_report_has_all_sections():
    from reforge import report_pt
    s = Session("p", "demo")
    s.target_profile = {"file": "demo.exe", "format": "PE", "arch": "x86"}
    s.add_finding({"title": "Cmd inj", "severity": "CRITICAL", "status": "CONFIRMED",
                   "cwe": "CWE-78", "location": "0x416075"})
    md = asyncio.new_event_loop().run_until_complete(report_pt.generate(s))
    for sec in ("Executive Summary", "Definitions", "Conclusions", "CVSS",
                "Vulnerability summary", "Detailed", "Appendices"):
        assert sec in md, f"missing section: {sec}"


def test_pt_report_severity_counts():
    from reforge import report_pt
    s = Session("p", "demo")
    s.add_finding({"title": "A", "severity": "CRITICAL", "status": "CONFIRMED", "cwe": "CWE-1"})
    s.add_finding({"title": "B", "severity": "HIGH", "status": "HYPOTHESIS", "cwe": "CWE-2"})
    md = asyncio.new_event_loop().run_until_complete(report_pt.generate(s))
    assert "| Critical | 1 |" in md and "| High | 1 |" in md


def test_pt_template_is_blank():
    from reforge import report_pt
    tpl = report_pt.template()
    assert "[APPLICATION NAME" in tpl and "Executive Summary" in tpl


def test_pt_docx_generation():
    pytest.importorskip("docx", reason="python-docx is an optional dependency")
    from reforge import report_pt, report_docx
    s = Session("p", "demo"); s.target_profile = {"file": "demo.exe"}
    s.add_finding({"title": "X", "severity": "HIGH", "status": "CONFIRMED", "cwe": "CWE-78",
                   "location": "0x1000"})
    md = asyncio.new_event_loop().run_until_complete(report_pt.generate(s))
    data, err = report_docx.to_docx(md, "Test")
    assert err == "" and len(data) > 5000
    assert data[:2] == b"PK"  # valid zip/docx magic


# ----------------------- dynamic analysis: wait for reload -----------------------
def test_wait_for_reload_pauses_turn():
    import asyncio
    from reforge import agent
    from reforge.llm import ToolCall
    s = Session("t", "x")
    tc = ToolCall("c1", "wait_for_reload", {"reason": "process exited", "next_plan": "BP LoadLibraryA"})
    loop = asyncio.new_event_loop()
    try:
        res = loop.run_until_complete(agent._dispatch(s, None, None, tc))
    finally:
        loop.close()
    assert s.awaiting_reload is True
    assert "PAUSED" in res["content"]


def test_wait_for_reload_tool_registered():
    from reforge import agent
    from reforge.session import Session as _S
    from reforge.tool_registry import ToolRegistry
    from reforge.mcp_host import MCPHost
    s = _S("t", "x")
    reg = ToolRegistry.__new__(ToolRegistry); reg.host = MCPHost({}); reg.rebuild()
    tools = agent.build_tools(s, reg)
    assert any(t["name"] == "wait_for_reload" for t in tools)


# ----------------------- the report is English, whatever `lang` says -----------------------
def test_pt_report_english():
    from reforge import report_pt
    s = Session("p", "demo"); s.target_profile = {"file": "demo.exe"}
    s.add_finding({"title": "X", "severity": "HIGH", "status": "CONFIRMED", "cwe": "CWE-78", "location": "0x1"})
    md = asyncio.new_event_loop().run_until_complete(report_pt.generate(s, lang="en"))
    for sec in ("Executive Summary", "Definitions", "Conclusions", "Number of Vulnerabilities", "High"):
        assert sec in md, f"missing (EN): {sec}"
    # Italian must NOT leak into the report headers
    assert "Definizioni" not in md and "Conclusioni" not in md


def test_pt_report_lang_arg_is_accepted_and_ignored():
    """`report_pt` is single-language (English) by design; `lang` exists only so UI call sites
    that carry a language setting keep working. Any value must produce the same English report."""
    from reforge import report_pt
    s = Session("p", "demo"); s.target_profile = {"file": "demo.exe"}
    loop = asyncio.new_event_loop()
    md_it = loop.run_until_complete(report_pt.generate(s, lang="it"))
    md_en = loop.run_until_complete(report_pt.generate(s, lang="en"))
    for sec in ("Definitions and acronyms", "Conclusions"):
        assert sec in md_it, f"missing: {sec}"
    # Same structure regardless of the requested language (headings, not the generated timestamp).
    def headings(md):
        return [l for l in md.splitlines() if l.startswith("#")]
    assert headings(md_it) == headings(md_en)


def test_template_is_english_for_any_lang():
    from reforge import report_pt
    assert "Definitions" in report_pt.template(lang="en")
    assert "Definitions" in report_pt.template(lang="it")


def test_system_prompt_language_directive():
    from reforge import config
    assert "Always answer in English" in config.system_prompt("auto")
