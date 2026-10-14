"""Structured reverse-engineering workflow (Phase 2.2).

Eight ordered phases, each with an objective, recommended tools, completion criteria and next-step
suggestions. Completion is judged **deterministically** from the session state (findings, evidence,
static baseline) — not by the LLM. The current phase is the first not-yet-complete phase, unless the
analyst pins one manually (session.phase). This guides the agent and is shown in the UI.
"""
from typing import Any, Dict, List

from . import findings as fx

_SINK_TYPES = {"mem_copy", "format", "unbounded", "exec", "load", "alloc_int", "file"}


def s_floss(ev_sources, tool_names) -> bool:
    return ("floss" in ev_sources) or ("floss" in tool_names) or ("libs" in tool_names)


def snapshot(session) -> Dict[str, Any]:
    F = getattr(session, "findings", []) or []
    E = getattr(session, "evidence", []) or []
    ev_sources = {(e.get("source") or "").lower() for e in E}
    ev_tools = " ".join((e.get("tool_name") or "") + " " + (e.get("summary") or "") for e in E).lower()
    vuln = [f for f in F if f.get("vuln_type") not in (None, "hardening", "third_party_component")]
    log = getattr(session, "investigation_log", []) or []
    tool_names = " ".join((e.get("tool") or "") for e in log).lower()
    # "Real work" = the agent actually ran tools or the user investigated, not just the auto static baseline.
    any_tool_run = len(log) > 0
    # Findings authored by the LLM/investigation (not the automatic static baseline).
    investigated_findings = [f for f in F if (f.get("evidence_source") or "").lower() not in ("static_analysis", "")
                             or f.get("status") in ("CONFIRMED", "confirmed_dynamic", "confirmed_static", "REJECTED")]
    return {
        "target_loaded": bool(getattr(session, "target_path", None)),
        "static_done": bool(getattr(session, "static_done", False)),
        "any_tool_run": any_tool_run,
        "has_libs": any(f.get("vuln_type") == "third_party_component" for f in F),
        "classified": s_floss(ev_sources, tool_names) or any(f.get("vuln_type") == "third_party_component" for f in F),
        "imports_reviewed": "import" in tool_names or "import" in ev_tools,
        "attack_surface": "attack_surface" in ev_tools or "attack_surface" in tool_names
                          or any(f.get("vuln_type") in _SINK_TYPES for f in investigated_findings),
        "vuln_candidates": [f for f in F if fx.category(f) in ("tentative", "confirmed")
                            and f.get("vuln_type") not in ("hardening",)],
        "confirmed": [f for f in F if fx.category(f) == "confirmed"],
        "dynamic_evidence": bool(ev_sources & {"x64dbg", "dynamic_analysis", "procmon"})
                            or any(s in tool_names for s in ("x64dbg", "procmon")),
        "tentative": [f for f in F if fx.category(f) == "tentative"],
        "report_generated": bool(getattr(session, "report_generated", False)),
        "n_vuln": len(vuln),
    }


# Each phase: key, title, objective, tools (search queries / tool hints), evidence, next_steps,
# and `done(s)` predicate over the snapshot.
PHASES: List[Dict[str, Any]] = [
    {"key": "triage", "title": "Triage",
     "objective": "Identify format, architecture, hashes, entropy and set the static baseline.",
     "tools": ["automatic static analysis", "file/headers"],
     "evidence": "Target profile (format/arch/hashes).",
     "next_steps": ["Set the target binary to start static analysis."],
     "done": lambda s: s["static_done"] and s["any_tool_run"]},
    {"key": "classification", "title": "Classification",
     "objective": "Estimate language/compiler, packing, and the included third-party libraries.",
     "tools": ["floss", "libs (component fingerprint)", "entropy"],
     "evidence": "Library version banners, entropy, obfuscated strings.",
     "next_steps": ["Run floss for obfuscated strings", "Check known libraries (CVE)."],
     "done": lambda s: s["classified"]},
    {"key": "imports", "title": "Import review",
     "objective": "Inventory the imported API surface and flag the security-relevant families.",
     "tools": ["list_imports", "find_dangerous_imports", "get_metadata"],
     "evidence": "Import table with the security-relevant symbols identified.",
     "next_steps": ["List the imports", "Flag the dangerous ones for source\u2192sink tracing."],
     "done": lambda s: s["imports_reviewed"]},
    {"key": "attack_surface", "title": "Attack surface",
     "objective": "Identify untrusted input sources and dangerous sinks.",
     "tools": ["attack_surface", "find_dangerous_imports"],
     "evidence": "Sink/source inventory.",
     "next_steps": ["Call attack_surface", "Classify the sinks by CWE."],
     "done": lambda s: s["attack_surface"]},
    {"key": "vuln_hunting", "title": "Vulnerability hunting",
     "objective": "Trace source→sink paths by decompiling the callers and record hypotheses.",
     "tools": ["decompile_callers", "get_function_xrefs", "string_uses", "vuln_checklist"],
     "evidence": "Source→sink paths, decompiled code.",
     "next_steps": ["Decompile the sink callers", "Trace the arguments back to the source."],
     "done": lambda s: bool(s["vuln_candidates"])},
    {"key": "exploitability", "title": "Exploitability",
     "objective": "Assess reachability/controllability and confirm at runtime where possible.",
     "tools": ["exploitability", "BreakAtApiAndInspect", "ReadCallArguments"],
     "evidence": "Exploitability verdict, dynamic proof.",
     "next_steps": ["Assess the exploitability of the candidates", "Confirm the critical sinks in x64dbg."],
     "done": lambda s: bool(s["confirmed"]) or s["dynamic_evidence"]},
    {"key": "reporting", "title": "Reporting",
     "objective": "Generate the structured report (confirmed / hypotheses / observations).",
     "tools": ["generate report"],
     "evidence": "Report with evidence references.",
     "next_steps": ["Generate the report from the Report button."],
     "done": lambda s: s["report_generated"]},
    {"key": "validation", "title": "Validation",
     "objective": "Validate the remaining hypotheses (confirm or reject) and resolve the warnings.",
     "tools": ["Validate with AI", "add_finding (update)"],
     "evidence": "Updated statuses (CONFIRMED/REJECTED).",
     "next_steps": ["Validate the open hypotheses with AI."],
     "done": lambda s: s["report_generated"] and not s["tentative"]},
]
_KEYS = [p["key"] for p in PHASES]


def _auto_index(s: Dict[str, Any]) -> int:
    for i, p in enumerate(PHASES):
        if not p["done"](s):
            return i
    return len(PHASES) - 1


def current_key(session) -> str:
    manual = getattr(session, "phase", None)
    if manual in _KEYS:
        return str(manual)
    return _KEYS[_auto_index(snapshot(session))]


def set_phase(session, key: str) -> bool:
    if key in _KEYS or key in (None, "auto", ""):
        session.phase = None if key in (None, "auto", "") else key
        return True
    return False


def guidance(session) -> Dict[str, Any]:
    s = snapshot(session)
    auto_i = _auto_index(s)
    cur = current_key(session)
    cur_i = _KEYS.index(cur)
    p = PHASES[cur_i]
    return {
        "phase": cur, "title": p["title"], "objective": p["objective"],
        "recommended_tools": p["tools"], "required_evidence": p["evidence"],
        "next_steps": p["next_steps"],
        "index": cur_i, "total": len(PHASES), "auto_phase": _KEYS[auto_i],
        "pinned": getattr(session, "phase", None) in _KEYS,
        "phases": [{"key": ph["key"], "title": ph["title"], "done": ph["done"](s)} for ph in PHASES],
    }


def prompt_block(session) -> str:
    g = guidance(session)
    return (f"[WORKFLOW] Current phase {g['index'] + 1}/{g['total']}: {g['title']}. "
            f"Objective: {g['objective']} Recommended tools: {', '.join(g['recommended_tools'])}. "
            f"Next steps: {'; '.join(g['next_steps'])}. "
            "Follow the phases without skipping them; once the objective is met, move to the next one.")
