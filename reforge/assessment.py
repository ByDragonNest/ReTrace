"""Deterministic assessment snapshot — the data behind the Assessment dashboard.

This module answers, in one pass and without any LLM, network call or subprocess: *what do we
actually know about this target right now?* Everything here is derived from state the session
already holds (target profile, static strings/imports, attack surface, findings, evidence,
investigation log, workflow phase). Nothing is invented: a value that cannot be computed is
reported as ``None``/empty rather than guessed, and every number is traceable to the records it
was counted from.

Three ideas drive the structure:

1. **Vulnerabilities, hardening weaknesses and informational signals are not the same thing.**
   The engine already distinguishes them (``vuln_type == "hardening"``, ``status == INDICATOR``,
   ``evidence_bundle.isolated_only``); the dashboard must not blend them into one scary number.
2. **Risk comes from demonstrated weaknesses, not from attack surface.** A binary that imports
   ``strcpy`` is not HIGH risk; a binary with a confirmed overflow is. Missing mitigations raise
   exploitability of a real bug, so they *amplify* risk but never create it on their own.
3. **Recommended next actions are observations, not suggestions.** Each one is emitted only when
   the underlying count is non-zero, and carries that count so the UI can show its basis.
"""
from typing import Any, Dict, List, Optional

from . import findings as fx
from . import severity as sev
from . import workflow

# Hardening/mitigation gaps: real weaknesses, but not vulnerabilities on their own.
_HARDENING_TYPES = {"hardening"}

# Findings the engine itself flagged as context rather than defect.
_INFO_STATUSES = {"indicator", "observation"}

# Review priority for a sink class, derived from its worst case if the sink turns out to be
# reachable from untrusted input. Nothing here describes behaviour ("persists", "injects") — only
# what an attacker could do with a defect at that sink.
_PRIORITY_BY_SEVERITY = {"CRITICAL": "high", "HIGH": "high", "MEDIUM": "medium", "LOW": "low",
                         "INFO": "low"}


# --------------------------------------------------------------------------------------
# finding classification
# --------------------------------------------------------------------------------------
def classify(f: Dict[str, Any]) -> str:
    """``vulnerability`` | ``hardening`` | ``informational`` | ``rejected``.

    This is the top-level split the dashboard and the posture view are built on. It deliberately
    sits *above* ``findings.category()`` (which grades confidence) and answers a different
    question: is this thing a defect, a missing defence, or a note?
    """
    status = (f.get("status") or "").strip().lower()
    if fx.normalize_status(f.get("status")) == "rejected":
        return "rejected"
    if (f.get("vuln_type") or "").strip().lower() in _HARDENING_TYPES:
        return "hardening"
    if status in _INFO_STATUSES:
        return "informational"
    bundle = f.get("evidence_bundle")
    if isinstance(bundle, dict) and bundle.get("isolated_only"):
        # A sink symbol with nothing else around it: attack surface, not a finding.
        return "informational"
    if sev.norm_severity(f.get("severity"), "INFO") == "INFO":
        return "informational"
    return "vulnerability"


def bucket(found: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Split a finding list into the four top-level buckets, preserving order."""
    out: Dict[str, List[Dict[str, Any]]] = {
        "vulnerabilities": [], "hardening": [], "informational": [], "rejected": [],
    }
    for f in found or []:
        key = classify(f)
        out["vulnerabilities" if key == "vulnerability" else key].append(f)
    return out


def severity_counts(found: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {band: 0 for band in sev.BANDS}
    for f in found or []:
        counts[sev.norm_severity(f.get("severity"), "INFO")] += 1
    return counts


def status_counts(found: List[Dict[str, Any]]) -> Dict[str, int]:
    """Counts over the deterministic status lattice (confirmed / tentative / observation / rejected)."""
    counts = {"confirmed": 0, "tentative": 0, "observation": 0, "rejected": 0}
    for f in found or []:
        counts[fx.category(f)] += 1
    return counts


# --------------------------------------------------------------------------------------
# risk
# --------------------------------------------------------------------------------------
def risk(vulnerabilities: List[Dict[str, Any]],
         hardening: List[Dict[str, Any]],
         analyzed: bool = True) -> Dict[str, Any]:
    """Overall risk band, with the reasoning that produced it.

    The band is the highest severity among *confirmed* vulnerabilities; if nothing is confirmed it
    is the highest severity among tentative ones, demoted one step because it is not yet
    demonstrated. Missing mitigations never raise the band by themselves — they are reported as an
    amplifier so the analyst sees why an open bug would be worse here than elsewhere.

    ``analyzed=False`` (no static pass yet) yields ``UNKNOWN`` rather than ``NONE``: "we have not
    looked" and "we looked and found nothing" must not render the same.
    """
    if not vulnerabilities:
        if not analyzed:
            return {"band": "UNKNOWN", "confirmed": False,
                    "basis": "Static analysis has not run for this target yet.",
                    "amplifiers": _amplifiers(hardening)}
        return {"band": "NONE", "confirmed": False,
                "basis": "Static analysis completed and recorded no vulnerability for this target.",
                "amplifiers": _amplifiers(hardening)}

    confirmed = [f for f in vulnerabilities if fx.category(f) == "confirmed"]
    pool, demote, basis_kind = (confirmed, False, "confirmed") if confirmed else (vulnerabilities, True, "unconfirmed")
    top = min(pool, key=lambda f: sev.severity_rank(f.get("severity")))
    band = sev.norm_severity(top.get("severity"), "INFO")
    if demote:
        band = _demote(band)

    if basis_kind == "confirmed":
        basis = (f"{len(confirmed)} confirmed vulnerability"
                 f"{'' if len(confirmed) == 1 else 's'}; highest severity "
                 f"{sev.norm_severity(top.get('severity'), 'INFO')}.")
    else:
        basis = (f"No confirmed vulnerability yet. {len(vulnerabilities)} unconfirmed "
                 f"candidate{'' if len(vulnerabilities) == 1 else 's'}; highest claimed severity "
                 f"{sev.norm_severity(top.get('severity'), 'INFO')}, shown one band lower until "
                 "evidence supports it.")
    return {"band": band, "confirmed": bool(confirmed), "basis": basis,
            "top_finding": top.get("title"), "amplifiers": _amplifiers(hardening)}


def _demote(band: str) -> str:
    order = sev.BANDS                      # CRITICAL .. INFO
    i = order.index(band) if band in order else len(order) - 1
    return order[min(i + 1, len(order) - 1)]


def _amplifiers(hardening: List[Dict[str, Any]]) -> List[str]:
    """Missing mitigations, phrased as what they do to an *existing* bug."""
    out = []
    for f in hardening or []:
        title = (f.get("title") or "").strip()
        if title:
            out.append(title)
    return out[:12]


# --------------------------------------------------------------------------------------
# attack surface
# --------------------------------------------------------------------------------------
def attack_surface(session) -> Dict[str, Any]:
    """Attack surface as dangerous sinks and untrusted input sources.

    This is the whole model: operations that break a program when they receive attacker-controlled
    data, and the places such data enters. There is no behavioural capability taxonomy — "does this
    binary inject / persist / keylog" is a malware-classification question ReTrace does not ask.

    Reads ``session.attack_surface`` (produced by the offline static pass) and regroups it. Returns
    empty structures — never placeholders — when static analysis has not run.
    """
    surf = getattr(session, "attack_surface", {}) or {}
    sinks = surf.get("sinks") or {}
    sources = surf.get("sources") or {}

    sink_rows = []
    for klass, apis in sinks.items():
        apis = sorted({a for a in (apis or []) if a})
        if not apis:
            continue
        meta = _sink_meta(klass)
        sink_rows.append({
            "klass": klass,
            "label": meta["label"],
            "cwe": meta["cwe"],
            "potential_severity": meta["potential_severity"],
            "priority": _PRIORITY_BY_SEVERITY.get(meta["potential_severity"], "low"),
            "why": meta["why"],
            "apis": apis,
            "count": len(apis),
        })
    sink_rows.sort(key=lambda r: (sev.severity_rank(r["potential_severity"]), -r["count"]))

    # Input sources grouped by where the untrusted data comes from, so the analyst can reason about
    # reachability ("is this sink fed by the network, or only by a config file?").
    by_origin: Dict[str, List[str]] = {}
    for symbol, origin in (sources or {}).items():
        by_origin.setdefault(origin, []).append(symbol)
    source_groups = [{"origin": origin, "symbols": sorted(syms), "count": len(syms)}
                     for origin, syms in sorted(by_origin.items())]
    source_rows = [{"symbol": s, "origin": origin} for s, origin in sorted((sources or {}).items())]

    return {
        "available": bool(sink_rows or source_rows),
        "sinks": sink_rows,
        "sources": source_rows,
        "source_groups": source_groups,
        "signal_count": sum(r["count"] for r in sink_rows) + len(source_rows),
        "note": surf.get("note") or "",
    }


def _sink_meta(klass: str) -> Dict[str, Any]:
    """Label, CWE, worst case and plain-language explanation for a sink class.

    Read from ``reforge.sinks`` so there is one source of truth: the UI never re-describes a sink
    class in its own words.
    """
    from .sinks import _CLASS, _PLAIN              # single source of truth, no duplication
    cwe, potential, note, _impact = _CLASS.get(klass, ("", "INFO", "", ""))
    return {"label": klass.replace("_", " "), "cwe": cwe, "potential_severity": potential,
            "note": note, "why": _PLAIN.get(klass, "")}


# --------------------------------------------------------------------------------------
# coverage
# --------------------------------------------------------------------------------------
def coverage(session, buckets: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    """How far the assessment has actually got — all ratios over real records.

    ``None`` where a ratio has no denominator (no findings yet), so the UI can show "—" instead of
    a misleading 0% or 100%.
    """
    reviewable = buckets["vulnerabilities"] + buckets["hardening"]
    total = len(reviewable)
    with_evidence = sum(1 for f in reviewable
                        if f.get("evidence_refs") or f.get("evidence") or f.get("evidence_source"))
    confirmed = sum(1 for f in reviewable if fx.category(f) == "confirmed")
    dynamic = sum(1 for f in reviewable
                  if fx.normalize_status(f.get("status")) == "confirmed_dynamic")

    phases = workflow.guidance(session)
    done_phases = sum(1 for p in phases["phases"] if p["done"])

    log = getattr(session, "investigation_log", []) or []
    return {
        "findings_total": total,
        "evidence_backed": with_evidence,
        "evidence_backed_pct": _pct(with_evidence, total),
        "confirmed": confirmed,
        "confirmed_pct": _pct(confirmed, total),
        "dynamically_confirmed": dynamic,
        "dynamically_confirmed_pct": _pct(dynamic, total),
        "evidence_items": len(getattr(session, "evidence", []) or []),
        "tool_calls": len(log),
        "phases_done": done_phases,
        "phases_total": len(phases["phases"]),
        "phase_pct": _pct(done_phases, len(phases["phases"])),
        "static_done": bool(getattr(session, "static_done", False)),
        "strings": len(getattr(session, "static_strings", []) or []),
        "imports": len(getattr(session, "static_imports", []) or []),
        "artifacts": len(getattr(session, "artifacts", []) or []),
    }


def _pct(n: int, total: int) -> Optional[int]:
    if not total:
        return None
    return int(round(100.0 * n / total))


# --------------------------------------------------------------------------------------
# recommended next actions
# --------------------------------------------------------------------------------------
def next_actions(session, buckets: Dict[str, List[Dict[str, Any]]],
                 surface: Dict[str, Any], cov: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Context-aware next steps, each backed by a count taken from real project state.

    An action is emitted only when its trigger condition holds, so an empty list is a valid and
    honest result (it means there is nothing obvious left to do). ``view`` tells the UI where to
    send the analyst; ``prompt`` is an optional agent instruction, present only where asking the
    agent is genuinely the next step.
    """
    out: List[Dict[str, Any]] = []

    def add(key, title, detail, priority, view, count=None, prompt=None):
        out.append({"key": key, "title": title, "detail": detail, "priority": priority,
                    "view": view, "count": count, "prompt": prompt})

    if not getattr(session, "target_path", None):
        add("load_target", "Load a target binary",
            "An assessment starts from an executable. Upload one or point ReTrace at a local path; "
            "offline static triage runs immediately.", "p0", "projects")
        return out

    if not getattr(session, "static_done", False):
        add("run_static", "Run static triage",
            "The target is set but the offline static pass has not completed. It produces hashes, "
            "sections, entropy, imports, mitigations and the attack surface with no LLM required.",
            "p0", "assessment")
        return out

    tentative_high = [f for f in buckets["vulnerabilities"]
                      if fx.category(f) == "tentative"
                      and sev.severity_rank(f.get("severity")) <= sev.severity_rank("HIGH")]
    if tentative_high:
        add("validate_high", f"Validate {len(tentative_high)} high-severity candidate"
                             f"{'' if len(tentative_high) == 1 else 's'}",
            "These are claimed HIGH or CRITICAL but have no confirming evidence. They decide the "
            "overall risk band, so they are the highest-value thing to settle next.",
            "p0", "findings", len(tentative_high))

    no_evidence = [f for f in buckets["vulnerabilities"]
                   if not (f.get("evidence_refs") or f.get("evidence") or f.get("evidence_source"))]
    if no_evidence:
        add("weak_evidence", f"Attach evidence to {len(no_evidence)} finding"
                             f"{'' if len(no_evidence) == 1 else 's'}",
            "A finding with no linked evidence cannot be defended in a report. Collect the call "
            "site, decompiled snippet or runtime observation that supports it.",
            "p1", "findings", len(no_evidence))

    high_sinks = [s for s in surface.get("sinks", [])
                  if sev.severity_rank(s["potential_severity"]) <= sev.severity_rank("HIGH")]
    if high_sinks and not buckets["vulnerabilities"]:
        total_apis = sum(s["count"] for s in high_sinks)
        add("trace_sinks", f"Trace {total_apis} dangerous sink"
                           f"{'' if total_apis == 1 else 's'} to an input source",
            "The attack surface contains sinks whose worst case is HIGH or CRITICAL, but no "
            "source→sink path has been demonstrated yet. Decompile the callers and follow each "
            "argument back to untrusted input.",
            "p1", "assessment", total_apis,
            prompt="Trace the dangerous sinks in the attack surface back to an untrusted input "
                   "source. For each one, locate the call site with Ghidra xrefs, decompile the "
                   "caller, and record a finding only once a source→sink path is demonstrated.")

    if surface.get("sources") and not cov["dynamically_confirmed"] and buckets["vulnerabilities"]:
        add("dynamic_confirm", "Confirm findings dynamically",
            "Untrusted input sources are present and there are open candidates, but nothing has "
            "been observed at runtime. Dynamic confirmation is what promotes a finding to "
            "CONFIRMED — and it requires your approval for every state-changing action.",
            "p1", "playbooks")

    if not cov["artifacts"]:
        add("add_artifacts", "Add runtime artifacts",
            "Procmon traces, PCAPs and crash dumps let the offline heuristic engine corroborate "
            "static leads without running the sample from ReTrace.",
            "p2", "artifacts")

    if (buckets["vulnerabilities"] or buckets["hardening"]) and not getattr(session, "report_generated", False):
        add("generate_report", "Generate the assessment report",
            "A complete deterministic report can be produced from the current findings at any "
            "time — it does not need an LLM and it marks the current state of the assessment.",
            "p2", "reports")

    out.sort(key=lambda a: a["priority"])
    return out


# --------------------------------------------------------------------------------------
# recent activity
# --------------------------------------------------------------------------------------
def activity(session, limit: int = 12) -> List[Dict[str, Any]]:
    """Most recent investigation events, newest first. Tool calls only — the factual record."""
    log = list(getattr(session, "investigation_log", []) or [])
    rows = []
    for entry in reversed(log[-limit:]):
        rows.append({
            "ts": entry.get("ts"),
            "tool": entry.get("tool"),
            "ok": not entry.get("is_error"),
            "approved": entry.get("approved"),
            "preview": (entry.get("result_preview") or "")[:160],
        })
    return rows


# --------------------------------------------------------------------------------------
# the snapshot
# --------------------------------------------------------------------------------------
def snapshot(session) -> Dict[str, Any]:
    """The full deterministic assessment state for one project."""
    found = list(getattr(session, "findings", []) or [])
    buckets = bucket(found)
    surface = attack_surface(session)
    cov = coverage(session, buckets)

    profile = dict(getattr(session, "target_profile", None) or {})
    profile["loaded"] = bool(getattr(session, "target_path", None))
    profile["path"] = getattr(session, "target_path", None)

    return {
        "target": profile,
        "risk": risk(buckets["vulnerabilities"], buckets["hardening"],
                     analyzed=bool(getattr(session, "static_done", False))),
        "counts": {
            "vulnerabilities": len(buckets["vulnerabilities"]),
            "hardening": len(buckets["hardening"]),
            "informational": len(buckets["informational"]),
            "rejected": len(buckets["rejected"]),
            "severity": severity_counts(buckets["vulnerabilities"]),
            "status": status_counts(buckets["vulnerabilities"]),
        },
        "attack_surface": surface,
        "coverage": cov,
        "workflow": workflow.guidance(session),
        "next_actions": next_actions(session, buckets, surface, cov),
        "activity": activity(session),
    }
