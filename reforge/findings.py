"""Deterministic finding semantics (Phase 1.1/1.4) and report validation (Phase 2.5).

No LLM involved: status normalization, a confidence score derived from evidence signals, and a set
of pre-export validation warnings so weak findings are never silently promoted.
"""
from typing import Any, Dict, List, Optional

# Structured status lattice. Legacy values are mapped onto it.
LATTICE = ["observation", "lead", "hypothesis", "needs_review",
           "confirmed_static", "confirmed_dynamic", "rejected"]
_LEGACY = {
    "confirmed": "confirmed_static", "confirmed_static": "confirmed_static",
    "confirmed_dynamic": "confirmed_dynamic",
    "hypothesis": "hypothesis", "lead": "lead", "observation": "observation",
    "needs_review": "needs_review", "rejected": "rejected",
    # engine (v61) state names -> report lattice
    "indicator": "lead", "probable": "needs_review", "false_positive": "rejected",
}
_BASE_CONF = {
    "confirmed_dynamic": 0.90, "confirmed_static": 0.75, "needs_review": 0.50,
    "hypothesis": 0.35, "lead": 0.25, "observation": 0.20, "rejected": 0.0,
}
_CONFIRMED = {"confirmed_static", "confirmed_dynamic"}
_TENTATIVE = {"hypothesis", "lead", "needs_review"}


def normalize_status(status: Optional[str]) -> str:
    # Every caller passes `finding.get("status")`, which is None on a finding that has not
    # been given one yet; the body always tolerated that, the annotation did not say so.
    return _LEGACY.get((status or "").strip().lower(), "hypothesis")


def _ev_text(f: Dict[str, Any]) -> str:
    """Evidence as a flat string. `evidence` may be a list (heuristic/static findings) or a string."""
    ev = f.get("evidence")
    if isinstance(ev, (list, tuple)):
        return " ".join(str(x) for x in ev)
    return str(ev or "")


def category(finding: Dict[str, Any]) -> str:
    """confirmed | tentative | observation | rejected — drives report grouping."""
    st = normalize_status(finding.get("status"))
    if st == "rejected":
        return "rejected"
    # Missing-mitigation / neutral observations belong to the attack-surface section regardless
    # of their (often CONFIRMED) status — they are not vulnerabilities by themselves.
    if st == "observation" or finding.get("vuln_type") == "hardening":
        return "observation"
    if st in _CONFIRMED:
        return "confirmed"
    return "tentative"


def _has_precise_location(f: Dict[str, Any]) -> bool:
    loc = (f.get("location") or "").lower()
    return bool(loc) and ("0x" in loc or "@" in loc or any(c.isdigit() for c in loc)
                          or "fun_" in loc or "sub_" in loc)


def sources(f: Dict[str, Any]) -> List[str]:
    out = set()
    if f.get("evidence_source"):
        out.add(str(f["evidence_source"]).strip().lower())
    for r in (f.get("evidence_refs") or []):
        out.add(str(r).strip().lower())
    for key in ("references", "sources"):
        v = f.get(key)
        if isinstance(v, str):
            out.update(p.strip().lower() for p in v.replace(";", ",").split(",") if p.strip())
        elif isinstance(v, (list, tuple)):
            out.update(str(p).strip().lower() for p in v if str(p).strip())
    return sorted(out)


def confidence(f: Dict[str, Any]) -> float:
    st = normalize_status(f.get("status"))
    c = _BASE_CONF.get(st, 0.3)
    ev = _ev_text(f) or str(f.get("description") or "")
    if _has_precise_location(f):
        c += 0.08
    if len(ev) > 40:
        c += 0.07
    extra = max(0, len(sources(f)) - 1)
    c += min(0.12, 0.06 * extra)
    # A dangerous sink that is only *imported* (not shown reached) shouldn't look confirmed.
    if st not in _CONFIRMED and ("import table" in ev.lower() or "symbol inventory" in ev.lower()):
        c -= 0.12
    return round(max(0.0, min(0.97, c)), 2)


def confidence_value(v, default: float = 0.0) -> float:
    """Return a numeric confidence in [0,1] from user/LLM-provided values.

    Thin wrapper over the centralized normalizer (reforge.severity) so there is a single
    implementation. Kept for backward compatibility with existing callers/imports.
    """
    from . import severity as _sev
    return _sev.norm_confidence(v, default)


def confidence_pct(v, default: float = 0.0) -> int:
    from . import severity as _sev
    return _sev.confidence_pct(v, default)


def missing_validation(f: Dict[str, Any]) -> List[str]:
    st = normalize_status(f.get("status"))
    miss = []
    sev = (f.get("severity") or "INFO").upper()
    ev = (_ev_text(f) + " " + str(f.get("description", ""))).lower()
    if st != "confirmed_dynamic" and sev in ("CRITICAL", "HIGH"):
        miss.append("dynamic proof")
    if not any(k in ev for k in ("source", "sink", "xref", "trace", "argument", "reach")):
        miss.append("input reachability (source→sink)")
    if not _has_precise_location(f):
        miss.append("precise location")
    if len(sources(f)) < 2 and st in _CONFIRMED:
        miss.append("second independent source")
    return miss


def enrich(f: Dict[str, Any]) -> Dict[str, Any]:
    """Attach deterministic confidence + structured status if not already set. Mutates and returns f."""
    f["status_norm"] = normalize_status(f.get("status"))
    if f.get("confidence") in (None, ""):
        f["confidence"] = confidence(f)
    return f


# --------------------------- report validation (2.5) ---------------------------
def validate(session) -> List[Dict[str, str]]:
    """Return pre-export warnings. Each: {level: 'warn'|'info', msg}."""
    F = session.findings or []
    warns: List[Dict[str, str]] = []
    confirmed = [f for f in F if category(f) == "confirmed"]
    tentative = [f for f in F if category(f) == "tentative"]

    if not confirmed:
        warns.append({"level": "info", "msg": "No CONFIRMED finding: the report contains only "
                                               "hypotheses/observations to validate."})
    if tentative:
        warns.append({"level": "warn", "msg": f"{len(tentative)} unvalidated hypotheses: "
                                              "confirm or reject them before delivering."})
    for f in F:
        if category(f) == "observation":
            continue
        title = f.get("title", "(untitled)")
        if not (f.get("evidence") or f.get("evidence_source") or f.get("evidence_refs")):
            warns.append({"level": "warn", "msg": f"'{title}': no linked evidence."})
        sev = (f.get("severity") or "INFO").upper()
        if sev in ("CRITICAL", "HIGH") and not _has_precise_location(f):
            warns.append({"level": "warn", "msg": f"'{title}' ({sev}) has no precise location "
                                                  "(function/offset)."})
        if category(f) == "confirmed" and len(sources(f)) < 2:
            warns.append({"level": "info", "msg": f"'{title}' confirmed from a single source: "
                                                  "consider independent corroboration."})
        if normalize_status(f.get("status")) == "confirmed_dynamic":
            ev = _ev_text(f).lower()
            if not any(k in ev for k in ("runtime", "x64dbg", "debug", "observ", "breakpoint")):
                warns.append({"level": "warn", "msg": f"'{title}' marked confirmed_dynamic but "
                                                      "the evidence does not cite a runtime confirmation."})
    # Truncated tool outputs anywhere in the investigation.
    log = getattr(session, "investigation_log", []) or []
    if any("truncat" in str(e).lower() for e in log):
        warns.append({"level": "info", "msg": "Some tool outputs were truncated: "
                                              "a manual review may be needed."})
    return warns
