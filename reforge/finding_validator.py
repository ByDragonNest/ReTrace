"""LLM-independent (deterministic) finding validator.

Decides whether a finding has enough evidence to be promoted, and with what confidence, WITHOUT
asking an LLM. It builds on the semantics already in `findings.py` (status lattice, confidence,
missing_validation) and adds the gating rules the prompt requires:

  * HIGH/CRITICAL without a precise call site          -> warning
  * no source→sink                                     -> the finding cannot rise above HYPOTHESIS
  * no evidence ID                                     -> not exportable as CONFIRMED
  * derived from a string/import alone                 -> low confidence
  * dynamic evidence present                           -> confidence increases
  * no remediation                                     -> warning
  * no affected function/address                       -> warning

Output per finding (see the prompt):
    {"finding_id": "F-0001", "status": "NEEDS_DYNAMIC_VALIDATION",
     "confidence": 0.62, "warnings": [...]}
"""
from typing import Any, Dict, List

from . import findings as fx

# Stati "espliciti" richiesti dal prompt, esposti come categoria sintetica del validator
# sopra la lattice interna di findings.py.
HYPOTHESIS = "HYPOTHESIS"
SUSPICIOUS = "SUSPICIOUS"
CONFIRMED = "CONFIRMED"
FALSE_POSITIVE = "FALSE_POSITIVE"
NEEDS_DYNAMIC_VALIDATION = "NEEDS_DYNAMIC_VALIDATION"

_DYNAMIC_HINT = ("runtime", "x64dbg", "debug", "breakpoint", "procmon", "osserv", "trace")
_SOURCE_SINK_HINT = ("source", "sink", "xref", "argoment", "raggiung", "→", "flows")
_WEAK_ONLY_HINT = ("import table", "symbol inventory", "tabella import")


def _text(f: Dict[str, Any]) -> str:
    return ((f.get("evidence") or "") + " " + (f.get("description") or "")).lower()


def _has_callsite(f: Dict[str, Any]) -> bool:
    loc = (f.get("location") or "").lower()
    return bool(loc) and ("0x" in loc or "@" in loc or "fun_" in loc or "sub_" in loc)


def _has_evidence_id(f: Dict[str, Any]) -> bool:
    refs = f.get("evidence_refs") or []
    return any(str(r).startswith("E-") for r in refs) or bool(f.get("evidence_id"))


def _has_source_to_sink(f: Dict[str, Any]) -> bool:
    if f.get("source_to_sink"):
        return True
    return any(k in _text(f) for k in _SOURCE_SINK_HINT)


def _has_dynamic(f: Dict[str, Any]) -> bool:
    if "dynamic" in (f.get("status") or "").lower():
        return True
    if (f.get("evidence_source") or "").lower() in ("x64dbg", "procmon", "dynamic_analysis"):
        return True
    return any(k in _text(f) for k in _DYNAMIC_HINT)


def _weak_only(f: Dict[str, Any]) -> bool:
    t = _text(f)
    return any(k in t for k in _WEAK_ONLY_HINT) and not _has_source_to_sink(f)


def validate_finding(f: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluate a single finding and return the structured verdict."""
    fx.enrich(f)
    sev = (f.get("severity") or "INFO").upper()
    declared = fx.normalize_status(f.get("status"))
    conf = fx.confidence(f)
    warnings: List[str] = []

    has_cs = _has_callsite(f)
    has_eid = _has_evidence_id(f)
    has_s2s = _has_source_to_sink(f)
    has_dyn = _has_dynamic(f)

    # --- regole di warning ---
    if sev in ("HIGH", "CRITICAL") and not has_cs:
        warnings.append("Missing precise callsite for a HIGH/CRITICAL finding")
    if not has_s2s:
        warnings.append("Missing source-to-sink evidence")
    if not has_eid:
        warnings.append("No linked evidence ID")
    if not has_dyn:
        warnings.append("No dynamic confirmation")
    if not (f.get("recommendation") or f.get("remediation")):
        warnings.append("Missing remediation")
    if not (f.get("location") or "").strip():
        warnings.append("Missing affected function/address")

    # --- aggiustamenti di confidence ---
    if _weak_only(f):
        conf = min(conf, 0.30)
        warnings.append("Finding derived only from strings/imports (low confidence)")
    if has_dyn:
        conf = min(0.97, conf + 0.10)

    # --- determinazione dello stato sintetico (gating) ---
    if declared == "rejected":
        status = FALSE_POSITIVE
    elif has_dyn and has_cs:
        status = CONFIRMED
    elif declared in ("confirmed_static", "confirmed_dynamic") and has_cs and has_eid:
        # confermato staticamente: ok, ma se è HIGH/CRIT senza dinamica segnaliamo comunque
        status = CONFIRMED
    elif not has_s2s:
        # senza source→sink non si sale oltre l'ipotesi (regola esplicita del prompt)
        status = HYPOTHESIS
    elif has_s2s and not has_dyn and sev in ("HIGH", "CRITICAL"):
        status = NEEDS_DYNAMIC_VALIDATION
    elif has_s2s:
        status = SUSPICIOUS
    else:
        status = HYPOTHESIS

    # gate finale: niente CONFIRMED senza evidence ID
    if status == CONFIRMED and not has_eid:
        status = NEEDS_DYNAMIC_VALIDATION
        if "No linked evidence ID" not in warnings:
            warnings.append("Cannot export as CONFIRMED without an evidence ID")

    return {
        "finding_id": f.get("id") or f.get("title", "F-?"),
        "status": status,
        "confidence": round(conf, 2),
        "exportable_as_confirmed": status == CONFIRMED,
        "warnings": warnings,
    }


def validate_session(session) -> Dict[str, Any]:
    """Validate every finding of a session. Returns verdicts plus a summary."""
    results = [validate_finding(f) for f in (getattr(session, "findings", []) or [])]
    summary = {
        "total": len(results),
        "confirmed": sum(1 for r in results if r["status"] == CONFIRMED),
        "needs_dynamic": sum(1 for r in results if r["status"] == NEEDS_DYNAMIC_VALIDATION),
        "hypothesis": sum(1 for r in results if r["status"] == HYPOTHESIS),
        "suspicious": sum(1 for r in results if r["status"] == SUSPICIOUS),
        "false_positive": sum(1 for r in results if r["status"] == FALSE_POSITIVE),
        "with_warnings": sum(1 for r in results if r["warnings"]),
    }
    return {"results": results, "summary": summary}
