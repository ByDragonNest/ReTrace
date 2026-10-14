"""Finding state model and programmatic transition criteria (prompt §1).

The lifecycle is a strict, ordered lattice. A finding's *maximum attainable* status is a pure
function of the evidence attached to it — an LLM (or any narrative layer) can NEVER promote a
finding: it can only propose evidence, and evidence is what promotes.

    OBSERVATION < INDICATOR < HYPOTHESIS < PROBABLE < CONFIRMED_STATIC < CONFIRMED_DYNAMIC
    REJECTED is terminal and orthogonal.

Mandatory rules (from the spec):
  * isolated import OR isolated string  -> at most INDICATOR
  * string with coherent context but no observed use -> at most HYPOTHESIS
  * call-site found but source->sink incomplete       -> HYPOTHESIS
  * component identified by >=2 independent fingerprints -> PROBABLE
  * complete source->sink, function reachable, control absent -> CONFIRMED_STATIC
  * behaviour observed and reproduced at runtime       -> CONFIRMED_DYNAMIC
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

OBSERVATION = "OBSERVATION"
INDICATOR = "INDICATOR"
HYPOTHESIS = "HYPOTHESIS"
PROBABLE = "PROBABLE"
CONFIRMED_STATIC = "CONFIRMED_STATIC"
CONFIRMED_DYNAMIC = "CONFIRMED_DYNAMIC"
REJECTED = "REJECTED"

ORDER: List[str] = [
    OBSERVATION, INDICATOR, HYPOTHESIS, PROBABLE, CONFIRMED_STATIC, CONFIRMED_DYNAMIC,
]
_RANK = {s: i for i, s in enumerate(ORDER)}
CONFIRMED = {CONFIRMED_STATIC, CONFIRMED_DYNAMIC}

# Map every legacy / free-text status onto the canonical model. Anything unknown falls to
# HYPOTHESIS (never to a confirmed state — promotion must be earned).
_LEGACY = {
    "observation": OBSERVATION, "obs": OBSERVATION, "hardening": OBSERVATION,
    "lead": INDICATOR, "indicator": INDICATOR, "token_present": INDICATOR,
    "hypothesis": HYPOTHESIS, "hypothetical": HYPOTHESIS, "candidate": HYPOTHESIS,
    "needs_review": HYPOTHESIS, "suspicious": HYPOTHESIS,
    "needs_dynamic_validation": PROBABLE, "probable": PROBABLE, "likely": PROBABLE,
    "confirmed": CONFIRMED_STATIC, "confirmed_static": CONFIRMED_STATIC,
    "confirmed_dynamic": CONFIRMED_DYNAMIC,
    "rejected": REJECTED, "false_positive": REJECTED, "fp": REJECTED,
}


def normalize(status: Any) -> str:
    return _LEGACY.get(str(status or "").strip().lower(), HYPOTHESIS)


def rank(status: Any) -> int:
    s = normalize(status)
    return _RANK.get(s, _RANK[HYPOTHESIS])


def is_confirmed(status: Any) -> bool:
    return normalize(status) in CONFIRMED


# --------------------------------------------------------------------------- evidence gating
def _ev(f: Dict[str, Any]) -> Dict[str, Any]:
    """Evidence bundle for a finding, defaulting to an empty structure. Callers set the flags
    from real observations (Ghidra xrefs, x64dbg traces, fingerprints, ...)."""
    return f.get("evidence_bundle") or {}


def max_attainable(f: Dict[str, Any]) -> Tuple[str, List[str]]:
    """Return (max_status, reasons). Pure function of the finding's evidence bundle.

    The bundle keys (all optional, all booleans/ints unless noted):
      isolated_only        : derives from a single import OR a single string, nothing else
      string_context       : string sits in a coherent context (but no observed use)
      call_site            : a real call site (addr+function) was located
      source, sink         : source and sink identified
      reachable            : the containing function is reachable from an entry/source
      dataflow_complete    : source->sink dataflow is complete (no gap)
      control_absent       : the mitigating control is observed to be absent (not merely unseen)
      independent_fingerprints : int, number of independent fingerprints (>=2 => component match)
      runtime_observed     : behaviour reproduced at runtime (x64dbg/procmon)
      observation_only     : a neutral fact / hardening posture, not a vuln by itself
    """
    ev = _ev(f)
    if ev.get("observation_only"):
        return OBSERVATION, ["neutral observation / hardening posture"]

    # CONFIRMED_DYNAMIC: reproduced at runtime.
    if ev.get("runtime_observed"):
        return CONFIRMED_DYNAMIC, ["behaviour observed and reproduced at runtime"]

    # CONFIRMED_STATIC: full source->sink, reachable, control observed absent.
    s2s_complete = all(ev.get(k) for k in ("source", "sink", "call_site",
                                           "reachable", "dataflow_complete", "control_absent"))
    if s2s_complete:
        return CONFIRMED_STATIC, ["complete source->sink, function reachable, control absent"]

    # PROBABLE: component identified by >=2 independent fingerprints.
    if int(ev.get("independent_fingerprints") or 0) >= 2:
        return PROBABLE, [">=2 independent fingerprints"]

    # HYPOTHESIS: call-site present but source->sink incomplete; or coherent-context string.
    if ev.get("call_site") and not s2s_complete:
        return HYPOTHESIS, ["call site found but source->sink incomplete"]
    if ev.get("string_context"):
        return HYPOTHESIS, ["string in coherent context, no observed use"]

    # INDICATOR: isolated import or isolated string.
    if ev.get("isolated_only") or ev.get("source") or ev.get("sink"):
        return INDICATOR, ["isolated import/string signal"]

    return INDICATOR, ["insufficient evidence: default to INDICATOR"]


def resolve(f: Dict[str, Any], proposed: Any = None) -> Dict[str, Any]:
    """Determine the finding's effective status, capping any proposal at the attainable ceiling.

    `proposed` may come from a heuristic or an LLM. It is honoured only if it does NOT exceed the
    evidence-derived ceiling. A REJECTED proposal is always honoured (rejection needs no promotion).
    Returns {status, capped(bool), ceiling, reasons}.
    """
    if normalize(proposed) == REJECTED or normalize(f.get("status")) == REJECTED:
        return {"status": REJECTED, "capped": False, "ceiling": REJECTED,
                "reasons": ["explicitly rejected"]}

    ceiling, reasons = max_attainable(f)
    want = proposed if proposed is not None else f.get("status")
    want_norm = normalize(want)
    if rank(want_norm) > rank(ceiling):
        return {"status": ceiling, "capped": True, "ceiling": ceiling,
                "reasons": reasons + [f"proposal {want_norm} exceeds evidence ceiling {ceiling}"]}
    # A proposal below the ceiling is respected (analyst may deliberately keep it low).
    return {"status": want_norm, "capped": False, "ceiling": ceiling, "reasons": reasons}


def apply(f: Dict[str, Any], proposed: Any = None) -> Dict[str, Any]:
    """Mutate `f` in place: set f['status'] to the resolved value, record the gating trace."""
    r = resolve(f, proposed)
    f["status"] = r["status"]
    f["status_ceiling"] = r["ceiling"]
    f["status_capped"] = r["capped"]
    f.setdefault("status_reasons", [])
    f["status_reasons"] = r["reasons"]
    return f
