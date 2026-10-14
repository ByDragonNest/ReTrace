"""Evidence gating for source-to-sink vulnerabilities (prompt §5).

A CONFIRMED_STATIC source-to-sink finding requires ALL of:
  source, sink, call_site, containing_function, reachability, dataflow,
  observed_controls, control_insufficiency_reason.

If any element is missing the finding CANNOT be CONFIRMED_STATIC — the missing elements become
coverage gaps / missing validation steps. Crucially, "no xrefs found" is a COVERAGE GAP, not a
confirmation of absence.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

REQUIRED = [
    "source", "sink", "call_site", "containing_function", "reachability",
    "dataflow", "observed_controls", "control_insufficiency_reason",
]

_LABEL = {
    "source": "untrusted input source",
    "sink": "dangerous sink",
    "call_site": "concrete call site (address)",
    "containing_function": "containing function",
    "reachability": "reachability from the source",
    "dataflow": "source->sink dataflow",
    "observed_controls": "observed validation/controls",
    "control_insufficiency_reason": "reason the control is insufficient",
}


def evaluate(s2s: Dict[str, Any]) -> Tuple[bool, List[str], Dict[str, bool]]:
    """Return (complete, gaps, presence). `s2s` is the evidence bundle for one chain.

    `no_xrefs=True` explicitly does NOT satisfy reachability; it is recorded as a gap.
    """
    presence: Dict[str, bool] = {}
    gaps: List[str] = []
    for key in REQUIRED:
        val = s2s.get(key)
        # "no xrefs found" never counts as reachability evidence.
        if key == "reachability" and s2s.get("no_xrefs"):
            val = None
            gaps.append("no xrefs found -> reachability unknown (coverage gap, not confirmation)")
        present = bool(val)
        presence[key] = present
        if not present and not (key == "reachability" and s2s.get("no_xrefs")):
            gaps.append(f"missing: {_LABEL[key]}")
    complete = all(presence.values())
    return complete, gaps, presence


def to_bundle(s2s: Dict[str, Any]) -> Dict[str, Any]:
    """Translate an s2s evidence dict into the status.evidence_bundle keys the state model reads."""
    complete, gaps, presence = evaluate(s2s)
    return {
        "source": presence["source"],
        "sink": presence["sink"],
        "call_site": presence["call_site"],
        "reachable": presence["reachability"],
        "dataflow_complete": presence["dataflow"],
        "control_absent": bool(s2s.get("control_insufficiency_reason")),
        "_gaps": gaps,
        "_complete": complete,
    }


def gate_finding(f: Dict[str, Any]) -> Dict[str, Any]:
    """Attach the evidence bundle + coverage gaps to a source-to-sink finding, then let the state
    model cap its status. Mutates and returns f."""
    from . import status as st
    s2s = f.get("source_to_sink") or {}
    bundle = to_bundle(s2s)
    gaps = bundle.pop("_gaps")
    bundle.pop("_complete", None)
    f["evidence_bundle"] = {**(f.get("evidence_bundle") or {}), **bundle}
    if gaps:
        cg = list(f.get("coverage_gaps") or [])
        for g in gaps:
            if g not in cg:
                cg.append(g)
        f["coverage_gaps"] = cg
        mv = list(f.get("missing_validation_steps") or [])
        for g in gaps:
            if g not in mv:
                mv.append(g)
        f["missing_validation_steps"] = mv
    st.apply(f, f.get("status"))
    return f
