"""Adapter between legacy findings and the v61 engine.

Existing findings (from the heuristic engine, the LLM, or manual entry) carry free-text
`evidence`/`location`/`status` fields, not the structured `evidence_bundle` the state model reads.
`infer_bundle()` reconstructs a bundle from those legacy signals so a legitimately-evidenced
finding keeps its status, while an under-evidenced one is capped exactly as the spec requires.

`normalize()` is the single choke point the report (and, optionally, the agent) call: it infers
bundles, gates source->sink evidence, applies the anti-FP rules, caps each status to its evidence
ceiling, scores risk, and deduplicates — returning COPIES so the session store stays untouched
(the raw status the analyst typed is preserved; the report shows the gated view).
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from . import antifp, dedup, evidence_gate, schema, status as st

_PRECISE_LOC = re.compile(r"0x[0-9a-f]+|@|\bfun_[0-9a-f]+|\bsub_[0-9a-f]+", re.I)
_DYNAMIC = re.compile(r"runtime|x64dbg|breakpoint|procmon|observed at runtime|reproduc", re.I)
_S2S_HINT = re.compile(r"source.?to.?sink|source->sink|dataflow|traces? back|reaches the sink|"
                       r"argument derives", re.I)
_CONTROL_ABSENT = re.compile(r"no validation|without validation|missing (?:check|bound|control)|"
                             r"unbounded|no length (?:check|limit)|absent control|not validated", re.I)
_ISOLATED = re.compile(r"import table|symbol inventory|version banner|embedded data|"
                       r"strings?/symbols?|present in the import", re.I)
_FINGERPRINT_HINT = re.compile(r"fingerprint|banner|constant|signature|symbol", re.I)


def _text(f: Dict[str, Any]) -> str:
    ev = f.get("evidence")
    ev = " ".join(str(x) for x in ev) if isinstance(ev, (list, tuple)) else str(ev or "")
    return " ".join([ev, str(f.get("description") or ""), str(f.get("evidence_source") or ""),
                     str(f.get("evidence_type") or "")]).lower()


def infer_bundle(f: Dict[str, Any]) -> Dict[str, Any]:
    """Reconstruct an evidence_bundle from a legacy finding's fields.

    An already-present, non-empty `evidence_bundle` is trusted and returned as-is (engine-authored
    findings pass through untouched).
    """
    existing = f.get("evidence_bundle")
    if existing:
        return dict(existing)

    # A full structured source_to_sink dict is authoritative.
    if f.get("source_to_sink"):
        b = evidence_gate.to_bundle(f["source_to_sink"])
        b.pop("_gaps", None)
        b.pop("_complete", None)
        return b

    text = _text(f)
    declared = st.normalize(f.get("status"))
    loc = str(f.get("location") or "")
    bundle: Dict[str, Any] = {}

    # Neutral observation / hardening posture.
    if f.get("vuln_type") == "hardening" or declared == st.OBSERVATION:
        return {"observation_only": True}

    # Dynamic confirmation.
    if declared == st.CONFIRMED_DYNAMIC or _DYNAMIC.search(text):
        if declared == st.CONFIRMED_DYNAMIC or f.get("evidence_source", "").lower() in (
                "x64dbg", "procmon", "dynamic_analysis"):
            return {"runtime_observed": True}

    call_site = bool(_PRECISE_LOC.search(loc)) or bool(_PRECISE_LOC.search(text))
    fingerprints = f.get("fingerprints")
    if isinstance(fingerprints, (list, tuple)) and len(fingerprints) >= 2:
        bundle["independent_fingerprints"] = len(fingerprints)

    s2s_hint = bool(_S2S_HINT.search(text))
    control_absent = bool(_CONTROL_ABSENT.search(text))
    isolated = bool(_ISOLATED.search(text)) and not call_site and not s2s_hint

    # A declared static confirmation is honoured only if the evidence actually supports a full
    # source->sink with an absent control; otherwise it is capped downstream.
    if declared == st.CONFIRMED_STATIC and call_site and s2s_hint and control_absent:
        return {"source": True, "sink": True, "call_site": True, "reachable": True,
                "dataflow_complete": True, "control_absent": True}

    if call_site:
        bundle["call_site"] = True
    if s2s_hint:
        bundle["source"] = True
        bundle["sink"] = True
    if control_absent:
        bundle["control_absent"] = True
    if isolated:
        bundle["isolated_only"] = True
    if not bundle:
        # coherent context but no observed use -> hypothesis ceiling; else isolated indicator.
        if declared in (st.HYPOTHESIS, st.PROBABLE) or f.get("evidence"):
            bundle["string_context"] = True
        else:
            bundle["isolated_only"] = True
    return bundle


def normalize(findings: List[Dict[str, Any]], binary_sha256: str = "") -> List[Dict[str, Any]]:
    """Return gated + risk-scored + deduplicated COPIES of `findings` for the report/agent view."""
    work: List[Dict[str, Any]] = []
    for f in findings or []:
        g = dict(f)
        declared = st.normalize(g.get("status"))
        g["declared_status"] = declared
        g["evidence_bundle"] = infer_bundle(g)
        if g.get("source_to_sink"):
            evidence_gate.gate_finding(g)
        antifp.apply_rules(g)
        st.apply(g, declared)
        # transparency: note when the delivered status was capped below what was declared.
        if st.rank(declared) > st.rank(g["status"]):
            g["status_capped_note"] = (f"declared {declared}, capped to {g['status']} "
                                       f"({'; '.join(g.get('status_reasons', []))})")
        schema.enrich_risk(g)
        work.append(g)
    return dedup.deduplicate(work, binary_sha256)
