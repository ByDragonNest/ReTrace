"""LLM enrichment safety guard (prompt §14) and toolchain-aware remediation (prompt §16).

The narrative layer may ENRICH an existing finding (clearer wording, conditional impact) but must
never: invent links between unrelated evidence, raise severity without new evidence, change status,
add duplicate vulnerabilities, invent attack scenarios/environment/privileges/compliance scope, or
assign arbitrary deadlines. This module diffs an LLM-enriched finding against the deterministic
original and rejects any forbidden mutation, keeping the deterministic value.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

from . import status as st

# Fields the LLM is allowed to touch (purely descriptive).
_ALLOWED = {"title", "description", "impact", "recommendation", "plain", "narrative"}
# Fields that are deterministic and must survive unchanged.
_LOCKED = {"status", "severity", "confirmed_severity", "cvss_score", "cvss_vector",
           "confidence", "remediation_priority", "id", "cwe", "evidence_bundle"}


def sanitize_enrichment(original: Dict[str, Any], enriched: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """Merge only allowed descriptive changes from `enriched` into a copy of `original`.

    Returns (safe_finding, rejected_changes). Locked fields are restored from the original even if
    the LLM changed them.
    """
    out = dict(original)
    rejected: List[str] = []
    for k, v in (enriched or {}).items():
        if k in _ALLOWED:
            out[k] = v
        elif k in _LOCKED and v not in (None, "", [], {}) and v != original.get(k):
            rejected.append(f"blocked change to locked field '{k}'")
        # unknown fields from the LLM are ignored (no silent new keys).
    # Guard against status/severity escalation smuggled through description text.
    from . import claims as cl
    if out.get("description"):
        rev = cl.review(str(out["description"]), set(original.get("evidence_refs") or []))
        if rev["removed"]:
            rejected += [f"removed unsupported claim: {c[:60]}…" for c in rev["removed"]]
        out["description"] = rev["clean_text"] or original.get("description", "")
    return out, rejected


def enforce_conditional_language(f: Dict[str, Any]) -> Dict[str, Any]:
    """For non-confirmed findings, ensure impact/description use conditional language."""
    if st.is_confirmed(f.get("status")):
        return f
    for key in ("impact", "description"):
        txt = str(f.get(key) or "")
        if txt and not re.search(r"\b(if confirmed|may|might|could|would|requires validation|"
                                 r"potential|assuming)\b", txt, re.I):
            f[key] = "If confirmed, " + txt[0].lower() + txt[1:]
    return f
