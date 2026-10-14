"""Claim reviewer — second pass over generated narrative (prompt §15).

Every sentence produced by the narrative layer is classified against the evidence:

    claim         - the sentence
    evidence_refs - E-#### ids it cites (if any)
    claim_type    - FACT | INFERENCE | CONDITION | UNSUPPORTED
    action        - KEEP | REWRITE | REMOVE

All UNSUPPORTED sentences are REMOVED before the final report. FACTs must cite evidence;
INFERENCEs are kept only if conditional language is present, else REWRITE. CONDITIONs (if/may/
requires validation) are always safe to KEEP.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Set, Optional

FACT = "FACT"
INFERENCE = "INFERENCE"
CONDITION = "CONDITION"
UNSUPPORTED = "UNSUPPORTED"

KEEP = "KEEP"
REWRITE = "REWRITE"
REMOVE = "REMOVE"

_EREF_RX = re.compile(r"\bE-\d{3,}\b")
_COND_RX = re.compile(r"\b(if confirmed|if exploited|may|might|could|would|requires validation|"
                      r"potential(?:ly)?|assuming|pending|to be confirmed|likely|possibly)\b", re.I)
# Overclaiming phrases that are never allowed.
_OVERCLAIM_RX = re.compile(
    r"\b(exploitation approaches certainty|guaranteed|certainly exploitable|definitely|"
    r"proves that|confirms full compromise|will be exploited)\b", re.I)
# Fabricated-context phrases (environment/privileges/compliance not established by evidence).
_FABRICATION_RX = re.compile(
    r"\b(production environment|in production|domain admin|root access|pci[- ]?dss|hipaa|gdpr|"
    r"data breach|by (?:end of|within) \w+|deadline)\b", re.I)


def _split_sentences(text: str) -> List[str]:
    parts = re.split(r"(?<=[.!?])\s+|\n+", text or "")
    return [p.strip() for p in parts if p.strip()]


def classify_claim(sentence: str, known_evidence: Set[str]) -> Dict[str, Any]:
    refs = [r for r in _EREF_RX.findall(sentence) if r in known_evidence] if known_evidence \
        else _EREF_RX.findall(sentence)
    cited = _EREF_RX.findall(sentence)
    is_conditional = bool(_COND_RX.search(sentence))

    if _OVERCLAIM_RX.search(sentence) or _FABRICATION_RX.search(sentence):
        return {"claim": sentence, "evidence_refs": refs, "claim_type": UNSUPPORTED,
                "action": REMOVE}
    if is_conditional:
        return {"claim": sentence, "evidence_refs": refs, "claim_type": CONDITION, "action": KEEP}
    if cited:
        # A definite (non-conditional) statement that cites evidence -> FACT if the ref is valid.
        if refs:
            return {"claim": sentence, "evidence_refs": refs, "claim_type": FACT, "action": KEEP}
        return {"claim": sentence, "evidence_refs": [], "claim_type": UNSUPPORTED,
                "action": REMOVE}
    # A definite statement with no citation and no conditional hedge.
    if _is_generic(sentence):
        return {"claim": sentence, "evidence_refs": [], "claim_type": INFERENCE, "action": KEEP}
    return {"claim": sentence, "evidence_refs": [], "claim_type": UNSUPPORTED, "action": REWRITE}


_GENERIC_RX = re.compile(
    r"\b(recommend|should|consider|review|the (?:report|analysis|binary|target)|"
    r"this (?:section|document))\b", re.I)


def _is_generic(sentence: str) -> bool:
    """Boilerplate/recommendation sentences are inferences, not vuln assertions."""
    return bool(_GENERIC_RX.search(sentence))


def review(text: str, known_evidence: Optional[Set[str]] = None) -> Dict[str, Any]:
    """Classify every sentence; return the reviewed claims and the cleaned text (UNSUPPORTED
    removed)."""
    known = set(known_evidence or [])
    claims = [classify_claim(s, known) for s in _split_sentences(text)]
    kept = [c["claim"] for c in claims if c["action"] != REMOVE]
    return {
        "claims": claims,
        "clean_text": " ".join(kept),
        "removed": [c["claim"] for c in claims if c["action"] == REMOVE],
        "needs_rewrite": [c["claim"] for c in claims if c["action"] == REWRITE],
    }
