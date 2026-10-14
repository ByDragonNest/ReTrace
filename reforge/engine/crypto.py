"""Layered crypto-usage detection (prompt §9).

A crypto token being present is not the same as a vulnerable crypto USE. Five separate levels:

    TOKEN_PRESENT           - a string like "rc4"/"MD5"/"SHA1_Init" exists
    IMPLEMENTATION_PRESENT  - an actual implementation/library is present (constants, S-boxes)
    REFERENCED              - the implementation is referenced from code (xref exists)
    CALLED                  - a call site invokes it
    SECURITY_USE_CONFIRMED  - it is demonstrably used for a security purpose (confidentiality/
                              integrity/auth), not as a non-security checksum

Only SECURITY_USE_CONFIRMED can back a CONFIRMED_STATIC weak-crypto finding. A bare "rc4"/"MD5"/
"Rc2"/"SHA1_Init" string maps to INDICATOR.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from . import status as st

TOKEN_PRESENT = "TOKEN_PRESENT"
IMPLEMENTATION_PRESENT = "IMPLEMENTATION_PRESENT"
REFERENCED = "REFERENCED"
CALLED = "CALLED"
SECURITY_USE_CONFIRMED = "SECURITY_USE_CONFIRMED"

LEVELS = [TOKEN_PRESENT, IMPLEMENTATION_PRESENT, REFERENCED, CALLED, SECURITY_USE_CONFIRMED]

# Weak algorithm tokens -> (label, cwe, potential severity if used for security).
_WEAK = [
    (re.compile(r"(?i)\brc4\b|arcfour|rc4_set_key"), "RC4", "CWE-327", "HIGH"),
    (re.compile(r"(?i)\brc2\b|calg_rc2"), "RC2", "CWE-327", "MEDIUM"),
    (re.compile(r"(?i)\bmd5\b|md5_init|calg_md5"), "MD5", "CWE-328", "MEDIUM"),
    (re.compile(r"(?i)sha-?1\b|sha1_init|calg_sha1"), "SHA-1", "CWE-328", "MEDIUM"),
    (re.compile(r"(?i)\bdes\b|des_set_key|3des|calg_3?des"), "DES/3DES", "CWE-327", "HIGH"),
    (re.compile(r"(?i)-ecb|_ecb\b|mode_ecb"), "ECB mode", "CWE-327", "HIGH"),
]


def detect_level(*, token: bool = False, implementation: bool = False,
                 referenced: bool = False, called: bool = False,
                 security_use: bool = False) -> str:
    """Highest justified level given the observed facts."""
    if security_use and called:
        return SECURITY_USE_CONFIRMED
    if called:
        return CALLED
    if referenced:
        return REFERENCED
    if implementation:
        return IMPLEMENTATION_PRESENT
    return TOKEN_PRESENT if token else TOKEN_PRESENT


def _bundle_for(level: str) -> Dict[str, Any]:
    if level == SECURITY_USE_CONFIRMED:
        return {"source": True, "sink": True, "call_site": True, "reachable": True,
                "dataflow_complete": True, "control_absent": True}
    if level == CALLED:
        return {"call_site": True}
    if level in (REFERENCED, IMPLEMENTATION_PRESENT):
        return {"string_context": True}
    return {"isolated_only": True}


def classify(text: str, *, evidence: Optional[Dict[str, bool]] = None) -> List[Dict[str, Any]]:
    """Scan text for weak-crypto tokens; return one finding per algorithm at the correct level.

    `evidence` (optional) can raise the level: keys implementation/referenced/called/security_use.
    Without it, a bare token maps to INDICATOR (never CONFIRMED).
    """
    ev = evidence or {}
    out = []
    for rx, label, cwe, sev in _WEAK:
        if not rx.search(text or ""):
            continue
        level = detect_level(token=True, implementation=ev.get("implementation", False),
                             referenced=ev.get("referenced", False), called=ev.get("called", False),
                             security_use=ev.get("security_use", False))
        bundle = _bundle_for(level)
        f = {
            "title": f"Weak crypto: {label}",
            "vuln_type": "weak_crypto",
            "root_cause": label,
            "component": label,
            "cwe": cwe,
            "location": "strings/symbols",
            "crypto_level": level,
            "potential_severity": sev,
            "evidence_bundle": bundle,
            "assumptions": ["algorithm assumed used for a security purpose"]
            if level != SECURITY_USE_CONFIRMED else [],
            "missing_validation_steps": [] if level == SECURITY_USE_CONFIRMED else [
                "confirm the algorithm is used for confidentiality/integrity, not a plain checksum",
                "locate call site and trace security-relevant data through it",
            ],
        }
        st.apply(f, None)  # status derived from the evidence bundle
        out.append(f)
    return out
