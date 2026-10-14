"""Hardcoded-secret confirmation (prompt §8).

The old scanner promoted "Password", "PASS:", GUI labels etc. to CONFIRMED secrets. This module
replaces that with a strict confirmation gate. A candidate is a CONFIRMED secret only if ALL hold:

  * a concrete VALUE is present (not just the word "password");
  * entropy AND format are compatible with a real secret;
  * it sits in a key=value / connection-string / JSON / XML / assignment context;
  * it is NOT a UI resource / property name / error message / placeholder;
  * it has an xref to an auth / connection / decryption function.

Anything failing these stays at INDICATOR/HYPOTHESIS. The report shows ONLY a redacted value and a
hash — never the plaintext. The engine also refuses to auto-infer shared passwords, DB/API access,
production environment, breach or compliance impact from mere presence.
"""
from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from typing import Any, Dict, List

from . import status as st

# Words that are NOT secrets on their own (labels, placeholders, property names).
_DENY_EXACT = {
    "password", "passwd", "pwd", "username", "user", "login", "badpassword",
    "pass", "pass:", "password:", "secret", "token", "apikey", "api_key",
    "changeme", "example", "test", "dummy", "none", "null", "<password>", "yourpassword",
}
_DENY_SUBSTR = ("error", "invalid", "failed", "label", "caption", "hint", "tooltip",
                "placeholder", "property", "field", "prompt", "message", "enter your")

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((k / n) * math.log2(k / n) for k in c.values())


def _looks_like_value(v: str) -> bool:
    """A concrete secret value: adequate length, mixed alphabet or high entropy, not a dictionary
    placeholder."""
    v = v.strip()
    if len(v) < 6:
        return False
    if v.lower() in _DENY_EXACT:
        return False
    if _entropy(v) < 2.6 and not re.search(r"[0-9]", v):
        return False
    return True


def _redact(v: str) -> str:
    v = v.strip()
    keep = 2 if len(v) <= 8 else 3
    return v[:keep] + "…" + f"({len(v)} chars)"


def _hash(v: str) -> str:
    return "sha256:" + hashlib.sha256(v.encode("utf-8")).hexdigest()[:16]


def classify_secret(candidate: Dict[str, Any], *,
                    xref_to_sensitive_fn: bool = False,
                    is_ui_resource: bool = False) -> Dict[str, Any]:
    """Decide the status of one secret candidate. Returns a finding-shaped dict (no plaintext)."""
    raw = str(candidate.get("value") or "").strip()
    context = candidate.get("context") or ""
    reasons: List[str] = []
    bundle = {}

    low = raw.lower()
    denied = (low in _DENY_EXACT) or any(s in low for s in _DENY_SUBSTR) or is_ui_resource
    has_value = _looks_like_value(raw)
    has_context = context in ("assignment", "connection_string", "json", "xml")

    if denied:
        reasons.append("looks like a label/placeholder/UI resource, not a value")
    if not has_value:
        reasons.append("no concrete high-entropy value")
    if not has_context:
        reasons.append("not in a key=value/connection/JSON/XML context")
    if not xref_to_sensitive_fn:
        reasons.append("no xref to an auth/connection/decryption function")

    confirmed = has_value and has_context and (not denied) and xref_to_sensitive_fn
    if confirmed:
        bundle = {"source": True, "sink": True, "call_site": True, "reachable": True,
                  "dataflow_complete": True, "control_absent": True}
        status = st.CONFIRMED_STATIC
    elif has_value and has_context:
        bundle = {"string_context": True}
        status = st.HYPOTHESIS
    elif has_value or has_context:
        bundle = {"isolated_only": True}
        status = st.INDICATOR
    else:
        bundle = {"isolated_only": True}
        status = st.INDICATOR

    f = {
        "title": "Hardcoded secret candidate",
        "vuln_type": "hardcoded_secret",
        "root_cause": "hardcoded-credential",
        "cwe": "CWE-798",
        "location": "embedded data",
        "status": status,
        "evidence_bundle": bundle,
        "potential_severity": "HIGH",
        # Report shows ONLY redacted + hash. Plaintext is never stored on the finding.
        "value_redacted": _redact(raw) if has_value else "(no value)",
        "value_hash": _hash(raw) if raw else "",
        "assumptions": [],
        "missing_validation_steps": [r for r in reasons] if status != st.CONFIRMED_STATIC else [],
        # Explicitly forbid the auto-inferences the old pipeline made.
        "forbidden_inferences_blocked": [
            "shared password across installs", "database access", "API access",
            "production environment", "data breach", "compliance violation",
        ],
    }
    st.apply(f, status)
    return f
