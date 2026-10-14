"""Risk field separation, justified CVSS, and dual overall-risk (prompt §2 and §13).

A finding carries SEPARATE risk fields so a hypothesis can never masquerade as a confirmed
vulnerability:

    status                    - lifecycle state (engine.status)
    confidence                - [0,1] belief the finding is real
    potential_severity        - worst-case IF the hypothesis were confirmed
    confirmed_severity        - severity backed by confirmed evidence (None until confirmed)
    remediation_priority      - P1..P4, driven by confirmed_severity + confidence
    cvss_score / cvss_vector  - ONLY for confirmed findings, every metric justified by a fact
    evidence_refs             - list of E-#### ids
    assumptions               - explicit assumptions the finding rests on
    missing_validation_steps  - what still has to be checked
    coverage_gaps             - what the tools could not observe

CVSS RULES
  * No CVSS for OBSERVATION / INDICATOR / HYPOTHESIS (returns None).
  * No hard-coded band scores (the old 8.0 / 5.5 / 3.0 defaults are gone).
  * Every CVSS metric must be justified by an observed fact; an unjustified metric is dropped and
    the vector is marked incomplete rather than invented.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import status as st

# Severity bands -> a *range*, never a single invented number.
BANDS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_BAND_RANGE = {"CRITICAL": (9.0, 10.0), "HIGH": (7.0, 8.9), "MEDIUM": (4.0, 6.9),
               "LOW": (0.1, 3.9), "INFO": (0.0, 0.0)}

RISK_FIELDS = [
    "status", "confidence", "potential_severity", "confirmed_severity",
    "remediation_priority", "cvss_score", "cvss_vector", "evidence_refs",
    "assumptions", "missing_validation_steps", "coverage_gaps",
]

# The eight base metrics of CVSS 3.1 and the evidence key that justifies each one.
_CVSS_METRICS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
_METRIC_JUSTIFIER = {
    "AV": "attack_vector_observed",   # e.g. reachable from network vs local only
    "AC": "attack_complexity_observed",
    "PR": "privileges_observed",
    "UI": "user_interaction_observed",
    "S": "scope_observed",
    "C": "impact_confidentiality_observed",
    "I": "impact_integrity_observed",
    "A": "impact_availability_observed",
}


def norm_band(v: Any, default: str = "INFO") -> str:
    t = str(v or "").strip().upper()
    return t if t in _BAND_RANGE else default


def cvss_from_vector(vector: str) -> Optional[float]:
    """Compute the CVSS 3.1 base score from a full vector string. Returns None if incomplete."""
    if not vector:
        return None
    parts = dict(p.split(":", 1) for p in vector.replace("CVSS:3.1/", "").split("/") if ":" in p)
    if not all(m in parts for m in _CVSS_METRICS):
        return None
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}.get(parts["AV"])
    ac = {"L": 0.77, "H": 0.44}.get(parts["AC"])
    scope_changed = parts["S"] == "C"
    pr = {"N": 0.85, "L": 0.68 if not scope_changed else 0.5,
          "H": 0.27 if not scope_changed else 0.5}.get(parts["PR"])
    ui = {"N": 0.85, "R": 0.62}.get(parts["UI"])
    imp = {"H": 0.56, "L": 0.22, "N": 0.0}
    c, i, a = imp.get(parts["C"]), imp.get(parts["I"]), imp.get(parts["A"])
    # Explicit rather than `if None in (...)`: a membership test over a tuple of maybe-None
    # floats reads as a guard but does not narrow the types, so every use below was an operation
    # on a possible None that only happened to be safe.
    if av is None or ac is None or pr is None or ui is None:
        return None
    if c is None or i is None or a is None:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed \
        else 6.42 * iss
    exploit = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    raw = min((1.08 if scope_changed else 1.0) * (impact + exploit), 10.0)
    import math
    return math.ceil(raw * 10) / 10.0


def justified_cvss(f: Dict[str, Any]) -> Dict[str, Any]:
    """Build a CVSS vector using ONLY metrics justified by observed facts (prompt §2).

    Reads `f['cvss_metrics']` = {"AV":"N", ...} and `f['cvss_justification']` = set/list of
    evidence keys present. A metric is kept only if its justifier key is present. If any of the
    eight metrics is unjustified, the score is None and the vector carries an `(incomplete)` tag —
    we never fall back to 8.0/5.5/3.0.
    """
    if not st.is_confirmed(f.get("status")):
        return {"score": None, "vector": None,
                "note": "CVSS withheld: not a confirmed finding"}
    metrics = {k.upper(): str(v).upper() for k, v in (f.get("cvss_metrics") or {}).items()}
    justified = set(f.get("cvss_justification") or [])
    kept, missing = {}, []
    for m in _CVSS_METRICS:
        if m in metrics and _METRIC_JUSTIFIER[m] in justified:
            kept[m] = metrics[m]
        else:
            missing.append(m)
    if missing:
        vec = "CVSS:3.1/" + "/".join(f"{m}:{kept[m]}" for m in _CVSS_METRICS if m in kept)
        return {"score": None, "vector": vec + " (incomplete)",
                "note": "unjustified metrics dropped: " + ", ".join(missing)}
    vector = "CVSS:3.1/" + "/".join(f"{m}:{kept[m]}" for m in _CVSS_METRICS)
    return {"score": cvss_from_vector(vector), "vector": vector, "note": "fully justified"}


def remediation_priority(f: Dict[str, Any]) -> str:
    """P1..P4 from confirmed_severity and confidence. Hypotheses get at best P3 (validation-first)."""
    from .. import severity as _sev
    conf_sev = f.get("confirmed_severity")
    confidence = _sev.norm_confidence(f.get("confidence"), 0.0)
    if st.is_confirmed(f.get("status")) and conf_sev:
        band = norm_band(conf_sev)
        if band == "CRITICAL":
            return "P1"
        if band == "HIGH":
            return "P1" if confidence >= 0.8 else "P2"
        if band == "MEDIUM":
            return "P2" if confidence >= 0.8 else "P3"
        return "P3"
    # Unconfirmed: priority is to validate, never above P3.
    pot = norm_band(f.get("potential_severity"))
    return "P3" if pot in ("CRITICAL", "HIGH") else "P4"


def enrich_risk(f: Dict[str, Any]) -> Dict[str, Any]:
    """Populate the separated risk fields deterministically. Mutates and returns f."""
    status = st.normalize(f.get("status"))
    # potential vs confirmed severity are distinct.
    pot = norm_band(f.get("potential_severity") or f.get("severity"))
    f["potential_severity"] = pot
    if st.is_confirmed(status):
        f["confirmed_severity"] = norm_band(f.get("confirmed_severity") or f.get("severity"))
    else:
        f["confirmed_severity"] = None
    cvss = justified_cvss(f)
    f["cvss_score"] = cvss["score"]
    f["cvss_vector"] = cvss["vector"]
    f.setdefault("assumptions", [])
    f.setdefault("missing_validation_steps", [])
    f.setdefault("coverage_gaps", [])
    f.setdefault("evidence_refs", [])
    f["remediation_priority"] = remediation_priority(f)
    return f


# --------------------------------------------------------------------------- dual overall risk (§13)
def _band_rank(b: str) -> int:
    return BANDS.index(norm_band(b))


def overall_risk(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Two independent risk values (prompt §13).

    overall_confirmed_risk           : depends ONLY on unique CONFIRMED_STATIC/DYNAMIC findings.
    potential_risk_if_hypotheses_confirmed : worst-case across hypotheses/probables too.
    Also returns the per-bucket breakdown the report must show separately.
    """
    confirmed = [f for f in findings if st.is_confirmed(f.get("status"))]
    hypotheses = [f for f in findings
                  if st.normalize(f.get("status")) in (st.HYPOTHESIS, st.PROBABLE)]
    observations = [f for f in findings
                    if st.normalize(f.get("status")) in (st.OBSERVATION, st.INDICATOR)]

    def worst(bucket, field):
        best = "INFO"
        for f in bucket:
            b = norm_band(f.get(field) or f.get("severity"))
            if _band_rank(b) < _band_rank(best):
                best = b
        return best if bucket else "NONE"

    return {
        "overall_confirmed_risk": worst(confirmed, "confirmed_severity"),
        "potential_risk_if_hypotheses_confirmed": worst(confirmed + hypotheses, "potential_severity"),
        "counts": {
            "vulnerabilities_confirmed": len(confirmed),
            "hypotheses": len(hypotheses),
            "observations": len(observations),
        },
        "confirmed": confirmed,
        "hypotheses": hypotheses,
        "observations": observations,
    }
