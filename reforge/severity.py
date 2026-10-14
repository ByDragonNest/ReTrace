"""Centralized severity / CVSS / confidence normalization (single source of truth).

WHY THIS EXISTS
---------------
LLMs, NVD responses and user input put heterogeneous values into severity/confidence/score
fields: floats (0.8), ints (80), percentages ("80%"), and assorted labels
("critical", "high", and the Italian "alta"/"media" a model occasionally returns). Accepting
those on INPUT is not bilingualism - every value this module *returns* is a canonical English
band, and that is what reaches the report. Report generation and SBOM/SARIF export used to call
float()/int() on those values directly, producing crashes such as:

    ValueError: could not convert string to float: high

This module is the *one place* (prompt §8: "Applica la normalizzazione in un punto unico")
that converts any of those shapes into:

  * a canonical severity band:        norm_severity()  -> "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"|"INFO"
  * a numeric CVSS-like score [0,10]: cvss_score()     -> float, never raises
  * a confidence in [0,1]:            norm_confidence()-> float, never raises

Every conversion is total: unknown/None/garbage inputs return a safe default instead of raising.
"""
from __future__ import annotations

from typing import Any, Optional

# Canonical bands, ordered most→least severe (index doubles as a sort key).
BANDS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_ORDER = {b: i for i, b in enumerate(BANDS)}

# Label aliases (EN + IT + common short forms) -> canonical band.
_SEV_LABELS = {
    "critical": "CRITICAL", "critica": "CRITICAL", "critico": "CRITICAL", "crit": "CRITICAL",
    "high": "HIGH", "alta": "HIGH", "alto": "HIGH", "elevata": "HIGH", "elevato": "HIGH",
    "medium": "MEDIUM", "media": "MEDIUM", "medio": "MEDIUM", "med": "MEDIUM", "moderate": "MEDIUM",
    "low": "LOW", "bassa": "LOW", "basso": "LOW",
    "info": "INFO", "informational": "INFO", "informativa": "INFO", "none": "INFO",
    "unknown": "INFO", "n/a": "INFO", "na": "INFO",
}

# Lower bound of each CVSS v3.1 qualitative band. These are the *floor* of a range, NOT a
# representative/invented score. They are only ever used when a caller explicitly opts in
# (allow_band_default=True); the report no longer invents 8.0/5.5/3.0 for un-scored findings
# (prompt §2: "Non usare score predefiniti 8.0, 5.5 e 3.0").
_BAND_FLOOR = {"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 4.0, "LOW": 0.1, "INFO": 0.0}

# Confidence anchor per band (when a confidence field carries a severity-like label).
_BAND_TO_CONF = {"CRITICAL": 0.95, "HIGH": 0.80, "MEDIUM": 0.55, "LOW": 0.30, "INFO": 0.15}


def _to_float(v: Any) -> Optional[float]:
    """Best-effort float parse for numbers, "0.8", "80%", "8,1". Returns None on failure."""
    if v is None or v == "":
        return None
    if isinstance(v, bool):  # avoid True->1.0 surprises
        return None
    if isinstance(v, (int, float)):
        return float(v)
    t = str(v).strip().lower().replace(",", ".")
    pct = t.endswith("%")
    if pct:
        t = t[:-1].strip()
    try:
        x = float(t)
    except (TypeError, ValueError):
        return None
    return x / 100.0 if pct else x


def norm_severity(v: Any, default: str = "INFO") -> str:
    """Map any severity expression to a canonical band string.

    Accepts labels ("high", "alta"), numeric CVSS scores (8.1, "8.1"), and CVSS bands from NVD.
    Numbers are bucketed with standard CVSS v3 thresholds.
    """
    if v is None or v == "":
        return default
    if isinstance(v, str):
        t = v.strip().lower()
        if t in _SEV_LABELS:
            return _SEV_LABELS[t]
    f = _to_float(v)
    if f is not None:
        # Treat 0..1 as a fraction of 10 (some callers store normalized scores).
        score = f * 10.0 if 0.0 < f <= 1.0 else f
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0.0:
            return "LOW"
        return "INFO"
    return default


def severity_rank(v: Any) -> int:
    """Sortable rank: 0 (CRITICAL) .. 4 (INFO). Unknown -> 5 (after INFO)."""
    return _ORDER.get(norm_severity(v, default="INFO"), 5)


def cvss_score(v: Any, severity: Any = None, default: float = 0.0,
               allow_band_default: bool = False) -> float:
    """Return a numeric CVSS-like score in [0,10]. Never raises.

    Priority: explicit numeric/percent value -> (only if allow_band_default) the band floor
    -> default. With allow_band_default=False (the default) a bare severity label yields `default`
    instead of an invented representative score, so hypotheses are never shown a fabricated CVSS.
    """
    f = _to_float(v)
    if f is not None:
        score = f * 10.0 if 0.0 < f <= 1.0 else f
        return round(max(0.0, min(10.0, score)), 1)
    if not allow_band_default:
        return default
    # v may itself be a label, or fall back to the severity argument.
    band = norm_severity(v if (isinstance(v, str) and v.strip()) else severity, default="")
    if band:
        return _BAND_FLOOR[band]
    return default


def norm_confidence(v: Any, default: float = 0.0) -> float:
    """Return confidence in [0,1] from float/int/percent/label. Never raises."""
    if v is None or v == "":
        return default
    if isinstance(v, str):
        t = v.strip().lower()
        if t in _SEV_LABELS:
            return _BAND_TO_CONF[_SEV_LABELS[t]]
    f = _to_float(v)
    if f is None:
        return default
    if f > 1.0:                       # 80 / "80%" already divided by _to_float
        f = f / 100.0 if f <= 100.0 else 1.0
    return round(max(0.0, min(1.0, f)), 2)


def confidence_pct(v: Any, default: float = 0.0) -> int:
    """Confidence as an integer percentage 0..100. Never raises."""
    return int(round(norm_confidence(v, default) * 100))
