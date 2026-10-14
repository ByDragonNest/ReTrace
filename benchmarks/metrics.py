"""Finding identity and scoring for the benchmark harness.

A benchmark needs a stable answer to "is this the same finding?". CWE alone is too coarse - six
different missing mitigations all map to CWE-693 - and the full title is too brittle, since
rewording a sentence would look like a regression. The key is therefore the finding's
`vuln_type` plus the discriminating tail of its title, which is the part that names *which*
mitigation, library or algorithm was found.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Set

_SLUG = re.compile(r"[^a-z0-9]+")


def _slug(text: str) -> str:
    return _SLUG.sub("-", str(text or "").lower()).strip("-")


def finding_key(finding: Dict[str, Any]) -> str:
    """Stable identity, e.g. `hardening/dep-nx`, `weak_crypto/rc4`, `third_party/openssl-1-0-2k`."""
    vuln_type = _slug(finding.get("vuln_type") or finding.get("category") or "finding")
    title = str(finding.get("title") or "")
    # Drop a leading "<category>: " prefix so rewording the prefix is not a regression.
    tail = title.split(": ", 1)[1] if ": " in title else title
    return f"{vuln_type}/{_slug(tail)}"


@dataclass
class Score:
    """Confusion counts plus the identities behind them, so a failure is actionable."""
    true_positives: Set[str] = field(default_factory=set)
    false_positives: Set[str] = field(default_factory=set)
    false_negatives: Set[str] = field(default_factory=set)

    @property
    def precision(self) -> float:
        denom = len(self.true_positives) + len(self.false_positives)
        return len(self.true_positives) / denom if denom else 1.0

    @property
    def recall(self) -> float:
        denom = len(self.true_positives) + len(self.false_negatives)
        return len(self.true_positives) / denom if denom else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def merge(self, other: "Score") -> "Score":
        return Score(self.true_positives | other.true_positives,
                     self.false_positives | other.false_positives,
                     self.false_negatives | other.false_negatives)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "tp": len(self.true_positives), "fp": len(self.false_positives),
            "fn": len(self.false_negatives),
            "precision": round(self.precision, 4), "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "false_positives": sorted(self.false_positives),
            "false_negatives": sorted(self.false_negatives),
        }


def score(expected: Iterable[str], actual: Iterable[str]) -> Score:
    """Expected is EXHAUSTIVE: anything reported and not expected is a false positive.

    A benchmark that only checks "were the planted defects found" measures recall and calls it
    quality. The cost of a vulnerability-research tool is the noise, so the corpus declares the
    complete correct answer and everything else counts against precision.
    """
    exp, act = set(expected), set(actual)
    return Score(true_positives=exp & act, false_positives=act - exp, false_negatives=exp - act)


def percentile(values: List[float], pct: float) -> float:
    """Nearest-rank percentile: the smallest value at or above which `pct`% of the data falls.

    Spelled out rather than taken from a library because the definition must not drift. Several
    interpolation methods are in common use and they disagree by a whole rank on small samples -
    quietly switching between them would move a published p95 with no change to the product.
    """
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = math.ceil(pct / 100.0 * len(ordered))
    return ordered[max(1, min(len(ordered), rank)) - 1]


def evidence_completeness(findings: List[Dict[str, Any]]) -> float:
    """Share of findings that carry a source, an evidence type and a CWE.

    An unattributable finding cannot be defended to a customer, so this is tracked as a quality
    metric in its own right rather than folded into precision.
    """
    if not findings:
        return 1.0
    complete = sum(
        1 for f in findings
        if f.get("evidence_source") and f.get("evidence_type") and f.get("cwe")
    )
    return complete / len(findings)
