"""Write-time admission: the single door every finding comes through (slice P1-S1/S2/S3).

The canonical model in this package was only ever applied when a *report* was rendered
(`report_pt._engine_view`), over data that had been stored unvalidated. So the product's central
claim - evidence-first, nothing promoted without support - was enforced at rendering time, on
whatever had already been written. A finding could sit in the database for weeks carrying a
severity nothing justified, and look fine until someone exported it.

`admit()` moves that enforcement to the moment a finding is written:

    validate  ->  (LLM enrichment sanitised)  ->  evidence-gate + anti-FP + status cap
              ->  risk scoring  ->  provenance stamp

Three rules the rest of the code cannot opt out of:

1. **A structurally invalid record is rejected, not coerced.** Silently repairing a malformed
   finding is how an unsupported claim acquires a plausible shape.
2. **An LLM may only enrich prose.** Status, severity, CVSS, confidence and CWE come from
   deterministic logic; `llm_safety.sanitize_enrichment()` restores any of them the model touched,
   and the attempt is recorded on the finding rather than discarded.
3. **Every admitted finding carries its provenance**: schema version, origin, the tool and version
   that produced it, and the status originally declared versus the one the evidence allows.

See docs/adr/0002-canonical-finding-pipeline.md.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple

from . import adapter, llm_safety, status as st

#: Bumped when the stored shape changes in a way a reader must know about.
SCHEMA_VERSION = 1

#: Where a finding came from. `llm` is the only origin whose risk fields are not trusted.
ORIGIN_STATIC = "static_analysis"
ORIGIN_HEURISTIC = "heuristics"
ORIGIN_DYNAMIC = "dynamic_analysis"
ORIGIN_LLM = "llm"
ORIGIN_HUMAN = "human"
ORIGINS = {ORIGIN_STATIC, ORIGIN_HEURISTIC, ORIGIN_DYNAMIC, ORIGIN_LLM, ORIGIN_HUMAN}

_MAX_TITLE = 300
_MAX_TEXT = 20000
_VALID_BANDS = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


class FindingRejected(ValueError):
    """A candidate finding is structurally invalid and was not stored."""

    def __init__(self, reason: str, field: str = ""):
        super().__init__(reason)
        self.reason = reason
        self.field = field


def validate(candidate: Any) -> Dict[str, Any]:
    """Structural validation. Raises FindingRejected; never repairs.

    Deliberately narrow: this checks that the record is *a finding*, not that its content is
    correct. Correctness is the evidence gate's job, and conflating the two would let a
    well-formed but unsupported claim through on the strength of its shape.
    """
    if not isinstance(candidate, dict):
        raise FindingRejected(f"a finding must be an object, got {type(candidate).__name__}")

    title = str(candidate.get("title") or "").strip()
    if not title:
        raise FindingRejected("a finding must have a title", "title")
    if len(title) > _MAX_TITLE:
        raise FindingRejected(f"title exceeds {_MAX_TITLE} characters", "title")

    for field in ("description", "impact", "recommendation", "remediation"):
        value = candidate.get(field)
        if isinstance(value, str) and len(value) > _MAX_TEXT:
            raise FindingRejected(f"{field} exceeds {_MAX_TEXT} characters", field)

    for field in ("severity", "potential_severity", "confirmed_severity"):
        value = candidate.get(field)
        if value not in (None, "") and str(value).strip().upper() not in _VALID_BANDS:
            raise FindingRejected(
                f"{field}={value!r} is not one of {sorted(_VALID_BANDS)}", field)

    confidence = candidate.get("confidence")
    if confidence not in (None, ""):
        try:
            numeric = float(confidence)
        except (TypeError, ValueError):
            raise FindingRejected(f"confidence={confidence!r} is not a number", "confidence") from None
        if not 0.0 <= numeric <= 1.0:
            raise FindingRejected(f"confidence={numeric} is outside [0, 1]", "confidence")

    cwe = candidate.get("cwe")
    if cwe not in (None, "") and not str(cwe).upper().startswith("CWE-"):
        raise FindingRejected(f"cwe={cwe!r} must look like 'CWE-123'", "cwe")

    refs = candidate.get("evidence_refs")
    if refs is not None and not isinstance(refs, (list, tuple)):
        raise FindingRejected("evidence_refs must be a list", "evidence_refs")

    return dict(candidate)


def admit(candidate: Dict[str, Any], *, origin: str,
          prior: Optional[Dict[str, Any]] = None,
          binary_sha256: str = "",
          tool: str = "", tool_version: str = "") -> Tuple[Dict[str, Any], List[str]]:
    """Validate, sanitise, gate and stamp a finding. Returns (admitted, rejected_changes).

    `prior` is the existing finding being updated, if any. When `origin` is `llm`, only the
    descriptive fields of `candidate` are allowed to reach the stored record; every deterministic
    field is restored from `prior`, and what was blocked is returned *and* recorded on the finding
    so the attempt is visible rather than silently dropped.
    """
    if origin not in ORIGINS:
        raise FindingRejected(f"unknown origin {origin!r}; expected one of {sorted(ORIGINS)}",
                              "origin")

    merged = validate(candidate)
    rejected: List[str] = []

    if prior is not None:
        if origin == ORIGIN_LLM:
            merged, rejected = llm_safety.sanitize_enrichment(prior, merged)
        else:
            base = dict(prior)
            base.update({k: v for k, v in merged.items() if v not in (None, "", [], {})})
            if "evidence_bundle" not in candidate:
                # The prior's bundle was INFERRED from the prior's fields. After a merge those
                # fields have changed, so inheriting it would freeze the first assessment: new
                # runtime evidence could never promote a finding that started as a hypothesis,
                # because `adapter.infer_bundle` trusts any bundle already present. Drop it and
                # let it be re-derived from the merged record. An explicitly supplied bundle is
                # the caller's assertion and is kept.
                base.pop("evidence_bundle", None)
            merged = base

    declared = st.normalize(merged.get("status"))
    gated = adapter.normalize([merged], binary_sha256)
    if not gated:
        raise FindingRejected("the finding was eliminated by deduplication during admission")
    admitted = gated[0]

    admitted["schema_version"] = SCHEMA_VERSION
    admitted["origin"] = origin
    admitted["declared_status"] = declared
    admitted.setdefault("admitted_at", time.time())
    admitted["updated_at"] = time.time()
    if tool:
        admitted["produced_by_tool"] = tool
    if tool_version:
        admitted["produced_by_tool_version"] = tool_version
    if rejected:
        # Kept on the record: an operator reviewing a finding should be able to see that a model
        # tried to raise its severity and was stopped.
        history = list(admitted.get("blocked_enrichment") or [])
        history.extend(rejected)
        admitted["blocked_enrichment"] = history
    return admitted, rejected


def is_admitted(finding: Dict[str, Any]) -> bool:
    """True when a stored finding already carries the current admission stamp."""
    return finding.get("schema_version") == SCHEMA_VERSION and bool(finding.get("origin"))


def admit_legacy(finding: Dict[str, Any], *, binary_sha256: str = "") -> Dict[str, Any]:
    """Bring a finding stored before write-time admission up to the canonical shape.

    Used when loading an existing project. Best-effort by design: a legacy record that cannot be
    validated is returned untouched and flagged, because refusing to open an old project would be
    a worse failure than showing one unvalidated finding with a visible marker on it.
    """
    if is_admitted(finding):
        return finding
    try:
        admitted, _ = admit(finding, origin=finding.get("origin") or ORIGIN_HUMAN,
                            binary_sha256=binary_sha256)
        admitted["migrated_from_legacy"] = True
        return admitted
    except FindingRejected as exc:
        out = dict(finding)
        out["admission_error"] = str(exc)
        out["schema_version"] = 0
        return out
