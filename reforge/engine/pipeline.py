"""Mandatory analysis pipeline A..H (prompt §3).

The workflow is reorganized into eight ordered stages. Each stage is a pure(ish) function over an
`EngineContext`; the LLM narrative stage (F) can only ENRICH, and stage G (claim verification)
strips anything unsupported before the report is built (H).

    A. Evidence collection
    B. Candidate generation
    C. Static / dynamic validation
    D. Deduplication and root-cause grouping
    E. Risk scoring
    F. LLM narrative enrichment (optional, additive)
    G. Claim verification
    H. Report generation
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from . import (antifp, claims, dedup, evidence_gate, llm_safety, schema,
               status as st, tools)


@dataclass
class EngineContext:
    binary_sha256: str = ""
    toolchain: str = "unknown"
    raw_tokens: List[str] = field(default_factory=list)     # extracted strings
    candidates: List[Dict[str, Any]] = field(default_factory=list)  # proposed findings
    ledger: tools.ToolLedger = field(default_factory=tools.ToolLedger)
    known_evidence: set = field(default_factory=set)
    # populated as the pipeline runs:
    findings: List[Dict[str, Any]] = field(default_factory=list)
    risk: Dict[str, Any] = field(default_factory=dict)
    report: Dict[str, Any] = field(default_factory=dict)


# --------------------------------------------------------------------------- stages
def stage_a_evidence(ctx: EngineContext) -> EngineContext:
    """Collect/normalize evidence. Candidate evidence arrives from the caller's analyzers; there is
    no indicator-of-compromise extraction here — ReTrace reports vulnerabilities, not indicators."""
    return ctx


def stage_b_candidates(ctx: EngineContext) -> EngineContext:
    """Candidate generation is the caller's job (crypto.classify, secrets.classify_secret, sink
    inventory, libs fingerprint, ...). Here we simply adopt whatever candidates were provided and
    ensure each has an evidence bundle."""
    for f in ctx.candidates:
        f.setdefault("evidence_bundle", {})
    ctx.findings = list(ctx.candidates)
    return ctx


def stage_c_validation(ctx: EngineContext) -> EngineContext:
    """Static/dynamic validation: gate source->sink evidence, apply anti-FP rules, cap status."""
    for f in ctx.findings:
        if f.get("source_to_sink"):
            evidence_gate.gate_finding(f)
        antifp.apply_rules(f)
        # dynamic claims require a clean dynamic run.
        if f.get("evidence_bundle", {}).get("runtime_observed") and not ctx.ledger.dynamic_ran_cleanly():
            f["evidence_bundle"]["runtime_observed"] = False
            cg = list(f.get("coverage_gaps") or [])
            cg.append("dynamic confirmation claimed but no clean x64dbg/procmon observation")
            f["coverage_gaps"] = cg
        st.apply(f, f.get("status"))
    return ctx


def stage_d_dedup(ctx: EngineContext) -> EngineContext:
    ctx.findings = dedup.deduplicate(ctx.findings, ctx.binary_sha256)
    return ctx


def stage_e_risk(ctx: EngineContext) -> EngineContext:
    for f in ctx.findings:
        f.setdefault("confidence", _base_confidence(f))
        schema.enrich_risk(f)
    ctx.ledger.apply_penalties(ctx.findings)
    ctx.risk = schema.overall_risk(ctx.findings)
    return ctx


def stage_f_enrichment(ctx: EngineContext, enrich_fn: Optional[Callable] = None) -> EngineContext:
    """Optional LLM narrative. `enrich_fn(finding)->dict` returns proposed descriptive changes; we
    sanitize them so locked fields never move."""
    if not enrich_fn:
        for f in ctx.findings:
            llm_safety.enforce_conditional_language(f)
        return ctx
    for f in ctx.findings:
        try:
            proposed = enrich_fn(f) or {}
        except Exception:
            proposed = {}
        safe, rejected = llm_safety.sanitize_enrichment(f, proposed)
        safe["_enrichment_rejected"] = rejected
        f.clear()
        f.update(safe)
        llm_safety.enforce_conditional_language(f)
    return ctx


def stage_g_claim_review(ctx: EngineContext) -> EngineContext:
    """Verify every narrative claim; strip UNSUPPORTED sentences."""
    for f in ctx.findings:
        for key in ("description", "impact", "narrative"):
            if f.get(key):
                rev = claims.review(str(f[key]), ctx.known_evidence)
                f[key] = rev["clean_text"]
                if rev["removed"]:
                    f.setdefault("removed_claims", []).extend(rev["removed"])
    return ctx


def stage_h_report(ctx: EngineContext) -> EngineContext:
    """Assemble the report model: confirmed vs hypotheses vs observations, dual risk, tool coverage,
    limitations. Counts use UNIQUE findings only."""
    ctx.report = {
        "overall_confirmed_risk": ctx.risk.get("overall_confirmed_risk"),
        "potential_risk_if_hypotheses_confirmed": ctx.risk.get("potential_risk_if_hypotheses_confirmed"),
        "counts": {
            **ctx.risk.get("counts", {}),
            "unique_findings": dedup.unique_count(ctx.findings),
        },
        "vulnerabilities_confirmed": ctx.risk.get("confirmed", []),
        "hypotheses": ctx.risk.get("hypotheses", []),
        "observations": ctx.risk.get("observations", []),
        "tool_coverage": ctx.ledger.summary(),
        "limitations": ctx.ledger.limitations(),
    }
    return ctx


def _base_confidence(f: Dict[str, Any]) -> float:
    """A modest status-anchored confidence; tool penalties are applied afterwards."""
    anchor = {st.CONFIRMED_DYNAMIC: 0.9, st.CONFIRMED_STATIC: 0.75, st.PROBABLE: 0.55,
              st.HYPOTHESIS: 0.35, st.INDICATOR: 0.2, st.OBSERVATION: 0.2, st.REJECTED: 0.0}
    return anchor.get(st.normalize(f.get("status")), 0.3)


STAGES = [stage_a_evidence, stage_b_candidates, stage_c_validation, stage_d_dedup,
          stage_e_risk, stage_g_claim_review, stage_h_report]  # F is inserted when enrich_fn given


def run(ctx: EngineContext, enrich_fn: Optional[Callable] = None) -> EngineContext:
    """Run the full A..H pipeline. Deterministic without `enrich_fn`."""
    stage_a_evidence(ctx)
    stage_b_candidates(ctx)
    stage_c_validation(ctx)
    stage_d_dedup(ctx)
    stage_e_risk(ctx)
    stage_f_enrichment(ctx, enrich_fn)
    stage_g_claim_review(ctx)
    stage_h_report(ctx)
    return ctx
