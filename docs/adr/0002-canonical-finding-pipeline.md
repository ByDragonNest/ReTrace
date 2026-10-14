# ADR 0002 — One canonical pipeline; the schema is validated at write time

**Status:** accepted · **Date:** 2026-10-13 · **Closes:** P1-7, P1-8

## Context
Two finding models coexist: `reforge/findings.py` (the lattice the application uses) and
`reforge/engine/` (the canonical model). The canonical model runs only inside
`report_pt._engine_view()` at report-build time, and that function reassigns `session.findings`
in place. `engine/pipeline.py` — the documented A..H stage machine — has zero callers, as do
`engine.crypto`, `engine.secrets`, `engine.tools`, `engine.ghidra_strategy` and, critically,
`engine.llm_safety`, whose `sanitize_enrichment()` is the guard that stops a model from raising a
severity or changing a status.

The consequence is that the product's central claim — evidence-first, no unsupported promotion —
is enforced at rendering time over data that was stored unvalidated.

## Decision
1. `engine/pipeline.py` becomes the **only** path from candidate to stored finding. `add_finding`
   and every deterministic analyzer enter through it.
2. The canonical schema is **versioned** and validated on write. A record that fails validation is
   rejected, never silently coerced.
3. `engine/llm_safety.sanitize_enrichment()` is invoked on every LLM-touched finding, on every path.
4. Structured LLM output is schema-validated before use; a validation failure is an error, not a
   partial result. Best-effort scraping (`llm.salvage_tool_calls`) survives only as an explicitly
   labelled compatibility fallback for weak local models, and may never produce a finding.
5. `reforge/findings.py` becomes a thin read-side compatibility shim with a documented, versioned
   migration for existing projects.
6. Report generation becomes a pure read of validated data and stops mutating session state.

## Consequences
One place to test the invariants; one place to measure precision. Existing projects need a
migration. Report output may change where it previously depended on report-time normalization —
that difference must be captured as a benchmark delta, not assumed benign.

## Alternatives rejected
*Delete `engine/` and keep the legacy model* — discards the best-designed part of the codebase
(justified CVSS, separated severities, enrichment locking).
*Keep both and sync them* — two sources of truth is the defect being fixed.
