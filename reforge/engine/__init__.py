"""ReTrace analysis engine (v61): evidence-gated, deduplicated, claim-verified vulnerability
analysis and reporting. See the module docstrings for the mapping to the specification sections.

The engine is deterministic and LLM-independent by default: the LLM can only enrich narrative
(stage F) and every enriched claim is verified (stage G) before the report is built (stage H).
"""
from . import (adapter, antifp, claims, crypto, dedup, evidence_gate, ghidra_strategy,
               llm_safety, pipeline, schema, secrets, status, tools)

__all__ = [
    "status", "schema", "dedup", "evidence_gate", "tools", "secrets", "crypto",
    "antifp", "claims", "llm_safety", "ghidra_strategy", "pipeline", "adapter",
]
