# ADR 0003 — Manifest-declared capability replaces name-regex risk classification

**Status:** accepted · **Date:** 2026-10-13 · **Closes:** T-4, part of P0-4

## Context
`policy.risk_class()` classifies a tool by applying regexes to the **unqualified tool name**, a
string the MCP server itself chooses. A server exposing a destructive operation named
`analyze_report` is classified `safe_read` and, in `assisted` mode, executes without approval. The
catalogue is deny-by-exception: any tool any connected server offers is callable.

`mcp_host.py` already provides the right transport controls — connect timeout, per-call timeout,
per-server circuit breaker, output cap — which should be kept.

## Decision
Every server ships a **versioned manifest**: name, version, author, tool schemas, declared
capability, risk class, cost and prerequisites. The gateway then:
- resolves risk from the **manifest**, not from the tool name; name-regex classification remains
  only as a fallback that forces the **highest** risk class when no manifest exists, never the
  lowest;
- enforces a **deny-by-default allow-list** of servers and tools;
- validates input and output against the declared JSON Schema;
- authenticates server identity and the channel (mTLS for remote);
- applies timeout, cancellation, idempotent-only retry, circuit breaker and quotas;
- isolates crashes, caps and sanitizes output;
- applies distinct policy for read / sensitive-read / network / execute / write / patch /
  memory-write;
- audits every call and supports controlled replay;
- records the **tool name and version into every piece of evidence** the call produces.

## Consequences
A trustworthy gate, and reproducible evidence (T-11). Cost: every bundled server needs a manifest,
and third-party servers without one are treated as high-risk — deliberately, so that adding an
unknown server cannot silently widen the blast radius.
