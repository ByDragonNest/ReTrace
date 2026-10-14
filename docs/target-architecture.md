# ReTrace — target architecture

ReTrace is a vulnerability-research workbench for **one analyst, or a small team sharing one
install**. That sentence is the architecture: it decides what gets built and, more usefully, what
does not.

Design constraints, in priority order:

1. **The single-workstation case must stay trivial.** One `pip install`, one command, SQLite, no
   broker, no container, no server to operate. An analyst with a laptop and no network is the
   primary user, not a degraded one.
2. **`team` is the same code with a harder posture, not a different product.** No fork, no parallel
   implementation, no capability that exists only in one profile. The difference is which defaults
   are forced, not which code runs.
3. **Deterministic evidence is the system of record.** The model is an orchestration and
   interpretation layer over it, never the source of a fact.

An earlier draft of this document described a control plane, an analysis plane, worker pools, a
durable queue and a PostgreSQL adapter set. That was written against a brief asking for an
enterprise platform. It is recorded here as **cut by product decision** rather than deleted, so the
reasoning survives: see [What was cut](#what-was-cut) and ADRs
[0004](adr/0004-worker-isolation.md) and [0005](adr/0005-persistence-profiles.md), both superseded.

## Profiles

Two, and the second exists only to stop a shared install from inheriting defaults that are
reasonable for one person on their own machine.

| | `workstation` | `team` |
|---|---|---|
| Who | one analyst, one machine | a few analysts, one shared install |
| Store | SQLite + filesystem | SQLite + filesystem |
| Jobs | in-process registry | in-process registry |
| Identity | the local operator, trusted by the loopback | OIDC bearer + RBAC, **loopback trust off** |
| Model egress | `frontier` (the analyst decides per call) | `hybrid`, forced — minimized, redacted context only |
| Unisolated dynamic execution | permitted, gated by approval | **refused** |
| Autonomous safety mode | selectable | forced down to `assisted` |
| Paths outside the workspace | selectable | refused |

`team` is not a scale setting: same store, same job registry, same code path. It is one branch,
`settings._harden_for_profile`, which forces six values and can only ever tighten them — and
because `validate_assignment` re-runs it, a field set afterwards cannot loosen the posture back.
If a team outgrows one SQLite file, the symptom is write contention on `projects`; that is the
signal to revisit, not a headcount.

## Shape

One process. The API, the SPA, the orchestrator, the MCP host and the analysis code all live in it.
There is no control plane and no analysis plane, because there is nothing to separate them across.

```
retrace serve
 └─ FastAPI ── SPA (static, English-only)
    ├─ identity + RBAC (route_policy: deny-by-default, 74 route/method pairs)
    ├─ session / project store ── SQLite (migrations, optimistic locking, retention)
    ├─ canonical pipeline ── engine/intake.admit() is the only write path for a finding
    ├─ MCP gateway ── manifest-declared risk, schema-validated in and out
    ├─ model gateway ── profile, classification, redaction, ledger, budget
    └─ execution ── Isolation.NONE | SUBPROCESS (CONTAINER/VM declared, not built)
```

### Isolation

Write-class and dynamic work runs through `reforge/execution.py`, which carries an explicit
isolation contract and quotas. `SUBPROCESS` is implemented and is the default for that class of
work, so limits bind the job rather than the whole application.

The honest answer to the rest is **the analyst's own RE VM**. Confirming a memory-corruption bug
means driving a program off its intended path with inputs built to corrupt it; a working proof of
concept is, by construction, attacker-shaped data executing on whatever machine ReTrace is running
on. ReTrace does not solve that with infrastructure at this scale — it tells you to run it on the
VM you already have next to x64dbg and Ghidra, and on a shared install it refuses unisolated
dynamic execution outright. See the superseded [ADR 0004](adr/0004-worker-isolation.md).

### MCP gateway

One control point for every tool call, replacing name-regex classification:

- **Versioned manifest per server** — name, version, tool schemas, declared risk class, output
  schema, output cap. Risk comes from the manifest, not from a regex over a name the server chose.
  The name heuristic survives as a **floor-raiser only**: a manifest can never declare a tool safer
  than its name suggests. See [ADR 0003](adr/0003-mcp-gateway.md).
- Deny-by-default allow-list; JSON-Schema validation of input **and** output; timeout, circuit
  breaker and output-size cap in the transport; distinct policy for read / sensitive-read /
  network / execute / write / patch; every call audited; tool name and version recorded into every
  piece of evidence.

### Model gateway

Provider-agnostic, policy-driven, measurable. Four operating profiles: `offline_deterministic`,
`local_only`, `hybrid` (minimized, redacted context only), `frontier`. Every outbound request is
classified by data class, redacted, recorded (what, to whom, which model, why) and budgeted. Model
names live in profiles, never in logic. All structured output is schema-validated and **fails
closed**. A shared install is forced to `hybrid`, which means a binary or a full decompilation
never leaves the machine.

## Canonical pipeline

One path from artifact to report; no parallel logic:

```
intake/fingerprint → format+arch+toolchain+protections → deterministic extraction
  → candidate generation → call graph / xref / source→sink → reachability + missing control
  → static (and when required dynamic) validation → Evidence Graph correlation
  → root-cause dedup → CWE/status/confidence/severity/priority → human review → report/export
```

`engine/intake.admit()` is the only way a finding is written — from the LLM, from a static
analyzer, or from an import — and it validates the canonical schema at write time rather than at
report time.

## Finding as the contract

A versioned, validated schema carrying: stable id · artefact/function/address/call-site/arch · CWE
and category · root cause · source, sink, data flow, missing control · status (`observation |
indicator | hypothesis | probable | confirmed-static | confirmed-dynamic | rejected |
accepted-risk`) · calibrated confidence · **separate** potential and confirmed severity · CVSS 3.1
with per-metric justification · evidence refs with tool names and versions · assumptions,
limitations, validation gaps · impact and remediation · author, reviewer, timestamps, history ·
suppression/risk-acceptance with reason and expiry.

(CVSS 4.0 is **not** implemented. `engine/schema.py` scores 3.1 only. Adding 4.0 is a contained
piece of work and is listed in the roadmap; this document does not claim it.)

Invariants, enforced in code and tested:
- No promotion on a string, an import, or a model response alone.
- No CVSS on a non-confirmed finding; an unjustified metric is dropped, never defaulted.
- HIGH/CRITICAL requires strong, reproducible evidence; dynamic confirmation when impact is not
  statically demonstrable. Exceptions are explicit and reviewed.
- No LLM output changes status, severity or CVSS without deterministic validation.

## Persistence

SQLite and the filesystem. One store, no adapter interface, because an interface with one
implementation is indirection rather than abstraction.

What is kept from the superseded persistence ADR, because it was about discipline and not about
scale, and all of it is implemented: versioned reversible migrations with a **mandatory**
pre-migration backup taken through SQLite's own backup API; optimistic locking on the row version,
so two people with the same project open cannot silently overwrite each other — which is the
concurrency problem a small team actually has; retention as soft-delete plus a separate deliberate
purge; pruned backups; documented restore.

## Observability and audit

Structured JSON logs with a correlation id, actor and project · counters and histograms with
service-level indicators · hash-chained append-only audit for approvals, policy changes, exports
and deletions (tamper-**evident**: it detects edits, it does not prevent them) · centralized
redaction · a support bundle that is scrubbed of identifiers before it is written.

Distributed tracing is not implemented and is not planned: there is one process to trace.

## Architecture decisions

| ADR | Decision | Status |
|---|---|---|
| [0001](adr/0001-config-and-secrets.md) | Typed layered configuration; the source tree is never written | accepted |
| [0002](adr/0002-canonical-finding-pipeline.md) | One canonical pipeline; schema validated at write time | accepted |
| [0003](adr/0003-mcp-gateway.md) | Manifest-declared capability replaces name-regex risk classification | accepted |
| [0004](adr/0004-worker-isolation.md) | VM/dedicated Windows workers for native dynamic tooling | **superseded** — run on the analyst's existing RE VM |
| [0005](adr/0005-persistence-profiles.md) | One repository interface, SQLite and PostgreSQL adapters | **superseded** — SQLite only |

## What was cut

Cut on 2026-10-13 by product decision ("a tool for a single analyst and small teams"). None of it
is a capability gap to apologise for; each is work that would have had no one to serve.

| Cut | Why |
|---|---|
| `enterprise` profile | It behaved identically to `team` — the hardening branch only ever asked "is this workstation?". A label implying a distinction the code did not make. |
| Control plane / analysis plane split | There is one process. Separating planes separates nothing. |
| Managed Windows worker fleet | Disproportionate to the risk at this scale. The analyst's existing RE VM closes most of it for the cost of a paragraph of documentation. |
| PostgreSQL adapter, object storage, durable queue, repository interface | They exist to support concurrent writers across nodes. This product has one node. |
| HA, autoscaling, multi-node, service accounts | Scale answers to a scale problem nobody has here. |
| Tamper-**proof** audit (external notarisation, WORM) | The hash chain already detects tampering by the one or few people who have the box. Proof requires a third party this product does not have. |
| Licensing and feature flags | A single-tenant install sold to one analyst or one team does not need enforcement machinery. |
| Alerting, SLO validation, on-call | The SLIs exist and are readable. There is no operations team to page. |
