# ReTrace — observability, audit and service levels

Three streams, deliberately separate. Mixing them is how an audit trail becomes something you have
to redact before you can hand it over, and how an operational log becomes something you cannot
send to support.

| stream | what it answers | where | tamper-evident |
|---|---|---|---|
| **Operational logs** | what the system is doing | stdout / collector | no |
| **Audit trail** | who did what, and what was refused | `$REFORGE_STATE_DIR/audit/audit.jsonl` | yes, hash-chained |
| **Egress ledger** | what left this machine, to whom, why | the audit trail, `llm.egress*` | yes |

**Customer content belongs in none of them.** Findings, evidence, decompiled code and extracted
strings live in the Evidence Graph. `observability.scrub()` removes what a pattern can find —
symbol names, hex dumps — on the way into a log; project names, which no pattern can find, are
removed by name when a support bundle is built.

## Correlation

Every request gets an `X-Correlation-Id`, generated if the client did not supply one and returned
on the response. It is carried in a `contextvars` so it reaches every log line from every module
without being threaded through a hundred signatures, and it appears in `correlation_id` on each
structured record. A user reporting a problem can quote it.

Set `log_format = "json"` for one structured object per line with the correlation id, actor and
project — what a collector needs. The default stays `text`, which is what a terminal needs.

## Metrics

`GET /api/metrics` returns JSON; `GET /api/metrics?fmt=prometheus` returns the text exposition
format. In-process on purpose: a workstation install must not need a metrics backend to be
observable, and the same numbers scrape into one when there is a fleet.

| metric | type | labels |
|---|---|---|
| `retrace_http_requests_total` | counter | `route`, `method`, `status` |
| `retrace_http_request_seconds` | summary | `route` |
| `retrace_uptime_seconds` | gauge | — |

Histograms keep a bounded reservoir (2048 samples): unbounded retention in a long-running process
is a leak. Percentiles are nearest-rank, the same definition the benchmark harness uses.

## Service level indicators

Computed from live counters by `GET /api/metrics`. **An SLI with no traffic behind it reports
`null`, not a flattering default** — an availability of 100% derived from zero requests is a
number that reads like one that means something.

| SLI | definition |
|---|---|
| API availability | 1 − (5xx responses ÷ all responses) |
| API latency | p95 of `retrace_http_request_seconds` |
| Job success rate | 1 − (failed jobs ÷ finished jobs) |
| Tool call success rate | successful MCP calls ÷ all MCP calls |

### Proposed objectives — not yet measured against production

These are **targets to validate**, not claims. No deployment has run long enough to say whether
they are achievable, and publishing an SLO nobody has measured is how an SLO becomes decoration.

| objective | proposed target | window |
|---|---|---|
| API availability | ≥ 99.5% | 30 days |
| API latency p95 (non-analysis routes) | ≤ 500 ms | 30 days |
| Job success rate | ≥ 98% excluding operator cancellation | 30 days |
| Durability of findings and evidence | no loss on clean shutdown or crash | always |

Analysis routes are excluded from the latency objective: a Ghidra decompilation takes as long as
it takes, and an objective that punishes correct behaviour trains people to game it.

## Support bundle

`GET /api/support-bundle` (requires `audit:read`) produces a zip meant to be **sendable without
review**:

- versions and the dependency set — half of all problems are a version
- the resolved security posture
- configuration, with every credential masked (the bundle says a key *exists*, never its value)
- the MCP server catalogue and manifest state — names only, never command lines, because a
  command line carries a sample path and a sample path carries a customer name
- metrics and SLIs
- the audit chain's integrity verdict and counts — never the entries, which name projects
- recent operational log lines, scrubbed twice: patterns first, then project names by name

What it never contains: samples, findings, evidence, decompiled code, strings, project names, or
any credential. If something in it should not leave your organisation, that is a bug.

## What is not built

- **Distributed tracing.** Correlation ids tie a request's own log lines together; they do not
  propagate across process boundaries to an MCP server, and there is no span model. Not planned:
  ReTrace is one process, and tracing earns its cost across many. See
  [Out of scope](ROADMAP.md#out-of-scope).
- **Dashboards and alerting.** The metrics are exposed in a format a backend can scrape; nothing
  here defines alert rules, and a rule nobody has tuned against real traffic is noise.
- **Log shipping.** Structured output exists; delivery to a collector is deployment configuration.
- **Tamper-proof audit.** The chain is tamper-*evident*: someone with write access can rewrite the
  file and recompute it. An external witness — a WORM store or a remote collector — is what makes
  it proof, and it is not built.
