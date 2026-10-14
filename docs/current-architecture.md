# ReTrace — current architecture (as built)

Snapshot date: 2026-10-13. Baseline commit: `89c721a`.
Everything below was read from the source tree; nothing is assumed from the README.

## 1. Process model

One Python process. `reforge/__main__.py` starts `uvicorn` on `config.HOST:config.PORT`
(default `127.0.0.1:8000`) serving the FastAPI app in `reforge/server.py`. The SPA in `web/`
is served by the same process. MCP servers are child processes spawned over stdio by
`reforge/mcp_host.py`. There is no worker process, no queue broker and no second tier.

```
browser (web/) ──HTTP + SSE──► uvicorn ─► FastAPI app (reforge/server.py, ~70 routes)
                                             │
      ┌──────────────────────┬───────────────┼────────────────┬───────────────────┐
  SessionStore            agent loop     approval gate     MCPHost            report
 (reforge/session.py)  (reforge/agent.py) (reforge/policy.py) (reforge/mcp_host.py) (reforge/report_pt.py)
      │                      │                                  │
  SQLite reforge.db     LLM adapters                    stdio child processes
  + projects/*.json    (reforge/llm.py)                 servers/*.py, GhidraMCP, x64dbg
      │                   │        │
 evidence_graph.py   Anthropic   OpenAI-compatible/Ollama
      │
  optional Neo4j mirror (reforge/neo4j_sync.py)
```

## 2. Components and responsibilities

| Layer | Module(s) | Responsibility | LOC |
|---|---|---|---|
| HTTP/API | `reforge/server.py` | ~70 unversioned `/api/...` routes, SSE stream, auth middleware, static SPA mount. Handlers also perform orchestration, persistence and Evidence-Graph projection. | 1311 |
| Agent loop | `reforge/agent.py` | Tool-spec generation, agentic loop, meta-tools (`add_finding`, `search_tools`, `attack_surface`, `exploitability`, …), per-vuln-class playbook text. | 1140 |
| LLM | `reforge/llm.py`, `reforge/llm_cost.py` | `BaseLLM` with `AnthropicLLM` and `LocalLLM` (OpenAI-compatible). Tolerant JSON/CLI "salvage" parsing of pseudo tool calls. Token accounting. | 472 + 57 |
| MCP host | `reforge/mcp_host.py`, `reforge/tool_registry.py` | Multi-server stdio/http/sse connections, namespaced `server__tool` catalog, per-call timeout, circuit breaker, output cap. | 257 |
| Policy | `reforge/policy.py` | Maps an unqualified tool name to a risk class (`safe_read`/`sensitive_read`/`dynamic_execution`/`write_or_patch`/`network`) and decides approval per `SAFETY_MODE`. | 160 |
| Auth | `reforge/auth.py` | One pure function: shared-token check with a loopback-trust bypass. | 28 |
| Analysis (deterministic) | `static_analysis.py`, `heuristics.py`, `sinks.py`, `source_to_sink.py`, `xref_enrich.py`, `string_signal.py`, `hardening.py`, `libs.py`, `cryptosec.py`, `bindiff.py` | Offline, LLM-free extraction and candidate generation. | ~2000 |
| Finding semantics | `reforge/findings.py` (legacy lattice), `reforge/engine/` (canonical v61 model) | **Two coexisting models.** See §4. | 112 + ~1100 |
| Evidence | `reforge/evidence.py`, `evidence_graph.py`, `graph_diff.py`, `neo4j_sync.py` | Per-project SQLite evidence graph, optional Neo4j mirror. | ~900 |
| Persistence | `reforge/db.py`, `reforge/session.py`, `reforge/config.py` paths | SQLite `reforge.db` + mirrored `projects/*.json`; sessions and jobs as files. | ~400 |
| Jobs | `reforge/job_manager.py`, `reforge/jobs.py` | In-process job registry persisted to `jobs/`. Restored at startup in `lifespan`. | ~300 |
| Reporting/export | `report_pt.py`, `report_docx.py`, `report_export.py`, `sbom_sarif.py`, `raw_export.py` | Deterministic report build, DOCX/PDF/HTML, SARIF, CycloneDX. | ~1400 |
| SPA | `web/app.js` (4272 LOC / 283 KB), `assessment.js`, `palette.js`, `styles.css` (141 KB), `index.html` | No build step, no framework, no bundler. 247 inline i18n keys. | 8186 |
| MCP servers | `servers/*.py` (22 files) | attack_surface, hardening, libs, crypto, bindiff, floss, tshark, procmon, reach(angr), fuzz, frida, driver, winsec, sbom, findings, x64dbg (2029 LOC). | ~7000 |

## 3. Data flow

1. **Intake** — `POST /api/projects/{pid}/upload` (binary) or `/artifacts` (Procmon XML, pcap, logs).
   `artifacts.store_stream` streams to `workspace/<pid>/<sanitized-name>`, computes SHA-256,
   detects type, builds a record. Small artifacts get an immediate offline overview
   (`artifact_overview.build_overview`) and heuristic pass (`heuristics.analyze`).
   The upload handler then **injects a synthetic `user` message into the session transcript** so
   the model learns the artifact id (`server.py:362`).
2. **Static triage** — `agent._ensure_static(session)` runs on target set, with or without an LLM.
3. **Agent turn** — `POST /api/message` → `agent` loop → `llm.run()` → tool calls →
   `policy.requires_approval()` → (optionally) an approval future resolved by `POST /api/approve`
   → `MCPHost.call()` → result truncated to `TOOL_RESULT_MAX_CHARS` and appended to history.
4. **Evidence** — tool results are recorded as evidence rows; Procmon summaries are projected into
   the Evidence Graph (`server._try_project_procmon_summary`).
5. **Findings** — written by the `add_finding` meta-tool (`agent.py:408`, `session.add_finding`)
   and by deterministic analyzers. Stored in the session in the **legacy** shape.
6. **Report** — `report_pt.build()` calls `_engine_view(session)`, which runs the canonical engine
   adapter over the stored findings and swaps `session.findings` for the normalized view while the
   body is rendered, restoring it in a `finally` (`report_pt.py:601-625`). Export to
   MD/DOCX/PDF/HTML/SARIF/CycloneDX.

## 4. The two finding models

- `reforge/findings.py` — lattice `observation | lead | hypothesis | needs_review |
  confirmed_static | confirmed_dynamic | rejected`, with a `_LEGACY` map that also accepts the
  engine's names (`indicator`, `probable`, `false_positive`).
- `reforge/engine/` — the documented canonical model: separated `potential_severity` /
  `confirmed_severity`, justified CVSS (`engine/schema.py:justified_cvss` refuses to invent a
  score when a metric is unjustified), evidence gating, anti-FP, dedup, claim verification.

Measured wiring (greps over `reforge/` and `tests/`, excluding `reforge/engine/` itself):

| engine module | external callers |
|---|---|
| `schema`, `dedup` | 2 each — both from `report_pt.py` |
| `adapter`, `claims`, `status` | 1 each — all from `report_pt.py` |
| `antifp`, `evidence_gate` | 0 direct; reached transitively via `adapter` |
| `pipeline`, `crypto`, `secrets`, `tools`, `ghidra_strategy`, `llm_safety` | **0** |

The A..H pipeline in `engine/pipeline.py` — the stage machine the docstrings present as the
mandatory analysis path — has **no caller anywhere in the product**. The canonical model is a
report-time projection, not the system of record.

> **Updated 2026-10-13 (slice P1-S1/S2/S3).** `engine/intake.py` now runs the canonical model at
> **write** time: `session.add_finding()` admits every finding through validation, the evidence
> gate, the anti-FP rules, the status cap and risk scoring, and `engine/llm_safety` is invoked on
> every LLM-originated update. Legacy projects are upgraded on load. `engine/pipeline.py`,
> `crypto`, `secrets`, `tools` and `ghidra_strategy` remain without callers — see the roadmap.

## 5. Trust boundaries

See `docs/data-flow-and-trust-boundaries.md`. Summary: the only enforced boundary is
`auth.authorize()` (shared token, bypassed for loopback) plus `policy.requires_approval()`
(disabled entirely in the shipped `SAFETY_MODE = "autonomous"`).

## 6. Configuration and state

- Configuration is **Python source**: `reforge/config.py`. `config.persist_to_file()` rewrites
  that file with regex substitutions at runtime; `_migrate_secrets_out_of_source()` rewrites it at
  import time.
- `REFORGE_STATE_DIR` redirects `reforge.db`, `projects/`, `sessions/`, `jobs/`, `workspace/`.
- It does **not** redirect `.reforge_secrets.json` (pinned to `ROOT`, `config.py:SECRETS_FILE`) or
  `knowledge/.reforge_index.json` (`knowledge.py:57`). Both are written into the source tree.

## 7. What is genuinely strong today

Not to be lost in any refactor:

- `engine/schema.py` — refuses to emit a CVSS score for a non-confirmed finding and drops
  unjustified metrics instead of falling back to a band default. This is the right behaviour and
  rare in this product category.
- `engine/llm_safety.py` — allow-list of LLM-touchable fields, locked deterministic fields.
- `policy.py` — risk classes carry a plain-language `consequence()` and a `risk_level()`, so an
  approval card can state what is being authorized rather than showing raw JSON.
- `mcp_host.py` — per-server circuit breaker, per-call timeout, output cap; one dead server does
  not take down the catalog.
- `assessment.py`, `report_pt.py` — deterministic, LLM-free report and dashboard.
- `conftest.py` — `REFORGE_STATE_DIR` isolation (incomplete, see §6, but the intent is right).
