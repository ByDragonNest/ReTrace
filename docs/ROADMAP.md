# ReTrace — roadmap

Baseline commit `89c721a` · last updated 2026-10-13.
Gap IDs refer to `docs/gap-analysis.md`. A phase is not complete until every acceptance criterion
in it is demonstrated by an automated test or a recorded measurement.

Status key: ☐ not started · ◐ in progress · ☑ done and verified · ✂ **out of scope**

**Scope, decided 2026-10-13:** ReTrace is a tool for **a single analyst and small teams**. Work
that only pays off at enterprise scale is marked ✂ and kept in the table with its reason, not
deleted — a backlog that silently loses rows stops being a record of what was decided. Nothing
marked ✂ is a defect or a gap; each is work that would have had no one to serve. The summary is at
the end, under [Out of scope](#out-of-scope).

---

## Phase P0 — make the base safe and reproducible

*Goal: a clean checkout installs, starts, tests reproducibly, writes nothing into its own source,
and defaults to a closed posture.*

| # | Slice | Gaps | Status |
|---|---|---|---|
| P0-S1 | Packaging, declared dependencies, state/secret isolation, EOL normalization, minimal CI | P0-1, P0-2, P3-16 | ☑ |
| P0-S2 | Fail-closed defaults + typed configuration facade | P0-3, P0-4 | ☑ |
| P0-S3 | Upload limits, magic-byte gating, quarantine, archive safety | P0-5, T-2 | ☑ |
| P0-S4 | Sanitized release artifact + secret rotation executed | P0-6 | ☑ build+verify script, enforced in CI; rotation remains the operator's action |
| P0-S5 | Route/error-model audit, uniform error contract, `/api/v1` prefix with a compatibility alias | P2-13 (partial) | ☑ |
| P0-S6 | Benchmark + profiling baseline on synthetic fixtures | P1-9 (baseline only) | ☑ |
| P0-S7 | Workstation installation documentation rewritten against the real install path | P0-1 | ☑ |

**Acceptance for P0**
- `pip install .` + one documented command starts the API and serves the SPA from a clean checkout.
- A test asserts the source tree is byte-identical before and after the full suite plus an app import.
- Shipped defaults are `assisted`, workspace-confined, no loopback trust when a token exists; a test asserts them.
- Uploads are bounded; oversized, zero-byte, corrupt-archive and traversal-filename cases are tested.
- The release artifact contains no `.git`, database, WAL/SHM, `projects/`, `workspace/`, `sessions/`, `jobs/`, cache, sample or secrets file — asserted against an allow-list.
- CI runs install-from-clean, lint, type check and the full suite on every push.
- A benchmark baseline exists and is reproducible.

## Phase P1 — correctness and precision

| # | Slice | Gaps | Status |
|---|---|---|---|
| P1-S1 | Canonical versioned finding schema, validated at write time | P1-7 | ☑ |
| P1-S2 | Single candidate→finding choke point (`engine/intake`); legacy projects migrated on load | P1-7 | ☑ (see note) |
| P1-S3 | `llm_safety.sanitize_enrichment()` invoked on every LLM-touched finding | P1-7, T-8 | ☑ |
| P1-S4 | Schema-validated structured LLM output, fail-closed; versioned prompts; cache keyed on model+prompt version | P1-8 | ☑ |
| P1-S5 | Source→sink and reachability hardening; argument-level sink checks; safe-wrapper recognition | §7.2 | ☑ |
| P1-S6 | False-positive and regression benchmark with published numbers | P1-9 | ☑ |
| P1-S7 | Reports with per-metric justified severity/CVSS; evidence and prompt versioning | T-11 | ☑ |
| P1-S8 | Confinement by default; allow-list of external roots replaces the deny-list | P1-12 | ☑ |
| P1-S9 | Origin validation, opt-in CORS, rate limiting (cookie hardening and `?token=` removal done in P0-S2) | P1-10 (partial), T-5 | ☑ |

**Acceptance for P1**
- No finding is stored without passing canonical schema validation.
- No LLM output can change status, severity or CVSS without deterministic validation — tested adversarially.
- Published precision / recall / F1 / FP-rate per CWE against the fixture corpus, comparable across releases.
- Every exported finding carries provenance, evidence refs and a coherent status.
- Identical artifact + tool versions + configuration produce identical results.

## Phase P2 — shared installs

| # | Slice | Gaps | Status |
|---|---|---|---|
| P2-S1 | Identity, OIDC, RBAC, project isolation | P1-10 | ☑ (bearer; interactive login flow deferred) |
| P2-S2 | Isolation contract, ephemeral workspaces, quotas, subprocess target | P2-15, T-3 | ☑ |
| ~~P2-S2b~~ | ~~Durable queue and managed worker fleet~~ | T-3 | ✂ ADR 0004 superseded — run on the analyst's existing RE VM |
| P2-S3 | MCP gateway: manifests, allow-list, schema validation, server identity | ADR 0003, T-4 | ◐ manifests, allow-list, fail-closed risk, provenance, **argument validation**; channel auth and output validation open |
| P2-S4 | Model gateway: four operating profiles, classification, redaction, egress ledger, budgets | §9.1, T-10 | ◐ profiles, classification, redaction, ledger, **budgets**; routing open |
| P2-S5 | Versioned migrations with mandatory backup, rollback, optimistic locking, retention | ADR 0005 | ☑ |
| ~~P2-S5b~~ | ~~PostgreSQL + object storage adapters behind a repository interface~~ | ADR 0005 | ✂ ADR 0005 superseded — SQLite only; one node has one writer |
| P2-S6 | Hash-chained audit, correlation ids, structured logs, metrics, four SLIs, support bundle | §12 | ☑ |
| ~~P2-S6b~~ | ~~Distributed tracing, alerting, SLO validation against real traffic~~ | §12 | ✂ one process to trace, no operations team to page |
| P2-S7 | On-premise and air-gapped deployment, offline bundle | §16.14 | ◐ offline bundle, built and verified with the index disabled; **network-level egress enforcement open** |
| P2-S8 | Monolith decomposition: routers, domain layer, SPA modularization | P2-13 | ◐ authorization **and ownership** enforced centrally; decomposition itself not started |
| P2-S9 | Server-tree consolidation (`servers/` vs untracked `mcp_servers/`) | P2-14 | ☑ |
| P2-S10 | English-only UI, enforced by test; accessibility basics (landmarks, labels, focus, contrast) | P3-17, §13 | ☑ |
| ~~P2-S10b~~ | ~~Italian localization~~ | §13 | ✂ product decision 2026-10-13: the app is English-only |
| P2-S10c | Formal WCAG 2.1 AA audit | §13 | ☐ needed only to sell into public administration (EN 301 549); see the note under Out of scope |

**Acceptance for P2**
- A shared install cannot be reached without a bearer token: `auth_trust_localhost` is forced off
  and a test asserts it cannot be set back on.
- Every route is authorized from one declarative table; a route added without an entry is refused,
  and a test asserts the table covers the registered routes.
- A tool call's risk comes from the server's manifest; an undeclared tool is refused. A name that
  suggests danger can raise the floor but never lower it.
- No binary and no full decompilation leaves the machine on a shared install — the model profile is
  forced to `hybrid` and the egress ledger records every outbound request.
- A schema change has a forward migration, a reverse, and a backup taken before either runs.
- Two analysts saving the same project cannot silently overwrite one another.
- The offline bundle installs with the package index disabled and the app starts with no network.

## Phase P3 — what is left that this product actually wants

| # | Slice | Status |
|---|---|---|
| P3-S1 | CVSS 4.0 alongside 3.1, same per-metric justification rule | ☐ |
| P3-S2 | Ticketing and CI/CD export (Jira, GitHub issues, SARIF) | ☐ |
| P3-S3 | Customizable policy packs — a team's own sink list, severity floors and approval rules | ☐ |
| P3-S4 | Update channel and signed releases | ☐ |
| ~~P3-S5~~ | ~~Multi-node, autoscaling, worker pools, service accounts~~ | ✂ scale answers to a scale problem nobody here has |
| ~~P3-S6~~ | ~~Licensing and feature flags~~ | ✂ a single-tenant install does not need enforcement machinery |
| ~~P3-S7~~ | ~~Opt-in product analytics~~ | ✂ an analyst running this on an RE VM is not a telemetry source |

---

## Out of scope

Decided 2026-10-13: **ReTrace is a tool for a single analyst and small teams.** These rows are kept
so the decision is legible later. None is a defect, and none is a capability the product is
missing — each is work with nobody to serve at this scale.

| Cut | Was | Why it is not built |
|---|---|---|
| `enterprise` deployment profile | a third profile beside `workstation` and `team` | It behaved **identically** to `team`: the hardening branch only ever asked "is this workstation?". A label implying a distinction the code did not make. |
| Managed Windows worker fleet (P2-S2b) | the answer to threat T-3 | Disproportionate at this scale. The analyst's existing RE VM closes most of the exposure for the cost of a paragraph of documentation, and a shared install already refuses unisolated dynamic execution. [ADR 0004](adr/0004-worker-isolation.md), superseded. |
| PostgreSQL, object storage, durable queue, repository interface (P2-S5b) | the `enterprise` persistence profile | They exist to support concurrent writers across nodes; this product has one node. An interface with one implementation is indirection, not abstraction. [ADR 0005](adr/0005-persistence-profiles.md), superseded. |
| Distributed tracing, alerting, SLO validation (P2-S6b) | §12 | There is one process to trace, and no operations team to page. The SLIs exist and are readable. |
| Tamper-**proof** audit | WORM store / external notarisation | The hash chain already detects tampering by the one or few people who have the box. Proof needs a third party this product does not have. The audit is documented as tamper-*evident* and the distinction is stated, not blurred. |
| Multi-node, autoscaling, service accounts (P3-S5) | Phase P3 | Scale answers to a scale problem nobody here has. |
| Licensing and feature flags (P3-S6) | Phase P3 | A single-tenant install sold to one analyst or one team does not need enforcement machinery. |
| Product analytics (P3-S7) | Phase P3 | An analyst running this on an isolated RE VM is not a telemetry source, and asking to be one costs more trust than the data is worth. |
| Italian localization (P2-S10b) | §13 | Product decision: the app is English-only. The bilingual machinery was built and then removed; `tests/test_localization_a11y.py` now enforces English as a contract. |

**WCAG 2.1 AA (P2-S10c) is left open rather than cut**, because whether it matters is a sales
question and not an engineering one. It is a legal requirement for selling into public
administration in the EU (EN 301 549) and is increasingly asked for in large-enterprise
procurement. For a tool bought by individual analysts and small teams it is not, and what is
already implemented — landmarks, labelled controls, visible focus, keyboard reachability, contrast
— covers the practical ground. A real audit needs assistive technology and a human using it; it
cannot be asserted in a test, and this roadmap does not pretend otherwise.

---

## Changelog

### 2026-10-14 — Only what runs is tracked

The repository was re-created from a folder that no longer held `.gitignore`, `.gitattributes`
or `.github/`, and a single `git add -A` published the project database, a project, a workspace
holding an analysed executable and its graph, the audit chain, the knowledge index cache,
bytecode, the egg-info build output and the operator's catalogue. The three control files are
restored, and the rules now describe kinds rather than names: whole state directories
(`projects/`, `sessions/`, `jobs/`, `workspace/`, `uploads/`, `audit/`, `cache/`), every database
and backup, every analysed-sample extension (`*.exe`, `*.dll`, `*.sys`, `*.bin`, `*.sqlite`,
archives, captures), the operator's `mcp.servers.json` (the shipped template is
`reforge/mcp.servers.default.json`, and the app falls back to it), and everything in
`knowledge/` except the shipped methodology. The `.gitkeep` placeholders are gone: the app creates
its directories itself at start-up. 128 tracked files left the index; 209 remain, all source,
tests, docs and packaging metadata.

Two guards, so this is the last time: the CI hygiene rule and its local test now match the same
scope, and a new test asks `git check-ignore` for one path of each kind that must never be
committed (and for the shipped files that must stay), so a missing or weakened ignore file fails
the suite rather than the next push. The clean history is on the local branch `clean-main`;
moving `main` onto it is the owner's step.

### 2026-10-14 — General review: leftovers, bugs and three optimisations

A pass over the whole tree, requested as "check everything, fix bugs and leftovers, optimise".

**Leftover Italian, round two.** The English-only guard scanned string literals against a curated
word list, and the list was what someone remembered. Two wider detectors - an AST walk over every
string constant and docstring with ~250 Italian words, plus a morphology check on strings that
contain no English function word - found ~130 more: section titles and verdict lines in ten MCP
servers (`reach`, `winsec`, `driver`, `fuzz`, `procmon`, `findings`, `attack_surface`, `sbom`,
`floss`, `frida`), the `…(troncato)` truncation marker in all of them, the artifact-overview
headlines, the phase block the agent injects into every local-model step (`[Fase 3/8 … Prossimo:
…]`), the `list_artifacts` result, eight labels in the SPA (graph tables, the phase pop-over, the
report placeholders), the CycloneDX route description published in the OpenAPI document, and the
module docstrings of eight package modules. All translated. The guard's word list grew by ~120
words, and two new tests cover what the literal scan skips by design: MCP tool docstrings (the
description the model reads to choose a tool) and API route docstrings (the OpenAPI description).
`servers/mcp_config.example.json` - an Italian, Windows-only duplicate of the shipped catalogue
that nothing referenced - is removed.

**Bugs.** `reachable_sinks` accepted `max_depth` and ignored it, so "reachable within 12 calls"
meant "reachable at any depth"; the search is now bounded. `db.migrate_json_projects()` re-saved
every JSON mirror on every start, which bumped each row's version each time the server came up and
let a stale mirror overwrite the database it mirrors; it now imports only what the database lacks
(test added). `Response` was imported twice in `server.py`; five modules read files with
`open().read()` and no context manager; five unused locals and thirty unused imports are gone;
`winsec` listed `difxapi.dll` twice; six dead functions in `app.js` are removed. `python
benchmarks/run.py` failed with a relative-import error (only `python -m benchmarks.run` worked);
both forms run now.

**Optimisations.** The four SPA bundles (~440 KB) were served `no-cache` without ever answering a
revalidation, so every reload re-sent all of them; the asset routes now answer `304 Not Modified`
on a matching ETag (test added). A streamed reply re-parsed and re-rendered the whole message on
every token; rendering is coalesced to one paint per animation frame, and the last frame still
paints after the turn ends. Opening a project rebuilt the findings list once per stored finding; it
renders once. The database layer was measured and left alone: init, save, load and list each cost
under 0.5 ms per call on the real database, so there was nothing to win there.

Tests: 880 → **884**. Full suite green on 3.10, 3.12 and 3.14; ruff blocking set, mypy over the
whole package, benchmark gate without regression.

**Dormant code removed, on the owner's call.** A detector for "defined but referenced nowhere in
the tree" found five functions and six methods that no caller, test or server used:
`engine.ghidra_strategy.detect_toolchain` (with its signature table),
`engine.llm_safety.toolchain_remediation`, `engine.secrets.extract_candidates` (with its four
regexes; `classify_secret` stays), `engine.crypto.level_rank`, `identity_providers._fetch_jwks`
(with its cache: `PyJWKClient` caches keys itself), and `EvidenceGraph.add_string`,
`add_toolcall`, `add_component`, `add_dynamic_event`, `link_artifact_to_tool`, `list_nodes`. They
were features nothing was wired to, not APIs anyone called; the owner chose removal over keeping
them dormant. The detector reports nothing else.

**Public history rewritten.** `reforge.db.backup-20261013-191551` (159 KB of projects),
`audit/audit.jsonl`, `projects/82afbc549ac0.json` and `GhidraMCP-1-4.zip` had been committed to
the public repository and were only untracked at HEAD, which leaves them one click away in the
history. The history was rewritten with `git filter-repo --invert-paths` in a fresh clone, the
final tree verified identical to the old head commit by commit, and brought back as the local
branch `rewritten-main`. 15 commits became 14: the commit that only removed those files became
empty. Publishing it is a force push of that branch over `main`, guarded by
`--force-with-lease` on the old commit, and that push is the owner's action. GitHub keeps
unreachable objects for a while and may hold cached views; asking GitHub Support to run garbage
collection is the step after that.

### 2026-10-14 — Windows CI suspended until it can be run from Windows

After the previous fixes every job is green except `test (windows-latest, py3.12)`. The failures
there cannot be reproduced on this Mac, and the runner's logs are not readable without a login,
so the job stayed red with nobody able to act on it. The matrix entry is commented out in
`ci.yml` with the reason, not deleted: the suite must run on Windows (PE, x64dbg and Procmon are
Windows-first), and the owner will run and fix it from a Windows machine. Until then CI covers
Ubuntu on Python 3.10 and 3.12. Recorded in `requirements-review.md` §16 as the gap it is.

### 2026-10-14 — CI red on GitHub: four causes, none visible from a Mac on 3.14

The suite was green locally and red on every CI job but hygiene, lint and dist. Reproduced by
building the CI environment here (`uv`-installed CPython 3.10 and 3.12, only the `dev` extra):

* **`types` job** installed `mypy` alone, so `[tool.mypy]`'s pydantic plugin could not import and
  the job died before checking anything. It installs the project now.
* **mypy** had a real error the local run did not show: `server.py` assigned a `FileResponse` to
  a variable first typed by a `RedirectResponse`. Annotated as `Response`.
* **3.10** could not collect `test_packaging_and_state.py`: `import tomllib` is 3.11+. The
  `tomli` backport is in the dev extra for `python_version < "3.11"`.
* **benchmark** failed on p95 latency: the committed baseline is from a laptop (35 ms); the same
  commit measured 143 ms on the runner with nothing changed. Latency is advisory now and fails only
  on a catastrophic move (20x, 500 ms floor); the gate is precision, recall, false positives,
  crashes and reproducibility.
* **Windows** (not reproducible here): `benchmarks/run.py` imported the POSIX-only `resource` at
  module level, which every `tests/test_benchmarks.py` test imports. Guarded; RSS reads 0.0 there.
* A test of mine from last night assumed the `openai` SDK was installed. It no longer does.

Also found: the last commits pushed a pre-migration **database backup** (every project in full),
the audit chain and a third-party release archive to a public repository. `.gitignore`, the CI
hygiene rule and a local test (`test_no_runtime_state_or_archive_is_tracked_by_git`) now refuse
them; they have been untracked. Removing them from HEAD does not remove them from history.

### 2026-10-14 — "Sending…" that never went away, and resending a message

Four ways a turn ends (`done`, `error`, `stopped`, a refused `POST /api/message`) reset three
different subsets of the status bar, the composer and the Stop button; a refused POST reset
nothing and was not even read (`await fetch(...)` with no look at the status); and a stream that
reconnected to a restarted server — which happened to the user several times today — had nothing
to resync from, so the bar stayed on "Sending…" with the composer disabled until a reload.

One `setIdle()` now, called from every ending; `sendMessage` reads the answer and says why a send
was refused (409: a turn is still running); `GET /api/projects/{pid}` carries `busy` and the SPA
re-reads it on every `EventSource` open, so the server's view wins. `/api/stop` emits the idle
status too. The end-of-turn status text was `"Pronto"` and two others were Italian - the guard's
word list did not have them; it does now.

Resend: every user bubble has a ↻ button (same text, current mode, refused while a turn runs), and
ArrowUp in an empty composer recalls the last message to edit or resend.
`tests/test_turn_lifecycle.py`, 8 tests.

**The actual cause, found by reproducing it.** A project's events lived in one `asyncio.Queue`
with one consumer: open the project in two tabs — or in the Browser pane and the user's own window,
which is how this whole day was spent — and each event went to whichever reader woke first. The
other tab never saw "The model is thinking…", never saw `done`, and sat on "Sending…". The stream
now gives each attached tab its own bounded queue (`Session.subscribe()`), `emit` broadcasts, the
backlog reaches the first tab to open, a detached stream is removed, and the stream sends a
keepalive comment every 15 s so idle connections are not closed by proxies.
`tests/test_event_broadcast.py`, 5 tests.

**And the reason the local model never answered at all:** `No module named 'openai'` — the SDK
behind the local provider was not installed in the interpreter running ReTrace (the `local`
extra). The product said "No LLM configured" for a fully configured provider. `NoLLM` now carries
the construction failure; `llm.provider_problem()` surfaces it in `/api/status` (`llm_error`, ahead
of anything the probe says), in the banner, in `retrace check` (`llm: local - NOT READY: …
pip install "retrace[local]"`) and in the failed turn. A `user_message` event is echoed so a second
tab shows the message that started the turn.

### 2026-10-14 — "I cannot get the local LLM to work"

The configuration was right: provider `local`, model `qwen3:30b`, URL `http://127.0.0.1:11434/v1`.
Ollama was installed and **not running**. Nothing in the product said so: `llm_available` meant
"a provider is configured", the banner stayed hidden, and the first turn died with the SDK's
`APIConnectionError: Connection error.`

* `GET /api/status` now carries `llm_reachable` / `llm_error` / `llm_base_url`, from a cached
  probe of `<local_base_url>/models` (`llm.local_reachable`, 10 s TTL; never probes a cloud
  provider from a status poll). The SPA banner distinguishes "not configured" from "configured,
  not running".
* A failed turn goes through `llm.explain_error`: connection refused → the URL and how to start
  the server; timeout → which ceiling and whether the model may still be loading; unknown model →
  the `ollama pull` line.
* `local_timeout_s` (600 s) beside `llm_timeout_s` (120 s): the ceiling added yesterday was sized
  for a cloud provider and would have cut a 30B local model mid-answer.

* The step after "not running" is "running with nothing pulled": the same probe reads the
  `/models` listing and reports `model 'qwen3:30b' is not on the server (available: none). Pull
  it with ollama pull …` while `llm_reachable` is true, and the banner shows it before the first
  turn fails. This is exactly the state this machine was in once Ollama was started.

`tests/test_local_llm_reachability.py`, 14 tests. Documented in `docs/installation.md` under
*Local model*.

### 2026-10-13 — "My MCP servers do not load, and the JSON looks right"

It was right. Every entry in the shipped catalogue says `"command": "python"`, which exists on
Windows and not on this Mac (`python3` only). The spawn failed with `FileNotFoundError: [Errno 2]
No such file or directory` — naming neither the command nor the fix — and all nine servers showed
as unavailable at once, including the eight that needed nothing at all.

`mcp_host.resolve_stdio_command()` now runs the servers with **the interpreter ReTrace itself is
running in** when a bare `python`/`python3`/`py` is not on the PATH. That is the right default
regardless of platform: the bundled servers need the same `mcp` package ReTrace imports, and
`sys.executable` is the one place it is certain to be. Any other missing command is refused by
name; a script path that does not exist is refused before the child is spawned — so the Ghidra
placeholder now reads `script not found: PATH/TO/GhidraMCP/bridge_mcp_ghidra.py … (it is still the
placeholder)` instead of crashing inside the child. Verified: 8 servers connected, 59 tools, one
actionable error (`tests/test_mcp_spawn.py`, 7 tests).

Also: the shipped catalogue's comments were still Italian (the file was never in the guard's
scope - it is now), and the README gained a section on **Ghidra via the external GhidraMCP
server**, which ReTrace does not bundle.

### 2026-10-13 — Review against the brief; the defects it found

**839 tests** (from 829). mypy is now blocking over the **whole package** (77 files), not a
scoped list. [requirements-review.md](requirements-review.md) records, section by section, what
the brief asked for, what is met with which evidence, what is partly met, what is not, and what
was cut by the product decision.

What the review found and fixed, in the order it hurt:

* **The SPA did not load.** Two `Object.assign(I18N.it, …)` blocks had outlived the catalogue
  they extended and threw at script load. 829 tests were green. The page was blank. A static
  guard that checks for a string is not a test of whether the page runs — a browser-level
  end-to-end test is now the top open item in §14.
* **The project list never rendered**: four SPA call sites expected a bare array from an
  endpoint that answers an envelope. One `fetchProjects()` reader.
* **75 type errors outside the old mypy scope**, several real: a handler returning a dict where
  its caller expected a string (a rejected finding reached the model as a dict with
  `is_error=False`), an import of a `slugify` that did not exist (the report TOC could never
  have resolved), `.group()` on a match that could be None, the MCP host dereferenced before
  start-up (now a 503). Scope widened to the tree so a new module is checked by default.
* **`retrace config set` was documented and did not exist.** Implemented, with `config show`
  and `check`, through the same `Settings` model the server uses (`tests/test_cli.py`).
* **No explicit LLM timeout** (SDK default: ten minutes). `llm_timeout_s` / `llm_max_retries`.
* **English-only was a claim, not a fact.** The guard looked at six hand-picked modules. The
  MCP servers (~300 literals), the SPA's copy tables, the graph-diff highlights, seven playbook
  prompts and five backend modules were still Italian. All translated; the guard is a curated
  word list over everything that ships, with three named input-tolerance sites.

### 2026-10-13 — English-only, checked rather than asserted

**829 tests** (from 757). The ✂ on Italian was a decision; this is what it took to make it true.

`test_localization_a11y.py` named **six** backend modules to scan for Italian literals, and the six
were the ones someone remembered. Scanning the whole tree instead found four more that were
emitting Italian into API responses:

* `graph_diff.security_highlights()` built the entire graph-diff highlight list in Italian
  ("Nuovo sink pericoloso introdotto…") and `server.py` returned it under `highlights` — the
  longest-lived leak, and the one most visible on screen;
* `jobs.py` raised `ValueError("nessun target impostato per il progetto")`, which becomes an error
  body;
* `playbook.py` reported every validation failure in Italian;
* `xref_enrich.py` put "(nessuno: server Ghidra non disponibile)" in its result.

The guard is now parametrized over `reforge/**/*.py` discovered from the tree. A guard that only
looks where you remembered to look is not a guard, it is a record of what you remembered — the
same lesson as the untracked `mcp_servers/` tree in P2-S9, which is why it is worth writing down
twice.

**The SPA's graph vocabulary was pairs.** `NODE_TYPE_LABELS` and `EDGE_TYPE_LABELS` held 41
`["italiano","english"]` entries read through `_pick`, which always took index 1. Half of every
entry was unreachable and still had to be kept in step with the half that rendered — and an entry
added as a bare string would have rendered as the empty label `_pick` returns for a missing row.
Unreachable data that can still break the thing reading it is worse than dead code. One string per
entry now, `_pick` gone, and a test that fails if a pair comes back.

**One test was pinned to the Italian copy.** `test_enrich_without_host_degrades` asserted
`"nessuno" in xref_tool`, so translating the string broke it — the test was checking the sentence
rather than the behaviour. It now asserts that no tool is named when none was available, which is
the thing that actually has to hold.

`intent.py` and `severity.py` keep their Italian **input** patterns, and say why in a comment: an
analyst typing `mostrami le stringhe` should still reach STRINGS_TRIAGE, and a model that answers
`"alta"` should still normalize to HIGH. Accepting a word on input is not shipping a second
language; every value either module *returns* is English.

### 2026-10-13 — Scope: a tool for one analyst and small teams

The brief this repository was rebuilt against asked for an enterprise platform. The product
decision is narrower, and taking it changes what "done" means for roughly a third of the backlog.

**The `enterprise` profile was a label, not a behaviour.** `_harden_for_profile` has exactly one
branch — `if self.deployment_profile == "workstation": return self` — so `enterprise` and `team`
produced byte-identical settings. Three values in an enum where two of them are the same value is
a promise to the reader that the code does not keep. `Profile` is now
`Literal["workstation", "team"]`.

**Two ADRs are superseded rather than edited.** [0004](adr/0004-worker-isolation.md) argued for a
managed Windows worker fleet, and it argued for it on malware-analysis grounds — "dynamic analysis
executes hostile code". That framing was wrong for this product and was already corrected in the
threat model: the binary is benign but untrusted, and the real exposure is that a *working proof of
concept* is attacker-shaped data executing on the analyst's machine, caused by the analyst. The
proportionate answer at this scale is the RE VM they already have, plus the subprocess target and
the refusal of unisolated execution on a shared install — both implemented.
[0005](adr/0005-persistence-profiles.md) argued for a repository interface with SQLite and
PostgreSQL behind it; a second adapter supports concurrent writers across nodes, and there is one
node. What those ADRs got right was the *discipline* — migrations with a mandatory backup,
optimistic locking, retention with a separate purge — and all of it is kept and implemented.

**Nothing was deleted from the backlog.** Cut items stay in their tables struck through, marked ✂,
each with the reason, and are summarised under [Out of scope](#out-of-scope). A backlog that
quietly loses rows stops being a record of what was decided and becomes a record of what someone
currently remembers.

**P2 got acceptance criteria.** P0 and P1 had them; P2 did not, which meant its slices were marked
◐ against a standard that was never written down. Seven criteria now, all of them things a test or
a measurement can settle.

Four slices moved to ☑ because the part that remained open was the part that is now out of scope:
P2-S2 (isolation contract — the fleet was the open half), P2-S5 (migrations — PostgreSQL was),
P2-S6 (audit and SLIs — tracing and alerting were), P2-S10 (English UI and a11y basics — the
Italian catalogue was). The docs follow: `target-architecture.md` is rewritten around one process,
and both enterprise-named documents are renamed, because a filename is a claim about the product
too.

Renamed: `ROADMAP_ENTERPRISE.md` → `ROADMAP.md`, `enterprise-gap-analysis.md` → `gap-analysis.md`.

### 2026-10-13 — The last three closeable residuals

**758 tests** (from 740). Lint, mypy and the benchmark all clean.

#### Optimistic locking is now a check, not a counter

The `version` column existed from migration 2 and nothing read it, which made it a record of how
many times a row had been overwritten rather than a guard against overwriting. Two analysts with
the same project open both save; the second silently discarded the first one's findings.

`save_project(payload, expected_version=…)` compares **inside the same lock and connection as the
write** — a check in a separate transaction would be a race with a longer window, which is worse
than no check because it looks like one. `Session` carries the version it loaded and passes it on
every `persist()`; `persist(check_version=False)` is for the caller that has decided to win, and
is an argument rather than a separate method so the decision is visible at the call site.

#### Retention hides, and only a deliberate second step erases

`retain_until` and `deleted_at` were recorded and nothing acted on them. A sweep now runs at
startup when `retention_days` is set — and it **soft-deletes**: the row stays, the project
disappears from listings, `restore_project()` brings it back.

Automatically destroying an engagement's findings on a timer is not something a tool should do. A
retention policy is usually set once, by someone estimating, and the first time it fires on real
work it has to be recoverable. `purge_expired()` is the separate step that actually removes them,
it reports what would go when called without `confirm`, and it is audited with the ids it removed.

Default is 0 — keep everything.

#### Backups are pruned

They accumulated beside the database, one full copy each, until the disk the product is trying to
protect filled up. `backup_retention_count` (default 10) keeps the most recent; the backup just
taken is never pruned, and a file that cannot be removed is logged rather than failing the
migration it is attached to.

**What remains open is what needs something outside this machine:** a PostgreSQL server to test an
adapter against, a Windows VM for T-3, a WORM store for a tamper-proof audit, real traffic for
alert thresholds, a native speaker for the Italian, and assistive technology plus a human for WCAG.
Each is recorded against its slice with that reason rather than as a to-do.

### 2026-10-13 — P2-S5 · S7 (part) ☑ Migrations with backup, and a verified offline bundle

**740 tests** (from 710).

#### P2-S5 — versioned migrations

The schema was created by `CREATE TABLE IF NOT EXISTS` and never changed. That works exactly
once: the first time a column must be added to a database already holding a customer's
engagements, there is no path from what they have to what the code expects, and the options are
"lose the data" or "never change the schema".

`reforge/migrations.py`: three migrations, each with a reverse, applied at start. **A backup is
taken first or the migration does not run** — using SQLite's own backup API rather than a file
copy, because a copy taken mid-write can be torn and this is the one moment that must not produce
a corrupt rescue copy. A failed migration leaves the database unchanged, says where the backup is,
and ReTrace continues on the old schema rather than refusing to start.

What the migrations add: `owner` (indexed, backfilled from the payload), `version` for optimistic
locking, and `retain_until` / `deleted_at` for retention.

**This closed a stated residual risk:** project visibility was resolved by loading and parsing
*every* project. It is now a `WHERE` clause.

**Two defects found doing it**

1. **A column nothing wrote.** `save_project()` predates the `owner` column, so every new project
   answered "no owner" in the column while its payload said otherwise — the index existed, the
   query used it, and the answer was wrong. The project-listing test caught it the moment the
   query replaced the scan.
2. **`db.py` captured the database path at import.** `DB_FILE` was a module-level constant, so any
   later change to the configured path was ignored — including one made through the settings
   facade. Invisible while nothing else read the path independently; the moment the migration
   runner did, the two disagreed and migrations ran against a different file than the tables. The
   path is now read live.

#### P2-S7 — an offline bundle that is verified, not asserted

Air-gapped installation was documented as "build the bundle with `pip download`" — an instruction,
not a deliverable, whose failure mode surfaces on the far side of the air gap.

`scripts/build_offline_bundle.py` builds the wheel plus its closure, writes POSIX and Windows
installers and a checksummed manifest, and **verifies the bundle by installing it with the package
index disabled**. That is the only check that means anything: a missing dependency fails on the
connected machine rather than on the isolated one.

Verified end to end: 38 wheels, checksums match, `pip install --no-index` succeeds, and the
installed package imports and reports 79 routes with no network.

**Residual risk**
1. **No PostgreSQL or object-storage adapter.** ADR 0005 asks for one repository interface with
   two adapter sets. The migrations, the backup discipline and the schema are the foundation;
   the second adapter needs a server to test against and I have none here. Writing untested SQL
   that *looks* finished would be worse than this entry.
2. **Egress is still not enforced at the network level.** The offline bundle makes installation
   work without a network; the `offline_deterministic` and `local_only` profiles prevent model
   calls and record that nothing left. An operator can still change the profile, so the claim is
   "configured and auditable", not "enforced" — and `docs/installation.md` says exactly that.
3. **A bundle is per platform and per Python minor version.** Stated in its README, not solved.
4. **Optimistic locking is a column, not yet a check.** `version` increments on every save and
   nothing yet refuses a write whose base version is stale.
5. **Retention columns exist; no sweeper runs.** `retain_until` and `deleted_at` are recorded and
   nothing acts on them.
6. Backups accumulate next to the database and are never pruned.

### 2026-10-13 — Defect pass: the residual risks that could be closed here

Six items previously recorded as residual risk. **710 tests** (from 697); mypy now **blocking** in CI.

| # | residual risk | closed |
|---|---|---|
| P2-S3 r1 | tool **results** unvalidated | `output_schema` + per-tool `max_output_chars`, enforced in `MCPHost.call` |
| P2-S2 r1 | isolation contract with nowhere to go | a real `SUBPROCESS` target with enforceable limits |
| P2-S6 r1 | correlation stopped at the HTTP layer | the tool-call log line carries it |
| P2-S10 r3 | `tr(it, en)` pairs unchecked | asserted, both directions |
| P2-S10 r5 | `prefers-reduced-motion` ignored | honoured |
| P1-S11 | mypy advisory | **blocking**; 0 errors in the scoped modules |

**Output validation.** Arguments came from us; the reply comes from the server, and it is the
reply that flows into evidence, into the model's context and into a report. A non-conforming
result now fails the call and counts against the server's circuit breaker. A per-tool output
ceiling sits below the global cap — a tool that should return a verdict has no business returning
a megabyte, and the global cap is too loose to notice.

**A second execution target.** `Isolation.NONE` was the only one on offer, which made the whole
contract a declaration with nowhere to go. A subprocess is **not** a privilege boundary and still
does not satisfy `dynamic_execution` — but it gives limits that bind the job instead of the
application, a kill switch that works, and crash containment.

`best_target_for` also changed to pick the **weakest sufficient** target rather than the strongest
available. Isolation costs a spawn, and paying it where it buys nothing is how a control becomes
the thing people turn off: reads stay in-process, writes get the child.

**Two defects found while fixing these**

1. **The first subprocess implementation was a fork bomb.** It used `multiprocessing` with the
   `spawn` context, which re-imports the caller's `__main__` in the child — so any caller without
   a `__main__` guard forks itself endlessly. It hung immediately when run. A library cannot
   depend on its callers getting that right, and the failure mode is not an error. Rewritten with
   an explicit `subprocess` invocation: no re-import, no pickling, JSON over stdout.
2. **`run_isolated` could not call positional-only functions** — `time.sleep`, `math.factorial`
   and a good deal of the standard library. A runner with that hole in it would have been found
   much later, by someone else. It now takes `args` as well as `payload`, and arguments that
   cannot cross the boundary produce a clear error rather than a failure deep inside a child.

**Also:** `engine/schema.py` guarded with `if None in (av, ac, pr, ...)`, which reads as a guard
and does not narrow — every use below was an operation on a possible `None` that only happened to
be safe. Made explicit.

**What was NOT closed, and why**

- **WCAG conformance** — needs a real assistive technology and a human. Structural checks are in
  place; colour contrast, focus order through modals and screen-reader behaviour on the dynamic
  panels are not verified, and claiming conformance without that would be the kind of unverified
  claim this work has avoided throughout.
- **Italian translation quality** — complete and in parity; whether it is *good* needs a speaker
  reviewing it in context.
- **T-3 / the worker fleet** — reduced again by the subprocess target, not closed. A separate
  kernel is what contains a kernel-level exploit, and that is a VM.
- **Tamper-proof audit, alerting rules, SLO validation** — each needs something outside this
  machine: a WORM store, real traffic, a production deployment.

### 2026-10-13 — P2-S10 (part) ☑ Localization and accessibility

**Files added** — `tests/test_localization_a11y.py` (24).
**Files changed** — `reforge/web/app.js`, `reforge/web/index.html`, `reforge/web/styles.css`,
`reforge/server.py`, `reforge/agent.py`, `reforge/mcp_host.py`, `reforge/artifacts.py`,
`reforge/job_manager.py`, `reforge/config.py`, `tests/test_v54_platform.py`.

**Three defects, all found by measuring rather than reading**

1. **The Italian catalogue was unreachable code.** `applyLang(lang)` ignored its argument and
   hardcoded `LANG = "en"`. 247 keys were being maintained in parity with the English ones and
   could never be displayed. A language the product ships, maintains and cannot show is worse
   than one it does not ship.
2. **`<html lang="it">` while the interface was English.** A screen reader picks pronunciation
   from that attribute, so the entire interface was being read aloud with the wrong phonetics —
   unintelligible, not merely wrong.
3. **Eight `data-i18n` keys referenced in the markup existed in neither catalogue** — the whole
   Evidence Graph section. Those headings rendered from their hardcoded fallback and could not be
   translated at all.

**What landed**

| | before | after |
|---|---|---|
| Italian interface | impossible — the switch ignored its argument | works; `ui_lang` comes from the server |
| `<html lang>` | hardcoded `it`, content English | follows the interface language |
| catalogue parity | unverified | enforced by test, both directions |
| keys referenced but undeclared | 8, silently untranslatable | 0, enforced by test |
| skip-to-content link | none | present, focusable, styled off-screen not `display:none` |
| agent status region | not announced | `role="status" aria-live="polite"` |
| radio groups | four unrelated radios to a screen reader | `role="radiogroup"` + `aria-labelledby` |
| user-facing Italian in the backend | 8 strings across 6 modules | 0, enforced by test |
| machine-readable codes on tool errors | none | `tool_timeout`, `server_breaker_open`, `awaiting_approval` |

The backend now speaks one language and emits a **stable code** beside the prose; the SPA does the
localising. That way the backend does not need to know the operator's language, and adding a third
one is not a backend release.

**Tests:** 673 → **697 (+24)**.

**Residual risk**
1. **No WCAG audit.** What landed are the defects a structural check can find: landmarks, labels,
   live regions, skip link, document language. Colour contrast, focus order through the modals,
   and screen-reader behaviour on the dynamic panels have **not** been checked — they need a real
   assistive technology and a human, and claiming conformance without that would be exactly the
   kind of unverified claim this project has been avoiding.
2. **The Italian catalogue's quality is unverified.** It is complete and in parity; whether the
   translations are good is a question for a speaker reviewing them in context.
3. Strings built in JavaScript via `tr(it, en)` pairs are not covered by the parity test — only
   the `data-i18n` catalogue is. A missing pair there degrades to showing the other language.
4. The report templates and the DOCX/PDF exports are English only.
5. `prefers-reduced-motion` is not honoured; the status pulse animates regardless.

### 2026-10-13 — Completing the ◐ pieces of phase P2

Four gaps named as residual risk in earlier slices, now closed. **673 tests** (from 637).

**Files added** — `tests/test_completions.py` (36).
**Files changed** — `reforge/server.py`, `reforge/mcp_manifest.py`, `reforge/mcp_host.py`,
`reforge/job_manager.py`, `reforge/model_gateway.py`, `reforge/agent.py`, `reforge/settings.py`,
`reforge/config.py`, `pyproject.toml`, `requirements.txt`,
`tests/test_packaging_and_state.py`.

#### P2-S8 risk 2 — project ownership, enforced centrally

Enumerating the live app found **29 routes that read or wrote a project with only a permission
check behind them** — `/evidence`, `/strings`, `/graph`, `/export/sarif`, `POST /target` among
them. Holding `project:read` says you may read projects, not that you may read *that* one.

Patching 29 handlers would have repeated exactly the mistake P2-S8 exists to fix, so the check
moved into the middleware: the matched route's path parameters now yield the project id, and
visibility is checked once, for every route whose path names a project. A refusal answers **404,
not 403** — 403 would confirm the project exists to someone with no right to know that.

Verified against the running app: an analyst who is not a member now gets 404 on all of
`/evidence`, `/strings`, `/graph`, `/export/sarif`, `/assessment`, `/report/{id}/validate` and
`POST /target`, while the owner still gets 200.

#### P2-S3 risk 1 — tool arguments validated against their declared schema

The manifest carried `input_schema` and nothing checked against it. `MCPHost.call()` now validates
before dispatch — a test asserts the ordering — so a model that invented an argument is stopped
before that argument reaches a debugger attached to a live process.

The server validates too, but to protect *itself*; this protects the host, and only one of the two
is under our control. `jsonschema` became a core dependency rather than an extra: the fallback
structural check is narrower and this is a security control.

#### P2-S6 risk 6 — the two SLIs that always read `null`

`job_success_rate` and `tool_call_success_rate` had definitions and no counters feeding them.
`retrace_jobs_total` and `retrace_tool_calls_total` now exist, with duration summaries beside
them. A metrics failure cannot fail a job — tested.

#### P2-S4 risk 1 — per-project spend ceiling

`project_budget_usd`, checked **before** a turn rather than after. A budget checked afterwards is
an invoice. 0 means unlimited and is the workstation default: an analyst paying for their own key
does not need the tool second-guessing them. Exceeding it is recorded in the egress ledger.

**Residual risk**
1. **Output validation is still open.** Arguments are checked; tool *results* are not. ADR 0003
   asks for both, and a malicious server's reply is the direction the host is more exposed to.
2. The ownership check consults `store.get()` per request. Correct, and it loads a project to
   answer a question a `WHERE` clause should answer — P2-S5.
3. Budgets are per project and per-process. There is no tenant-level ceiling and no reset period;
   the figure is an estimate from the local price list, because the provider's actual number
   arrives too late to enforce anything.
4. Channel authentication and server identity for MCP remain unbuilt (P2-S3 risk 2).
5. Still no distributed tracing and no alerting (P2-S6 risks 1 and 2).

### 2026-10-13 — P2-S6 (part) ☑ Correlation, metrics, SLIs, sanitized support bundle

**Files added** — `reforge/observability.py`, `reforge/support_bundle.py`,
`docs/observability-and-slo.md`, `tests/test_observability.py` (27).
**Files changed** — `reforge/server.py`, `reforge/settings.py`, `reforge/config.py`,
`reforge/route_policy.py`, `tests/test_upload_limits.py`.

**What was missing.** Logs were unstructured lines with no correlation: output from the API, the
agent, the MCP host and the LLM layer interleaved with every other request and nothing tied them
together. There were no metrics at all, so "is this deployment healthy" and "did that change make
anything slower" had no answer but anecdote. And there was no way to ask a customer for
diagnostics without asking them to send material they are under NDA to protect.

**What landed**

| | before | after |
|---|---|---|
| correlating one request's logs | impossible | `X-Correlation-Id` on every request and log line |
| log format | text only | `text` or `json`, one object per line with actor and project |
| metrics | none | counters + summaries, JSON and Prometheus text |
| SLIs | none | 4, computed from live counters |
| support diagnostics | send us your logs | a bundle meant to be sendable without review |
| customer content in logs | unguarded | scrubbed on the way in |
| tests | 610 | **637 (+27)** |

Observability is the **outermost** middleware, so it counts requests the policy and auth layers
refuse. A deployment refusing half its traffic is exactly what metrics should show, and a filter
that only counted what got through would hide it.

**An SLI with no traffic behind it reports `null`.** 100% availability derived from zero requests
is a number that reads like one that means something.

**Three defects found while building this**

1. **A real leak in the support bundle.** `scrub()` removed symbol names and hex dumps but not
   *project names* — and a project is named after the customer, which is exactly what the bundle's
   README promises is absent. No pattern can find these, so they are now removed by name, longest
   match first so `acme-corp-2024` does not leave `-2024` behind.
2. **My first version of these tests grepped the raw zip bytes**, which is unsound in both
   directions: the payload is DEFLATE-compressed, so a secret that *is* present may not appear
   literally and a marker that is absent may appear by coincidence. They passed for the wrong
   reason until the assertions decompressed first — which is how defect 1 surfaced.
3. **`observability.py` imported `benchmarks.metrics`** for its percentile. `benchmarks/` is
   excluded from the wheel, so the shipped product would have depended on something it does not
   ship. Six lines duplicated instead.

Also: the archive-extraction guard from P0-S3 fired on the bundle's `zipfile.ZipFile(...)`. It was
right to be noisy and wrong to be imprecise — *writing* an archive is not *extracting* one. The
guard now looks for extraction verbs and read-mode opens rather than the class name, and a second
test pins the bundle to write-only.

**Residual risk**
1. **No distributed tracing.** Correlation ids tie a request's own lines together; they do not
   propagate to an MCP server or a worker, and there is no span model. Worth doing once there is
   a fleet (P2-S2).
2. **No alerting.** Metrics are exposed in a scrapeable format; no alert rules exist, and a rule
   nobody has tuned against real traffic is noise.
3. **The SLOs are proposals, not measurements.** `docs/observability-and-slo.md` says so: no
   deployment has run long enough to say whether the targets are achievable.
4. **The audit trail is still tamper-evident, not tamper-proof** (unchanged from P2-S1).
5. Metrics are per process and reset on restart. Durable history is the collector's job, and
   there is no collector.
6. Only HTTP requests are instrumented. Job outcomes and MCP tool calls have SLI definitions and
   no counters feeding them yet — `job_success_rate` and `tool_call_success_rate` will read
   `null` until they do.

**Next:** P2-S5 (PostgreSQL and object storage adapters) or P2-S7 (air-gapped deployment bundle).
Both need infrastructure I can design and write but not verify here, which is worth saying before
starting rather than after.

### 2026-10-13 — P2-S2 (part) ☑ Execution isolation contract, ephemeral workspaces, quotas

**Scope, stated first.** This does **not** build a worker fleet. There is still exactly one
execution target — the ReTrace process — and it provides no boundary. What landed is the contract
that must exist before a fleet is worth building, and that is useful without one: dangerous work
is now *refusable*, *bounded* and *visible* instead of silently running next to the analyst's SSH
keys. T-3 is reduced, not closed. The slice stays ◐.

**Files added** — `reforge/execution.py`, `tests/test_execution_isolation.py` (20).
**Files changed** — `reforge/agent.py`, `reforge/job_manager.py`, `reforge/server.py`,
`reforge/settings.py`, `reforge/config.py`, `README.md`.

**What landed**

| | before | after |
|---|---|---|
| where sample code runs | the analyst's session, unstated | an execution target that **declares** `Isolation.NONE` |
| `dynamic_execution` on `team`/`enterprise` | ran | **refused**, and the setting cannot be flipped back |
| `dynamic_execution` on a workstation | ran silently | runs, with a warning naming what it runs beside, every time |
| job scratch space | the shared workspace | per-job, mode `0700`, deleted and **deletion verified** |
| a job that never finishes | held a worker forever | stopped at a wall-clock ceiling |
| an unrecognised risk class | treated as safe | asks for the strongest isolation |

The isolation check runs **before** the approval prompt — a test asserts the ordering in
`agent._dispatch`. Asking an operator to authorise something the deployment must not do at all is
not a decision worth offering them.

The workstation case is deliberately permissive. Refusing there would mean the analyst debugs the
sample outside the tool, with no approval gate, no evidence and no record — worse on every axis
than running it inside with a warning. `team` and `enterprise` get no such latitude.

**Verified:** a job's workspace is created, used, and gone afterwards with `workspace_deleted:
true` persisted on the job record so it can be audited after the fact; a simulated failed removal
produces `JOB WORKSPACE NOT DELETED ... a customer sample may be left on disk`.

**Tests:** 589 → **609 (+20)**.

**Residual risk**
1. **No isolated worker exists.** `Isolation.SUBPROCESS`, `CONTAINER` and `VM` are defined and
   nothing implements them. On a workstation, sample code still executes in the ReTrace process
   with the analyst's privileges. **T-3 is reduced, not closed** — the ranking-1 threat stays open
   until there is a Windows VM worker (ADR 0004).
2. **Quotas are partial.** `setrlimit` bounds *this process*, so it bounds a job only because a
   job currently is this process; it is applied and then restored rather than left in place.
   Memory and disk ceilings are declared and not enforced. Real enforcement needs the separate
   process the fleet would provide.
3. **Jobs are durable only as JSON files.** Still in-process, still single-node, no queue, no
   resume-after-crash beyond what `load_persisted()` already did. P2-S5.
4. **No network restriction per job.** `ExecutionTarget.network` is declared and nothing enforces
   it; the in-process target has the host's full network access.
5. The ephemeral workspace is per *job*. Tool calls made directly through the agent loop — which
   is most of them — still use the project workspace.

**Next:** P2-S6 (audit, observability, tracing, SLI/SLO) or P2-S5 (PostgreSQL and object storage
adapters behind the repository interface, which residual risk 3 depends on).

### 2026-10-13 — P2-S4 (part) ☑ Model gateway: profiles, classification, redaction, ledger

**Closes T-10.**

**Files added** — `reforge/model_gateway.py`, `tests/test_model_gateway.py` (26).
**Files changed** — `reforge/llm.py`, `reforge/server.py`, `reforge/settings.py`,
`reforge/config.py`, `reforge/route_policy.py`, `README.md`, `docs/installation.md`.

**The defect.** Whether a customer's decompiled code reached a cloud provider was decided by one
setting — `llm_provider` — and nothing else. No classification of what was about to be sent, no
redaction on the outbound path (`redact.py` existed and was used for *displaying* settings), no
egress allow-list, and no record of what had been sent, to whom, or why. An operator could not
answer "did any of this customer's binary reach Anthropic", which for a product handling material
under NDA is the question.

**The four profiles, measured end to end**

| profile | metadata | finding | decompiled code | raw bytes |
|---|---|---|---|---|
| `offline_deterministic` | refused | refused | refused | refused |
| `local_only` | refused | refused | refused | refused |
| `hybrid` | sent | sent | **refused** | **refused** |
| `frontier` | sent | sent | sent | sent |

`hybrid` is forced on `team` and `enterprise` and cannot be relaxed (§9.1). `frontier` is the
workstation default — the analyst's own machine, their own call, every request in the ledger.

**Enforcement is inside the remote provider**, not at the call sites: a check at the caller is a
check the next caller forgets. A test reads `AnthropicLLM`'s source and fails if an outbound
method does not pass through `_guard()`. The whole conversation is classified as one payload,
because a request is only as safe as its most sensitive part.

**The ledger records shape, never payload**: data class, provider, model, purpose, character
count, redaction count. A ledger you have to redact before showing it is not evidence of anything.
`GET /api/egress` is readable by anyone who can read projects, not only an administrator — an
analyst must be able to check what their own work sent.

**Three defects found while building this**

1. **The classifier was too aggressive.** A single `FUN_00401250` reference marked a payload as
   decompiled code, so a finding citing the function it was found in — which is what findings do —
   was refused under `hybrid`. That is the profile being useless rather than strict. Now two
   independent markers, or one plus C-like block structure.
2. **The summary counted local calls as egress**, so a `local_only` deployment could never
   demonstrate that nothing had left — the one claim the ledger exists to support. Local requests
   are still recorded, but only remote ones count as egress.
3. My first redaction accounting mixed a character delta with a count of secrets and was neither.
   Replaced with an explicit count of applied redactions.

**Tests:** 563 → **589 (+26)**.

**Residual risk**
1. **No budgets and no routing.** §9.1 also asks for per-project and per-tenant spend limits and
   task-based routing by sensitivity, cost and latency. Neither exists; `llm_cost.py` accounts
   after the fact.
2. **Enforcement is application-level.** A determined operator can change the profile, and a
   compromised process is not stopped by its own bookkeeping. A credible air-gapped deployment
   also needs egress blocked outside the application — P2-S7.
3. **Classification is heuristic.** It is deliberately tuned to over-refuse rather than under-
   refuse, but a payload that is neither obviously code nor obviously prose can land either way.
   Callers that know should pass `declared=`; almost none do yet.
4. The ledger shares the audit trail's tamper-evidence, and its limits (P2-S6).
5. `local_api_key`, `NVD_ONLINE_LOOKUP` and any MCP server that makes its own network calls are
   outside this gate. It governs *model* egress, not all egress.

**Next:** P2-S2 (durable jobs and isolated workers — closes T-3, dynamic analysis still runs in the
analyst's own session) or P2-S6 (audit, observability, tracing, SLI/SLO).

### 2026-10-13 — P2-S3 (part) ☑ MCP gateway: manifests and fail-closed risk

**Closes T-4**, the last Critical-impact threat in the model.

**Files added** — `reforge/mcp_manifest.py`, `reforge/manifests/*.json` (17),
`tests/test_mcp_gateway.py` (25).
**Files changed** — `reforge/policy.py`, `reforge/mcp_host.py`, `reforge/agent.py`,
`reforge/settings.py`, `reforge/config.py`, `pyproject.toml`.

**The defect.** `policy.risk_class()` decided how dangerous a tool is by running regexes over its
*unqualified name* — a string the MCP server itself chooses. A server exposing a destructive
operation as `analyze_report` was classified `safe_read` and, in `assisted` mode, executed
**without approval**. The catalogue was deny-by-exception: any tool any connected server offered
was callable.

**Three inversions**

1. **Risk comes from a versioned manifest, not from a name.** 17 manifests ship, generated from
   the servers' own `@mcp.tool()` decorators so a manifest cannot silently disagree with the
   server it describes — a test re-derives four of them from source and fails on drift.
2. **An unmanifested server gets a floor.** This is the part that actually closes T-4, and my
   first attempt did not: taking "the higher of the catalogue hint and the name heuristic" closes
   nothing, because *both come from the server*. An unmanifested tool is now at least
   `sensitive_read` regardless of what the server says about itself, which in `assisted` mode
   surfaces as an approval rather than a silent execution.
3. **A manifested server is an allow-list.** A tool it did not declare is refused, at the host, so
   a server that grows a capability after review does not get to use it silently.

A manifest can raise a tool's class but never lower it below what its name suggests: it is the
authority on what a tool does, not a licence to relabel `memory_write` as a read.

| | before | after |
|---|---|---|
| `evil__analyze_report` (destructive, benign name) | `safe_read`, **ran unattended** | `sensitive_read`, **approval required** |
| `hardening__hardening_audit` | `safe_read` | `safe_read` — unchanged, no friction added |
| `ghidra__decompile_function` | `safe_read` | `safe_read` — unchanged |
| `ghidra__patch_bytes` | `write_or_patch` | `write_or_patch` |
| a tool a manifested server never declared | callable | **refused at the host** |
| evidence provenance | tool name only | tool + server + **server version** + risk class + where the decision came from |
| tests | 538 | **563 (+25)** |

**GhidraMCP is treated differently, on purpose.** It is third party and its full tool list cannot
be enumerated from here, so its manifest **classifies without allow-listing**
(`allow_undeclared_tools: true`, `safe_read` default, the twelve mutating tools named explicitly).
Inventing an allow-list for a server you cannot enumerate refuses legitimate tools, which
operators fix by turning the whole mechanism off.

**Two defects found while building this**

1. **ReTrace's own meta-tools were caught by the third-party floor.** `search_tools` and
   `workflow_status` run in-process in `agent.py`; the floor exists to distrust *servers*. They
   now resolve against their own `builtin` manifest.
2. **A manifest that over-classifies is its own failure mode.** The generator applied frida's
   server default to all four of its tools, making `list_sink_presets` — which returns a static
   list — `dynamic_execution`. Corrected by hand. An approval card that fires on everything trains
   the operator to approve without reading, which ends the gate as surely as not having one.

Also: the test I wrote against `frida__frida_trace` failed because that tool does not exist (the
real name is `trace_sinks`). The allow-list caught my own wrong assumption, which is the behaviour
working.

**Residual risk**
1. **Input/output JSON-Schema validation is not implemented.** The manifest carries `input_schema`
   and nothing validates against it yet. ADR 0003 asks for both directions.
2. **No server identity or channel authentication.** mTLS for remote MCP, and verifying that the
   server you connected to is the one the manifest describes, are not done. A manifest currently
   binds to a server *name*, which the local config chooses — fine for bundled stdio servers,
   insufficient for a remote one.
3. **Manifests are not signed.** A manifest in the install directory is as trustworthy as the
   install directory. Signing and provenance belong with artifact signing (P2 release work).
4. The x64dbg manifest classifies 30 of its 40 tools as `sensitive_read` because the server is
   attached to a live process. That is defensible and it is also blunt — per-tool review would
   likely move some to `safe_read`.
5. Risk resolution runs per call with no caching. Measured cost is negligible at current catalogue
   sizes; it is a dictionary lookup plus a regex.

**Next:** P2-S4 (model gateway: the four operating profiles, data classification, redaction, egress
ledger — closes T-10) or the remaining half of P2-S3 (I/O schema validation).

### 2026-10-13 — P2-S8 (part) ☑ Default-deny route authorization

**Scope, stated plainly.** P2-S8 is "routers, domain layer, SPA modularization". This delivers the
**authorization** part of it — the piece that closes residual risk 2 from P2-S1 and that I
proposed doing first. `reforge/server.py` is still 1,400+ lines and the SPA is still one file;
**the decomposition has not started.** The slice stays ◐.

**Files added** — `reforge/route_policy.py`, `tests/test_route_policy.py` (20).
**Files changed** — `reforge/server.py`, `pyproject.toml`, `requirements.txt`.

**The defect.** P2-S1 put permission checks on eleven routes by hand. Enumerating the live app
found **69 API route/method pairs**, so ~50 were unguarded — among them
`POST /api/projects/{pid}/target`, which chooses the binary to analyse,
`GET /api/projects/{pid}/evidence`, `GET /api/projects/{pid}/export/sarif` and `POST /api/jobs`.

The specific holes mattered less than the shape: a route added later was **unguarded by default**,
and nothing caught it. Per-route checks written by hand are a policy you have to remember.

**What landed**

- `route_policy.ROUTE_PERMISSIONS` declares a permission (or explicit `PUBLIC`) for all 69 pairs.
  The entire authorization surface is now one reviewable table rather than a property you
  establish by reading 1,400 lines of handlers.
- A middleware resolves the route template *before* dispatch (Starlette records the match only
  during dispatch, which is after the decision has to be made) and refuses anything undeclared.
- Two typo-resistance properties, both tested: an unknown permission string fails **closed**, and
  an undeclared route fails **closed**.
- `test_every_api_route_declares_who_may_call_it` fails the build when a new route appears without
  an entry. `test_the_table_declares_no_route_that_does_not_exist` catches the opposite — a stale
  entry is a permission nobody enforces and a reader being misled.
- `PUBLIC` is capped at `/api/status` and `/api/whoami` by test, and no state-changing method may
  be public. Growth in that list is the policy quietly dissolving.

| | before | after |
|---|---|---|
| API route/method pairs | 69 | 69 |
| with a declared policy | 11 (by hand, in handlers) | **69 (one table)** |
| unguarded by default | ~50 | **0 — undeclared is refused** |
| a new route added tomorrow | open | refused until declared |
| tests | 518 | **538 (+20)** |

Verified on a live server that the SPA still works end to end: every route the UI calls answers
200 for the local operator, while an undeclared route and an under-privileged caller are refused.

`starlette` is now declared as a direct dependency — the middleware imports it for route matching,
and the packaging test correctly refused to let that ride on FastAPI's transitive copy.

**Residual risk**
1. **The decomposition is not done.** `server.py` remains ~1,450 lines mixing HTTP, orchestration
   and persistence; `reforge/web/app.js` remains 4,300 lines. Extracting routers and a domain
   layer is the rest of P2-S8 and is a large, separate piece of work.
2. The coarse gate answers "may this principal do this kind of thing". Per-project scoping still
   depends on a handler calling `require_project()`, and only eleven do. A route that reads a
   project without that call is permission-checked but not ownership-checked — closing that
   properly means the project id becoming a typed dependency, which belongs with the router split.
3. The table is matched on the route template string. Renaming a path in a decorator without
   updating the table turns the route off rather than opening it — fail-closed, but the failure
   surfaces as a 403 rather than a clear "you renamed this", until the stale-entry test runs.

**Next:** P2-S3 — the MCP gateway (manifests, allow-list, schema validation, tool version into
evidence). It closes T-4, the one remaining Critical-impact threat in the model.

### 2026-10-13 — P2-S1 · S9 ☑ Identity, RBAC, project isolation, audit

**Files added** — `reforge/identity.py`, `reforge/identity_providers.py`, `reforge/audit.py`,
`tests/test_identity_rbac.py` (40).
**Files changed** — `reforge/server.py`, `reforge/session.py`, `reforge/settings.py`,
`reforge/config.py`, `pyproject.toml`, `tests/test_scope.py`, `tests/test_packaging_and_state.py`,
`.gitignore`, `README.md`.

**The defect.** One process-wide shared token and nothing else. Anyone who could reach the API
could read, modify, export or delete every project of every customer, and nothing recorded who
did. `DELETE /api/projects/{pid}` required only the ability to reach the endpoint.

**What landed**

| | before | after |
|---|---|---|
| identity | a shared token | `local` operator (workstation) or OIDC bearer validation |
| roles | none | 5 roles, explicit permission sets, no hierarchy |
| project visibility | every project to every caller | owner + named members + cross-project permissions |
| `DELETE /api/projects` | reachable = permitted | `project:delete` **and** visibility |
| settings / MCP servers / raw export | reachable = permitted | `settings:write` / `server:manage` / `raw:export` |
| who did what | unrecorded | hash-chained append-only JSONL, grants **and** refusals |
| tests | 477 | **518 (+41)** |

Roles are explicit sets, not a ladder. A hierarchy reads well until one role needs an ability a
notionally lower one must not have — then the ladder is wrong and every check on it is wrong too.
Concretely: a **security manager** may delete projects and read the audit trail but **cannot**
change settings or manage MCP servers. Running an engagement and administering the platform are
different jobs, and the person doing the first should not be able to turn off the controls on the
second.

**Three defects found while building this**

1. **A route that bypassed the isolation I had just added.** Refactoring the listing endpoint left
   `/api/projects/_all_unfiltered_disabled` returning the unfiltered list. Removed, and
   `test_no_route_returns_the_unfiltered_project_list` greps the source so it cannot come back.
2. **An unreachable identity provider surfaced as a raw transport error**, so an IdP outage would
   have become a 500 on every request. Now `IdentityProviderUnavailable` → **503**, kept distinct
   from 401: "your token is invalid" and "we cannot check your token" are different answers, and
   collapsing them tells an operator their users' logins broke when the IdP is simply down.
   A malformed token is also rejected on shape before any network call.
3. **The packaging test caught `jwt` and `httpx` as undeclared lazy imports** — now the `oidc`
   extra.

**P2-S9 — and a correction to my own analysis.** I had recorded the untracked `mcp_servers/` as
the *newer* tree. It was **older**: it still carried `capa_mcp.py` (malware-capability tooling its
own `check_deps.py` labelled "orientato al malware") and an `x64dbg.py` describing "C2
connections", which the tracked copy had already corrected to vulnerability-research framing. A
leftover from before the malware-oriented content was removed, not an unfinished rename. Moved out
of the working copy (recoverably — see below), and `tests/test_scope.py` now fails if a second
server tree, or a `capa`/`yara` server in *any* tree, reappears. The old guard only looked in
`servers/`, which is why this sat unnoticed.

**Residual risk**

1. **The interactive OIDC login flow is not implemented** — authorization code, PKCE, callback,
   session establishment. `oidc_bearer` validates tokens, which is the enforcement half and what
   an API needs; a browser must get its token from an authenticating proxy. A deployment
   configured for it with no bearer token is **refused**, not waved through.
2. **Enforcement is applied per route, by hand.** Eleven routes carry checks; the rest rely on the
   shared token plus project visibility. A route added without a check is unguarded, and nothing
   catches that yet — a default-deny router is the right fix and belongs with P2-S8.
3. **Project listing resolves ownership by loading each project.** Fine at workstation and small-
   team scale, wrong for thousands of projects: an `owner` column and a WHERE clause belong with
   P2-S5.
4. **The audit trail is tamper-evident, not tamper-proof.** Someone with write access can rewrite
   the file and recompute the chain. An external witness (WORM store or remote collector) is
   P2-S6 proper.
5. **No user management.** Roles come from the IdP's claims; there is no in-product user store,
   invitation flow or per-project member management UI. `USER_MANAGE` exists as a permission with
   nothing behind it yet.
6. Projects created before this slice have no owner and stay visible to everyone who can read
   projects — the alternative was locking analysts out of their own history on upgrade.

**Next:** P2-S3 (MCP gateway: manifests, allow-list, schema validation — closes T-4, the one
remaining Critical-impact threat) or P2-S8 (default-deny router, which closes residual risk 2).

### 2026-10-13 — P1-S5 · S6 ☑ Source→sink hardening, measured

**Files changed** — `reforge/source_to_sink.py` (engine rewritten), `benchmarks/corpus.py`,
`benchmarks/run.py`, `benchmarks/baseline.json`, `tests/test_benchmarks.py` (+8).

**The defect, quantified before touching anything.** `build_candidate_chains()` emitted the full
cartesian product of sources × sinks. Measured on an ordinary, well-written Windows program
(`recv`, `getenv`, `GetCommandLineW`, `memcpy`, `strncpy`, `sprintf`, `CreateProcessW`,
`LoadLibraryW`, `malloc`, `fopen`): **32 "chains" at confidence 0.40–0.55**, none with a call
site, none with any dataflow — including `recv → LoadLibraryW` at 0.55. Both endpoints existing in
an import table is attack surface. Presenting it as a chain, at a confidence that reads like a
lead, is the noise this product category dies of (prompt §7.2).

**Three controls, in order of how much they actually buy**

1. **Tiering, and a hard confidence cap per tier.** A chain now states what is known about it —
   `capability`, `path`, `dataflow`, `confirmed` — as a field the evidence gate reads rather than
   infers from prose. `capability` is capped at 0.20. Also fixed: `validation_seen=False` was
   adding confidence, where "not seen" meant *nobody had looked* — absence of evidence scored as
   evidence of absence. It now only counts once a call site exists.
2. **Aggregation at capability tier.** Rows are grouped by (source kind, sink class) instead of by
   symbol pairing. At this tier nothing distinguishes `recv → memcpy` from `recv → sprintf`; what
   the analyst needs is one row naming all the symbols. Symbol-level identity returns as soon as
   there is a call site, because from then on the rows are distinct code locations.
3. **Mitigation recognition.** A bounded counterpart in the same binary (`strcpy_s` beside
   `strcpy`) is recorded against the chain and costs it confidence. It does not eliminate it — the
   unsafe symbol is still imported — but the analyst sees it.

**Stated honestly: the plausibility matrix buys less than it looks like.** At symbol granularity
almost every pairing is possible *with a conversion* — network bytes really can become a DLL path —
so it drops very little. What it buys is the `conversion` label and its confidence penalty, not
the dropping. It is not a reachability analysis and the module no longer implies it is.

| ordinary program | before | after |
|---|---|---|
| rows emitted | 32 | **10** |
| max confidence | 0.55 | **0.20** |
| rows above `capability` with no call site | 32 | **0** |
| symbols named | all | all (nothing lost to grouping) |

**P1-S6 — measured, not asserted.** The benchmark gained a source→sink dimension: rows emitted,
max confidence, tier violations, with a ceiling declared per fixture. Two fixtures added —
`pe_ordinary_program.exe` (the cartesian-explosion case) and `pe_bounded_string_api.exe` (unsafe
symbol beside its bounded counterparts, the mid-migration codebase).

Corpus-wide: **40 pairings → 18 rows, 0 tier/confidence violations**, precision and recall
unchanged at 1.000. Two tests assert the guard actually fails when the engine gets noisier again —
a benchmark nobody can make fail is not a gate.

**Tests:** 469 → **477**.

**Residual risk**
1. The benchmark's source→sink dimension measures *volume and claim level*, not correctness: there
   is no fixture with a known real chain to verify it is found. That needs a compiled program with
   a planted vulnerability and a live Ghidra, which the synthetic corpus deliberately avoids.
   **Recall on real chains is therefore still unmeasured.**
2. Reachability is still import-table reasoning. Nothing here resolves a call graph, so a sink
   reached only through an indirect call, a vtable or a dynamically resolved import is invisible.
3. The mitigation table is a list of known bounded APIs. A project's own safe wrapper is not
   recognised, and recognising one needs the call-graph work above.
4. Severity banding remains unmeasured: the corpus checks which findings appear, not whether each
   landed in the right band.

**Phase P1 is complete.** Next: P2 — identity and RBAC (P2-S1), durable jobs and isolated workers
(P2-S2), the MCP gateway with manifests (P2-S3). These are infrastructure slices, each
substantially larger than anything in P0 or P1.

### 2026-10-13 — P1-S4 · S7 · S8 · S9 ☑ Structured output, reproducibility, confinement, request policy

**Files added** — `reforge/llm_schema.py`, `reforge/prompts.py`, `reforge/llm_cache.py`,
`tests/test_llm_structured.py` (35), `tests/test_request_policy.py` (18).
**Files changed** — `reforge/llm.py`, `reforge/string_signal.py`, `reforge/workspace.py`,
`reforge/server.py`, `reforge/settings.py`, `reforge/config.py`, `reforge/report_pt.py`,
`tests/test_finding_admission.py`, `README.md`.

#### P1-S4 — structured output that fails closed
`complete_json()` scraped the first brace-balanced object out of whatever the model said and
returned `{}` when nothing parsed — indistinguishable from "the model answered with an empty
object", and for the local provider that was the *primary* path. `llm_schema.structured()` now
validates against a declared Pydantic schema, retries once with the specific validation error fed
back, and **raises** when the attempts are spent. The schema sent as the instruction is the same
object used to validate, so the two cannot drift.

Prompts are versioned by content hash (`reforge/prompts.py`): edit a prompt and its version
changes, which invalidates its cache entries and shows up in the report. The cache
(`reforge/llm_cache.py`) keys on provider + model + prompt version + schema version + input, so an
upgraded model or an edited prompt is a miss rather than a stale hit.

Wired into its real consumer, `string_signal.llm_reclassify` — not left unused the way
`engine/pipeline` was.

**Salvage demoted.** `salvage_tool_calls()` recovered tool calls from free text with no
restriction on which tool, so a sentence the model was only *discussing* could be scraped into an
`add_finding` call: a fabricated claim with a real title on it. Salvaged calls are now restricted
to read-only tools (ADR 0002: best-effort parsing "may never produce a finding"). A misread
`list_imports` costs one wasted call; a misread `add_finding` costs the product's credibility.

#### P1-S7 — the report says what produced it
A `## Reproducibility` section records the artifact SHA-256, analyzer versions, prompt versions
and a fingerprint of the settings that can change a *result* — deliberately not the port or the
log level, so a cosmetic change does not look like a different analysis. Acceptance criterion 9
is only checkable if the report records these. Tested to carry no secret.

#### P1-S8 — allow-list replaces deny-list
`external_roots` names the directories that may be analyzed besides the workspace. The shipped
deny-list covered `/etc`, `/root`, `/proc`, `/sys`, `/boot`, `/dev`, Windows system directories and
`~/.ssh` — and missed `~/.aws`, `~/.config`, `~/Library/Keychains`, `~/.docker` and `/var`, all
verified by test. It survives only as a secondary net for the legacy permissive mode.

A bug found by its own test: a relative entry was silently resolved against the current working
directory, so the allow-list would have meant different things depending on where the server was
started. Relative entries are now refused with a log line.

#### P1-S9 — the drive-by is closed
A state-changing API call whose `Origin` is not ReTrace's own is refused 403. Verified against a
live server:

| | result |
|---|---|
| `POST multipart` with `Origin: https://evil.example` | **403** |
| `POST json` with a foreign `Origin` | **403** |
| same-origin `POST` from the UI | passes |
| `GET` cross-origin (browser's own SOP applies) | 200 |
| curl / CLI with no `Origin` | passes |

CORS stays off unless an origin is named: with no CORS headers a browser already refuses to *read*
a cross-origin reply, and adding a permissive policy "so it works" throws that away. Rate limiting
is a per-client fixed-window counter, 600/min, bounded in memory.

**Tests:** 412 → **469 (+57)**. Lint, benchmark, type check and release artifact all green.

**Residual risk**
1. **P1-S5 and P1-S6 are not done.** Source→sink and reachability hardening (argument-level sink
   checks, safe-wrapper recognition) and the false-positive benchmark on a realistic corpus are the
   two slices that would substantiate the product's precision claims. The current benchmark covers
   the deterministic header/string analyzers only.
2. `complete_json()` is still tolerant, by design — it is the transport under `structured()`. Any
   caller using it directly keeps the old failure mode; `string_signal` was the only one, and it
   was converted.
3. Rate limiting is per-process and per-IP. Behind a reverse proxy every client looks like one
   address; real quotas belong with the control plane (P2).
4. `Origin` checking relies on the browser sending it. That is guaranteed for cross-origin requests
   from a page, which is the threat; it is not a defence against a non-browser attacker, who never
   needed CSRF in the first place.
5. The LLM cache stores customer-derived text under `STATE_ROOT/cache/llm`. It inherits the state
   directory's handling and is never written to a report or log, but it is data at rest with no
   separate retention policy yet.

**Next:** P1-S5 — argument-level sink analysis and safe-wrapper recognition, measured by an
expanded false-positive corpus (P1-S6). Those two belong together: the hardening is only
defensible with the measurement.

### 2026-10-13 — Fix: the P0-S2 auth default broke the bundled SPA

**Reported by the operator**, who found a wall of `401 Unauthorized` in the server log and a UI
that did nothing.

**What happened.** P0-S2 shipped `auth_trust_localhost = false` for every profile. The bundled SPA
carries no token and relies on nothing but being loopback, so opening `http://127.0.0.1:8000`
directly gave: page loads (static assets are deliberately open) → every `/api` call 401 → the UI
looping on `GET /api/projects/undefined` and `GET /api/stream/undefined`. The only way in was the
bootstrap link from the log, which the operator had no reason to know they now needed.

The default was arguable. **The silence was the defect**: `reforge/web/app.js` has ~90 raw
`fetch()` call sites, most of the form `(await fetch(...)).json()` inside a `try/catch`, so an
HTTP 401 became a JSON parse error and was swallowed. Nothing reached the screen.

**Three fixes, in order of importance**

1. `reforge/web/app.js` — `window.fetch` is wrapped once, at the top. A 401 on an `/api/` call
   raises a banner saying what happened and what to do. Behaviour on success is unchanged, and
   every existing and future call site is covered without touching any of them.
2. `reforge/server.py` — `GET /` now issues the session cookie to a caller that **would have been
   allowed to call the API**, so the cookie is the durable credential rather than the reason the
   caller was let in. Tightening `auth_trust_localhost` afterwards cannot break an open tab.
3. `reforge/settings.py` — `auth_trust_localhost` defaults to `true` on `workstation`; `team` and
   `enterprise` still force it `false` and cannot be relaxed. This is what §10.1 asks for: the
   workstation profile may be simpler, as long as it is clearly distinct.

Also: `GET /favicon.ico` returned 404 on every page load; it now answers 204.

**A bug introduced and caught during this fix.** The first version of (2) set the cookie for
anyone reaching `index()`. The auth middleware deliberately lets *every* non-`/api` path through
so the SPA loads for anyone — so "reached the index route" is not evidence of authorisation, and
that version handed the session credential to any client that could fetch `/`. Caught by
`test_a_wrong_bootstrap_token_just_serves_the_page_and_sets_nothing`, which existed for exactly
this. The cookie is now issued only after re-asking `auth.authorize()` the question it would ask
of an API call.

**Verified against a live server**, not only in tests:

| | `workstation` | `enterprise` |
|---|---|---|
| `GET /` from loopback, no token | 200, cookie issued | 200, **no cookie** |
| `GET /api/status` after that | **200** | **401** |
| after the bootstrap link | 200 | **200** |
| cookie flags | `HttpOnly; SameSite=strict; Max-Age=43200; Path=/` | same |

**Tests:** 410 → **412**. Three tests asserted the old default and were rewritten to assert the
profile-dependent contract and the cookie-issuing rule.

**Residual risk.** The 401 banner is the only centralised HTTP error handling in the SPA; other
failure modes (500, network loss) are still swallowed per call site. A real fetch helper belongs
with the SPA modularisation in P2-S8.

### 2026-10-13 — P1-S1 · S2 · S3 ☑ Write-time finding admission

**Closes:** most of P1-7 and T-8. **Partially:** P1-8.

**Files added** — `reforge/engine/intake.py`, `tests/test_finding_admission.py` (29 tests).
**Files changed** — `reforge/session.py` (`add_finding`, `from_dict`), `reforge/agent.py`
(both call sites), `tests/test_security.py`.

**The defect.** The canonical model lived in `reforge/engine/` and ran only when a *report* was
rendered, over data that had been stored unvalidated. A finding could sit in the database claiming
`CONFIRMED` with nothing behind it and look correct until someone exported it.
`engine/llm_safety.sanitize_enrichment()` — the guard that stops a model raising a severity — had
**no caller anywhere in the product**.

**Before → after**

| | before | after |
|---|---|---|
| when the evidence gate runs | at report render | **at write** |
| an unevidenced `CONFIRMED` | stored as CONFIRMED, corrected on the way out | stored as `HYPOTHESIS` with `declared_status` and a cap note |
| CVSS on an unconfirmed finding | emitted from the stored severity | `None`; `potential_severity` recorded separately |
| a malformed finding | coerced by `findings.enrich()` | **rejected**, with the offending field named |
| an LLM raising status/severity/CVSS | accepted — merge took the newest non-empty value | restored from the prior, attempt recorded in `blocked_enrichment` |
| provenance on a stored finding | none | schema version, origin, tool + version, declared vs delivered status |
| legacy projects | left in the legacy shape | upgraded on load, unupgradeable records kept and flagged |
| `engine.intake` external callers | — | 8 |
| tests | 381 | **410 (+29)** |

Benchmark unchanged (precision 1.000, recall 1.000, no regression) — expected, since the corpus
exercises deterministic analyzers whose findings were already well-evidenced. That it did *not*
move is the useful result: the gate tightened without discarding correct findings.

**Two defects found while building this**

1. A declared `CONFIRMED_DYNAMIC` update could never promote a finding, because the prior's
   *inferred* `evidence_bundle` was inherited on merge and `adapter.infer_bundle` trusts any
   bundle already present. The first assessment froze permanently. The bundle is now re-derived
   on merge unless the caller supplies one explicitly.
2. `tests/test_security.py::test_finding_update_on_match` asserted that declaring `CONFIRMED`
   stored `CONFIRMED`. That assertion *was* the defect. It is replaced by three tests covering the
   new contract; the merge semantics it also covered still pass unchanged.

**Residual risk**

1. **`engine/pipeline.py` still has no caller.** ADR 0002 says it becomes the only path; what was
   built is `engine/intake` as the choke point instead. Its stages A and B are documented no-ops
   and C–E duplicate `adapter.normalize`, which `intake` calls directly, so routing one finding at
   a time through a batch stage machine would add indirection without adding enforcement.
   Consolidating or deleting `pipeline` — along with `engine/crypto`, `secrets`, `tools` and
   `ghidra_strategy`, all still unreferenced — is follow-up work. **ADR 0002 is not fully
   discharged, and the gap analysis says so.**
2. **P1-8 is only half closed.** Findings are schema-validated on write, but `llm.salvage_tool_calls()`
   still scrapes tool calls from free text for local models, with no JSON Schema validation and no
   fail-closed behaviour. That is P1-S4.
3. `reforge/findings.py` still holds a second status lattice. It is now a read-side shim
   (`enrich()` runs after admission for fields the report consumes) but it has not been reduced to
   one.
4. The evidence gate's inference is regex-driven (`adapter.infer_bundle`). It reconstructs a
   structured bundle from free-text evidence, which is a heuristic standing in for structured
   provenance the producers should emit directly.
5. Severity thresholds and the cap ladder are not themselves benchmarked: the corpus measures
   which findings appear, not whether each landed in the right band. P1-S6.

**Next:** P1-S4 — schema-validated, fail-closed structured LLM output, and versioned prompts.

### 2026-10-13 — P0-S4 · S5 · S6 · S7 ☑ Release engineering, API contract, benchmarks, docs

Four slices, closing the rest of phase P0.

#### P0-S4 — self-contained, verified release artifact
`git mv web reforge/web` so the SPA ships inside the package; `scripts/build_release.py` builds
sdist + wheel, verifies both against an allow-list and emits `SHA256SUMS`; CI runs the same script
and a **`wheel-runs-alone`** job that installs only the wheel and serves the UI from a directory
with no checkout in it.

Two defects were found by actually trying a wheel-only install:
- the SPA lived outside the package, so `StaticFiles` raised at import;
- `mcp.servers.json` was unpackaged **and** a missing catalogue raised out of the lifespan, killing
  the app. A default catalogue is now packaged, resolution is
  `STATE_ROOT → checkout → packaged default`, and a missing or malformed catalogue degrades to
  "no MCP servers" — which acceptance criterion 4 always claimed but the code did not do.

#### P0-S5 — API versioning and one error contract
`/api/v1/...` is canonical, served by a path rewrite so there is still exactly one implementation
of each of the ~70 routes; `/api/...` stays as a compatibility alias. Every error now answers
`{"error": {"code", "message", "status", "context?}}` with a stable identifier. Two paths were
outside the contract and are now inside it: the auth middleware's hand-rolled Italian 401, and
unmatched `/api/...` paths that fell through to the SPA's `StaticFiles` plain-text 404.

#### P0-S6 — benchmark and profiling baseline
`benchmarks/` with a deterministic, toolchain-free fixture generator (`synth.py` builds genuinely
`pefile`-parseable PE32+ and ELF64 images), 13 fixtures with ground truth derived from each
fixture's **specification** rather than from current output, exhaustive scoring (anything reported
and not expected is a false positive), and a committed `baseline.json` gated in CI.

It found a real false positive on its first run: `malformed_header_only.bin`, a 514-byte `MZ` stub
followed by a byte ramp, was reported MEDIUM **"Likely packed / obfuscated"** — entropy 8.0 tripped
the whole-image check while the failed `pefile` parse made the import-count corroboration default
to "tiny". A packing claim is a claim about a program, and there was none. Fixed in
`static_analysis.py` by requiring a parsed image of at least one page.

| deterministic path | before | after |
|---|---|---|
| precision | 0.975 | **1.000** |
| recall | 1.000 | 1.000 |
| F1 | 0.987 | **1.000** |
| false positives | 1 | **0** |
| FP per artifact | 0.077 | **0.000** |
| crashes on malformed input | 0 | 0 |
| evidence completeness | 0.886 | 0.963 |
| latency p50 / p95 / p99 | — | 0.89 / 4.58 / 34.21 ms |
| peak RSS | — | 40.8 MB |
| reproducible across 3 identical runs | — | yes |

**What that number is not.** 1.000 on 13 synthetic fixtures means "on these known inputs the
deterministic analyzers report exactly the right things". It is a regression gate, not evidence of
product precision. Decompilation, call-graph reachability, source→sink and anything
LLM-orchestrated are **not measured at all** — those need a real compiled program and a live
Ghidra, and no figure for them exists yet. `benchmarks/README.md` says so in the same words.

#### P0-S7 — installation and operation documentation
`docs/installation.md`: install, state layout, first start and the bootstrap link, MCP catalogue
resolution, air-gapped use **with its limits stated**, upgrade (including that safety settings are
deliberately not carried forward), release verification, support bundle, uninstall.

**Tests:** 343 → **378 (+35)**. CI blocking lint clean. `python -m benchmarks.run` reproducible.

**Residual risk**
1. Precision is measured only on the deterministic path. The product's headline claims concern
   evidence quality on real binaries, which the corpus does not reach. P1-S6.
2. `/api/v1` is a rewrite, not a separate route table: a genuine v2 with different shapes needs the
   router split (P2-S8) first.
3. The release is signed only by checksum. Artifact signing and provenance are P2.
4. `docs/installation.md` covers the workstation profile only, because that is the only profile
   that exists.
5. The error envelope is uniform at the boundary, but handler messages are still a mix of English
   and Italian prose. The `code` is now stable, so a client no longer depends on the prose — but
   P3-17 is still open.

**Phase P0 is complete.** Next: **P1-S1/S2/S3** — the canonical finding schema validated at write
time, `engine/pipeline` as the only candidate→finding path, and
`llm_safety.sanitize_enrichment()` actually invoked.

### 2026-10-13 — P0-S3 ☑ Upload limits, magic-byte typing, archive and XML safety

**Closes:** P0-5, and T-2 except parser fuzzing.

**Files added** — `reforge/safe_xml.py`, `tests/test_upload_limits.py` (39 tests).
**Files changed** — `reforge/artifacts.py` (storage path rewritten), `reforge/settings.py`,
`reforge/config.py`, `reforge/server.py`, `reforge/artifact_overview.py`, `reforge/heuristics.py`,
`servers/procmon_mcp.py`, `tests/test_v57_backend.py`.

**Before → after**

| | before | after |
|---|---|---|
| size cap | none — `while True: out.write(chunk)` | `max_upload_bytes` (1 GiB), enforced on bytes that arrive, not on `Content-Length` |
| file count / project bytes | none | `max_artifacts_per_project` (500), `max_project_bytes` (20 GiB) |
| free disk | never checked | `min_free_disk_bytes` (1 GiB) checked before the write and every 64 MiB during it |
| rejected upload | partial file left on disk | written to `.tmp-`, removed on any failure; nothing partial is ever an artifact |
| second endpoint | `/upload` had its own unguarded write loop | both endpoints share one enforced path |
| HTTP contract | n/a | 413 too large · 409 quota/count · 507 no space |
| stored filename | the uploader's, sanitised, with collision suffixes | generated `<artifact-id><ext-from-detected-type>`; original kept as metadata |
| file mode | process default (often `0o644`) | `0o600`, never executable, never group/world readable |
| type detection | after the full write; no archive types | same magic-first sniff, plus 8 archive formats and Mach-O; `type_mismatch` surfaced |
| archives | unrecognised, stored as "binary" | recognised, stored opaque, `expandable: false`, documented no-extraction policy |
| XML entity bomb | parsed — two parsers run automatically on upload | refused before parsing at all 3 sites; refusal reported as an error, not an empty result |
| tests | 304 | **343 (+39)** |

**Verified**

- 343 passed / 1 skipped; CI blocking lint clean; `S314` (untrusted XML) down from 3 unguarded
  sites to 0, the two remaining uses carrying a justified `noqa` next to their guard.
- End to end on a clean install with `max_upload_bytes=64 KiB`, `max_artifacts_per_project=3`:
  a PE named `harmless.txt` stored as `A-….bin type=pe_binary mismatch=True`; a ZIP stored as
  `type=archive`; an oversize upload 413; a fourth file 409; all stored files `0o600`.
- An uploaded entity bomb is stored (it is evidence) but both automatic parsers decline it with
  `{"error": "XML declares a DOCTYPE; refused before parsing…"}` rather than returning
  `events: 0` — a silent empty result would be a false negative, which is worse than a crash in
  an AST tool.

**Residual risk**

1. **No parser fuzzing.** `pefile` is used in six modules and `artifacts.detect_type` reads
   attacker-controlled headers; neither has property-based or fuzz coverage. This is the largest
   remaining piece of T-2 → P1-S6.
2. **No per-phase timeout.** A pathological-but-valid file can still occupy a worker for a long
   time. Bounded by `tool_call_timeout` only for MCP calls, not for in-process analysis.
3. **Quarantine is permissions-based, not a sandbox.** Files are stored non-executable, owner-only,
   under the project directory. A separate non-executable mount, per-customer isolation and
   verifiable deletion are P2-S2.
4. **The no-extraction policy is a product decision, not a technical barrier.** It is enforced by
   a test that fails if extraction code appears; if archive support is ever wanted it needs bomb,
   traversal, symlink and nesting defences designed in from the start.
5. The XML guard scans the first 64 KiB for a DOCTYPE and assumes UTF-8/BOM. A UTF-16 document
   with a late DOCTYPE would slip past the scan — ElementTree would then expand it. Narrow, but
   real; tightening it means a byte-order-aware prolog reader.
6. `max_upload_bytes` defaults to 1 GiB. Large firmware or a multi-GB Procmon export needs an
   explicit, deliberate raise. That is the intended direction of the error.

**Next:** P0-S6 — benchmark and profiling baseline, or P0-S4 — sanitized release artifact.

### 2026-10-13 — P0-S2 ☑ Typed layered configuration + fail-closed defaults

**Closes:** P0-3, P0-4. **Partially:** P1-12 (confinement default flipped), T-6 (credential out of the URL).

**Files added** — `reforge/settings.py`, `tests/test_settings_and_defaults.py`.
**Files changed** — `reforge/config.py` (now a facade), `reforge/server.py`, `pyproject.toml`,
`README.md`, `docs/adr/0001-config-and-secrets.md`, `docs/gap-analysis.md`.

**Before → after**

| | before | after |
|---|---|---|
| where settings live | `reforge/config.py`, rewritten by regex at runtime | typed model + `STATE_ROOT/settings.json`; source never written |
| layering | none | defaults → legacy block (once) → file → `REFORGE_*` env → profile |
| invalid value | applied, or a partial relaxation left behind | rejected by name; running settings untouched |
| `safety_mode` | `autonomous` → **0** of 6 risky tools gated | `assisted` → **6** of 6 gated, read-only analysis still ungated |
| `allow_outside_workspace` | `true` → any non-deny-listed file in the analyst's home readable | `false` → refused |
| `auth_trust_localhost` | `true` → any local process reaches `/api` | `false` → credential required |
| credential transport | `?token=` accepted on every API call; JS-readable cookie | header or `HttpOnly`/`SameSite=Strict`/`Max-Age` cookie; query string refused on `/api` |
| remote browser use | broken — nothing ever set the cookie the middleware read | bootstrap link sets it, SSE and `fetch()` authenticate |
| deployment profiles | none | `workstation` / `team` / `enterprise`; non-workstation cannot be relaxed |
| posture visibility | one Italian log line | full posture at every start + warning per relaxation + legacy-drift report |
| tests | 266 | **304 (+38)** |
| mypy on security-critical modules | 9 errors | 8, none in `settings.py` or `config.py` (pydantic plugin enabled) |

**Verified**

- 304 passed / 1 skipped; CI blocking lint subset (`E9,F821,F822`) clean.
- Fresh install, no settings file: `Profile: workstation | safety=assisted (approval gate ON) | external paths=False`.
- Legacy migration on this working copy carried `llm_provider=local` and `local_model=qwen3:30b`
  forward and explicitly refused to carry `safety_mode=autonomous`, `allow_outside_workspace`,
  `auth_trust_localhost` — logged, not silent.
- `enterprise` profile constructed with every relaxation requested at once: all four forced back.
- Persisting settings in a subprocess left `reforge/config.py` byte-identical (sha256 compared).
- A sentinel API key passed to `persist_settings()` does not appear in `settings.json`.
- Bootstrap: `GET /?token=…` → 303 to `/`, cookie `HttpOnly; SameSite=Strict; Max-Age`, and the
  cookie then authenticates `/api/status`; `GET /api/status?token=…` → 401.

**Residual risk**

1. `auth_trust_localhost=false` is a **visible behaviour change**: the browser must be opened via
   the bootstrap link once per 12 h instead of just `http://127.0.0.1:8000`. Deliberate, and the
   link is printed at every start.
2. `safety_mode=assisted` will prompt for approval where the previous shipped build did not. Also
   deliberate — it is the gap being closed. `REFORGE_SAFETY_MODE=autonomous` restores the old
   behaviour on a workstation.
3. The legacy `USER SETTINGS` block still physically exists in `reforge/config.py`. Keeping it is
   what makes the one-time migration possible for existing installs; `legacy_drift()` stops it
   becoming a silent footgun. Deleting it is a P2 cleanup once no install predates P0-S2.
4. CSRF tokens, a strict CORS policy and rate limiting are **not** in this slice — T-5 (a
   cross-origin simple `POST multipart` from a page the analyst visits) is reduced by dropping
   loopback trust but not formally closed. P1-S9.
5. Confinement is now on by default, but when an operator turns it off the fallback is still the
   incomplete deny-list in `workspace.py`. The allow-list of permitted roots is P1-S8.
6. `reforge/config.py` is still 400+ lines of facade plus a dead literal block. It shrinks when
   item 3 lands.

**Next:** P0-S3 — upload limits, magic-byte gating, archive safety, quarantine.

### 2026-10-13 — P0-S1 ☑ Packaging, dependency declaration, state isolation, CI

**Closes:** P0-1, P0-2, P3-16. **Partially:** P0-6 (artifact check in CI; rotation is the operator's action).

**Files added** — `pyproject.toml`, `.gitattributes`, `.github/workflows/ci.yml`,
`tests/test_packaging_and_state.py`, `docs/` (8 documents + 5 ADRs).
**Files changed** — `requirements.txt`, `README.md` (Setup/Run), `reforge/config.py`,
`reforge/knowledge.py`, `reforge/__main__.py`, `reforge/server.py`.
**Untracked** — `.DS_Store`, `servers/.DS_Store` (`git rm --cached`; files remain on disk).

**Before → after**

| | before | after |
|---|---|---|
| `pip install -r requirements.txt && python -m reforge` | `ModuleNotFoundError: No module named 'fastapi'` | starts; 72 routes; SPA served (200, 50 246 bytes) |
| declared runtime deps | 3 of 8 module-level imports | 8 of 8, verified by test |
| optional deps | undeclared or mixed into an unrelated file | 6 named extras, all lazy-imported |
| importing the package | writes `.reforge_secrets.json` + `knowledge/.reforge_index.json` into the source tree | source tree byte-identical; both land under `STATE_ROOT` |
| read-only install | silent write failure → new token every start | persistence failure is logged, not swallowed |
| config at import | rewrites `reforge/config.py` to blank a key literal | copies the key to the store and warns; no source write |
| entry point | `python -m reforge` only | `retrace` console script + `python -m reforge` |
| `git diff --stat` | 100 files, 25 852 +/− (2 real lines) | `.gitattributes` added; renormalization is a separate, deliberate commit |
| CI | none | test (Ubuntu 3.10 and 3.12; Windows suspended until it can be run from a Windows machine), hygiene, lint, types, dist-sanitization |
| tests | 256 | 266 (+10) |

**Verified**

- Clean `git archive HEAD` checkout + fresh venv: reproduced the original `ModuleNotFoundError`.
- Sanitized copy + fresh venv + `pip install -e ".[dev]"`: import OK, `GET /` 200, 266 passed / 1 skipped.
- MCP servers all unavailable → host reports `0 tools` and the app serves normally (graceful degradation, §16.4/16.5).
- Timestamp sentinel across a full suite run + an app import: zero files created or modified in the source tree.
- `python -m build` → sdist + wheel, asserted free of secrets, databases, state directories and caches.
- `retrace` console script installed; `prompts/*.md` and 11 `playbooks/*.yaml` present in the wheel.

**Residual risk**

1. `config.persist_to_file()` still rewrites `reforge/config.py` on `POST /api/settings`. Not on
   the import path, so install and test reproducibility are unaffected. Marked DEPRECATED in the
   source; removed in **P0-S2**.
2. The wheel does not bundle `web/`; `server._resolve_web_root()` already supports a packaged
   layout, so bundling is a file move in **P0-S4**.
3. Shipped defaults are still fail-open (`SAFETY_MODE = "autonomous"`, `ALLOW_OUTSIDE_WORKSPACE`,
   `AUTH_TRUST_LOCALHOST`). Untouched here deliberately — changing a safety default is its own
   slice with its own tests. **P0-S2**.
4. `.reforge_secrets.json` exists in this working tree. Rotation is `docs/secret-rotation.md` and
   requires operator action at the issuer; it cannot be done from here.
5. Line endings are not yet renormalized — only the policy is in place. Renormalizing rewrites all
   100 files and must be its own commit, after the pending working-tree changes are committed.
6. Lint (1 487 findings) and mypy (9) are advisory in CI. Two items surfaced and deferred to P1:
   `reforge/evidence_graph.py:416,430` string-built SQL, and 51 `try/except/pass` + 28 bare
   `except` sites that hide failures. The mypy hits in `engine/schema.py` were checked and are
   narrowing false positives, not defects.

**Next:** P0-S2 — typed configuration + fail-closed defaults.
