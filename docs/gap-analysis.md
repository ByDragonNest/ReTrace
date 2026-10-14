# ReTrace — gap analysis

Baseline commit `89c721a`, snapshot 2026-10-13. Every finding below was reproduced against a
clean `git archive HEAD` checkout in a throwaway directory, never against the working tree.

**Reproduction environment**

```bash
git archive HEAD | tar -x -C /tmp/clean
python3 -m venv /tmp/venv && /tmp/venv/bin/pip install -r /tmp/clean/requirements.txt
cd /tmp/clean && REFORGE_STATE_DIR=/tmp/state /tmp/venv/bin/python -c "import reforge.server"
```

Severity key — **P0** blocks a customer install or breaks a safety claim · **P1** correctness and
precision of the product's core output · **P2** operating a shared install · **P3** ecosystem.

**Scope note (2026-10-13).** This document was written against a brief asking for an enterprise
platform, and its title said so. ReTrace is a tool for **a single analyst and small teams**. Two
closing criteria below asked for enterprise-scale deliverables and are re-stated; the gaps
themselves were real and the analysis of them stands. Nothing is removed — see
[Out of scope](ROADMAP.md#out-of-scope) for what was cut and why.

---

## P0

### P0-1 — The documented install path does not produce a working application
*Impact: critical · Likelihood: certain (reproduced) · Effort: S* — **CLOSED in slice P0-S1**

`requirements.txt` declares `mcp`, `pefile`, `requests`. The application additionally imports, at
module import time: `fastapi`, `uvicorn`, `pydantic` (`reforge/server.py:9-12`,
`reforge/__main__.py:2`), `yaml` (`reforge/playbook.py`), `openai` (`reforge/llm.py`),
`anthropic` (`reforge/llm.py`), `docx` (`reforge/report_docx.py`), `xhtml2pdf`
(`reforge/report_export.py`), `pypdf`/`fitz` (`reforge/knowledge.py`), plus `python-multipart`
which FastAPI requires for the `UploadFile` routes. Observed:

```
ModuleNotFoundError: No module named 'fastapi'
  File ".../reforge/server.py", line 9, in <module>
```

There is no `pyproject.toml`, no lock file, no console entry point, no extras split.
`pip install -r requirements.txt && python -m reforge` — the README's own instructions — fails.

**Closing criterion:** a clean checkout + documented command starts the API and serves the SPA; a
test asserts that every third-party top-level import in `reforge/` is covered by a declared
dependency or guarded by an optional-import fallback.

### P0-2 — Importing the package writes a credential into the source tree
*Impact: critical · Likelihood: certain (reproduced) · Effort: S* — **CLOSED in slice P0-S1**

`reforge/config.py` pins `SECRETS_FILE = ROOT / ".reforge_secrets.json"` where `ROOT` is the
**source** root, and at import time generates an auth token and writes it there when none exists.
`knowledge.py:57` writes `knowledge/.reforge_index.json` the same way. `REFORGE_STATE_DIR`
redirects the database, projects, sessions, jobs and workspace — but not these two.

Running the suite in the clean checkout created, inside the source tree:
`.reforge_secrets.json`, `knowledge/.reforge_index.json`, `.pytest_cache/`.

Consequences: a read-only install (site-packages, container image, air-gapped media) silently
fails the write — it is wrapped in `try/except: pass` — so a **new token is generated on every
start** and the previous one stops working; the release artifact is contaminated; and the §16
acceptance criterion "no writes into the source repository during tests" fails.

**Closing criterion:** secrets and derived indexes live under `STATE_ROOT`; a test asserts the
source tree is byte-identical before and after a full suite run plus an app import.

### P0-3 — Configuration is implemented as source-code mutation
*Impact: high · Likelihood: certain · Effort: M* — **CLOSED in slice P0-S2**

`config.persist_to_file()` regex-rewrites `reforge/config.py` when settings change in the UI
(`POST /api/settings` → `config.py:persist_to_file`). `_migrate_secrets_out_of_source()` rewrites
the same file at import. There is no typed configuration object, no precedence chain, no
validation, and no way to ship an immutable application image: every customer install becomes a
divergent fork of the source, and an upgrade overwrites their settings.

**Closing criterion:** layered, typed, validated config (defaults → file → env → secret provider →
audited admin override); `reforge/config.py` becomes a schema + loader that never writes itself;
settings changes persist to a state-dir file.

### P0-4 — Shipped defaults are fail-open, and contradict both the comment above them and the README
*Impact: critical · Likelihood: certain · Effort: S* — **CLOSED in slice P0-S2**

| Setting | Shipped value | What the code comment / README says |
|---|---|---|
| `SAFETY_MODE` (`config.py:93`) | `"autonomous"` | comment on the line above: *"DEFAULT is `assisted`"* |
| `REQUIRE_APPROVAL` (`config.py:38`) | `False` | README: *"anything that runs code … pauses for your approval"* |
| `ALLOW_OUTSIDE_WORKSPACE` (`config.py:110`) | `True` | any absolute path on the host is analyzable |
| `AUTH_TRUST_LOCALHOST` (`config.py:101`) | `True` | any local process reaches `/api` with no token |

With `SAFETY_MODE = "autonomous"`, `policy.requires_approval()` returns `False` unconditionally
(`policy.py:103`) — the approval gate, the product's central safety claim, is **off in the shipped
configuration**. The server logs a warning at startup and proceeds.

**Closing criterion:** defaults are fail-closed (`assisted`, confinement on, loopback not trusted
when a token exists); relaxing any of them is an explicit, audited operator action; a test asserts
the shipped defaults.

### P0-5 — Uploads are unbounded and untyped at the storage boundary
*Impact: high · Likelihood: high · Effort: S* — **CLOSED in slice P0-S3**

`POST /api/projects/{pid}/upload` (`server.py:311`) loops `await file.read(1 MB)` and writes until
the stream ends. `artifacts.store_stream` (`artifacts.py:157`) does the same. There is no size
limit, no file-count limit, no per-project quota, no free-space check, no magic-byte gate before
the bytes land on disk, no quarantine directory and no non-executable storage mode. Type
detection (`artifacts.detect_type`) happens *after* the full write.

**Closing criterion:** configurable size/count/quota limits enforced *during* streaming with the
partial file removed on violation; magic-byte detection; upload tests with an oversized file, a
zero-byte file, a corrupt archive and a traversal filename.

### P0-6 — The distributable is not sanitized, and live secrets are present now
*Impact: critical · Likelihood: certain · Effort: S*

The working tree currently contains `reforge.db` (77 KB), `reforge.db-wal` (78 KB),
`reforge.db-shm`, `.reforge_secrets.json`, `projects/`, `workspace/`, `sessions/`, `jobs/` and a
**tracked** `.DS_Store`. `.gitignore` covers most of these, but `.DS_Store` was committed before
the rule existed so the rule does not apply to it, and nothing produces a sanitized release
artifact — there is no packaging step at all.

`.reforge_secrets.json` holds the API access token and any configured provider key. Its value was
not read and is not reproduced anywhere in this analysis. It must be treated as exposed on this
host and rotated. Procedure: `docs/secret-rotation.md`.

**Closing criterion:** a `make dist` / build step emits an artifact that provably excludes `.git`,
databases and WAL/SHM, `projects/`, `workspace/`, `sessions/`, `jobs/`, caches, samples and any
secrets file; a test asserts the artifact's file list against an allow-list.

---

## P1

### P1-7 — The canonical engine is not on the analysis path
*Impact: high · Likelihood: certain · Effort: L* — **LARGELY CLOSED in slice P1-S1/S2/S3** (see note at the end of this entry)

`reforge/engine/pipeline.py` documents and implements the mandatory A..H pipeline. It has **zero
callers**. `engine.crypto`, `engine.secrets`, `engine.tools`, `engine.ghidra_strategy` and
`engine.llm_safety` likewise have zero callers outside the package. The parts that do run —
`schema`, `adapter`, `dedup`, `antifp`, `evidence_gate`, `status`, `claims` — run only inside
`report_pt._engine_view()` at **report build time**: the function swaps `session.findings` for the
normalized view while the body renders and restores it in a `finally`, so the normalization is a
side effect of rendering rather than a property of the stored data.

Meanwhile `reforge/findings.py` keeps a second, different status lattice that the rest of the
application uses. Two models, one system of record, normalization applied last.

Concretely: `engine/llm_safety.sanitize_enrichment()` — the guard that prevents an LLM from
raising severity or changing status — is **not invoked anywhere**.

**Closing criterion:** one canonical finding schema, versioned and validated at write time;
`add_finding` and every deterministic analyzer go through it; `engine/pipeline` is the only path
from candidate to stored finding; `findings.py` becomes a thin compatibility shim with a
documented migration.

### P1-8 — LLM output is scraped, not validated
*Impact: high · Likelihood: high · Effort: M*

`llm.salvage_tool_calls()` (`llm.py:138`) recovers tool calls from free text via JSON scraping and
a CLI-flag parser; `_first_json_object()` tolerates fences and surrounding prose;
`complete_json()` returns `{}` when parsing fails. For the local provider this best-effort path is
the **primary** path, not a fallback. There is no JSON Schema or Pydantic validation of model
output, no constrained decoding, no bounded schema-retry, and no fail-closed behaviour: an
unparseable response degrades silently instead of refusing to produce a finding.

**Closing criterion:** every structured LLM output is schema-validated before use; validation
failure is an error, never a partial result; prompts are versioned and the cache key includes
model + prompt version.

### P1-9 — No benchmark or evaluation framework
*Impact: high · Likelihood: certain · Effort: L*

No `benchmarks/`, no `evals/`, no corpus, no ground truth, no precision/recall/F1, no false-positive
rate, no per-phase timing, no p50/p95/p99, no token/cost/latency measurement, no cross-release
comparison. The README's precision and anti-false-positive claims are therefore unfalsifiable, and
no change to the engine can be shown to improve or regress anything.

**Closing criterion:** `benchmarks/` with synthetic vulnerable/patched fixture pairs and
documented ground truth; `evals/` for model behaviour; a published baseline; CI fails on
regression beyond a stated threshold.

### P1-10 — Authentication is a shared secret; there is no identity, RBAC, CSRF or CORS policy
*Impact: high · Likelihood: high · Effort: L*

`reforge/auth.py` compares one process-wide token and returns `True` for any loopback client when
`AUTH_TRUST_LOCALHOST` is set (the default). There are no users, no organizations, no
project-level authorization, no roles, no service accounts, no session expiry or revocation, and
no audit of who approved a gated action.

No `CORSMiddleware` is installed and no CSRF token exists. Because loopback is trusted, a page the
analyst visits in the same browser can issue *simple* cross-origin requests — notably
`POST multipart/form-data`, which is not preflighted — against `http://127.0.0.1:8000/api/...`.
The attacker cannot read the response, but `/api/projects/{pid}/upload` and
`/api/projects/{pid}/artifacts` are reachable write endpoints.

**Closing criterion:** OIDC SSO, RBAC (Administrator / Security Manager / Analyst / Reviewer /
Read-only), per-project authorization, `SameSite`/`Secure`/`HttpOnly` cookies, CSRF tokens on
state-changing routes, a strict same-origin CORS policy, and tests for each.

### P1-11 — No CI, no lint, no type checking, no security scanning; the suite is unit-only
*Impact: high · Likelihood: certain · Effort: M*

No `.github/`. 256 tests pass in ~1.0 s against a clean checkout, which is the signature of pure
unit tests: there is no integration test that starts the app, no MCP contract test, no end-to-end
test, no migration test, no concurrency test, no fuzz/property test on the untrusted parsers
(`artifacts.detect_type`, the Procmon XML reader, `bindiff`, PE parsing). The `anthropic`,
`openai`, `python-docx`, `xhtml2pdf` and `pypdf` paths are not installed in the baseline
environment and are therefore wholly unexercised.

**Closing criterion:** CI runs install-from-clean, lint, type check, the full suite, secret
scanning and dependency/licence scanning on every push; MCP contract tests and parser fuzzing exist.

### P1-12 — Deny-list path confinement is incomplete
*Impact: medium · Likelihood: medium · Effort: S*

`workspace.safe_resolve()` rejects traversal and resolves symlinks — correct — but with
`ALLOW_OUTSIDE_WORKSPACE = True` (the default) confinement is replaced by a deny-list
(`workspace.py:_DENY_PARTS`, `_DENY_NAMES`) covering `/etc`, `/root`, `/proc`, `/sys`, `/boot`,
`/dev`, Windows system directories and `.ssh`. It does not cover `~/.aws`, `~/.config`,
`~/Library/Keychains`, `~/.docker`, `/var`, `/usr/local/etc` or cloud-credential paths. A
deny-list at a security boundary is structurally incomplete.

**Closing criterion:** confinement is the default; external paths require an explicit, audited
allow-list of roots rather than a deny-list of exclusions.

---

## P2

### P2-13 — Monolithic modules block maintenance and review
*Impact: medium · Likelihood: certain · Effort: L*

`servers/x64dbg.py` 2029 LOC · `reforge/server.py` 1311 LOC with ~70 routes whose handlers mix
HTTP, orchestration, persistence and graph projection · `reforge/agent.py` 1140 LOC ·
`web/app.js` 4272 LOC / 283 KB with 316 top-level declarations · `web/styles.css` 141 KB.
No domain layer separate from API and persistence; no API versioning (`/api/...`, not
`/api/v1/...`); no uniform error model.

**Closing criterion:** routers split by domain behind a versioned prefix; a domain layer with its
own tests; the SPA split into modules; each extraction preceded by characterization tests.

### P2-14 — Two server trees, one of them untracked
*Impact: medium · Likelihood: certain · Effort: S* — **CLOSED in slice P2-S9**

`servers/` (tracked, 22 files) and `mcp_servers/` (**untracked**, 27 files) are near-identical.
`mcp.servers.json` references `servers/...`.

> **Corrected 2026-10-13 (slice P2-S9).** This entry originally said the untracked tree was the
> *newer* one. It was not: `mcp_servers/` was **older**. It still carried `capa_mcp.py` —
> malware-capability tooling its own `check_deps.py` labelled *"opzionale, orientato al malware"* —
> and an `x64dbg.py` that still described finding *"C2 connections"*, which the tracked copy had
> already corrected to *"which remote endpoints feed untrusted input into the process"*. Its
> `procmon_mcp.py` was 27 lines behind. It was a leftover from before the malware-oriented content
> was removed, not an unfinished rename. Moved out of the working copy; `tests/test_scope.py` now
> fails if a second server tree or a `capa`/`yara` server reappears in any of them.

**Closing criterion:** one tree, under version control, referenced by the manifest; the duplicate
removed with its unique content merged.

### P2-15 — Single-node persistence, in-process jobs, no migrations
*Impact: medium · Likelihood: high · Effort: L*

SQLite `reforge.db` plus mirrored `projects/*.json`; `job_manager` holds jobs in process and
persists them to `jobs/`, restoring on startup (`server.py:lifespan`). No schema migrations, no
optimistic locking or versioning on findings, no object storage, no durable queue, no backup or
restore procedure, no retention or per-customer deletion.

**Closing criterion (re-stated 2026-10-13):** versioned, reversible migrations with a mandatory
pre-migration backup; optimistic locking so concurrent saves cannot silently overwrite; retention
as soft-delete plus a separate deliberate purge; a documented backup and restore procedure.

~~a documented workstation profile (SQLite) and enterprise profile (RDBMS + object storage +
durable queue) behind one repository interface~~ — cut. A second adapter set exists to support
concurrent writers across nodes, and this product has one node; an interface with one
implementation is indirection, not abstraction. [ADR 0005](adr/0005-persistence-profiles.md) is
superseded. The *discipline* half of the original criterion is what mattered, and it is
implemented.

Single-node persistence is therefore no longer a gap. It is the design.

---

## P3

### P3-16 — Line-ending churn makes every diff unreviewable
*Impact: low operationally, high for support · Likelihood: certain · Effort: XS*

No `.gitattributes`. `git diff --stat` on the working tree reports **100 files changed, 25 852
insertions(+), 25 852 deletions(-)**; `git diff --ignore-all-space --stat` reports **1 file, 2
lines** (`reforge/config.py`: `LLM_PROVIDER` and `LOCAL_MODEL`, the operator's local settings).
Every tracked file is CRLF in the working tree and LF in `HEAD`. Code review, `git bisect`, and
patch-based customer support are all impossible in this state.

**Closing criterion:** `.gitattributes` normalizing text files; a single, deliberate
renormalization commit; CI rejects mixed endings.

### P3-17 — User-facing language is mixed
*Impact: low · Likelihood: certain · Effort: S*

`config.UI_LANG` states "ReTrace is English-only", yet API errors, startup logs and injected
transcript messages are Italian (`server.py:362` `"[SISTEMA] L'operatore ha caricato un
artifact…"`, `mcp_host.py:229` `"non ha risposto entro {timeout}s"`, `server.py:lifespan`
`"AUTH abilitata · loopback fidato=…"`). The SPA carries 247 inline i18n keys with no extraction
mechanism. §13 asked for Italian **and** English as a product feature; at the time of this snapshot it was
neither, it was both at random.

**Closing criterion (re-stated 2026-10-13):** the UI is English, and a test asserts it — no
Italian literal, no language toggle, no second catalogue to drift out of parity.

~~`it` and `en` complete, with parity enforced~~ — cut by product decision: the app is
English-only. The bilingual machinery was built under §13 and then removed; `test_localization_a11y.py`
now enforces English as a contract rather than enforcing parity between two catalogues.

The gap as *diagnosed* was correct and is closed either way: the failure was mixed language with no
extraction mechanism, and that is fixed.

---

## Summary table

| ID | Gap | Pri | Effort | Depends on | Status |
|---|---|---|---|---|---|
| P0-1 | Clean install broken; no packaging | P0 | S | — | ✅ P0-S1 |
| P0-2 | Import writes a credential into the source tree | P0 | S | — | ✅ P0-S1 |
| P0-3 | Configuration by source mutation | P0 | M | P0-1, P0-2 | ✅ P0-S2 |
| P0-4 | Fail-open shipped defaults | P0 | S | P0-3 | ✅ P0-S2 |
| P0-5 | Unbounded, untyped uploads | P0 | S | P0-3 | ✅ P0-S3 |
| P0-6 | Unsanitized distributable; secrets present | P0 | S | P0-1 | ✅ P0-S4 (rotation is the operator's) |
| P1-7 | Canonical engine not on the analysis path | P1 | L | P0-1 | ◐ write-time admission landed; `engine/pipeline` still unused |
| P1-8 | LLM output scraped, not validated | P1 | M | P1-7 | ✅ P1-S4 (schema-validated, fail-closed; salvage restricted to reads) |
| P1-9 | No benchmark/eval framework | P1 | L | P0-1 | ◐ deterministic + source→sink dimensions measured; model evals and real-chain recall open |
| P1-10 | Shared-token auth; no identity/RBAC/CSRF/CORS | P1 | L | P0-3 | ✅ P1-S9 + P2-S1 (OIDC bearer, RBAC, project isolation, audit) |
| P1-11 | No CI; unit-only suite | P1 | M | P0-1 | ◐ CI + API/contract tests landed; fuzz and MCP contract tests open |
| P1-12 | Deny-list path confinement | P1 | S | P0-4 | ✅ P1-S8 (allow-list `external_roots`) |
| P2-13 | Monolithic modules | P2 | L | P1-11 | ◐ authorization surface extracted (P2-S8); server.py and app.js still monolithic |
| P2-14 | Duplicate untracked server tree | P2 | S | — | ✅ P2-S9 |
| P2-15 | Single-node persistence, no migrations | P2 | L | P0-3 | ✅ P2-S5 (migrations, backup, locking, retention); multi-node adapters ✂ out of scope |
| P3-16 | Line-ending churn | P3 | XS | — | ✅ P0-S1 (`.gitattributes` + renormalization; CI rejects mixed endings) |
| P3-17 | Mixed user-facing language | P3 | S | P2-13 | ✅ P2-S10 (English throughout, enforced by test; Italian ✂ out of scope) |


---

## Addendum — status after slice P1-S1/S2/S3 (2026-10-13)

`engine/intake.admit()` is now the single door every finding comes through, called from
`session.add_finding()`. What that closed:

- the canonical schema is validated **on write**, and an invalid record is rejected rather than
  repaired;
- the evidence gate, anti-FP rules, status cap and risk scoring run before storage, so a finding
  can no longer sit in the database claiming CONFIRMED with nothing behind it;
- `engine/llm_safety.sanitize_enrichment()` is invoked on every LLM-originated update, and what it
  blocks is recorded on the finding instead of being dropped;
- every stored finding carries provenance: schema version, origin, producing tool and version,
  declared status versus delivered status;
- projects written before the change are upgraded on load.

**Not closed.** `engine/pipeline.py` still has no caller. Its stages A and B are documented
no-ops ("candidate generation is the caller's job") and C–E duplicate `adapter.normalize`, which
`intake` calls directly. Routing one finding at a time through a batch stage machine would add
indirection without adding enforcement. Consolidating `pipeline` with `intake`, or deleting it,
is follow-up work — as is `engine/crypto`, `engine/secrets`, `engine/tools` and
`engine/ghidra_strategy`, which remain unreferenced.
