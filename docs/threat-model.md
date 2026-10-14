# ReTrace — threat model

Baseline commit `89c721a`. Method: STRIDE over the trust boundaries in
`docs/data-flow-and-trust-boundaries.md`. Each threat states the control that exists today and
the gap that must close. `TB-n` and `P0-n`/`P1-n` are cross-references.

## Assets

**A1** customer binaries and traces (often under NDA) · **A2** derived analysis and findings ·
**A3** the analyst workstation (or the RE VM ReTrace runs on) · **A4** provider API
keys and the access token · **A5** the integrity of the report — a report asserting a vulnerability
that does not exist, or missing one that does, is the product's core liability.

## Adversaries

**ADV-1 — the analyzed artifact, and what you do to it.** The primary adversary, and the one most
easily mis-framed.

ReTrace analyses software that is **benign but untrusted** — a customer's own build, a third-party
component, a driver, firmware. It is not malware and is not assumed to be attacking anyone. Two
real risks remain, and neither needs it to be:

* **Malformed input breaking our parsers.** A corrupt PE, a 50 GB Procmon export, a string from
  the binary that the model reads as an instruction. This is ordinary untrusted-input handling and
  has nothing to do with intent.
* **What the analyst does to the program.** Confirming a memory-corruption bug means feeding it
  inputs designed to corrupt it and watching where control flow goes. A working proof of concept
  *is* arbitrary code execution — produced by the analyst, in a program that was never hostile.
  That is the risk in dynamic confirmation, and it is a vulnerability-research risk, not a malware
  one.

An earlier version of this document called ADV-1 "hostile content" and framed T-3 as "executing
hostile code". That is malware-analysis framing and it is wrong for this product: it inflates the
remedy (a detonation sandbox) for a problem whose actual shape is narrower.
**ADV-2 — a malicious or compromised MCP server.** Runs as a child process with the host's full
privileges.
**ADV-3 — a local process or a web page in the analyst's browser.** Reaches a loopback API that
trusts loopback.
**ADV-4 — a network attacker**, once the product is deployed beyond one workstation.
**ADV-5 — an over-broad insider.** No roles exist, so every user is an administrator.
**ADV-6 — the model itself**, producing confident, unsupported claims.

## Threats

### T-1 (ADV-1, TB-5) Prompt injection from analyzed content — *Tampering / Elevation*
A string inside the sample instructs the agent to approve an action, rewrite a finding, or exfiltrate
a path. **Today:** results are wrapped as DATA and the system prompt says not to trust them. That is
a prompt-level mitigation only. **Gap:** no sanitization, no detector, no adversarial test; and in
`SAFETY_MODE = "autonomous"` there is no human in the loop to catch a hijacked tool call.
**Close:** structural data/instruction separation, an injection corpus in `evals/`, the approval gate
fail-closed, and `llm_safety.sanitize_enrichment()` actually invoked (P0-4, P1-7).

### T-2 (ADV-1, TB-7) Malformed artifact causes resource exhaustion or memory-unsafety — *DoS*
Zip bomb, 50 GB Procmon XML, PE with pathological section tables, deeply nested archive.
**Mitigated in slice P0-S3:** per-upload size cap enforced on the bytes that actually arrive,
per-project file-count and byte quotas, a free-disk reservation checked before and during the
write, partial files removed on any rejection, and storage at mode `0o600` under a generated
filename. Archives are recognised by magic bytes, stored opaque and **never expanded** — the
no-extraction policy is the zip-bomb, entry-traversal and nesting mitigation, and a test fails the
build if extraction code appears. XML entity expansion ("billion laughs") is refused before
parsing at all three `iterparse` sites, two of which run unattended on upload; the refusal
surfaces as an explicit error rather than an empty result, so it cannot read as "nothing found".
**Still open:** `pefile` usage across six modules and `artifacts.detect_type` have no
property-based or fuzz coverage, and there are no per-phase timeouts. P1-S5/P1-S6.

### T-3 (ADV-1, TB-3/TB-4) Dynamic confirmation runs code whose control flow is being corrupted — *Elevation*
x64dbg, Frida and any `dynamic_execution` tool run the target on the analyst's host while the
analyst deliberately drives it off its intended path. The program is not hostile; the inputs are,
because that is the point. When the proof of concept works, something on that machine executes
attacker-shaped data — and the machine is the analyst's own, with their keys, their mail and every
other customer's binary on it.
**Partly mitigated.** The approval gate is on by default since P0-S2. Slice P2-S2 added an
isolation contract: each execution target declares what it actually isolates, `dynamic_execution`
asks for VM isolation, and the `team` profile **refuses** to run it in the control
plane with no way to opt back in. Jobs get ephemeral workspaces whose deletion is verified, and a
wall-clock ceiling.

**Still open.** On a workstation the target still runs in the ReTrace process with the analyst's
privileges — warned about every time rather than silent, which is visibility, not containment.

**Proportionate remedy.** The earlier entry here called for a managed Windows worker fleet. That
is the malware-analysis answer to a question this product does not ask, and it is more
infrastructure than the risk justifies for a tool whose dynamic confirmation is a minority of the
work. What the risk actually calls for, in order of cost:

1. **Run ReTrace itself on the RE virtual machine** the analyst almost certainly already has, next
   to x64dbg and Ghidra, rather than on their daily workstation. This is configuration and a
   sentence of documentation, and it closes most of the exposure.
2. **Refuse unisolated dynamic execution** where the deployment is shared — already done
   (`allow_unisolated_execution`, forced false on `team`).
3. A dedicated worker fleet only if and when customers run assessments unattended at a scale where
   step 1 stops being practical.

Ranked below T-8 and T-1 on that reading: both of those are about the product producing wrong
answers, which is the failure that loses a customer.

### T-4 (ADV-2, TB-4) Malicious or compromised MCP server — *Spoofing / Tampering / Elevation*
A server mis-declares a destructive tool under a benign name and is classified `safe_read`, or
returns crafted output to steer the agent, or simply reads the host filesystem.
**Closed in slice P2-S3** for the classification and allow-list halves: 17 versioned manifests
declare capability and risk class per tool, generated from the servers' own source; a manifested
server's manifest is an allow-list enforced at the host; an **unmanifested** server's tools are
floored at `sensitive_read` regardless of what the server says about itself, which is what stops a
destructive tool under a benign name from running unattended; and the server version is recorded
into every result for evidence provenance.

**Remaining:** JSON-Schema validation of input and output, server identity and channel
authentication (mTLS for remote MCP), manifest signing, and least-privilege execution. A manifest
today binds to a server *name* chosen by the local config — sufficient for bundled stdio servers,
insufficient for a remote one.

### T-5 (ADV-3, TB-1) Cross-origin drive-by against the loopback API — *Tampering*
A page the analyst visits issues `POST multipart/form-data` to `127.0.0.1:8000/api/projects/{pid}/upload`.
It is a *simple* request, so no preflight occurs; loopback is trusted, so no token is needed. The
response is unreadable to the attacker, but the write happens.
**Closed in slice P1-S9.** A state-changing API call whose `Origin` is not ReTrace's own is
refused `403 cross_origin_denied`; `Sec-Fetch-Site` is checked as a second signal; CORS stays off
unless an origin is explicitly named. Verified against a live server with a cross-origin
`POST multipart` — the exact shape of this attack. Clients with no `Origin` (curl, the CLI) are
unaffected, since a web page cannot make them. **Remaining:** the check relies on the browser
sending `Origin`, which is guaranteed for the threat described but is not a defence against a
non-browser attacker — who never needed CSRF in the first place.

### T-6 (ADV-3/ADV-4, TB-1) Credential exposure and weak session handling — *Information disclosure*
The token is accepted from `?token=`, so it lands in logs, history and referrers; it is printed to
stdout at startup; it lives in `.reforge_secrets.json` **inside the source tree** (P0-2); it is
process-wide, never expires and cannot be revoked. On a read-only install the write fails silently
and the token changes on every restart.
**Largely closed (P0-S1, P0-S2, the P0-S2 follow-up).** The secrets store moved under
`STATE_ROOT`; the API no longer accepts a token in the query string; `GET /` exchanges a bootstrap
token for an `HttpOnly`, `SameSite=Strict`, 12-hour cookie and issues it only to a caller that
would already have been allowed to call the API. **Remaining:** the token is still process-wide
with no per-user identity or revocation (P2-S1), and the bootstrap link is printed to stdout —
unavoidable while it is the only way to learn an auto-generated credential. Rotation:
`docs/secret-rotation.md`.

### T-7 (ADV-5, TB-1/TB-8) No authorization separation — *Elevation / Information disclosure*
Any user who can reach the API can read, modify, export or delete every project of every customer.
`DELETE /api/projects/{pid}` requires nothing beyond reaching the endpoint.
**Close:** RBAC, per-project authorization, append-only audit for export/delete/approval (P1-10).

### T-8 (ADV-6, TB-2/TB-6) Unsupported claims reaching a customer report — *Repudiation / integrity of A5*
The model raises a severity, invents an attack scenario, or promotes a hypothesis.
**Today:** the right mechanism exists (`engine/llm_safety.sanitize_enrichment()` with locked
deterministic fields; `engine/schema.justified_cvss()` refusing to invent a score) but it **is not
wired into the analysis path** (P1-7), and LLM output is scraped rather than schema-validated
(P1-8). **Closed in slices P1-S1/S2/S3 and P1-S4.** Findings are gated at write time, not at report
render; `llm_safety.sanitize_enrichment()` is invoked on every LLM-originated update and what it
blocks is recorded on the finding; structured model output is schema-validated and fails closed;
salvaged tool calls can no longer create a finding at all. **Remaining:** severity *banding* is
not itself benchmarked — the corpus measures which findings appear, not whether each landed in the
right band (P1-S6).

### T-9 (ADV-1, TB-8) Stored injection into report and SPA — *Tampering*
Attacker-controlled strings recovered from the sample flow into HTML/DOCX reports and into the SPA.
**Today:** no documented escaping policy at the render boundary; `web/app.js` builds markup from
template literals (`EMPTY_HTML` and similar) over 4272 lines.
**Close:** context-aware escaping at every sink, `Content-Disposition` and content-type hardening
on exports, and tests with hostile strings end to end.

### T-10 (TB-2/TB-9) Unauthorized data egress — *Information disclosure*
Customer code or strings reach a cloud model, or an MCP server makes an unexpected network call.
**Closed in slice P2-S4** at the application level: four operating profiles, payload
classification before anything is sent, redaction on the outbound path, and an auditable ledger of
what was sent, to whom, which model and why. `hybrid` is forced on `team` so a client's
decompiled code cannot reach an external provider. Enforcement sits inside the remote provider,
not at the call sites.

**Remaining:** egress allow-listing *outside* the application (a determined operator can change
the profile; a compromised process is not stopped by its own bookkeeping), per-project budgets,
and MCP servers that make their own network calls, which this gate does not govern.

### T-11 (TB-6/TB-8) Non-reproducible or unattributable results — *Repudiation*
No tool version in evidence, no config hash on the report, no migrations, no optimistic locking,
no report signature. A customer disputing a finding cannot be answered.
**Close:** record artifact hash + tool versions + config hash + prompt version on every finding;
sign or checksum the report; versioned migrations.

### T-12 (P0-6) Supply chain and release contamination — *Tampering / Information disclosure*
No lock file, no SBOM, no dependency or licence scanning, no signing, no sanitized release step;
the working tree carries a live secrets file and a populated database.
**Close:** the P0 slices below plus SBOM, scanning, signing and provenance (§10.4).

## Risk ranking

| Threat | Likelihood | Impact | Rank |
|---|---|---|---|
| T-3 Dynamic confirmation on the analyst's own machine | ~~High~~ Medium (P0-S2, P2-S2) | ~~Critical~~ High | **3** → re-ranked; the remedy is an RE VM, not a worker fleet |
| T-8 Unsupported claims in a customer report | ~~High~~ Low (P1-S1…S4) | Critical | **2** → closed; severity banding unmeasured |
| T-1 Prompt injection from the artifact | High | High | **3** |
| T-6 Credential exposure | ~~High~~ Low (P0-S1/S2) | High | **4** → largely closed; no identity yet |
| T-2 Malformed artifact DoS | ~~High~~ Low (P0-S3) | Medium | **5** → mitigated; parser fuzzing open |
| T-4 Malicious MCP server | ~~Medium~~ Low (P2-S3) | Critical | **6** → classification and allow-list closed; channel auth open |
| T-10 Unauthorized egress | ~~Medium~~ Low (P2-S4) | High | **7** → closed at the application level; network-level enforcement open |
| T-5 Cross-origin drive-by | ~~Medium~~ Low (P1-S9) | Medium | **8** → closed |
| T-7 No authorization separation | Medium (High in team mode) | High | **9** |
| T-9 Stored injection into report/SPA | Medium | Medium | **10** |
| T-11 Non-reproducible results | Certain | Medium | **11** |
| T-12 Supply chain / release | Certain | Medium | **12** |
