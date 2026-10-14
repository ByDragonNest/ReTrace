# ReTrace — installation and operation

Covers the **`workstation` profile** — one analyst, one machine, no external services — which is
how ReTrace is meant to be run. The **`team` profile**, a shared install for a few analysts, is the
same install with a harder posture and is described under [Shared install](#shared-install-the-team-profile).

There is no third profile. ReTrace is a tool for a single analyst and small teams; see
[Out of scope](ROADMAP.md#out-of-scope) for what that decision ruled out.

## Requirements

| | |
|---|---|
| Python | 3.10 or later (CI covers 3.10 and 3.12 on Linux, 3.12 on Windows) |
| OS | Linux, macOS or Windows. PE analysis, x64dbg, Procmon and Frida are Windows-first |
| Disk | the install is a few MB; plan for uploaded samples — the default project quota is 20 GiB |
| Network | **none required.** No telemetry, no licence check, no outbound call unless you enable one |

## Install

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install retrace                                     # or: pip install ./retrace-0.1.0-py3-none-any.whl
retrace
```

The wheel is self-contained: it carries the web UI, the prompts, the playbooks and a default MCP
catalogue, and runs from any working directory.

From a source checkout:

```bash
pip install -e ".[all,dev]"
python -m reforge
```

Optional features are extras, all lazily imported — the application starts and runs without any
of them, with that one feature unavailable:

| Extra | Enables |
|---|---|
| `cloud` | Anthropic provider |
| `local` | OpenAI-compatible / Ollama provider |
| `reports` | DOCX and PDF export |
| `knowledge` | PDF ingestion for `consult_methodology` |
| `neo4j` | optional Neo4j mirror of the Evidence Graph |
| `servers` | optional dependencies of the bundled MCP servers |

`angr` (for the reachability server) goes in its own virtualenv — see `requirements-angr.txt`.
It is ~1 GB with tightly pinned transitive dependencies and will fight anything it shares an
environment with.

## Where state lives

Everything mutable — project database, projects, sessions, jobs, uploaded samples, the settings
file, the secrets store and derived caches — lives under `REFORGE_STATE_DIR`. It defaults to the
current directory, which is fine for a quick try and wrong for anything you intend to upgrade:

```bash
export REFORGE_STATE_DIR=~/.local/share/retrace     # Windows: %LOCALAPPDATA%\ReTrace
retrace
```

```
$REFORGE_STATE_DIR/
├── settings.json            # typed settings (the Settings UI writes here)
├── .reforge_secrets.json    # access token + provider keys, chmod 600
├── reforge.db               # project database
├── projects/ sessions/ jobs/
├── workspace/<project>/artifacts/   # uploaded samples, 0600, never executable
└── cache/                   # derived indexes, safe to delete
```

ReTrace never writes inside its own installation directory. The test suite asserts it
(`tests/test_packaging_and_state.py`), so a read-only or signed install works.

## First start

```
Profile: workstation | safety=assisted (approval gate ON) | workspace=… | external paths=False
Auth enabled. Open this link ONCE to authenticate this browser:
    http://127.0.0.1:8000/?token=…
```

On the `workstation` profile, open `http://127.0.0.1:8000` — the first page load gives your
browser an `HttpOnly`, `SameSite=Strict` session cookie valid for 12 hours and you are done.

The printed link matters when loopback is **not** trusted: the `team` profile forces that, and you
can set `auth_trust_localhost=false` on a workstation you share with other local processes or
users. Then the link is how a browser gets its first credential. Either way it
is the cookie that authenticates afterwards, so tightening the setting later will not break a tab
that is already open.

Automation uses the `X-Reforge-Token` header; the API does not accept a token in the query string.

The startup banner is the whole security posture. If a line surprises you, the configuration is
wrong — see `README.md` → *Shipped posture*.

## Command line

The `retrace` console script is the whole automation surface besides the API:

| command | what it does |
|---|---|
| `retrace` / `retrace serve [--host H] [--port P]` | start the API and the SPA |
| `retrace config show` | the effective settings as JSON, secrets masked |
| `retrace config set KEY VALUE` | validate one setting through the same model the server uses and persist it to `settings.json` in the state directory |
| `retrace check` | import the app and report profile, state directory, settings file and route count — the thing to run after an upgrade |

`config set` refuses a value the server would refuse, applies the `team` hardening to what it
writes, and never accepts a secret (those go in the secrets store). It never touches the source
tree.

## Shared install (the `team` profile)

Same package, same command, one setting:

```bash
retrace config set deployment_profile team
```

It is not a scale switch — the store, the job registry and the code path are identical. It forces
six values and **can only tighten them**; `validate_assignment` re-runs the check, so a field set
afterwards cannot loosen the posture back:

| forced | from | why |
|---|---|---|
| `auth_required=true` | either | a shared install has more than one caller |
| `auth_trust_localhost=false` | `true` | "came from loopback" stops identifying anyone when several people reach the same box |
| `allow_outside_workspace=false` | either | one analyst's path escape is everyone's |
| `safety_mode=assisted` | `autonomous` | an unattended agent on shared work needs a human in the loop |
| `allow_unisolated_execution=false` | `true` | running a client's binary in the process that serves everyone else is not a tradeoff |
| `operating_profile=hybrid` | `frontier` | no binary and no full decompilation leaves the machine on one person's decision |

The startup log names every value it overrode, so a posture you did not expect is visible rather
than silent.

What you still have to provide: an OIDC issuer for `auth_mode=oidc` (`pip install 'retrace[oidc]'`),
and a backup of the state directory — see [Where state lives](#where-state-lives). What you do
**not** have to provide: a database server, a queue, or a reverse proxy. SQLite with optimistic
locking handles a handful of analysts; the limit is concurrent *writers*, and the symptom when you
reach it is write contention, not data loss.

Run it on a machine the team already trusts with client binaries — the same reasoning as the RE VM
in the README's isolation section. ReTrace does not isolate dynamic analysis from its own host.

## Local model (Ollama or any OpenAI-compatible server)

ReTrace talks to a local model through the OpenAI-compatible API, which needs the `local` extra
in **the interpreter that runs ReTrace** (the SDK is not a core dependency, because the product
must install and run with no model at all):

```bash
pip install "retrace[local]"
```

`retrace check` says whether the provider is ready, and if not, exactly what is missing — the SDK,
the server, or the model. With Ollama:

```bash
ollama serve
```

```bash
ollama pull qwen3:30b
```

then set `llm_provider=local`, `local_model=qwen3:30b` and leave `local_base_url` at
`http://127.0.0.1:11434/v1` (the Settings panel or `retrace config set`). `local_api_key` is a
placeholder most local servers ignore.

**"Configured" is not "running".** The status endpoint probes `<local_base_url>/models` (cached
for 10 s) and reports `llm_reachable`; the UI shows *Local LLM configured (model) but
http://127.0.0.1:11434/v1 is not reachable* until the server answers. A turn that fails on
transport names the URL and the fix instead of the SDK's `Connection error`.

Two ceilings: `llm_timeout_s` (default 120 s) for a cloud provider, `local_timeout_s` (default
600 s) for the local one — a local model loads its weights on the first call and does not stream,
so a long answer is minutes of wall clock before anything comes back. If turns time out while the
model is loading, raise `local_timeout_s`; if they time out every time, the model is too slow for
the hardware — pick a smaller one.

## MCP servers

`mcp.servers.json` declares which servers to connect to. Resolution order:

1. `$REFORGE_STATE_DIR/mcp.servers.json` — yours, survives upgrades
2. `./mcp.servers.json` — a source checkout
3. the packaged default

`mcp.servers.json` is git-ignored: like the database and the projects it belongs to the install,
not to the source, and a fresh clone runs from the packaged default until you create it.
Copy the default into your state directory and edit it there. Most bundled servers (Procmon,
hardening, libs, crypto, bindiff, floss, tshark) only need their optional pip dependency. **Ghidra**
and **x64dbg** need their own bridge installed separately; replace the `PATH/TO/...` placeholder
with a real path.

A server that will not start, crashes, or has no catalogue at all is **not fatal**: the host logs
it, reports it in the UI, and the deterministic analyzers, the Evidence Graph and the report keep
working. The product is designed to run with zero MCP servers.

## Air-gapped use

Works today, with limits worth stating plainly:

- **Does work**: `operating_profile = "offline_deterministic"` or `"local_only"`, deterministic
  analysis, Evidence Graph, assessment dashboard, reports and every export.
- **Checkable, not just claimed**: `GET /api/egress` reports whether anything has left this host.
  Under `local_only` every model request is recorded and none is remote, so
  `nothing_has_left_this_host` stays true and you can show it.
- `nvd_online_lookup` is off by default, so component fingerprinting stays offline (no CVE
  enrichment).
- **Installation** uses a bundle built on a connected machine:

  ```bash
  python scripts/build_offline_bundle.py --out offline-bundle --extras local
  python scripts/build_offline_bundle.py --verify offline-bundle    # do this BEFORE carrying it
  ```

  The verify step installs the bundle into a throwaway environment **with the package index
  disabled**, so a missing dependency fails there rather than on the far side of the air gap where
  nothing can be fixed. Then carry the directory across and run `./install.sh` (or
  `install.ps1`); both pass `--no-index` to pip and fetch nothing.

  A bundle is built for **one platform and one Python minor version**. Wheels for Linux/x86_64 and
  CPython 3.12 will not install on Windows or on 3.10 — build one per target.
- **Not yet**: egress is prevented by configuration and recorded in an application-level ledger,
  not enforced at the process or network level. A determined operator can change the profile; a
  compromised process is not stopped by its own bookkeeping. Network-level enforcement (egress
  allow-list outside the application) is P2-S7.

## Schema migrations

The database schema is versioned. On start, ReTrace applies any pending migration — and **takes a
backup first**, using SQLite's own backup API rather than a file copy, because a copy taken while
a write is in flight can be torn and this is the one moment that must not produce a corrupt rescue
copy. If the backup cannot be taken, the migration does not run.

A failed migration leaves the database as it was and says where the backup is. ReTrace then
continues on the old schema rather than refusing to start, so a migration problem is not also an
outage.

```bash
python -c "from reforge import migrations, config; print(migrations.status(config.PROJECTS_DB))"
```

Every migration declares its reverse. To go back a version:

```bash
python -c "from reforge import migrations, config; print(migrations.rollback(config.PROJECTS_DB, to=1))"
```

## Retention

Off by default: `retention_days = 0` keeps everything.

When set, a project whose last update is older than the window is **hidden, not erased** — the row
stays and `restore_project()` brings it back. Automatically destroying an engagement's findings on
a timer is not something a tool should do: a retention policy is usually set once, by someone
estimating, and the first time it fires on real work it has to be recoverable.

Permanent removal is a separate, deliberate step that shows you the list first:

```bash
curl -H "X-Reforge-Token: …" localhost:8000/api/retention            # what would go
curl -X POST -H "X-Reforge-Token: …" "localhost:8000/api/retention/purge?confirm=true"
```

Purging is audited with the project ids it removed.

Pre-migration backups are pruned to the most recent `backup_retention_count` (default 10). Each is
a full copy, and an unbounded series eventually fills the disk the product is protecting. The
backup just taken is never pruned.

## Concurrent edits

Project writes are version-checked. If two people have the same project open and both save, the
second gets a conflict rather than silently discarding the first one's findings — the API answers
with the current version and the message says to reload and re-apply.

## Upgrading

1. Stop ReTrace.
2. Back up `$REFORGE_STATE_DIR` — a plain directory copy is enough.
3. `pip install --upgrade retrace`
4. Start it and read the banner.

Settings live in `$REFORGE_STATE_DIR/settings.json` and are not touched by an upgrade. If you are
coming from a build that predates the typed settings, the `USER SETTINGS` block in
`reforge/config.py` is migrated **once** and then ignored; a later mismatch is reported at startup.

**Safety settings are deliberately not migrated.** An install running with the approval gate off
and no workspace confinement goes back to the fail-closed defaults, and you re-grant explicitly.
This is the one intentional breaking change in the P0 series.

## Verifying a release

```bash
sha256sum -c SHA256SUMS
python scripts/build_release.py --check-only --out dist   # from a checkout
```

The release artifacts are checked against an allow-list: no `.git`, no database or WAL, no
`projects/`, `workspace/`, `sessions/`, `jobs/`, no caches, no samples, no secrets. CI runs the
same script, so "it passed in CI" and "the artifact you received" mean the same thing.

## Support bundle

There is no sanitized support-bundle command yet (P3). Until there is, when reporting a problem
send the **startup banner**, the version (`pip show retrace`), and the relevant log lines —
and nothing from `workspace/`, which holds customer binaries.

## Uninstall

```bash
pip uninstall retrace
rm -rf "$REFORGE_STATE_DIR"     # this deletes every project, sample and finding
```

The state directory is the only thing outside the virtualenv. Deleting it is irreversible, and
revoking any provider key you configured is a separate step at the provider — see
`docs/secret-rotation.md`.
