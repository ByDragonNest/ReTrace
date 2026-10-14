# ADR 0001 — Typed layered configuration; never write the source tree

**Status:** implemented (P0-S1, P0-S2) · **Date:** 2026-10-13 · **Closes:** P0-2, P0-3, P0-4

## Context
`reforge/config.py` is both the schema and the storage of configuration. `persist_to_file()`
regex-rewrites it when a setting changes in the UI; `_migrate_secrets_out_of_source()` rewrites it
at import. `SECRETS_FILE` is pinned to the **source** root, so importing the package generates an
auth token and writes it into the source tree — reproduced in a clean checkout. On a read-only
install the write fails inside a bare `except: pass`, so a fresh token is minted on every start
and the previous one silently stops working. Shipped defaults (`SAFETY_MODE="autonomous"`,
`ALLOW_OUTSIDE_WORKSPACE=True`, `AUTH_TRUST_LOCALHOST=True`) are fail-open and contradict both the
comment above them and the README.

## Decision
1. Precedence: **safe defaults → config file → environment → secret provider (keychain/vault) →
   audited admin override**. Later layers win; every layer is typed and validated at load.
2. The application **never writes inside its own source tree**. All mutable state, including
   secrets and derived indexes, lives under `STATE_ROOT`.
3. Secrets are never written to source, reports, logs or project payloads, and never appear in a
   URL. The `?token=` query parameter is removed.
4. Defaults are **fail-closed**. Relaxing a safety default is an explicit, audited operator action,
   and the resolved posture is reported at startup and in `/api/.../status`.
5. `reforge/config.py` keeps its module-level names as a compatibility facade over the typed
   object, so the ~40 modules that read `config.X` do not all change at once.

## Consequences
Immutable application images and read-only installs work. Upgrades no longer overwrite customer
settings. Tests can assert the source tree is unchanged. Cost: a migration for existing installs
that have a secrets file at the old location (handled by read-old / write-new), and one
breaking change — the shipped `SAFETY_MODE` default moves to `assisted`, which will prompt for
approval where it previously did not. Documented in the changelog.

## Alternatives rejected
*Keep source-as-config* — incompatible with packaging, immutable deployment and upgrades.
*Environment variables only* — no validation, poor ergonomics for ~40 settings, secrets end up in
process listings.

## Implementation notes (2026-10-13)

Delivered in `reforge/settings.py` (typed model, layering, profile hardening) with
`reforge/config.py` reduced to a compatibility facade. Decisions taken while implementing:

- **The legacy block is migrated, not honoured.** `reforge/config.py` keeps its `USER SETTINGS`
  literals, read once by `settings.read_legacy_block()` via `ast` — parsed, never imported or
  executed — on an install that has no `settings.json` yet. A later mismatch is reported at
  startup by `config.legacy_drift()`, so editing the dead block cannot silently do nothing.
- **Safety settings never migrate** (`settings.NEVER_MIGRATED`). An install running
  `autonomous` with no confinement must not keep that posture across the upgrade whose purpose is
  to close it. The operator re-grants explicitly. This is the slice's one deliberate breaking
  change.
- **Profile hardening lives in the model**, as a pydantic `model_validator(mode="after")` with
  `validate_assignment=True`, so it also re-runs on a later assignment. There is exactly one place
  where "is this allowed in this profile" is decided and no call site can bypass it.
- **Validation happens before assignment.** `apply_runtime()` builds and validates a candidate and
  only then replaces the live object. An earlier draft validated in place, which left a rejected
  value applied when the constructor raised — caught by
  `test_an_invalid_runtime_change_leaves_the_running_settings_untouched`.
- **The legacy `require_approval` toggle can only tighten.** A stale `{"require_approval": false}`
  from an older client is logged and ignored; disabling the gate now requires asking for
  `safety_mode="autonomous"` by name.
- **`?token=` is a bootstrap, not a credential channel.** `GET /` accepts it once, exchanges it
  for an `HttpOnly`/`SameSite=Strict`/`Max-Age` cookie and 303-redirects to a clean URL. The API
  middleware no longer reads the query string at all. This also fixed a latent bug: nothing had
  ever *set* the cookie the middleware read, so remote browser use broke after the first request.
