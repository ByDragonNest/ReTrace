# Secret rotation procedure

## Why this exists

`.reforge_secrets.json` holds the API access token and any configured provider key
(`anthropic_api_key`, `nvd_api_key`, `neo4j_password`). The file is present in this working tree.
Its contents were **not read** during the gap analysis and are not reproduced in any document here.

Treat these credentials as **exposed on this host** and rotate them. Reasons, independent of
whether the file ever left the machine:

- `reforge/config.py` writes the file into the **source tree** (`SECRETS_FILE = ROOT / …`), not
  into the state directory. Any operation that copies or archives the source — a release build, a
  support bundle, a `tar`, a shared folder — carries it along.
- The token is printed to stdout at every start (`server.py` lifespan log) and is accepted from a
  `?token=` query parameter, so it predictably reaches terminal scrollback, shell history,
  browser history and referrer headers.
- The file was created automatically, so nobody chose when it was created or who has seen it.

## Procedure

1. **Stop ReTrace.** Rotation while the process is running leaves the old token live in memory.
2. **Revoke at the issuer first**, not locally — a local deletion does not invalidate anything:
   - Anthropic API key → revoke in the Anthropic console and issue a new one.
   - NVD API key → revoke and reissue at NVD.
   - Neo4j password → change on the Neo4j instance.
   The ReTrace access token is self-issued; deleting it locally is sufficient for that one.
3. **Remove the local file** (do not open it, do not copy it, do not paste its contents anywhere):
   ```bash
   shred -u .reforge_secrets.json 2>/dev/null || rm -P .reforge_secrets.json
   ```
4. **Provide the new values out of band** — environment variables, OS keychain or a vault.
   Never by editing a source file.
5. **Clear the derivative copies**: terminal scrollback and shell history where the startup log
   or a `?token=` URL appeared; browser history for `…/?token=…`; any support bundle or archive
   produced from this working tree.
6. **Verify**: start ReTrace, confirm the new token is in effect, and confirm the old provider key
   is rejected by the provider.

## Preventing recurrence

- Secrets move under `STATE_ROOT`, outside the source tree (ADR 0001).
- The `?token=` query parameter is removed; header or cookie only.
- The startup log prints a masked value only.
- Secret scanning runs in pre-commit and in CI.
- The release build asserts its file list against an allow-list and fails if any secrets file,
  database or state directory is present.
