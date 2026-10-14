"""MCP server exposing weak-crypto and hardcoded-secret scanning. Pure-Python; reuses
reforge.cryptosec. Secrets are redacted in the output.
"""
import os
import sys


# Make sibling modules importable regardless of the CWD used to spawn this process.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _reforge_locator import ensure_reforge, missing_reforge_message

_REFORGE_ROOT, _TRIED = ensure_reforge()

from mcp.server.fastmcp import FastMCP
try:
    from reforge.cryptosec import scan
    _IMPORT_ERROR = ""
except Exception as _e:  # noqa: BLE001
    scan = None
    _IMPORT_ERROR = str(_e)

mcp = FastMCP("crypto")


@mcp.tool()
def crypto_secrets_scan(path: str) -> str:
    """Scan a binary for weak/broken crypto (MD5/SHA1/DES/RC4/RC2/Blowfish/ECB), insecure RNG,
    and hardcoded secrets (private keys, cloud/API tokens, passwords). Secrets are returned
    REDACTED. `path` is the binary to scan."""
    if scan is None:
        return missing_reforge_message("crypto_secrets_scan", _TRIED, _IMPORT_ERROR)
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as e:
        return f"cannot read the file: {e}"
    return scan(data).get("text", "scan unavailable")


if __name__ == "__main__":
    mcp.run()
