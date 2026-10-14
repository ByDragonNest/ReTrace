"""MCP server exposing third-party component fingerprinting (+ optional NVD CVE lookup).
Pure-Python; reuses reforge.libs. The online lookup needs network and is opt-in per call.
"""
import os
import sys


# Make sibling modules importable regardless of the CWD used to spawn this process.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _reforge_locator import ensure_reforge, missing_reforge_message

_REFORGE_ROOT, _TRIED = ensure_reforge()

from mcp.server.fastmcp import FastMCP
try:
    from reforge.libs import audit
    _IMPORT_ERROR = ""
except Exception as _e:  # noqa: BLE001
    audit = None
    _IMPORT_ERROR = str(_e)

mcp = FastMCP("libs")


@mcp.tool()
def fingerprint_libraries(path: str, online: bool = False) -> str:
    """Detect embedded third-party libraries and their versions from a binary's version
    banners (OpenSSL, zlib, libpng, curl, SQLite, mbedTLS, libssh2, ...). Set online=true to
    attach candidate CVE IDs via an NVD keyword search (needs network). `path` is the binary."""
    if audit is None:
        return missing_reforge_message("fingerprint_libraries", _TRIED, _IMPORT_ERROR)
    res = audit(path, online=online)
    return res.get("text", res.get("error", "fingerprint unavailable"))


if __name__ == "__main__":
    mcp.run()
