"""MCP server exposing the binary hardening / exploit-mitigation audit (PE & ELF).
Pure-Python + pefile; no external CLI needed. Reuses reforge.hardening.
"""
import os
import sys


# Make sibling modules importable regardless of the CWD used to spawn this process.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _reforge_locator import ensure_reforge, missing_reforge_message

_REFORGE_ROOT, _TRIED = ensure_reforge()

from mcp.server.fastmcp import FastMCP
try:
    from reforge.hardening import audit
    _IMPORT_ERROR = ""
except Exception as _e:  # noqa: BLE001
    audit = None
    _IMPORT_ERROR = str(_e)

mcp = FastMCP("hardening")


@mcp.tool()
def hardening_audit(path: str) -> str:
    """Audit a PE or ELF binary for exploit mitigations (DEP/NX, ASLR/PIE, stack canary/GS,
    CFG, SafeSEH, RELRO, FORTIFY, Authenticode). Returns a mitigations table; missing ones
    raise the exploitability of memory-corruption bugs. `path` is the binary to check."""
    if audit is None:
        return missing_reforge_message("hardening_audit", _TRIED, _IMPORT_ERROR)
    res = audit(path)
    return res.get("text", res.get("error", "audit unavailable"))


if __name__ == "__main__":
    mcp.run()
