"""MCP server exposing security-oriented binary diff (patch-analysis triage). Pure-Python;
reuses reforge.bindiff. Compares two binary versions across security-relevant dimensions.
"""
import os
import sys


# Make sibling modules importable regardless of the CWD used to spawn this process.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _reforge_locator import ensure_reforge, missing_reforge_message

_REFORGE_ROOT, _TRIED = ensure_reforge()

from mcp.server.fastmcp import FastMCP
try:
    from reforge.bindiff import diff
    _IMPORT_ERROR = ""
except Exception as _e:  # noqa: BLE001
    diff = None
    _IMPORT_ERROR = str(_e)

mcp = FastMCP("bindiff")


@mcp.tool()
def binary_diff(path_a: str, path_b: str) -> str:
    """Security diff between two versions of a binary (A=old, B=new): changes in mitigations,
    imports, dangerous sinks, third-party library versions, weak crypto, hardcoded secrets and
    strings. Surfaces the security-relevant delta to triage a patch. Not a basic-block BinDiff."""
    if diff is None:
        return missing_reforge_message("binary_diff", _TRIED, _IMPORT_ERROR)
    res = diff(path_a, path_b)
    return res.get("text", res.get("error", "diff unavailable"))


if __name__ == "__main__":
    mcp.run()
