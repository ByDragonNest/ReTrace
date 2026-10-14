"""MCP server wrapping FLOSS.

The default pass is intentionally fast: static, stack, and tight strings only.
Decoded-string emulation is opt-in because it can take minutes on real samples.
"""
import json
import os
import sys
import subprocess

# Resolve external tools without depending on the PATH the MCP client happened to inherit.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _toolpath import resolve as _tool

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("floss")
CAP = 8000


def _run(cmd, timeout):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _floss_json(exe, path, analyses, min_length, timeout):
    base = [exe, "-j", "--minimum-length", str(min_length)]
    cmd = base + ["--only", *analyses, path]
    p = _run(cmd, timeout)
    if p.returncode != 0 and (
        "only" in (p.stderr or "").lower()
        or "unrecognized" in (p.stderr or "").lower()
        or "usage:" in (p.stderr or "").lower()
    ):
        # Older FLOSS releases do not support --only.
        p = _run(base + [path], timeout)
    return p


@mcp.tool()
def floss_obfuscated_strings(path: str, min_length: int = 5,
                             include_decoded: bool = False, timeout: int = 300,
                             max_mb: int = 80) -> str:
    """Recover stack/tight strings and, optionally, decoded strings.

    Args:
        path: binary path to analyze.
        min_length: minimum string length passed to FLOSS.
        include_decoded: enable slow decoded-string emulation.
        timeout: subprocess timeout in seconds.
        max_mb: refuse larger files by default to avoid MCP client timeouts.
    """
    exe = _tool("floss")
    if not exe:
        return "FLOSS is not installed. Install it with: pip install flare-floss"
    if not os.path.isfile(path):
        return f"FLOSS: file not found: {path}"
    size_mb = os.path.getsize(path) / (1024 * 1024)
    if max_mb and size_mb > max_mb:
        return (f"FLOSS: file too large for the quick MCP analysis "
                f"({size_mb:.1f} MB > {max_mb} MB). Raise max_mb and timeout "
                "deliberately, or run FLOSS by hand.")

    analyses = ["static", "stack", "tight"] + (["decoded"] if include_decoded else [])
    timed_out_decoded = False
    try:
        p = _floss_json(exe, path, analyses, min_length, timeout)
    except subprocess.TimeoutExpired:
        if not include_decoded:
            return (f"FLOSS: timeout after {timeout}s. Raise timeout/max_mb "
                    "or analyse this binary by hand.")
        timed_out_decoded = True
        try:
            p = _floss_json(exe, path, ["static", "stack", "tight"], min_length, min(timeout, 120))
        except subprocess.TimeoutExpired:
            return (f"FLOSS: timeout after {timeout}s even in the quick fallback. "
                    "Retry without include_decoded, raise timeout/max_mb, or use FLOSS by hand.")
    except Exception as exc:  # noqa: BLE001
        return f"FLOSS: execution error: {exc}"

    try:
        data = json.loads(p.stdout)
    except Exception:  # noqa: BLE001
        tail = (p.stderr or "").strip()[-800:]
        return (p.stdout or tail or "FLOSS: no output").strip()[:CAP]

    strings = data.get("strings", data)

    def collect(key):
        out = []
        for it in (strings.get(key, []) or []):
            s = it.get("string") if isinstance(it, dict) else str(it)
            if s:
                out.append(s)
        return out

    sections = []
    for key, label in [("decoded_strings", "DECODED"), ("stack_strings", "STACK"), ("tight_strings", "TIGHT"), ("static_strings", "STATIC")]:
        vals = collect(key)
        if vals:
            sections.append(f"## {label} ({len(vals)})\n" + "\n".join(vals[:150]))
    if not sections:
        note = "" if include_decoded else " (decoded strings not attempted: pass include_decoded=true to include them)"
        return f"FLOSS: no obfuscated strings found{note}."
    prefix = "Note: decoded strings timed out; showing the static/stack/tight fallback.\n\n" if timed_out_decoded else ""
    res = prefix + "\n\n".join(sections)
    return res[:CAP] + ("\n...(truncated)" if len(res) > CAP else "")


if __name__ == "__main__":
    mcp.run()
