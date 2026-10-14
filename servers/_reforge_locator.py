"""Locates the `reforge` package for the MCP servers that depend on it.

Why this exists
---------------
The four servers bindiff/crypto/hardening/libs import `reforge.*`. If the package is not found,
the `import` at the top of the file raises ModuleNotFoundError, the process dies before it can
even answer the MCP handshake, and the client shows nothing but:

    Server disconnected / Connection closed

which says nothing about what went wrong. The real cause ends up only in the log.

This module solves two problems:

1. **Finds `reforge` even when the servers have been moved.** It looks, in order, at the
   REFORGE_PATH environment variable, then walks up the directories from this file, then the CWD
   and its parents. Copying the servers into a folder outside the project is the most common way
   to break the import, because `reforge` stays behind.

2. **Never lets the server die.** If the package is not found the server still starts, and the
   tool returns a readable diagnosis inside the client, with the list of paths it tried. A tool
   that explains the problem beats a server that does not show up at all.
"""
from __future__ import annotations

import os
import sys
from typing import List, Optional, Tuple

_MAX_WALK = 6


def _candidate_roots() -> List[str]:
    """Directories that may hold the `reforge` package, in priority order."""
    roots: List[str] = []

    def add(p: Optional[str]) -> None:
        if not p:
            return
        p = os.path.abspath(p)
        if p not in roots:
            roots.append(p)

    # 1. Explicit override: always wins.
    env = os.environ.get("REFORGE_PATH")
    if env:
        add(env)
        # If the user points at the package itself rather than its parent, accept that too.
        add(os.path.dirname(env))

    # 2. Walk up from THIS file. Covers the <project>/servers/*.py layout with
    #    <project>/reforge/, and deeper nestings as well.
    here = os.path.dirname(os.path.abspath(__file__))
    cur = here
    for _ in range(_MAX_WALK):
        add(cur)
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent

    # 3. CWD and parents. The CWD an MCP client spawns the process with is unreliable (often
    #    C:\Windows\system32), but it works when the server is launched by hand.
    cur = os.path.abspath(os.getcwd())
    for _ in range(_MAX_WALK):
        add(cur)
        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent

    return roots


def _is_reforge_root(root: str) -> bool:
    pkg = os.path.join(root, "reforge")
    if not os.path.isdir(pkg):
        return False
    # Accept regular packages and namespace packages alike.
    return (os.path.isfile(os.path.join(pkg, "__init__.py"))
            or any(f.endswith(".py") for f in os.listdir(pkg)))


def ensure_reforge() -> Tuple[Optional[str], List[str]]:
    """Add the directory containing `reforge` to sys.path.

    Returns (root_found_or_None, list_of_paths_tried).
    Never raises: the caller decides how to degrade.
    """
    tried = _candidate_roots()
    for root in tried:
        try:
            if _is_reforge_root(root):
                if root not in sys.path:
                    sys.path.insert(0, root)
                return root, tried
        except OSError:
            continue
    return None, tried


def missing_reforge_message(module: str, tried: List[str], original_error: str = "") -> str:
    """Diagnostic message a tool returns when `reforge` is unavailable."""
    lines = [
        f"⚠ The `reforge` package was not found, so `{module}` cannot be used.",
        "",
        "This server is an MCP wrapper around your `reforge` package: without that package it has",
        "no logic of its own to run.",
        "",
        "**Most likely cause:** the server files were copied into a folder outside the project and",
        "`reforge/` stayed behind. The four servers bindiff, crypto, hardening and libs must stay",
        "next to the package, or be told where it is.",
        "",
        "**How to fix it — pick one of the three:**",
        "",
        "1. Set REFORGE_PATH in the MCP config to the folder that CONTAINS `reforge`:",
        '     "env": { "REFORGE_PATH": "C:/Users/<user>/Desktop/retrace" }',
        "",
        "2. Move the servers back into the project, next to `reforge/`, and use an absolute path",
        "   in the config (never a relative one: the spawn CWD is often C:\\Windows\\system32).",
        "",
        "3. Install `reforge` as a package in the environment:  pip install -e C:/path/to/project",
        "",
        f"**Paths searched ({len(tried)}):**",
    ]
    lines += [f"  - {p}" for p in tried[:12]]
    if len(tried) > 12:
        lines.append(f"  …and {len(tried) - 12} more")
    if original_error:
        lines += ["", f"Original error: {original_error}"]
    return "\n".join(lines)
