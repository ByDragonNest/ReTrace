"""Resolution of the external executables the MCP servers use.

Why this exists
---------------
`shutil.which()` only searches the PATH, and the PATH an MCP server sees is the one inherited
from the client at spawn time — not the one in your terminal. Adding a folder to the Windows PATH
has no effect on processes that are already running, so until the client is fully restarted the
server keeps failing to find the tool even though it works perfectly from a shell.

This module adds a deterministic way out: one environment variable per tool, settable in the
`env` block of the MCP config. With that, the PATH becomes irrelevant.

Search order, for the tool `syft`:
  1. the SYFT_PATH environment variable  (full path to the exe, or the folder containing it)
  2. the VA_TOOLS_DIR environment variable  (one folder shared by every tool)
  3. the PATH, through shutil.which
  4. a few usual locations on Windows
"""
from __future__ import annotations

import os
import shutil
import sys
from typing import List, Optional

IS_WIN = sys.platform.startswith("win")

# Where people usually drop standalone binaries on Windows.
_COMMON_WIN_DIRS = [
    r"C:\tools",
    r"C:\ProgramData\chocolatey\bin",
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\WinGet\Links"),
    os.path.expandvars(r"%USERPROFILE%\scoop\shims"),
    os.path.expandvars(r"%USERPROFILE%\tools"),
    os.path.expandvars(r"%USERPROFILE%\bin"),
]


def _exe_names(name: str) -> List[str]:
    if not IS_WIN:
        return [name]
    return [name + ".exe", name + ".cmd", name + ".bat", name]


def _check(candidate: str, name: str) -> Optional[str]:
    """Accepts either the executable's own path or the folder that contains it."""
    if not candidate:
        return None
    candidate = os.path.expandvars(os.path.expanduser(candidate))
    if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
        return candidate
    if os.path.isdir(candidate):
        for exe in _exe_names(name):
            full = os.path.join(candidate, exe)
            if os.path.isfile(full):
                return full
    return None


def resolve(name: str) -> Optional[str]:
    """Full path of the executable `name`, or None if not found."""
    # 1. per-tool override
    hit = _check(os.environ.get(f"{name.upper().replace('-', '_')}_PATH", ""), name)
    if hit:
        return hit

    # 2. one folder shared by every tool
    hit = _check(os.environ.get("VA_TOOLS_DIR", ""), name)
    if hit:
        return hit

    # 3. PATH
    hit = shutil.which(name)
    if hit:
        return hit

    # 4. usual locations
    if IS_WIN:
        for d in _COMMON_WIN_DIRS:
            hit = _check(d, name)
            if hit:
                return hit
    return None


def missing_message(name: str, install_hint: str = "") -> str:
    """Message when a tool cannot be found, with the way out that does not depend on the PATH."""
    var = f"{name.upper().replace('-', '_')}_PATH"
    lines = [f"`{name}` not found."]
    if install_hint:
        lines += ["", install_hint]
    lines += [
        "",
        "If `" + name + "` works from the terminal but not here, the problem is the PATH: an MCP",
        "server inherits the client's environment at spawn time, and changes to the Windows PATH",
        "do not reach processes that are already running. Two ways out:",
        "",
        f"  a) give the path in the MCP config, without touching the PATH:",
        f'       "env": {{ "{var}": "C:/tools/{name}.exe" }}',
        "     or one folder for every tool:",
        '       "env": { "VA_TOOLS_DIR": "C:/tools" }',
        "",
        "  b) add the folder to the user PATH and **fully restart the client**",
        "     (closing and reopening the window is not enough: the process has to end).",
    ]
    return "\n".join(lines)
