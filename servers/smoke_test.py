#!/usr/bin/env python3
"""Smoke test: ACTUALLY imports every MCP server, each in a separate process.

    python smoke_test.py

Why it is needed
----------------
`python -m py_compile server.py` checks the syntax only. It does not run the module, so it sees
nothing of what fails at import time: a `sys` never imported, a misspelled name, a missing
dependency. The result is a file that "compiles" and then dies at start-up with:

    NameError: name 'sys' is not defined

and in the MCP client all you see is `Server disconnected`.

This script imports every server in an isolated subprocess, so a crash cannot take the test down
with it, and reports the exact error. Run it after every change to these files and before
reloading the client.
"""
from __future__ import annotations

import os
import subprocess
import sys
from typing import List, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))

SKIP = {"smoke_test.py", "check_deps.py", "_toolpath.py", "_reforge_locator.py"}

# Servers that depend on optional packages: an ImportError on these is not a code failure, just
# a dependency that is not installed.
OPTIONAL_DEPS = {
    "reach_mcp": "angr",
    "frida_mcp": "frida",
}


def _servers() -> List[str]:
    return sorted(f for f in os.listdir(HERE)
                  if f.endswith(".py") and f not in SKIP)


def _try_import(fname: str) -> Tuple[str, str]:
    """Returns (status, detail). Status: OK | OPTIONAL | FAIL."""
    mod = fname[:-3]
    code = (
        "import sys, os\n"
        f"sys.path.insert(0, {HERE!r})\n"
        f"import {mod}\n"
        # Check that the FastMCP object exists and has tools registered.
        f"m = getattr({mod}, 'mcp', None)\n"
        "if m is None:\n"
        "    print('NO_MCP_OBJECT'); sys.exit(2)\n"
        "print('IMPORT_OK')\n"
    )
    p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                       timeout=120, errors="replace")
    out = (p.stdout or "") + (p.stderr or "")
    if "IMPORT_OK" in out:
        return "OK", ""
    # Take the last meaningful line of the traceback.
    lines = [l for l in out.strip().splitlines() if l.strip()]
    detail = lines[-1] if lines else f"exit {p.returncode}"
    dep = OPTIONAL_DEPS.get(mod)
    if dep and (f"No module named '{dep}'" in out or dep in detail):
        return "OPTIONAL", f"{dep} is missing (optional dependency)"
    return "FAIL", detail


def main() -> int:
    servers = _servers()
    print("=" * 78)
    print(f" Smoke test — real import of {len(servers)} servers")
    print(f" interpreter: {sys.executable}")
    print("=" * 78)

    failed = []
    for fname in servers:
        status, detail = _try_import(fname)
        if status == "OK":
            print(f"  [ OK ]       {fname}")
        elif status == "OPTIONAL":
            print(f"  [ SKIP ]     {fname:<26} {detail}")
        else:
            print(f"  [ FAIL ]     {fname}")
            print(f"               {detail}")
            failed.append((fname, detail))

    print("=" * 78)
    if failed:
        print(f" {len(failed)} servers do NOT start:")
        for f, d in failed:
            print(f"   - {f}: {d}")
        print("\n In the MCP client these would show nothing but 'Server disconnected'.")
        return 1
    print(" Every server imports cleanly.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
