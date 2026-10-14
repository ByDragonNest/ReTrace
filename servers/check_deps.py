#!/usr/bin/env python3
"""Environment check for the vulnerability-assessment MCP servers.

    python check_deps.py

Says, for each server, whether it is ready to use or what is missing. Run it after installing
and whenever a server stops working: nine times out of ten the problem is a missing dependency
or the wrong version of `mcp`.
"""
from __future__ import annotations

import importlib
import importlib.metadata as md
import shutil
import sys
from typing import Dict, List, Optional, Tuple

OK, KO, WARN = "[ OK ]", "[ -- ]", "[ !! ]"

# server -> (required python modules, required external executables, notes)
SERVERS: Dict[str, Tuple[List[str], List[str], str]] = {
    "attack_surface_mcp": (["mcp", "pefile"], [], ""),
    "winsec_mcp":         (["mcp", "pefile"], [], "ACL/service checks on Windows only"),
    "driver_mcp":         (["mcp", "pefile"], [], "device_access_check on Windows only"),
    "reach_mcp":          (["mcp", "angr"], [], "angr belongs in a separate venv"),
    "findings_mcp":       (["mcp"], [], ""),
    "fuzz_mcp":           (["mcp"], [], "gdb (Linux) or cdb (Windows) for triage"),
    "sbom_mcp":           (["mcp"], [], "syft/grype optional, falls back to detect_components"),
    "frida_mcp":          (["mcp", "frida"], [], "on Windows: admin for elevated processes"),
    "procmon_mcp":        (["mcp"], [], ""),
    "x64dbg":             (["mcp", "requests"], [], "needs the HTTP plugin inside x64dbg"),
    "floss_mcp":          (["mcp"], ["floss"], ""),
    "tshark_mcp":         (["mcp"], ["tshark"], "only if the target talks on the network"),
    "crypto_mcp":         (["mcp"], [], "needs the reforge package"),
    "hardening_mcp":      (["mcp"], [], "needs the reforge package"),
    "libs_mcp":           (["mcp"], [], "needs the reforge package"),
    "bindiff_mcp":        (["mcp"], [], "needs the reforge package"),
}

EXTERNAL = {
    "syft":    "SBOM (sbom_mcp)            — winget install Anchore.Syft",
    "grype":   "matching CVE (sbom_mcp)    — winget install Anchore.Grype",
    "tshark":  "pcap analysis (tshark_mcp) — install Wireshark",
    "floss":   "obfuscated strings         — pip install flare-floss",
    "gdb":     "crash triage on Linux      — apt install gdb",
    "cdb":     "crash triage on Windows    — Debugging Tools for Windows",
    "afl-fuzz": "fuzzing (AFL++)           — https://github.com/AFLplusplus/AFLplusplus",
}


def _version(mod: str) -> Optional[str]:
    try:
        return md.version(mod)
    except Exception:  # noqa: BLE001
        return None


def _importable(mod: str) -> bool:
    try:
        importlib.import_module(mod)
        return True
    except Exception:  # noqa: BLE001
        return False


def main() -> int:
    print("=" * 74)
    print(" Environment check — MCP servers for vulnerability assessment")
    print("=" * 74)

    py = sys.version_info
    print(f"\nPython {py.major}.{py.minor}.{py.micro}  ({sys.executable})")
    if (py.major, py.minor) < (3, 10):
        print(f"  {WARN} Python 3.10 or newer is required")
    else:
        print(f"  {OK} version is adequate")

    # --- the single most important check ---
    print("\n--- mcp package ---")
    mcp_ver = _version("mcp")
    if not mcp_ver:
        print(f"  {KO} mcp NOT installed   →   pip install 'mcp<2'")
        fatal = True
    else:
        major = int(mcp_ver.split(".")[0])
        if major >= 2:
            print(f"  {WARN} mcp {mcp_ver} — INCOMPATIBLE VERSION")
            print("       Since 2.0 FastMCP has been renamed MCPServer and the module")
            print("       mcp.server.fastmcp has been removed. Every server in this")
            print("       repository uses the v1 API and will fail at import.")
            print("       Fix with:   pip install 'mcp<2'")
            fatal = True
        elif not _importable("mcp.server.fastmcp"):
            print(f"  {WARN} mcp {mcp_ver} installed but mcp.server.fastmcp cannot be imported")
            fatal = True
        else:
            print(f"  {OK} mcp {mcp_ver} — FastMCP API available")
            fatal = False

    print("\n--- Python libraries ---")
    for mod in ("pefile", "requests", "frida", "angr", "anthropic"):
        v = _version(mod)
        if v:
            print(f"  {OK} {mod:<12} {v}")
        else:
            print(f"  {KO} {mod:<12} not installed")

    print("\n--- external executables ---")
    for exe, desc in EXTERNAL.items():
        path = shutil.which(exe)
        print(f"  {OK if path else KO} {exe:<10} {desc}")

    print("\n--- server status ---")
    ready, partial = [], []
    for name, (mods, exes, note) in sorted(SERVERS.items()):
        missing_mods = [m for m in mods if not _version(m) and not _importable(m)]
        missing_exes = [e for e in exes if not shutil.which(e)]
        if not missing_mods and not missing_exes:
            print(f"  {OK} {name:<22}" + (f"  ({note})" if note else ""))
            ready.append(name)
        else:
            miss = ", ".join(missing_mods + missing_exes)
            print(f"  {KO} {name:<22}  missing: {miss}")
            partial.append(name)

    print("\n" + "=" * 74)
    print(f" ready: {len(ready)}/{len(SERVERS)}")
    if fatal:
        print(" ⚠ the `mcp` problem blocks EVERY server: fix that one first.")
    elif partial:
        print(" The missing servers are optional: enable only the ready ones in the config.")
    print("=" * 74)
    return 1 if fatal else 0


if __name__ == "__main__":
    sys.exit(main())
