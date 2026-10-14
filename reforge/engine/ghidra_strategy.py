"""Compiler/toolchain-aware symbol/xref resolution strategy for Ghidra (prompt §7).

This module does NOT talk to Ghidra directly (that is the MCP server's job). It encodes the
*strategy*: given a detected compiler/toolchain, which resolution steps and tool calls the agent
should prefer to correctly resolve imports, IAT references, direct/indirect calls, ANSI/Wide
variants, wrappers, and — for Delphi — VMT/RTTI and virtual calls.

Rule: identify compiler/toolchain FIRST, then apply the specific strategy (Delphi gets dedicated
VMT/RTTI handling).
"""
from __future__ import annotations

from typing import Any, Dict

DELPHI = "delphi"
UNKNOWN = "unknown"

# Generic resolution steps, always applicable.
_BASE_STEPS = [
    "resolve PE import thunks (jmp [IAT]) to their real API names",
    "map IAT references so xrefs on imports are complete",
    "follow direct calls and attempt to resolve indirect calls via register/const tracking",
    "unify ANSI/Wide (A/W) variants to a single logical API",
    "see through 1-instruction wrapper/forwarder functions",
    "build the call graph and run p-code dataflow on sink arguments",
]

_DELPHI_STEPS = [
    "parse Delphi VMT (virtual method tables) to name class methods",
    "recover RTTI to label classes/fields and published methods",
    "resolve virtual calls via the VMT slot rather than treating them as indirect-unknown",
    "recognize Delphi register calling convention (EAX/EDX/ECX) when reading arguments",
    "treat System./Vcl. runtime names as library, not application, code",
]


def strategy(toolchain: str) -> Dict[str, Any]:
    tc = (toolchain or UNKNOWN).lower()
    steps = list(_BASE_STEPS)
    if tc == DELPHI:
        steps = _DELPHI_STEPS + steps
    return {
        "toolchain": tc,
        "steps": steps,
        "notes": ("Delphi-specific VMT/RTTI resolution enabled." if tc == DELPHI
                  else "Generic resolution; identify a more specific toolchain to refine."),
    }
