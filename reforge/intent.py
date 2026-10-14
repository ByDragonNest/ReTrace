"""Intent detection for cost-aware, progressive MCP tool loading.

PROBLEM (prompt §12)
--------------------
The old preload seeded a FIXED set of tools (decompile, list functions, xref, imports, strings)
on the first turn regardless of what the user actually wanted. If the user uploaded a Procmon XML
or asked about x64dbg, the wrong tools were loaded — wasting tokens/credits and missing the tools
that mattered. The model could still call search_tools, but started from the wrong place.

APPROACH
--------
Detect the user's intent from their message (and from uploaded artifact types), then load a small,
relevant tool set for THAT intent. Everything stays recoverable: search_tools remains available so
the model can always pull in a tool that wasn't preloaded (prompt §7.8 fallback). Nothing is ever
"stuck because the right tool wasn't loaded".

This module is pure (no I/O): it returns intent + query terms + a human-readable reason. The agent
turns the queries into tools via the existing ToolRegistry.search().
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

# Intent keys. Each maps to a focused set of retrieval queries for the registry.
PROCMON_IMPORT = "procmon_import"
DYNAMIC_ANALYSIS = "dynamic_analysis"
REPORT_GENERATION = "report_generation"
STATIC_RE = "static_re"
NETWORK_ANALYSIS = "network_analysis"
STRINGS_TRIAGE = "strings_triage"
GENERAL = "general"

# Retrieval queries per intent (fed to ToolRegistry.search). Deliberately small.
_INTENT_QUERIES: Dict[str, List[str]] = {
    PROCMON_IMPORT:    ["procmon load xml", "procmon events", "procmon behavior"],
    DYNAMIC_ANALYSIS:  ["breakpoint", "registers memory", "step run", "call arguments", "isdebugging"],
    REPORT_GENERATION: [],   # report is deterministic; no MCP tools needed
    STATIC_RE:         ["decompile function", "cross references xref", "list imports", "disassemble"],
    NETWORK_ANALYSIS:  ["pcap traffic", "http dns", "tcp stream"],
    STRINGS_TRIAGE:    ["strings", "floss obfuscated strings"],
    GENERAL:           ["list functions", "list imports"],
}

# Keyword triggers per intent. Order matters: earlier = higher priority.
# The Italian alternatives are INPUT tolerance, not a second language: the interface and
# everything ReTrace emits are English, but an analyst typing `mostrami le stringhe` should
# still land on STRINGS_TRIAGE rather than GENERAL. Matching more prompts costs nothing;
# it never puts a non-English word on the screen.
_PATTERNS = [
    (PROCMON_IMPORT, re.compile(
        r"\bprocmon\b|process\s*monitor|\beventi?\b.*\bxml\b|\bxml\b.*\bprocmon\b", re.I)),
    (DYNAMIC_ANALYSIS, re.compile(
        r"\bx64dbg\b|\bdebugger?\b|\bbreakpoint\b|\bbreak\b|\bregistri?\b|\bregisters?\b|"
        r"\bstep\b|\bdynamic\b|\bdinamic\w*|\bprocess(?:o)?\b.*\b(run|esegu|avvi)|"
        r"\bmemoria\b|\bstack\b|\btrace\b", re.I)),
    (NETWORK_ANALYSIS, re.compile(
        r"\bpcap\b|\bwireshark\b|\btshark\b|\btraffic\w*|\bpacchett|\bnetwork\b|\bdns\b|\bhttp\b", re.I)),
    (REPORT_GENERATION, re.compile(
        r"\breport\b|\brelazione\b|\bgenera\w*\s+(?:il\s+)?report|\bexport\w*\s+report|"
        r"\bpt\s*report\b|\bdocx\b|\bpdf\b.*report", re.I)),
    (STRINGS_TRIAGE, re.compile(
        r"\bstringhe?\b|\bstrings?\b|\bfloss\b|\bhigh[- ]signal\b", re.I)),
    (STATIC_RE, re.compile(
        r"\bdecompil\w*|\bdisassembl\w*|\bghidra\b|\bxref\b|\bcross[- ]reference|"
        r"\bimport\w*|\bfunzion\w*|\bfunction\w*|\bstatic\w*|\bstatica\b", re.I)),
]

# Artifact-type → intent (an uploaded Procmon XML strongly implies procmon_import).
_ARTIFACT_INTENT = {
    "procmon_xml": PROCMON_IMPORT,
    "pcap": NETWORK_ANALYSIS,
}


def detect(message: str, *, artifact_types: Optional[List[str]] = None) -> Dict[str, Any]:
    """Return {intent, queries, reason} for a user message + optional uploaded artifact types.

    Artifact types take precedence (a freshly uploaded Procmon XML is a strong signal), then
    message keywords, then a GENERAL fallback. The result is intentionally small and explicit so
    the agent can log WHY a tool set was loaded (prompt §7: log the reason for loading).
    """
    artifact_types = artifact_types or []
    for at in artifact_types:
        if at in _ARTIFACT_INTENT:
            intent = _ARTIFACT_INTENT[at]
            return {"intent": intent, "queries": list(_INTENT_QUERIES[intent]),
                    "reason": f"artifact of type '{at}' uploaded \u2192 intent {intent}"}

    text = message or ""
    for intent, pat in _PATTERNS:
        m = pat.search(text)
        if m:
            return {"intent": intent, "queries": list(_INTENT_QUERIES[intent]),
                    "reason": f"keyword '{m.group(0)}' in the message \u2192 intent {intent}"}

    return {"intent": GENERAL, "queries": list(_INTENT_QUERIES[GENERAL]),
            "reason": "no specific keyword \u2192 general intent (minimal tool loading)"}
