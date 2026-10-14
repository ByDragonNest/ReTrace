"""Risk policy for the semi-autonomous gate.

Per the chosen autonomy level, the agent runs freely EXCEPT for actions that
run code, write target memory/registers, patch/assemble, or write/delete files.
Those require explicit human approval.

Classification is on the *unqualified* tool name (after the "server__" prefix),
case-insensitive, with explicit allow/deny overrides taking precedence over keywords.
"""
import re
from typing import Tuple

# Always benign even if a keyword matches (analysis-only annotations & reads).
EXPLICIT_SAFE = {
    "debugsetbreakpoint", "debugdeletebreakpoint", "debugpause",
    "sethardwarebreakpoint", "deletehardwarebreakpoint", "getbreakpointlist",
    "commentset", "commentget", "labelset", "labelget", "labellist",
    "set_decompiler_comment", "set_disassembly_comment",
    "rename_function", "rename_function_by_address", "rename_data", "rename_variable",
    "set_function_prototype", "set_local_variable_type",
    "getpatchlist", "getpatchat",  # reads, not writes
}

# Always dangerous (explicit), regardless of keyword heuristics.
EXPLICIT_DANGEROUS = {
    "execcommand",                       # arbitrary x64dbg command
    "memorywrite", "memoryremotealloc", "memoryremotefree",
    "memorysetprotect", "setpagerights",
    "registerset", "flagset", "stackpush", "stackpop",
    "assemblerassemble", "assemblerassemblemem",
    "export_query_results",              # writes a file to disk
}

# Keyword fallback: matches run/step/write/patch/delete-style verbs.
DANGEROUS_RE = re.compile(
    r"(debugrun|debugstep|stepin|stepout|stepover|^run$|continue|"
    r"write|patch|assemble|alloc|free|setprotect|setpagerights|"
    r"regset|flagset|delete|remove)",
    re.IGNORECASE,
)


def classify(qualified_tool: str) -> Tuple[bool, str]:
    """Returns (requires_approval, reason). Kept for back-compat; prefer requires_approval()."""
    base = qualified_tool.split("__", 1)[-1].lower()
    if base in EXPLICIT_SAFE:
        return False, "analysis/read-only"
    if base in EXPLICIT_DANGEROUS:
        return True, "state-changing (run/write/patch/delete)"
    if DANGEROUS_RE.search(base):
        return True, "matches run/write/patch/delete policy"
    return False, "read-only"


# ---- Risk classes (Phase 0.3) --------------------------------------------------------------
# safe_read | sensitive_read | dynamic_execution | write_or_patch | network
_DYNAMIC_RE = re.compile(r"(debugrun|debugstep|stepin|stepout|stepover|^run$|continue|"
                         r"detonate|emulate|execute|execcommand)", re.IGNORECASE)
_WRITE_RE = re.compile(r"(write|patch|assemble|alloc|free|setprotect|setpagerights|regset|"
                       r"flagset|stackpush|stackpop|delete|remove|export)", re.IGNORECASE)
_NETWORK_RE = re.compile(r"(http|fetch|download|upload|nvd|online|remote|url|detonat)", re.IGNORECASE)
_SENSITIVE_READ_RE = re.compile(r"(memoryread|readmemory|dumpmemory|readmem|readfile|"
                                r"read_file|getsecret|dump|cred|password|registryread)", re.IGNORECASE)


def name_heuristic(qualified_tool: str) -> str:
    """Risk guessed from the tool's NAME. A hint, never the authority.

    The name is chosen by the MCP server, so this can only ever raise the floor. A server that
    names a destructive operation `analyze_report` matches nothing here - which is exactly why
    `risk_class()` no longer returns this value on its own (threat T-4).
    """
    base = qualified_tool.split("__", 1)[-1].lower()
    if base in EXPLICIT_SAFE:
        return "safe_read"
    if base in EXPLICIT_DANGEROUS or _WRITE_RE.search(base):
        return "write_or_patch"
    if _DYNAMIC_RE.search(base):
        return "dynamic_execution"
    if _NETWORK_RE.search(base):
        return "network"
    if _SENSITIVE_READ_RE.search(base):
        return "sensitive_read"
    return "safe_read"


def resolve_risk(qualified_tool: str, catalogue_hint: str = "") -> dict:
    """The full decision for a tool: manifest first, name heuristic as a floor-raiser.

    Returns the dict from `mcp_manifest.ManifestRegistry.resolve` - risk class, whether the tool
    is allowed at all, where the decision came from, and the server version to record in evidence.
    """
    from . import mcp_manifest

    server, _, tool = qualified_tool.partition("__")
    if not tool:
        # An unqualified name is one of ReTrace's own in-process meta-tools (reforge/agent.py),
        # not a tool from some MCP server. The unmanifested floor exists to distrust third-party
        # servers; applying it here would gate `search_tools`. They have their own manifest.
        server, tool = "builtin", qualified_tool
    return mcp_manifest.registry().resolve(
        server, tool, catalogue_hint=catalogue_hint,
        name_heuristic=name_heuristic(qualified_tool))


def risk_class(qualified_tool: str, catalogue_hint: str = "") -> str:
    """Risk class for a tool. Manifest-driven, falling back to the name heuristic as a FLOOR.

    Before slice P2-S3 this was the name heuristic alone, and a name matching no dangerous pattern
    meant `safe_read`. Absence of a match is not evidence of safety: an unmanifested tool now takes
    the higher of its catalogue hint and its name heuristic, and a manifested one cannot be
    declared below what its name suggests.
    """
    return resolve_risk(qualified_tool, catalogue_hint)["risk_class"]


# Which classes need approval in each safety mode.
_GATED_BY_MODE = {
    "autonomous": set(),
    "assisted": {"dynamic_execution", "write_or_patch", "network", "sensitive_read"},
    "safe": {"dynamic_execution", "write_or_patch", "network", "sensitive_read"},
}
_GATED_BY_MODE["safe"] = {"sensitive_read", "dynamic_execution", "write_or_patch", "network"}


def is_allowed(qualified_tool: str, catalogue_hint: str = "") -> Tuple[bool, str]:
    """(allowed, reason). A manifested server's manifest is an allow-list for its own tools."""
    decision = resolve_risk(qualified_tool, catalogue_hint)
    return bool(decision.get("allowed", True)), str(decision.get("reason", ""))


def requires_approval(qualified_tool: str, safety_mode: str,
                      catalogue_hint: str = "") -> Tuple[bool, str, str]:
    """Return (requires_approval, risk_class, reason) for the given tool under safety_mode."""
    decision = resolve_risk(qualified_tool, catalogue_hint)
    rc = decision["risk_class"]
    if not decision.get("allowed", True):
        return True, rc, decision.get("reason", "not declared in the server manifest")
    if decision.get("requires_approval_always"):
        # A tool whose risk the class system understates - an irreversible action that happens to
        # read. The manifest can force the gate; it can never remove it.
        return True, rc, "the manifest marks this tool as always requiring approval"
    if safety_mode == "autonomous":
        return False, rc, "autonomous mode"
    gated = _GATED_BY_MODE.get(safety_mode, _GATED_BY_MODE["assisted"])
    if safety_mode == "safe" and rc != "safe_read":
        return True, rc, f"safe mode gates all non-read actions ({rc})"
    if rc in gated:
        return True, rc, f"{rc} requires approval in {safety_mode} mode"
    return False, rc, "read-only"


# ---- Human-readable consequence per risk class --------------------------------------------
# The approval card must say what the operator is actually authorizing. A bare "Approve / Deny"
# on a raw JSON blob is not informed consent, so every gated class carries a plain-language
# statement of what it can do to the target or the host.
_CONSEQUENCE = {
    "dynamic_execution": "Runs code in the target process. Execution can change the process state "
                         "and can have side effects on this machine.",
    "write_or_patch": "Modifies state: target memory, registers, instructions, or files on disk. "
                      "The change persists after the call and may not be reversible.",
    "network": "Contacts a remote service. Data about the target may leave this machine.",
    "sensitive_read": "Reads potentially sensitive data (process memory, files, credentials). "
                      "The result is recorded as evidence and may appear in the report.",
    "safe_read": "Read-only analysis; no state is modified.",
}

_RISK_LEVEL = {
    "dynamic_execution": "HIGH",
    "write_or_patch": "HIGH",
    "network": "MEDIUM",
    "sensitive_read": "MEDIUM",
    "safe_read": "LOW",
}


def consequence(risk_class: str) -> str:
    """Plain-language statement of what approving a call of this class permits."""
    return _CONSEQUENCE.get(risk_class, _CONSEQUENCE["safe_read"])


def risk_level(risk_class: str) -> str:
    """Coarse HIGH/MEDIUM/LOW band for the approval card, derived from the risk class."""
    return _RISK_LEVEL.get(risk_class, "LOW")
