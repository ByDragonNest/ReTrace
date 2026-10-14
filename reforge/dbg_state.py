"""Deterministic x64dbg process-state oracle.

PROBLEM
-------
The agent used to infer "the debugged process has terminated" from the LLM's reading of debugger
output. Small models routinely misread a *timeout*, a *missed breakpoint*, or an *empty/stale
read* as termination, then call wait_for_reload and stall the investigation.

SOLUTION
--------
Termination is a fact the debugger can answer directly. The x64dbg MCP server exposes
`IsDebugging` and `IsDebugActive`. This module turns raw tool results into one of:

    RUNNING            - debuggee is alive (or we have no proof it isn't)
    TERMINATED         - strong evidence the debuggee ended
    UNKNOWN            - inconclusive (timeout / empty / error) -> treat as RUNNING for safety

Key rules (mirrors prompt §x64dbg):
  * a TIMEOUT is never TERMINATED
  * a single empty/no-event read is never TERMINATED
  * TERMINATED requires either an explicit exit signal OR isdebugging=false confirmed
    (optionally corroborated by a second consecutive negative check).

This module is pure and dependency-free so it is trivially unit-testable with mocked tool output.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional

RUNNING = "running"
TERMINATED = "terminated"
UNKNOWN = "unknown"

# Explicit, high-confidence termination markers in debugger text output.
_EXIT_PATTERNS = [
    re.compile(r"\bprocess\s+(?:has\s+)?(?:exited|terminated|ended)\b", re.I),
    re.compile(r"\bexit\s*code\b", re.I),
    re.compile(r"\bdebuggee\s+(?:stopped|gone|not\s+running)\b", re.I),
    re.compile(r"\bEXITPROCESS\b", re.I),
]

# Markers that explicitly mean "still alive" — override weak negative guesses.
_ALIVE_PATTERNS = [
    re.compile(r"\bisdebugging\W+true\b", re.I),
    re.compile(r"\bisdebugactive\W+true\b", re.I),
    re.compile(r"\bbreakpoint\s+hit\b", re.I),
    re.compile(r"\bpaused\s+at\b", re.I),
]


def _as_text(result: Any) -> str:
    if isinstance(result, dict):
        return str(result.get("text", "")) or ""
    return str(result or "")


def _is_error_or_timeout(result: Any) -> bool:
    if isinstance(result, dict):
        return bool(result.get("is_error") or result.get("timeout") or result.get("breaker"))
    return False


def parse_isdebugging(result: Any) -> Optional[bool]:
    """Interpret an IsDebugging/IsDebugActive tool result.

    Returns True (alive), False (not debugging), or None (inconclusive: timeout/error/garbage).
    A timeout or error is ALWAYS None, never False — we must not infer death from silence.
    """
    if _is_error_or_timeout(result):
        return None
    text = _as_text(result).strip()
    if not text or text == "(no output)":
        return None
    low = text.lower()
    # Try structured JSON first.
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            for k in ("isDebugging", "isdebugging", "isDebugActive", "result", "value"):
                if k in obj and isinstance(obj[k], bool):
                    return obj[k]
    except (ValueError, TypeError):
        pass
    if "true" in low and "false" not in low:
        return True
    if "false" in low and "true" not in low:
        return False
    return None


def classify_state(
    *,
    isdebugging_result: Any = None,
    last_text: str = "",
    prev_state: str = RUNNING,
    consecutive_negative: int = 0,
) -> Dict[str, Any]:
    """Combine an optional IsDebugging probe and the latest debugger text into a verdict.

    Args:
      isdebugging_result: raw result of an IsDebugging/IsDebugActive tool call (preferred signal).
      last_text:          the most recent debugger output text (run/step/inspect/etc).
      prev_state:         previously known state (for hysteresis).
      consecutive_negative: how many consecutive checks have already indicated "not debugging".

    Returns dict: {state, confidence, reason, consecutive_negative}.
    """
    text = last_text or ""
    # 1) Alive markers in text are decisive.
    for pat in _ALIVE_PATTERNS:
        if pat.search(text):
            return {"state": RUNNING, "confidence": "high",
                    "reason": f"alive marker matched: {pat.pattern}",
                    "consecutive_negative": 0}

    # 2) The IsDebugging probe is the authoritative oracle when conclusive.
    probe = parse_isdebugging(isdebugging_result) if isdebugging_result is not None else None
    if probe is True:
        return {"state": RUNNING, "confidence": "high",
                "reason": "isdebugging=true", "consecutive_negative": 0}
    if probe is False:
        neg = consecutive_negative + 1
        # One confirmed false is enough; a second consecutive negative makes it certain.
        return {"state": TERMINATED,
                "confidence": "high" if neg >= 2 else "medium",
                "reason": f"isdebugging=false (consecutive_negative={neg})",
                "consecutive_negative": neg}

    # 3) Explicit exit text without a probe -> terminated (medium/high).
    for pat in _EXIT_PATTERNS:
        if pat.search(text):
            return {"state": TERMINATED, "confidence": "high",
                    "reason": f"explicit exit marker: {pat.pattern}",
                    "consecutive_negative": consecutive_negative + 1}

    # 4) Timeout / empty / error -> inconclusive. NEVER terminated.
    if _is_error_or_timeout(isdebugging_result):
        return {"state": RUNNING, "confidence": "low",
                "reason": "probe timed out/errored — silence is not death, assume RUNNING",
                "consecutive_negative": consecutive_negative}
    if not text.strip():
        return {"state": prev_state if prev_state in (RUNNING, TERMINATED) else RUNNING,
                "confidence": "low",
                "reason": "no debugger output — inconclusive, keep previous state",
                "consecutive_negative": consecutive_negative}

    # 5) Default: nothing proves termination -> running.
    return {"state": RUNNING, "confidence": "low",
            "reason": "no termination evidence",
            "consecutive_negative": 0}


def is_terminated(verdict: Dict[str, Any]) -> bool:
    """True only when the verdict is an actual TERMINATED state."""
    return verdict.get("state") == TERMINATED
