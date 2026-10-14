"""Tool execution status and its effect on confidence/coverage (prompt §6).

Every tool run is recorded with one of:
    SUCCESS | PARTIAL | FAILED | NOT_RUN | UNSUPPORTED

Errors REDUCE the confidence of the findings that depended on that tool, and surface as
limitations. The engine keeps four semantically distinct notions apart and never conflates them:
    not_found      - the tool ran and did not find the thing
    not_observed   - the behaviour was not seen (e.g. dynamic run produced nothing)
    tool_failed    - the tool errored / could not run
    confirmed_absent - the tool positively established the thing is absent

Concretely: never claim dynamic analysis happened if x64dbg produced no valid observation; a
Ghidra "file not found" error is a limitation, not something to silently ignore.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

SUCCESS = "SUCCESS"
PARTIAL = "PARTIAL"
FAILED = "FAILED"
NOT_RUN = "NOT_RUN"
UNSUPPORTED = "UNSUPPORTED"

_STATES = {SUCCESS, PARTIAL, FAILED, NOT_RUN, UNSUPPORTED}
_CONF_PENALTY = {SUCCESS: 0.0, PARTIAL: 0.10, FAILED: 0.25, NOT_RUN: 0.15, UNSUPPORTED: 0.10}

# Evidence-semantics vocabulary (kept distinct on purpose).
NOT_FOUND = "not_found"
NOT_OBSERVED = "not_observed"
TOOL_FAILED = "tool_failed"
CONFIRMED_ABSENT = "confirmed_absent"


class ToolLedger:
    """Accumulates per-tool runs and computes coverage + confidence impact."""

    def __init__(self):
        self.runs: List[Dict[str, Any]] = []

    def record(self, tool: str, state: str, detail: str = "", affects: Optional[List[str]] = None):
        state = state if state in _STATES else FAILED
        self.runs.append({"tool": tool, "state": state, "detail": detail,
                          "affects": list(affects or [])})

    def limitations(self) -> List[str]:
        out = []
        for r in self.runs:
            if r["state"] in (FAILED, NOT_RUN, UNSUPPORTED, PARTIAL):
                out.append(f"{r['tool']}: {r['state']}"
                           + (f" — {r['detail']}" if r["detail"] else ""))
        return out

    def dynamic_ran_cleanly(self, tools=("x64dbg", "procmon")) -> bool:
        """True only if a dynamic tool ran with SUCCESS and produced observations."""
        for r in self.runs:
            if r["tool"].lower() in tools and r["state"] == SUCCESS:
                return True
        return False

    def penalty_for(self, finding_id: str) -> float:
        """Total confidence penalty for findings whose id appears in a run's `affects`."""
        pen = 0.0
        for r in self.runs:
            if finding_id in r["affects"]:
                pen += _CONF_PENALTY.get(r["state"], 0.0)
        return min(0.5, pen)

    def apply_penalties(self, findings: List[Dict[str, Any]]):
        from .. import severity as _sev
        for f in findings:
            pen = self.penalty_for(f.get("id", ""))
            if pen > 0:
                base = _sev.norm_confidence(f.get("confidence"), 0.0)
                f["confidence"] = round(max(0.0, base - pen), 2)
                note = f"confidence reduced by {pen:.2f} due to tool errors/gaps"
                cg = list(f.get("coverage_gaps") or [])
                if note not in cg:
                    cg.append(note)
                f["coverage_gaps"] = cg

    def summary(self) -> Dict[str, int]:
        s = {k: 0 for k in _STATES}
        for r in self.runs:
            s[r["state"]] += 1
        return s
