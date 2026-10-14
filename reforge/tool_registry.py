"""Hybrid tool retrieval (Phase 2.1).

Three layers, in decreasing precision:
  1. Exact match on qualified name or sanitized name.
  2. Keyword search: terms scored on name (×4), tags (×2), description (×1).
  3. Structural filters: risk_class whitelist, phase-aware tag boost, cost penalty.

Server metadata (tags, risk_class, cost) flows from mcp.servers.json -> ToolInfo -> here.
Phase-aware ranking uses the workflow module: recommended tools for the current phase get a score
bonus so the agent naturally picks the right tools at the right time without being told explicitly.
"""
import re
from typing import List, Optional, Sequence

from .mcp_host import MCPHost

_NAME_RE = re.compile(r"[^a-zA-Z0-9_-]")

ALWAYS_ON_RE = re.compile(
    r"^(get_status|get_metadata|get_loaded_file_summary|getmemorymap|"
    r"getmodulelist|list_functions|list_imports|isdebugactive|"
    r"x64dbg_process_state|x64dbg_is_debuggee_alive)$", re.I)

_PHASE_HINTS = {
    "triage":         ["list_imports","list_functions","get_metadata","get_loaded_file_summary","list_sections"],
    "classification": ["floss","entropy","strings","libs","classify"],
    "imports":        ["list_imports","find_dangerous_imports","get_metadata","import"],
    "attack_surface": ["find_dangerous_imports","sink","attack","decompile","xref"],
    "vuln_hunting":   ["decompile","xref","callers","string_uses","disassemble","get_function","strings"],
    "exploitability": ["breakpoint","inspect","readmem","stack","registers","step","run","args","memory"],
    "reporting":      [],
    "validation":     ["decompile","callers","inspect","xref"],
}


class ToolRegistry:
    def __init__(self, host: MCPHost):
        self.host = host
        self.rebuild()

    def rebuild(self) -> None:
        self._info = {}
        self._san  = {}
        self._rev  = {}
        seen: set[str] = set()
        for info in self.host.catalog():
            self._info[info.qualified] = info
            name = _NAME_RE.sub("_", info.qualified)[:64]
            while name in seen:
                name = (name[:60] + "_" + str(len(seen)))[:64]
            seen.add(name)
            self._san[info.qualified] = name
            self._rev[name] = info.qualified

    def qualified_for(self, sanitized: str) -> str:
        return self._rev.get(sanitized, sanitized)

    def spec(self, qualified: str) -> dict:
        info = self._info[qualified]
        return {"name": self._san[qualified],
                "description": f"[{info.server}] {info.description}",
                "input_schema": info.schema}

    def always_on(self) -> List[str]:
        return [q for q, i in self._info.items() if ALWAYS_ON_RE.match(i.name)]

    def search(self, query: str, limit: int = 8, *,
               server: Optional[str] = None,
               risk_classes: Optional[Sequence[str]] = None,
               phase: Optional[str] = None,
               session=None) -> List[str]:
        """Hybrid search: exact -> keyword (name x4, tags x2, desc x1) -> phase boost."""
        if phase is None and session is not None:
            try:
                from . import workflow as _wf
                phase = _wf.current_key(session)
            except Exception:
                pass

        terms = [t for t in re.split(r"\W+", (query or "").lower()) if len(t) >= 2]
        phase_hints = [h.lower() for h in (_PHASE_HINTS.get(phase or "") or [])]

        # Layer 1: exact match
        q_lower = (query or "").lower()
        exact = []
        for q, i in self._info.items():
            if server and i.server != server:
                continue
            if risk_classes and i.risk_class not in risk_classes:
                continue
            if q_lower in (q.lower(), self._san[q].lower(), i.name.lower()):
                exact.append(q)
        if exact:
            return exact[:limit]

        # Layer 2+3: keyword + tags + phase boost
        scored = []
        for q, i in self._info.items():
            if server and i.server != server:
                continue
            if risk_classes and i.risk_class not in risk_classes:
                continue
            name_l = i.name.lower()
            tags_l = " ".join(i.tags).lower()
            desc_l = (i.description or "").lower()

            score = sum(
                (4 if t in name_l else 0) +
                (2 if t in tags_l else 0) +
                (1 if t in desc_l else 0)
                for t in terms) if terms else 0

            if phase_hints:
                score += sum(2 for h in phase_hints if h in name_l or h in tags_l)

            if i.cost == "slow" and not any(t in ("decoded", "slow", "floss") for t in terms):
                score -= 2

            if score > 0:
                scored.append((score, q))

        scored.sort(key=lambda x: (-x[0], x[1]))
        return [q for _, q in scored[:limit]]

    def search_by_phase(self, phase: str, limit: int = 6) -> List[str]:
        hints = _PHASE_HINTS.get(phase, [])
        return self.search(" ".join(hints), limit, phase=phase) if hints else []

    def filter_by_risk(self, risk_classes: Sequence[str], limit: int = 20) -> List[str]:
        return [q for q, i in self._info.items() if i.risk_class in risk_classes][:limit]

    def describe(self, qualifieds: List[str]) -> str:
        out = []
        for q in qualifieds:
            i = self._info.get(q)
            if not i:
                continue
            first = (i.description or "").strip().splitlines()
            tags = f" [{', '.join(i.tags[:4])}]" if i.tags else ""
            out.append(f"- {q} [{i.risk_class}/{i.cost}]{tags} — {first[0][:80] if first else ''}")
        return "\n".join(out)

    def metadata_summary(self) -> List[dict]:
        return [{"qualified": q, "server": i.server, "name": i.name,
                 "risk_class": i.risk_class, "cost": i.cost, "tags": i.tags,
                 "description": (i.description or "").strip()[:120]}
                for q, i in self._info.items()]
