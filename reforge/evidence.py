"""Evidence objects (Phase 1.2): every conclusion should trace back to a piece of evidence.

An evidence record captures where a fact came from (tool/source + location), a short summary, a
capped raw excerpt, a content hash (for dedup), and a reference to the full raw output stored
outside the prompt. IDs are assigned by the session (`E-0001`, …).
"""
import hashlib
from typing import Any, Dict, Optional

EXCERPT_CAP = 1500
VALID_SOURCES = {"ghidra", "x64dbg", "floss", "tshark", "procmon",
                 "static_analysis", "dynamic_analysis", "llm", "user", "mcp"}


def _hash(text: str) -> str:
    return hashlib.sha1((text or "").encode("utf-8", "replace")).hexdigest()[:12]


def make(source: str, summary: str, raw: str = "", *, tool_name: str = "",
         location: Optional[Dict[str, Any]] = None, truncated: bool = False) -> Dict[str, Any]:
    """Build an evidence record (without an ID — the session assigns it)."""
    raw = raw or ""
    excerpt = raw[:EXCERPT_CAP]
    return {
        "source": source if source in VALID_SOURCES else "mcp",
        "tool_name": tool_name or "",
        "location": location or {},
        "summary": (summary or "").strip()[:300],
        "raw_excerpt": excerpt,
        "hash": _hash(raw or summary),
        "truncated": bool(truncated or len(raw) > EXCERPT_CAP),
    }


def location_from_finding(f: Dict[str, Any]) -> Dict[str, Any]:
    loc = f.get("location") or ""
    out: Dict[str, Any] = {}
    if loc:
        out["function" if ("fun_" in loc.lower() or "sub_" in loc.lower() or "@" in loc) else "address"] = loc
    return out
