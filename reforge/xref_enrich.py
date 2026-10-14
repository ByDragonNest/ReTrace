"""Source→sink enrichment through Ghidra's real xrefs (a dedicated job).

The candidate chains (`source_to_sink.from_session`) are only hypotheses: a source and a sink
both present in the binary. This module promotes them to *located* chains by asking the Ghidra
MCP server for the xrefs/call sites of each sink, so that the real function and address are
known. The result is persisted in the Evidence Graph as a `SOURCE_FLOWS_TO_SINK` edge carrying
the call site and function.

It never runs the binary and writes nothing into the target: only static reads from Ghidra. If
the Ghidra server is not connected or exposes no xref tool, it degrades cleanly (returns the
candidate chains without call sites, without errors).
"""
import re
from typing import Any, Dict, List, Optional

# Nomi di tool Ghidra (variano per server) che restituiscono i riferimenti a un simbolo/funzione.
_XREF_TOOL_RE = re.compile(r"(xref|get_xrefs|references_to|callers|find_references|"
                           r"get_references|who_calls)", re.IGNORECASE)
# Estrae indirizzi e nomi-funzione da output testuali eterogenei di Ghidra.
_ADDR_RE = re.compile(r"0x[0-9a-fA-F]{4,}")
_FUNC_RE = re.compile(r"\b(FUN_[0-9a-fA-F]+|sub_[0-9a-fA-F]+|[A-Za-z_][A-Za-z0-9_]{2,})\b")


def _find_xref_tool(host) -> Optional[str]:
    """Find a Ghidra tool that provides xrefs/callers. Returns its qualified name, or None."""
    if not host:
        return None
    try:
        catalog = host.catalog()
    except Exception:  # noqa: BLE001
        return None
    # Preferisci i tool del server ghidra.
    candidates = []
    for info in catalog:
        name = getattr(info, "name", "") or ""
        if _XREF_TOOL_RE.search(name):
            server = (getattr(info, "server", "") or "").lower()
            candidates.append((0 if "ghidra" in server else 1, info.qualified))
    candidates.sort()
    return candidates[0][1] if candidates else None


def _parse_callsites(text: str, max_sites: int = 5) -> List[Dict[str, str]]:
    """Extract plausible (function, address) pairs from textual xref output."""
    out: List[Dict[str, str]] = []
    seen = set()
    for line in (text or "").splitlines():
        addrs = _ADDR_RE.findall(line)
        if not addrs:
            continue
        # Preferisci nomi-funzione tipici di Ghidra (FUN_/sub_); altrimenti un identificatore
        # plausibile che non sia una parola di servizio dell'output (reference, xref, at, in…).
        fun_named = re.findall(r"\b(?:FUN_[0-9a-fA-F]+|sub_[0-9a-fA-F]+)\b", line)
        func = ""
        if fun_named:
            func = fun_named[0]
        else:
            stop = {"reference", "references", "xref", "xrefs", "at", "in", "to", "from",
                    "call", "calls", "caller", "callers", "found", "address"}
            for f in _FUNC_RE.findall(line):
                if f.startswith("0x") or f.lower() in stop:
                    continue
                func = f
                break
        addr = addrs[0]
        key = (func, addr)
        if key in seen:
            continue
        seen.add(key)
        out.append({"function": func, "callsite": addr})
        if len(out) >= max_sites:
            break
    return out


async def enrich_chains(session, host) -> Dict[str, Any]:
    """Enrich the session's candidate chains with Ghidra xrefs and persist them.

    Returns a summary: the number of chains, how many were located (with a real call site), and
    the tool used.
    """
    from . import source_to_sink as s2s, evidence_graph as eg

    chains = s2s.from_session(session)
    xref_tool = _find_xref_tool(host)
    localized = 0
    enriched: List[Dict[str, Any]] = []

    g = eg.for_session(session)
    binary_id = ""
    prof = getattr(session, "target_profile", None)
    if prof:
        binary_id = g.add_binary(prof)

    # Per evitare chiamate ridondanti, interroga ogni sink una sola volta.
    sink_sites: Dict[str, List[Dict[str, str]]] = {}
    for ch in chains:
        sink = ch.get("sink", "")
        if xref_tool and sink and sink not in sink_sites:
            try:
                res = await host.call(xref_tool, {"name": sink, "symbol": sink, "function": sink})
                txt = res.get("text", "") if isinstance(res, dict) else str(res)
                sink_sites[sink] = [] if (isinstance(res, dict) and res.get("is_error")) \
                    else _parse_callsites(txt)
            except Exception:  # noqa: BLE001
                sink_sites[sink] = []
        sites = sink_sites.get(sink, [])
        if sites:
            site = sites[0]
            ch = s2s.refine_chain(ch, function=site.get("function", ""),
                                  callsite=site.get("callsite", ""))
            localized += 1
        enriched.append(ch)
        try:
            g.record_chain(binary_id, ch)
        except Exception:  # noqa: BLE001
            pass

    return {
        "total": len(enriched),
        "localized": localized,
        "xref_tool": xref_tool or "(none: no Ghidra server available)",
        "chains": enriched[:100],
    }
