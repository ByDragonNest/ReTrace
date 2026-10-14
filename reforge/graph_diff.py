"""Diff of the Evidence Graph between two versions of the same target.

Answers "what changed between two versions of the binary" at graph level: functions, imports,
strings, sinks, sources and findings added or removed, and changes in security-relevant
attributes (a finding moving from HYPOTHESIS to CONFIRMED, a sink becoming validated, a new
source→sink chain).

It works on two JSON exports produced by `EvidenceGraph.to_json()` (or two graph instances), so
it is independent of the physical binary and complementary to `bindiff.py` (which compares the
raw files). Convention: A = previous version, B = new version.
"""
from typing import Any, Dict, List, Tuple

# Node types for which listing additions/removals in the diff makes sense.
_DIFFABLE = ("function", "import", "string", "sink", "source", "finding", "component")

# Attributi la cui variazione è rilevante per la sicurezza (per i nodi che restano).
_WATCH_ATTRS = {
    "finding": ["status", "severity", "confidence", "location"],
    "sink": ["validated", "klass"],
    "component": ["version", "risk"],
}


def _index(graph: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Map node id -> node, from the JSON export."""
    return {n["id"]: n for n in (graph.get("nodes") or [])}


def _edge_key(e: Dict[str, Any]) -> Tuple[str, str, str]:
    return (e.get("src", ""), e.get("dst", ""), e.get("type", ""))


def _label(n: Dict[str, Any]) -> str:
    return n.get("label") or n.get("id", "")


def diff_graphs(graph_a: Dict[str, Any], graph_b: Dict[str, Any]) -> Dict[str, Any]:
    """Compare two graph exports. Returns a structured dictionary of the changes."""
    ia, ib = _index(graph_a), _index(graph_b)
    keys_a, keys_b = set(ia), set(ib)

    added_ids = keys_b - keys_a
    removed_ids = keys_a - keys_b
    common_ids = keys_a & keys_b

    by_type: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    for t in _DIFFABLE:
        added = [{"id": i, "label": _label(ib[i]), "attrs": ib[i].get("attrs", {})}
                 for i in added_ids if ib[i]["type"] == t]
        removed = [{"id": i, "label": _label(ia[i]), "attrs": ia[i].get("attrs", {})}
                   for i in removed_ids if ia[i]["type"] == t]
        if added or removed:
            by_type[t] = {"added": added, "removed": removed}

    # Variazioni di attributi su nodi comuni (solo attributi "watched").
    changed: List[Dict[str, Any]] = []
    for i in common_ids:
        t = ib[i]["type"]
        watch = _WATCH_ATTRS.get(t)
        if not watch:
            continue
        aa, ab = ia[i].get("attrs", {}), ib[i].get("attrs", {})
        deltas = {}
        for k in watch:
            if aa.get(k) != ab.get(k):
                deltas[k] = {"from": aa.get(k), "to": ab.get(k)}
        if deltas:
            changed.append({"id": i, "type": t, "label": _label(ib[i]), "changes": deltas})

    # Archi aggiunti/rimossi (es. nuove catene source→sink, nuovi link evidenza→finding).
    ea = {_edge_key(e): e for e in (graph_a.get("edges") or [])}
    eb = {_edge_key(e): e for e in (graph_b.get("edges") or [])}
    edges_added = [dict(zip(("src", "dst", "type"), k)) for k in (set(eb) - set(ea))]
    edges_removed = [dict(zip(("src", "dst", "type"), k)) for k in (set(ea) - set(eb))]

    summary = {
        "nodes_added": len(added_ids),
        "nodes_removed": len(removed_ids),
        "nodes_changed": len(changed),
        "edges_added": len(edges_added),
        "edges_removed": len(edges_removed),
        "new_findings": sum(1 for i in added_ids if ib[i]["type"] == "finding"),
        "new_sinks": sum(1 for i in added_ids if ib[i]["type"] == "sink"),
        "new_source_to_sink": sum(1 for e in edges_added if e["type"] == "SOURCE_FLOWS_TO_SINK"),
    }
    return {
        "summary": summary,
        "by_type": by_type,
        "changed": changed,
        "edges": {"added": edges_added, "removed": edges_removed},
    }


def security_highlights(diff: Dict[str, Any]) -> List[str]:
    """The security-relevant changes in a graph diff, in plain language.

    These strings go straight into the response of `GET /api/projects/{pid}/graph/diff` and from
    there onto the screen, so they are UI copy and not a debugging aid. They were written in
    Italian, which made this the last path by which a non-English string reached the interface.
    """
    out: List[str] = []
    bt = diff.get("by_type", {})
    for s in bt.get("sink", {}).get("added", []):
        out.append(f"New dangerous sink introduced: {s['label']}.")
    for imp in bt.get("import", {}).get("added", []):
        out.append(f"New import: {imp['label']}.")
    for f in bt.get("finding", {}).get("added", []):
        sev = (f["attrs"].get("severity") or "?")
        out.append(f"New finding ({sev}): {f['label']}.")
    for c in diff.get("changed", []):
        if c["type"] == "finding" and "status" in c["changes"]:
            ch = c["changes"]["status"]
            out.append(f"Finding \u201c{c['label']}\u201d: status {ch['from']} \u2192 {ch['to']}.")
        if c["type"] == "sink" and "validated" in c["changes"]:
            ch = c["changes"]["validated"]
            if ch["to"]:
                out.append(f"Sink \u201c{c['label']}\u201d is now validated.")
    for e in diff.get("edges", {}).get("added", []):
        if e["type"] == "SOURCE_FLOWS_TO_SINK":
            out.append("New source\u2192sink chain detected.")
    return out


def diff_objects(graph_a, graph_b) -> Dict[str, Any]:
    """Convenience: takes two EvidenceGraph instances and diffs their exports."""
    return diff_graphs(graph_a.to_json(), graph_b.to_json())
