"""Optional Neo4j backend for the Evidence Graph.

WHY THIS EXISTS
---------------
The evidence graph lives in per-project SQLite and the in-app Evidence Graph renders from it — that is
the source of truth and needs no external services. Some analysts want the graph in Neo4j to run
Cypher and use Neo4j Browser / Bloom for link analysis. This module mirrors a project's graph into
Neo4j WITHOUT changing the existing store: SQLite stays authoritative; Neo4j is an export/sync
target plus a query surface.

DESIGN
------
* OPT-IN: nothing happens unless config.NEO4J_ENABLED and the `neo4j` driver is installed.
* IDEMPOTENT: nodes/edges are MERGEd on a stable key, so re-syncing a project updates in place.
* SCOPED: every node/edge is tagged with the project id, so one Neo4j instance can hold many
  projects and a project can be wiped/re-synced independently.
* DEGRADES CLEANLY: if the driver is missing or the server is unreachable, the API returns a clear
  status and a ready-to-run Cypher script the user can paste into Neo4j Browser — the rest of
  ReTrace is unaffected.

The graph payload is the canonical `{"nodes":[...], "edges":[...]}` shape produced by
EvidenceGraph.to_json(); see evidence_graph.py.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from . import config


def driver_available() -> bool:
    try:
        import neo4j  # noqa: F401
        return True
    except Exception:
        return False


def is_enabled() -> bool:
    return bool(getattr(config, "NEO4J_ENABLED", False))


def status() -> Dict[str, Any]:
    """Report whether Neo4j sync is enabled, the driver is present, and the server is reachable."""
    enabled = is_enabled()
    have_driver = driver_available()
    reachable: Optional[bool] = None
    error: Optional[str] = None
    if enabled and have_driver:
        try:
            drv = _connect()
            drv.verify_connectivity()
            drv.close()
            reachable = True
        except Exception as exc:  # noqa: BLE001
            reachable = False
            error = str(exc)[:300]
    return {
        "enabled": enabled,
        "driver_installed": have_driver,
        "uri": getattr(config, "NEO4J_URI", ""),
        "browser_url": _browser_url(getattr(config, "NEO4J_URI", "")),
        "database": getattr(config, "NEO4J_DATABASE", "neo4j"),
        "reachable": reachable,
        "error": error,
    }


def _browser_url(bolt_uri: str) -> str:
    """Best-effort Neo4j Browser URL from a bolt URI (bolt://host:7687 -> http://host:7474)."""
    m = re.match(r"^\w+://([^:/]+)(?::(\d+))?", bolt_uri or "")
    host = m.group(1) if m else "127.0.0.1"
    return f"http://{host}:7474/browser/"


def project_match_cypher(project_id: str) -> str:
    """A ready Cypher query that shows this project's whole graph in Neo4j Browser."""
    pid = project_id.replace("'", "")
    return (f"MATCH (n:ReforgeNode {{project_id: '{pid}'}}) "
            f"OPTIONAL MATCH (n)-[r {{project_id: '{pid}'}}]->(m) RETURN n, r, m")


def _connect():
    from neo4j import GraphDatabase
    return GraphDatabase.driver(
        config.NEO4J_URI,
        auth=(config.NEO4J_USER, config.NEO4J_PASSWORD),
    )


# --------------------------------------------------------------------------- label / value mapping
def _label(node_type: str) -> str:
    """Map a graph node type to a valid Neo4j label (PascalCase, alnum only)."""
    t = re.sub(r"[^A-Za-z0-9]+", " ", str(node_type or "Node")).title().replace(" ", "")
    return t or "Node"


def _rel(edge_type: str) -> str:
    """Map an edge type to a valid Neo4j relationship type (UPPER_SNAKE)."""
    r = re.sub(r"[^A-Za-z0-9]+", "_", str(edge_type or "RELATED")).upper().strip("_")
    return r or "RELATED"


def _clean_props(d: Dict[str, Any]) -> Dict[str, Any]:
    """Neo4j properties must be primitives or arrays of primitives. Flatten anything else to JSON."""
    out: Dict[str, Any] = {}
    for k, v in (d or {}).items():
        key = re.sub(r"[^A-Za-z0-9_]", "_", str(k))
        if isinstance(v, (str, int, float, bool)) or v is None:
            out[key] = v
        elif isinstance(v, (list, tuple)) and all(isinstance(x, (str, int, float, bool)) for x in v):
            out[key] = list(v)
        else:
            out[key] = json.dumps(v, ensure_ascii=False, default=str)
    return out


def _node_fields(n: Dict[str, Any]) -> Tuple[str, str, Dict[str, Any]]:
    nid = str(n.get("id") or n.get("node_id") or "")
    ntype = n.get("type") or n.get("node_type") or "node"
    props = _clean_props(n.get("properties") or n.get("attrs") or {})
    props["label"] = n.get("label") or props.get("label") or nid
    for extra in ("severity", "status", "confidence", "source"):
        if n.get(extra) is not None:
            props[extra] = n.get(extra)
    return nid, _label(ntype), props


def _edge_fields(e: Dict[str, Any]) -> Tuple[str, str, str, Dict[str, Any]]:
    src = str(e.get("source") or e.get("src") or e.get("from") or "")
    dst = str(e.get("target") or e.get("dst") or e.get("to") or "")
    etype = e.get("type") or e.get("edge_type") or "related"
    props = _clean_props(e.get("properties") or e.get("attrs") or {})
    return src, dst, _rel(etype), props


# --------------------------------------------------------------------------- sync
def sync_graph(project_id: str, graph_json: Dict[str, Any]) -> Dict[str, Any]:
    """Mirror a project's graph payload into Neo4j (MERGE-based, scoped by project_id).

    Returns counts. Raises RuntimeError with a clear message if sync isn't possible so the caller
    can fall back to the Cypher export.
    """
    if not is_enabled():
        raise RuntimeError("Neo4j is not enabled (config.NEO4J_ENABLED=False).")
    if not driver_available():
        raise RuntimeError("The 'neo4j' driver is not installed (pip install neo4j).")

    nodes = graph_json.get("nodes") or []
    edges = graph_json.get("edges") or []
    drv = _connect()
    db = getattr(config, "NEO4J_DATABASE", "neo4j")
    written_nodes = written_edges = 0
    try:
        with drv.session(database=db) as s:
            # Wipe this project's previous mirror so deletions are reflected (scoped, not global).
            s.run("MATCH (n:ReforgeNode {project_id:$pid}) DETACH DELETE n", pid=project_id)
            for n in nodes:
                nid, label, props = _node_fields(n)
                if not nid:
                    continue
                props["project_id"] = project_id
                s.run(
                    f"MERGE (n:ReforgeNode:`{label}` {{id:$id, project_id:$pid}}) SET n += $props",
                    id=nid, pid=project_id, props=props)
                written_nodes += 1
            for e in edges:
                src, dst, rel, props = _edge_fields(e)
                if not src or not dst:
                    continue
                props["project_id"] = project_id
                s.run(
                    "MATCH (a:ReforgeNode {id:$src, project_id:$pid}), "
                    "(b:ReforgeNode {id:$dst, project_id:$pid}) "
                    f"MERGE (a)-[r:`{rel}` {{project_id:$pid}}]->(b) SET r += $props",
                    src=src, dst=dst, pid=project_id, props=props)
                written_edges += 1
    finally:
        drv.close()
    return {"ok": True, "project_id": project_id, "nodes": written_nodes, "edges": written_edges,
            "database": db, "uri": config.NEO4J_URI}


# --------------------------------------------------------------------------- Cypher export (fallback)
def _cypher_literal(props: Dict[str, Any]) -> str:
    parts = []
    for k, v in props.items():
        parts.append(f"{k}: {json.dumps(v, ensure_ascii=False, default=str)}")
    return "{" + ", ".join(parts) + "}"


def to_cypher(project_id: str, graph_json: Dict[str, Any]) -> str:
    """Generate a standalone Cypher script that builds this project's graph in any Neo4j instance.

    This is the fallback when the driver/server isn't available: the analyst pastes it into Neo4j
    Browser. It is scoped/idempotent the same way sync_graph is.
    """
    nodes = graph_json.get("nodes") or []
    edges = graph_json.get("edges") or []
    lines: List[str] = [
        f"// ReTrace graph export — project {project_id}",
        f"// {len(nodes)} nodes, {len(edges)} edges",
        f"MATCH (n:ReforgeNode {{project_id: {json.dumps(project_id)}}}) DETACH DELETE n;",
        "CREATE CONSTRAINT reforge_node_id IF NOT EXISTS "
        "FOR (n:ReforgeNode) REQUIRE (n.id, n.project_id) IS NODE KEY;",
        "",
    ]
    for n in nodes:
        nid, label, props = _node_fields(n)
        if not nid:
            continue
        props["id"] = nid
        props["project_id"] = project_id
        lines.append(f"MERGE (n:ReforgeNode:`{label}` {{id: {json.dumps(nid)}, "
                     f"project_id: {json.dumps(project_id)}}}) SET n += {_cypher_literal(props)};")
    lines.append("")
    for e in edges:
        src, dst, rel, props = _edge_fields(e)
        if not src or not dst:
            continue
        props["project_id"] = project_id
        lines.append(
            f"MATCH (a:ReforgeNode {{id: {json.dumps(src)}, project_id: {json.dumps(project_id)}}}), "
            f"(b:ReforgeNode {{id: {json.dumps(dst)}, project_id: {json.dumps(project_id)}}}) "
            f"MERGE (a)-[r:`{rel}`]->(b) SET r += {_cypher_literal(props)};")
    return "\n".join(lines) + "\n"
