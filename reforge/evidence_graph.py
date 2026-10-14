"""Persistent Evidence Graph (SQLite).

Turns ReTrace from "a chat with MCP tools" into a binary security assessment platform: instead
of a flat list of findings in JSON, it builds a queryable store that links binaries, functions,
imports, strings, sinks, sources, tool calls, evidence, findings, components, dynamic events and
reports through typed relations.

Technology choice: SQLite (stdlib, zero dependencies, one file per project, rich SQL queries).
A graph of typed nodes and edges is modelled on two generic tables (`node`, `edge`) plus JSON
columns for the attributes: simple, robust, extensible without a migration per change.

A project's database lives in `<workspace>/<project_id>/graph.sqlite` (via `workspace`), or at
an explicit path (useful for in-memory tests: `path=":memory:"`).

It does NOT replace the `Session` (which stays the runtime source of truth): the Evidence Graph
is the persistent, queryable representation. `sync_from_session()` projects a session's state
into the graph idempotently.
"""
import json
import sqlite3
import time
from contextlib import closing
from typing import Any, Dict, List, Optional

# Tipi di nodo riconosciuti (allineati al prompt). Stringhe libere sono comunque accettate, ma
# questi sono i tipi "di prima classe" usati da query e UI.
NODE_TYPES = {
    "binary", "function", "import", "string", "sink", "source",
    "toolcall", "evidence", "finding", "report", "dynamic_event",
    "component", "risk",
    # v5.8: artifact pipeline + runtime activity + contextual observables
    "artifact",            # an uploaded file (Procmon XML, pcap, log, dump)
    "procmon_op",          # an aggregated Procmon operation cluster (e.g. "RegQueryValue ×1240")
    "file_path",           # a file path observed at runtime / in strings
    "registry_key",        # a registry key observed at runtime
    "network_endpoint",    # a host:port / URL / domain / IP observable
    "process",             # a process observed in Procmon
}

# Tipi di relazione riconosciuti.
EDGE_TYPES = {
    "FUNCTION_CALLS_FUNCTION",
    "FUNCTION_REFERENCES_STRING",
    "FUNCTION_CALLS_IMPORT",
    "SOURCE_FLOWS_TO_SINK",
    "TOOLCALL_GENERATED_EVIDENCE",
    "EVIDENCE_SUPPORTS_FINDING",
    "FINDING_VALIDATED_BY_EVIDENCE",
    "BINARY_CONTAINS_COMPONENT",
    "FINDING_AFFECTS_FUNCTION",
    "DYNAMIC_EVENT_CONFIRMS_FINDING",
    "BINARY_HAS_FUNCTION",
    "BINARY_HAS_IMPORT",
    "BINARY_HAS_STRING",
    "FINDING_HAS_RISK",
    # v5.8
    "ARTIFACT_PARSED_BY_TOOL",       # artifact -> toolcall
    "ARTIFACT_OBSERVED_PROCESS",     # artifact -> process
    "PROCESS_PERFORMED_OP",          # process -> procmon_op
    "PROCESS_ACCESSED_FILE",         # process -> file_path
    "PROCESS_ACCESSED_REGISTRY",     # process -> registry_key
    "PROCESS_CONNECTED_ENDPOINT",    # process -> network_endpoint
    "ARTIFACT_PRODUCED_EVIDENCE",    # artifact -> evidence
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS node (
    id        TEXT PRIMARY KEY,         -- es. "finding:F-0001", "func:0x401200"
    type      TEXT NOT NULL,
    label     TEXT,
    attrs     TEXT NOT NULL DEFAULT '{}',
    created   REAL NOT NULL,
    updated   REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_node_type ON node(type);

CREATE TABLE IF NOT EXISTS edge (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    src       TEXT NOT NULL,
    dst       TEXT NOT NULL,
    type      TEXT NOT NULL,
    attrs     TEXT NOT NULL DEFAULT '{}',
    created   REAL NOT NULL,
    UNIQUE(src, dst, type)
);
CREATE INDEX IF NOT EXISTS idx_edge_src  ON edge(src, type);
CREATE INDEX IF NOT EXISTS idx_edge_dst  ON edge(dst, type);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

SCHEMA_VERSION = "1"


def _now() -> float:
    return time.time()


def nid(node_type: str, key: str) -> str:
    """Canonical node ID, stable and readable (e.g. 'finding:F-0001')."""
    return f"{node_type}:{key}"


class _NoCloseProxy:
    """Wrap a shared connection (an in-memory DB) so that `closing()` does not close it.
    Delegates everything to the underlying connection; `close()` is a no-op."""
    def __init__(self, conn: sqlite3.Connection):
        self._c = conn

    def __getattr__(self, name):
        return getattr(self._c, name)

    def close(self):
        pass


class EvidenceGraph:
    """The evidence graph on SQLite. Thread/async-safe per operation (every method opens and
    closes its own connection; SQLite handles the file locking)."""

    def __init__(self, path: str):
        self.path = str(path)
        # Per :memory: serve una connessione condivisa: ogni connect() creerebbe un DB nuovo.
        self._shared = self._raw_conn() if self.path == ":memory:" else None
        self._init_db()

    # ---- infrastruttura -----------------------------------------------------
    def _raw_conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys=ON")
        return c

    def _conn(self):
        if self._shared is not None:
            return _NoCloseProxy(self._shared)
        return self._raw_conn()

    def _init_db(self) -> None:
        with closing(self._conn()) as c:
            c.executescript(_SCHEMA)
            c.execute("INSERT OR IGNORE INTO meta(key,value) VALUES('schema',?)",
                      (SCHEMA_VERSION,))
            c.commit()

    # ---- primitive nodi/archi ----------------------------------------------
    def upsert_node(self, node_type: str, key: str, label: str = "",
                    attrs: Optional[Dict[str, Any]] = None) -> str:
        """Create or update a node (attributes are merged). Returns the node id."""
        node_id = nid(node_type, key)
        attrs = attrs or {}
        now = _now()
        with closing(self._conn()) as c:
            row = c.execute("SELECT attrs FROM node WHERE id=?", (node_id,)).fetchone()
            if row:
                merged = json.loads(row["attrs"] or "{}")
                merged.update({k: v for k, v in attrs.items() if v not in (None, "")})
                c.execute("UPDATE node SET label=COALESCE(NULLIF(?,''),label), attrs=?, updated=? "
                          "WHERE id=?", (label, json.dumps(merged), now, node_id))
            else:
                c.execute("INSERT INTO node(id,type,label,attrs,created,updated) "
                          "VALUES(?,?,?,?,?,?)",
                          (node_id, node_type, label, json.dumps(attrs), now, now))
            c.commit()
        return node_id

    def add_edge(self, src_id: str, dst_id: str, edge_type: str,
                 attrs: Optional[Dict[str, Any]] = None) -> None:
        """Create a typed edge (idempotent on the (src, dst, type) triple)."""
        with closing(self._conn()) as c:
            c.execute("INSERT OR IGNORE INTO edge(src,dst,type,attrs,created) VALUES(?,?,?,?,?)",
                      (src_id, dst_id, edge_type, json.dumps(attrs or {}), _now()))
            c.commit()

    # ---- inserimenti di alto livello ---------------------------------------
    def add_binary(self, b: Dict[str, Any]) -> str:
        key = (b.get("sha256") or b.get("md5") or b.get("file") or "binary")[:64]
        return self.upsert_node("binary", key, b.get("file", key), b)

    def add_function(self, binary_id: str, addr: str, name: str = "",
                     attrs: Optional[Dict[str, Any]] = None) -> str:
        node = self.upsert_node("function", str(addr), name or str(addr), attrs)
        if binary_id:
            self.add_edge(binary_id, node, "BINARY_HAS_FUNCTION")
        return node

    def add_import(self, binary_id: str, name: str,
                   attrs: Optional[Dict[str, Any]] = None) -> str:
        node = self.upsert_node("import", name.lower(), name, attrs)
        if binary_id:
            self.add_edge(binary_id, node, "BINARY_HAS_IMPORT")
        return node

    def add_sink(self, name: str, attrs: Optional[Dict[str, Any]] = None) -> str:
        return self.upsert_node("sink", name.lower(), name,
                                {"validated": False, **(attrs or {})})

    def add_source(self, name: str, attrs: Optional[Dict[str, Any]] = None) -> str:
        return self.upsert_node("source", name.lower(), name, attrs)

    def add_evidence(self, eid: str, attrs: Optional[Dict[str, Any]] = None) -> str:
        return self.upsert_node("evidence", eid, eid, attrs)

    def add_finding(self, fid: str, attrs: Optional[Dict[str, Any]] = None) -> str:
        return self.upsert_node("finding", fid, (attrs or {}).get("title", fid), attrs)

    # ---- v5.8: artifact + runtime activity ---------------------------------
    def add_artifact(self, artifact_id: str, attrs: Optional[Dict[str, Any]] = None) -> str:
        a = attrs or {}
        label = a.get("name") or artifact_id
        return self.upsert_node("artifact", artifact_id, label, a)

    def add_process(self, name: str, attrs: Optional[Dict[str, Any]] = None) -> str:
        return self.upsert_node("process", (name or "process").lower(), name, attrs)

    def add_procmon_op(self, op: str, count: int = 0,
                       attrs: Optional[Dict[str, Any]] = None) -> str:
        label = f"{op} ×{count}" if count else op
        return self.upsert_node("procmon_op", (op or "op").lower(), label,
                                {"operation": op, "count": count, **(attrs or {})})

    def add_file_path(self, path: str, attrs: Optional[Dict[str, Any]] = None) -> str:
        key = str(abs(hash(path)) % (10 ** 12))
        return self.upsert_node("file_path", key, (path or "")[:120],
                                {"path": path, **(attrs or {})})

    def add_registry_key(self, key_path: str, attrs: Optional[Dict[str, Any]] = None) -> str:
        key = str(abs(hash(key_path)) % (10 ** 12))
        return self.upsert_node("registry_key", key, (key_path or "")[:120],
                                {"path": key_path, **(attrs or {})})

    def add_network_endpoint(self, endpoint: str, attrs: Optional[Dict[str, Any]] = None) -> str:
        return self.upsert_node("network_endpoint", (endpoint or "").lower()[:120],
                                endpoint, attrs)

    def link_artifact_to_process(self, artifact_id: str, process_id: str) -> None:
        self.add_edge(nid("artifact", artifact_id), process_id, "ARTIFACT_OBSERVED_PROCESS")

    def link_process_op(self, process_id: str, op_id: str) -> None:
        self.add_edge(process_id, op_id, "PROCESS_PERFORMED_OP")

    def link_process_file(self, process_id: str, file_id: str) -> None:
        self.add_edge(process_id, file_id, "PROCESS_ACCESSED_FILE")

    def link_process_registry(self, process_id: str, reg_id: str) -> None:
        self.add_edge(process_id, reg_id, "PROCESS_ACCESSED_REGISTRY")

    def link_process_endpoint(self, process_id: str, ep_id: str) -> None:
        self.add_edge(process_id, ep_id, "PROCESS_CONNECTED_ENDPOINT")

    # collegamenti semantici
    def link_evidence_to_finding(self, evidence_id: str, finding_id: str,
                                 validating: bool = False) -> None:
        self.add_edge(evidence_id, finding_id, "EVIDENCE_SUPPORTS_FINDING")
        if validating:
            self.add_edge(finding_id, evidence_id, "FINDING_VALIDATED_BY_EVIDENCE")

    def link_source_to_sink(self, source_id: str, sink_id: str,
                            attrs: Optional[Dict[str, Any]] = None) -> None:
        self.add_edge(source_id, sink_id, "SOURCE_FLOWS_TO_SINK", attrs)

    def link_finding_to_function(self, finding_id: str, function_id: str) -> None:
        self.add_edge(finding_id, function_id, "FINDING_AFFECTS_FUNCTION")

    def mark_sink_validated(self, name: str, validated: bool = True) -> None:
        self.upsert_node("sink", name.lower(), name, {"validated": validated})

    def record_chain(self, binary_id: str, chain: Dict[str, Any]) -> Dict[str, str]:
        """Persist a source→sink chain (possibly refined with real xrefs) as a
        `SOURCE_FLOWS_TO_SINK` edge carrying call site/function/argument in its attributes.
        Creates the missing source/sink/function nodes and, when the chain cites a call site,
        marks the sink as 'located' (validation stays a separate confirmation). Returns the
        node IDs."""
        src = self.add_source(chain.get("source", "input"))
        snk = self.add_sink(chain.get("sink", "sink"))
        attrs = {
            "function": chain.get("function", ""),
            "callsite": chain.get("callsite", ""),
            "argument": chain.get("argument", ""),
            "validation_seen": bool(chain.get("validation_seen")),
            "confidence": chain.get("confidence"),
            "confirmed_dynamic": bool(chain.get("confirmed_dynamic")),
            "evidence_refs": chain.get("evidence_refs", []),
        }
        self.link_source_to_sink(src, snk, attrs)
        out = {"source": src, "sink": snk}
        if chain.get("function") and binary_id:
            fn = self.add_function(binary_id, chain.get("callsite") or chain["function"],
                                   chain["function"])
            self.add_edge(fn, snk, "FUNCTION_CALLS_IMPORT")
            out["function"] = fn
        return out

    def chains(self) -> List[Dict[str, Any]]:
        """Every recorded source\u2192sink chain, with its attributes."""
        out = []
        for e in self.query_edges("SOURCE_FLOWS_TO_SINK"):
            a = e.get("attrs", {})
            out.append({"source": e["src"].split(":", 1)[-1], "sink": e["dst"].split(":", 1)[-1],
                        **a})
        return out

    # ---- query --------------------------------------------------------------
    def _nodes(self, c, node_type: str) -> List[Dict[str, Any]]:
        rows = c.execute("SELECT * FROM node WHERE type=? ORDER BY created", (node_type,)).fetchall()
        return [self._row_to_node(r) for r in rows]

    @staticmethod
    def _row_to_node(r: sqlite3.Row) -> Dict[str, Any]:
        return {"id": r["id"], "type": r["type"], "label": r["label"],
                "attrs": json.loads(r["attrs"] or "{}"),
                "created": r["created"], "updated": r["updated"]}

    def get_finding_with_evidence(self, finding_id: str) -> Dict[str, Any]:
        """A finding with the list of linked evidence and affected functions."""
        with closing(self._conn()) as c:
            row = c.execute("SELECT * FROM node WHERE id=?", (finding_id,)).fetchone()
            if not row:
                return {}
            f = self._row_to_node(row)
            ev = c.execute(
                "SELECT n.* FROM edge e JOIN node n ON n.id=e.src "
                "WHERE e.dst=? AND e.type='EVIDENCE_SUPPORTS_FINDING'", (finding_id,)).fetchall()
            f["evidence"] = [self._row_to_node(r) for r in ev]
            fn = c.execute(
                "SELECT n.* FROM edge e JOIN node n ON n.id=e.dst "
                "WHERE e.src=? AND e.type='FINDING_AFFECTS_FUNCTION'", (finding_id,)).fetchall()
            f["functions"] = [self._row_to_node(r) for r in fn]
            return f

    def unvalidated_sinks(self) -> List[Dict[str, Any]]:
        """Sinks not yet validated dynamically (e.g. 'CreateProcess not confirmed')."""
        with closing(self._conn()) as c:
            return [n for n in self._nodes(c, "sink")
                    if not n["attrs"].get("validated")]

    def findings_lacking_evidence(self, min_evidence: int = 2,
                                  severities=("HIGH", "CRITICAL")) -> List[Dict[str, Any]]:
        """High-severity findings with fewer than `min_evidence` linked evidence records."""
        out = []
        with closing(self._conn()) as c:
            for f in self._nodes(c, "finding"):
                sev = (f["attrs"].get("severity") or "").upper()
                if severities and sev not in severities:
                    continue
                n = c.execute("SELECT COUNT(*) AS k FROM edge WHERE dst=? AND "
                              "type='EVIDENCE_SUPPORTS_FINDING'", (f["id"],)).fetchone()["k"]
                if n < min_evidence:
                    f["evidence_count"] = n
                    out.append(f)
        return out

    def query_edges(self, edge_type: str) -> List[Dict[str, Any]]:
        with closing(self._conn()) as c:
            rows = c.execute("SELECT * FROM edge WHERE type=?", (edge_type,)).fetchall()
            return [{"src": r["src"], "dst": r["dst"], "type": r["type"],
                     "attrs": json.loads(r["attrs"] or "{}")} for r in rows]

    def get_node(self, node_id: str) -> Dict[str, Any]:
        """Return one node with incoming/outgoing relations for side-panel/API use."""
        with closing(self._conn()) as c:
            row = c.execute("SELECT * FROM node WHERE id=?", (node_id,)).fetchone()
            if not row:
                return {}
            node = self._row_to_node(row)
            inc = c.execute("SELECT * FROM edge WHERE dst=? ORDER BY id", (node_id,)).fetchall()
            out = c.execute("SELECT * FROM edge WHERE src=? ORDER BY id", (node_id,)).fetchall()
            node["incoming"] = [self._row_to_edge(r) for r in inc]
            node["outgoing"] = [self._row_to_edge(r) for r in out]
            return node

    def neighborhood(self, node_id: str, depth: int = 1, limit: int = 250) -> Dict[str, Any]:
        """Return a bounded subgraph around a node. Depth is intentionally small for UI safety."""
        depth = max(1, min(int(depth or 1), 3))
        seen = {node_id}
        frontier = {node_id}
        edges: List[Dict[str, Any]] = []
        with closing(self._conn()) as c:
            for _ in range(depth):
                if not frontier or len(seen) >= limit:
                    break
                placeholders = ",".join("?" for _ in frontier)
                rows = c.execute(
                    f"SELECT * FROM edge WHERE src IN ({placeholders}) OR dst IN ({placeholders}) "
                    "ORDER BY id LIMIT ?",
                    tuple(frontier) + tuple(frontier) + (limit,)
                ).fetchall()
                nxt = set()
                for r in rows:
                    e = self._row_to_edge(r)
                    edges.append(e)
                    for nid_ in (e["src"], e["dst"]):
                        if nid_ not in seen and len(seen) < limit:
                            seen.add(nid_)
                            nxt.add(nid_)
                frontier = nxt
            placeholders = ",".join("?" for _ in seen)
            rows = c.execute(f"SELECT * FROM node WHERE id IN ({placeholders})", tuple(seen)).fetchall()
            nodes = [self._row_to_node(r) for r in rows]
        ids = {n["id"] for n in nodes}
        edges = [e for e in edges if e["src"] in ids and e["dst"] in ids]
        return {"nodes": nodes, "edges": edges, "root": node_id, "depth": depth}

    def stats(self) -> Dict[str, int]:
        with closing(self._conn()) as c:
            out = {}
            for t in sorted(NODE_TYPES):
                out[t] = c.execute("SELECT COUNT(*) AS k FROM node WHERE type=?", (t,)).fetchone()["k"]
            out["edges"] = c.execute("SELECT COUNT(*) AS k FROM edge").fetchone()["k"]
            return out

    @staticmethod
    def _row_to_edge(r: sqlite3.Row) -> Dict[str, Any]:
        return {"id": f"edge:{r['id']}", "src": r["src"], "dst": r["dst"],
                "source": r["src"], "target": r["dst"], "type": r["type"],
                "attrs": json.loads(r["attrs"] or "{}"), "created": r["created"]}

    def summary(self) -> Dict[str, Any]:
        """Threat-map summary shaped for dashboards and API consumers."""
        with closing(self._conn()) as c:
            nodes_by_type = {r["type"]: r["k"] for r in
                             c.execute("SELECT type, COUNT(*) AS k FROM node GROUP BY type")}
            edges_by_type = {r["type"]: r["k"] for r in
                             c.execute("SELECT type, COUNT(*) AS k FROM edge GROUP BY type")}
            findings_by_status: Dict[str, int] = {}
            findings_by_severity: Dict[str, int] = {}
            for r in c.execute("SELECT attrs FROM node WHERE type='finding'").fetchall():
                a = json.loads(r["attrs"] or "{}")
                status = str(a.get("status") or "UNKNOWN").upper()
                severity = str(a.get("severity") or "INFO").upper()
                findings_by_status[status] = findings_by_status.get(status, 0) + 1
                findings_by_severity[severity] = findings_by_severity.get(severity, 0) + 1
            artifacts = {r["id"]: {"label": r["label"], **json.loads(r["attrs"] or "{}")}
                         for r in c.execute("SELECT id,label,attrs FROM node WHERE type='artifact'")}
        return {
            "nodes_by_type": nodes_by_type,
            "edges_by_type": edges_by_type,
            "findings_by_status": findings_by_status,
            "findings_by_severity": findings_by_severity,
            "artifacts": artifacts,
        }

    def to_json(self) -> Dict[str, Any]:
        """Export the whole graph as {nodes:[...], edges:[...]} (for UI/backup/diff)."""
        with closing(self._conn()) as c:
            nodes = [self._row_to_node(r)
                     for r in c.execute("SELECT * FROM node ORDER BY type,created").fetchall()]
            edges = [self._row_to_edge(r)
                     for r in c.execute("SELECT * FROM edge ORDER BY id").fetchall()]
        return {"schema": SCHEMA_VERSION, "nodes": nodes, "edges": edges,
                "stats": self.stats(), "summary": self.summary()}

    # ---- proiezione da una Session -----------------------------------------
    def sync_from_session(self, session) -> Dict[str, int]:
        """Project a Session's state into the graph, idempotently.

        Mapping: target_profile->binary, static_imports->import, evidence->evidence,
        findings->finding (+ evidence->finding and finding->function edges), and the sinks known
        from the dangerous imports. Returns the updated statistics.
        """
        binary_id = ""
        prof = getattr(session, "target_profile", None)
        if prof:
            binary_id = self.add_binary(prof)
        elif getattr(session, "target_path", None):
            binary_id = self.add_binary({"file": session.target_path})

        for imp in (getattr(session, "static_imports", []) or [])[:2000]:
            name = imp if isinstance(imp, str) else (imp.get("name") if isinstance(imp, dict) else str(imp))
            if name:
                self.add_import(binary_id, name)

        # sink dall'inventario (se disponibile)
        try:
            from . import sinks as _sinks
            imp_names = [i if isinstance(i, str) else (i.get("name") if isinstance(i, dict) else str(i))
                         for i in (getattr(session, "static_imports", []) or [])]
            inv = _sinks.inventory([n for n in imp_names if n])
            for klass, apis in (inv.get("sinks") or {}).items():
                for api in apis:
                    self.add_sink(api, {"klass": klass})
            for sym in (inv.get("sources") or {}):
                self.add_source(sym)
        except Exception:
            pass

        for ev in (getattr(session, "evidence", []) or []):
            eid = ev.get("id")
            if eid:
                self.add_evidence(eid, {"source": ev.get("source"),
                                        "summary": ev.get("summary"),
                                        "tool": ev.get("tool_name")})

        for f in (getattr(session, "findings", []) or []):
            fid = f.get("id") or f.get("title", "F-?")
            self.add_finding(fid, {
                "title": f.get("title"), "severity": f.get("severity"),
                "status": f.get("status"), "vuln_type": f.get("vuln_type"),
                "location": f.get("location"), "confidence": f.get("confidence"),
            })
            fnode = nid("finding", fid)
            loc = (f.get("location") or "").strip()
            if loc and binary_id:
                func = self.add_function(binary_id, loc, "")
                self.link_finding_to_function(fnode, func)
            for ref in (f.get("evidence_refs") or []):
                if str(ref).startswith("E-"):
                    self.link_evidence_to_finding(nid("evidence", str(ref)), fnode,
                                                  validating=("dynamic" in (f.get("status") or "").lower()))

        # v5.8: project uploaded artifacts as graph nodes (artifact view).
        for a in (getattr(session, "artifacts", []) or []):
            aid = a.get("id")
            if aid:
                self.add_artifact(aid, {"name": a.get("name"), "atype": a.get("type"),
                                        "size": a.get("size"), "sha256": a.get("sha256"),
                                        "source": a.get("source", "user_upload")})
        return self.stats()

    # ---- v5.8: project a compact Procmon summary (anti-noise) ----------------
    def project_procmon_summary(self, artifact_id: str, summary: Dict[str, Any], *,
                                top_ops: int = 12, top_paths: int = 15) -> Dict[str, int]:
        """Project a Procmon summary into the graph WITHOUT exploding 150k raw events.

        Only aggregated, high-signal nodes are created: the process, the top operation clusters,
        and the top file/registry/network paths. This honours the prompt's anti-noise requirement
        (cluster + top-N) instead of one node per event.
        """
        self.add_artifact(artifact_id, {"atype": "procmon_xml"})
        procs = summary.get("top_processes") or []
        # The dominant process (most events) anchors the runtime activity.
        main_proc = procs[0][0] if procs and isinstance(procs[0], (list, tuple)) else \
            (summary.get("filtered_process_name") or "process")
        pid_node = self.add_process(main_proc, {"events": procs[0][1] if procs else 0})
        self.link_artifact_to_process(artifact_id, pid_node)

        for op, cnt in (summary.get("top_operations") or [])[:top_ops]:
            op_node = self.add_procmon_op(op, cnt, {"source": "procmon"})
            self.link_process_op(pid_node, op_node)

        for path, cnt in (summary.get("top_file_paths") or [])[:top_paths]:
            fnode = self.add_file_path(path, {"count": cnt, "source": "procmon"})
            self.link_process_file(pid_node, fnode)

        for path, cnt in (summary.get("top_registry_paths") or [])[:top_paths]:
            rnode = self.add_registry_key(path, {"count": cnt, "source": "procmon"})
            self.link_process_registry(pid_node, rnode)

        for ep, cnt in (summary.get("top_network") or [])[:top_paths]:
            enode = self.add_network_endpoint(ep, {"count": cnt, "source": "procmon"})
            self.link_process_endpoint(pid_node, enode)

        return self.stats()


def for_session(session) -> EvidenceGraph:
    """Open or create the Evidence Graph of the project behind the session."""
    from . import workspace
    d = workspace.project_dir(session.id)
    return EvidenceGraph(str(d / "graph.sqlite"))
