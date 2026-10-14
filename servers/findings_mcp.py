"""MCP server: structured findings registry for a vulnerability assessment.

The deliverable of a VA is the report, not the tool output. Without a persistent store you end up
reconstructing findings by scrolling back through chat transcripts, losing evidence and
double-reporting the same bug found by two different tools.

SQLite-backed, so it survives across sessions. Implements CVSS v3.1 base scoring locally
(no network) and content-hash deduplication.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from typing import Any, Dict

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("findings")
CAP = 14000
DB_PATH = os.environ.get("VA_FINDINGS_DB",
                         os.path.join(os.path.expanduser("~"), ".va_findings.sqlite"))

SEVERITIES = ["info", "low", "medium", "high", "critical"]
STATUSES = ["draft", "confirmed", "false_positive", "wont_fix", "fixed"]

SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dedup_hash TEXT UNIQUE,
    title TEXT NOT NULL,
    target TEXT,
    cwe TEXT,
    severity TEXT,
    cvss_vector TEXT,
    cvss_score REAL,
    status TEXT DEFAULT 'draft',
    location TEXT,
    description TEXT,
    evidence TEXT,
    reproduction TEXT,
    remediation TEXT,
    tool TEXT,
    created_at TEXT,
    updated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_sev ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_status ON findings(status);
"""

# ---------------------------------------------------------------------------
# CVSS v3.1 base score
# ---------------------------------------------------------------------------
_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},          # scope unchanged
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},         # scope changed
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x: float) -> float:
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (i // 10000 + 1) / 10.0


def cvss31(vector: str) -> Dict[str, Any]:
    """Compute the CVSS v3.1 base score from a vector string."""
    v = vector.strip().upper()
    if v.startswith("CVSS:3.1/") or v.startswith("CVSS:3.0/"):
        v = v.split("/", 1)[1]
    parts = {}
    for chunk in v.split("/"):
        if ":" in chunk:
            k, val = chunk.split(":", 1)
            parts[k] = val
    required = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    missing = [r for r in required if r not in parts]
    if missing:
        return {"error": f"incomplete vector, missing: {', '.join(missing)}"}
    try:
        scope_changed = parts["S"] == "C"
        pr = _W["PR_C" if scope_changed else "PR"][parts["PR"]]
        iss = 1 - ((1 - _W["C"][parts["C"]]) * (1 - _W["I"][parts["I"]]) *
                   (1 - _W["A"][parts["A"]]))
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        else:
            impact = 6.42 * iss
        expl = 8.22 * _W["AV"][parts["AV"]] * _W["AC"][parts["AC"]] * pr * _W["UI"][parts["UI"]]
        if impact <= 0:
            score = 0.0
        elif scope_changed:
            score = _roundup(min(1.08 * (impact + expl), 10))
        else:
            score = _roundup(min(impact + expl, 10))
    except KeyError as e:
        return {"error": f"invalid value in the vector: {e}"}

    if score == 0:
        sev = "info"
    elif score < 4.0:
        sev = "low"
    elif score < 7.0:
        sev = "medium"
    elif score < 9.0:
        sev = "high"
    else:
        sev = "critical"
    return {"score": score, "severity": sev, "vector": f"CVSS:3.1/{v}"}


# ---------------------------------------------------------------------------
# storage
# ---------------------------------------------------------------------------
def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def _hash(title: str, location: str, cwe: str) -> str:
    key = f"{title.strip().lower()}|{location.strip().lower()}|{cwe.strip().upper()}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _cap(s: str) -> str:
    return s[:CAP] + "\n…(truncated)" if len(s) > CAP else s


def _row_summary(r: sqlite3.Row) -> str:
    score = f"{r['cvss_score']:.1f}" if r["cvss_score"] is not None else " - "
    return (f"[{r['id']:>3}] {str(r['severity'] or '?').upper():<8} {score:>4}  "
            f"{r['title']}  ({r['cwe'] or 'no CWE'}) [{r['status']}]")


# ---------------------------------------------------------------------------
# tools
# ---------------------------------------------------------------------------
@mcp.tool()
def finding_add(title: str, description: str = "", cwe: str = "", location: str = "",
                target: str = "", cvss_vector: str = "", severity: str = "",
                evidence: str = "", reproduction: str = "", remediation: str = "",
                tool: str = "", status: str = "draft") -> str:
    """Record a vulnerability finding. Deduplicated on (title, location, cwe), so the same issue
    found twice by different tools updates one entry instead of creating two.

    Provide cvss_vector (e.g. 'AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H') and the score and severity are
    computed automatically. `location` should be as precise as you can make it: a function name, an
    RVA, a file path. `evidence` is what proves the finding — tool output, a register dump, an ACL."""
    if status not in STATUSES:
        return f"invalid status: {status}. Valid: {', '.join(STATUSES)}"
    score, sev = None, severity.lower() if severity else ""
    if cvss_vector:
        c = cvss31(cvss_vector)
        if "error" in c:
            return f"CVSS: {c['error']}"
        score, sev, cvss_vector = c["score"], c["severity"], c["vector"]
    if sev and sev not in SEVERITIES:
        return f"invalid severity: {sev}. Valid: {', '.join(SEVERITIES)}"

    h = _hash(title, location, cwe)
    conn = _db()
    existing = conn.execute("SELECT id FROM findings WHERE dedup_hash=?", (h,)).fetchone()
    if existing:
        conn.execute("""UPDATE findings SET description=COALESCE(NULLIF(?,''),description),
                        evidence=COALESCE(NULLIF(?,''),evidence),
                        reproduction=COALESCE(NULLIF(?,''),reproduction),
                        remediation=COALESCE(NULLIF(?,''),remediation),
                        cvss_vector=COALESCE(NULLIF(?,''),cvss_vector),
                        cvss_score=COALESCE(?,cvss_score),
                        severity=COALESCE(NULLIF(?,''),severity),
                        tool=COALESCE(NULLIF(?,''),tool), updated_at=?
                        WHERE id=?""",
                     (description, evidence, reproduction, remediation, cvss_vector, score,
                      sev, tool, _now(), existing["id"]))
        conn.commit()
        fid = existing["id"]
        conn.close()
        return (f"Finding #{fid} already exists (same title+location+CWE): updated instead of "
                f"duplicated.")
    cur = conn.execute("""INSERT INTO findings (dedup_hash,title,target,cwe,severity,cvss_vector,
                          cvss_score,status,location,description,evidence,reproduction,
                          remediation,tool,created_at,updated_at)
                          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                       (h, title, target, cwe, sev or "info", cvss_vector, score, status,
                        location, description, evidence, reproduction, remediation, tool,
                        _now(), _now()))
    conn.commit()
    fid = cur.lastrowid
    conn.close()
    sc = f"{score:.1f}" if score is not None else "n/a"
    return f"Finding #{fid} recorded — {sev or 'info'} (CVSS {sc}) — {title}"


@mcp.tool()
def finding_list(status: str = "", min_severity: str = "", target: str = "") -> str:
    """List recorded findings, sorted by CVSS score descending. Filter by status, minimum severity
    or target. This is the working view during the assessment."""
    conn = _db()
    rows = conn.execute("SELECT * FROM findings").fetchall()
    conn.close()
    if status:
        rows = [r for r in rows if r["status"] == status]
    if target:
        rows = [r for r in rows if target.lower() in (r["target"] or "").lower()]
    if min_severity:
        if min_severity.lower() not in SEVERITIES:
            return f"invalid severity: {min_severity}"
        floor = SEVERITIES.index(min_severity.lower())
        rows = [r for r in rows
                if SEVERITIES.index(r["severity"] or "info") >= floor]
    if not rows:
        return "No matching finding."
    rows = sorted(rows, key=lambda r: (-(r["cvss_score"] or 0),
                                       -SEVERITIES.index(r["severity"] or "info")))
    counts: Dict[str, int] = {}
    for r in rows:
        counts[r["severity"] or "info"] = counts.get(r["severity"] or "info", 0) + 1
    head = "  ".join(f"{s}={counts[s]}" for s in reversed(SEVERITIES) if s in counts)
    return _cap(f"{len(rows)} finding — {head}\n\n" + "\n".join(_row_summary(r) for r in rows))


@mcp.tool()
def finding_get(finding_id: int) -> str:
    """Retrieve the full detail of one finding, including evidence and reproduction steps."""
    conn = _db()
    r = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    conn.close()
    if not r:
        return f"Finding #{finding_id} not found."
    return _cap(json.dumps({k: r[k] for k in r.keys()}, indent=2, ensure_ascii=False))


@mcp.tool()
def finding_update(finding_id: int, status: str = "", severity: str = "", cvss_vector: str = "",
                   evidence: str = "", reproduction: str = "", remediation: str = "",
                   description: str = "") -> str:
    """Update a finding — most often to move it from draft to confirmed once you have a working
    reproduction, or to false_positive once you have ruled it out. Recording false positives
    matters: it stops you re-investigating the same dead end."""
    conn = _db()
    r = conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,)).fetchone()
    if not r:
        conn.close()
        return f"Finding #{finding_id} not found."
    if status and status not in STATUSES:
        conn.close()
        return f"invalid status: {status}. Valid: {', '.join(STATUSES)}"
    score = None
    if cvss_vector:
        c = cvss31(cvss_vector)
        if "error" in c:
            conn.close()
            return f"CVSS: {c['error']}"
        score, severity, cvss_vector = c["score"], c["severity"], c["vector"]
    conn.execute("""UPDATE findings SET
                    status=COALESCE(NULLIF(?,''),status),
                    severity=COALESCE(NULLIF(?,''),severity),
                    cvss_vector=COALESCE(NULLIF(?,''),cvss_vector),
                    cvss_score=COALESCE(?,cvss_score),
                    evidence=COALESCE(NULLIF(?,''),evidence),
                    reproduction=COALESCE(NULLIF(?,''),reproduction),
                    remediation=COALESCE(NULLIF(?,''),remediation),
                    description=COALESCE(NULLIF(?,''),description),
                    updated_at=? WHERE id=?""",
                 (status, severity, cvss_vector, score, evidence, reproduction,
                  remediation, description, _now(), finding_id))
    conn.commit()
    conn.close()
    return f"Finding #{finding_id} updated."


@mcp.tool()
def cvss_calculate(vector: str) -> str:
    """Compute a CVSS v3.1 base score from a vector string, without recording anything.
    Example: AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H

    AV=Attack Vector (N/A/L/P), AC=Complexity (L/H), PR=Privileges Required (N/L/H),
    UI=User Interaction (N/R), S=Scope (U/C), C/I/A=Confidentiality/Integrity/Availability (H/L/N)."""
    c = cvss31(vector)
    if "error" in c:
        return c["error"]
    return f"{c['vector']}\nscore: {c['score']}  →  {c['severity'].upper()}"


@mcp.tool()
def export_report(target: str = "", min_severity: str = "", include_false_positives: bool = False,
                  output_path: str = "") -> str:
    """Export the findings as a Markdown report, ordered by severity, with an executive summary
    table followed by the full detail of each finding. Set output_path to also write it to disk."""
    conn = _db()
    rows = conn.execute("SELECT * FROM findings").fetchall()
    conn.close()
    if target:
        rows = [r for r in rows if target.lower() in (r["target"] or "").lower()]
    if not include_false_positives:
        rows = [r for r in rows if r["status"] not in ("false_positive",)]
    if min_severity:
        floor = SEVERITIES.index(min_severity.lower())
        rows = [r for r in rows if SEVERITIES.index(r["severity"] or "info") >= floor]
    if not rows:
        return "No findings to export."
    rows = sorted(rows, key=lambda r: -(r["cvss_score"] or 0))

    counts: Dict[str, int] = {}
    for r in rows:
        counts[r["severity"] or "info"] = counts.get(r["severity"] or "info", 0) + 1

    md = [f"# Vulnerability Assessment — {target or 'report'}",
          f"_Generated on {_now()}_\n",
          "## Summary\n",
          "| Severity | Count |", "|---|---|"]
    for s in reversed(SEVERITIES):
        if s in counts:
            md.append(f"| {s.capitalize()} | {counts[s]} |")
    md.append(f"| **Total** | **{len(rows)}** |\n")
    md.append("| # | Finding | Severity | CVSS | CWE | Status |")
    md.append("|---|---|---|---|---|---|")
    for r in rows:
        sc = f"{r['cvss_score']:.1f}" if r["cvss_score"] is not None else "-"
        md.append(f"| {r['id']} | {r['title']} | {(r['severity'] or '').capitalize()} | "
                  f"{sc} | {r['cwe'] or '-'} | {r['status']} |")

    md.append("\n---\n\n## Details\n")
    for r in rows:
        sc = f"{r['cvss_score']:.1f}" if r["cvss_score"] is not None else "n/a"
        md.append(f"### [{r['id']}] {r['title']}\n")
        md.append(f"**Severity:** {(r['severity'] or '').capitalize()} (CVSS {sc})  ")
        if r["cvss_vector"]:
            md.append(f"**Vector:** `{r['cvss_vector']}`  ")
        md.append(f"**CWE:** {r['cwe'] or 'n/a'}  ")
        md.append(f"**Component:** `{r['location'] or r['target'] or 'n/a'}`  ")
        md.append(f"**Status:** {r['status']}\n")
        if r["description"]:
            md.append(f"**Description**\n\n{r['description']}\n")
        if r["evidence"]:
            md.append(f"**Evidence**\n\n```\n{r['evidence']}\n```\n")
        if r["reproduction"]:
            md.append(f"**Reproduction**\n\n{r['reproduction']}\n")
        if r["remediation"]:
            md.append(f"**Remediation**\n\n{r['remediation']}\n")
        md.append("---\n")

    report = "\n".join(md)
    if output_path:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as fh:
                fh.write(report)
            return f"Report scritto in {output_path} ({len(rows)} finding, {len(report)} caratteri).\n\n" \
                   + _cap(report)
        except OSError as e:
            return f"write error: {e}\n\n" + _cap(report)
    return _cap(report)


@mcp.tool()
def finding_delete(finding_id: int, confirm: bool = False) -> str:
    """Permanently delete a finding. Requires confirm=true. Prefer setting status to
    false_positive: keeping the record documents what was checked and ruled out."""
    if not confirm:
        return ("confirm=true is required. Consider status='false_positive' instead: "
                "keeping the record documents what you checked and discarded.")
    conn = _db()
    cur = conn.execute("DELETE FROM findings WHERE id=?", (finding_id,))
    conn.commit()
    n = cur.rowcount
    conn.close()
    return f"Finding #{finding_id} deleted." if n else f"Finding #{finding_id} not found."


if __name__ == "__main__":
    mcp.run()
