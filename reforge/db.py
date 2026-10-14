"""SQLite persistence for ReTrace projects.

The JSON project files remain as a compatibility/export layer, but SQLite is the
authoritative indexed store for loading and listing projects.
"""
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import config

_LOCK = threading.RLock()


def db_file():
    """The database path, read live rather than captured at import.

    It used to be a module-level constant resolved when `db.py` was first imported, so any later
    change to the configured path was ignored - including one made through the settings facade.
    That stayed invisible while nothing else read the path independently; the moment the migration
    runner did, the two disagreed and migrations ran against a different file than the tables.
    """
    return getattr(config, "PROJECTS_DB", config.ROOT / "reforge.db")


def _connect() -> sqlite3.Connection:
    path = db_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path))
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    return con


def init() -> None:
    with _LOCK, _connect() as con:
        con.execute("""
        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY,
            name TEXT,
            created REAL,
            updated REAL,
            target_path TEXT,
            payload TEXT NOT NULL
        )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_projects_updated ON projects(updated DESC)")
    # Schema changes after the first release go through reforge/migrations.py, which backs the
    # database up before touching it. `CREATE TABLE IF NOT EXISTS` works exactly once: the first
    # time a column must be added to a database holding a customer's engagements, there is no
    # path from what they have to what the code expects.
    try:
        from . import migrations as _mig

        _mig.migrate(db_file())
    except Exception as exc:                 # noqa: BLE001 - never block startup on a migration
        import logging

        logging.getLogger("reforge.db").error(
            "schema migration failed: %s. The database is unchanged and a backup was taken "
            "beforehand; ReTrace continues on the old schema.", exc)


class StaleWrite(RuntimeError):
    """A write was based on a version of the project that is no longer current.

    Two analysts with the same project open both save; without this the second write silently
    discards the first one's findings. The column existed from migration 2 and nothing checked it,
    which made it a record of how many times a row had been overwritten rather than a guard
    against overwriting.
    """

    def __init__(self, pid: str, expected: int, actual: int):
        super().__init__(
            f"project '{pid}' has changed since it was loaded (expected version {expected}, "
            f"found {actual}). Reload it and re-apply your change; saving now would discard "
            "what the other write recorded.")
        self.project_id = pid
        self.expected = expected
        self.actual = actual


def project_version(pid: str) -> int:
    """Current row version, or 0 when the project is not stored yet."""
    init()
    with _LOCK, _connect() as con:
        row = con.execute("SELECT version FROM projects WHERE id = ?", (pid,)).fetchone()
    return int(row[0]) if row and row[0] is not None else 0


def save_project(payload: Dict[str, Any], expected_version: Optional[int] = None) -> int:
    init()
    now = time.time()
    pid = payload.get("id")
    if not pid:
        raise ValueError("project payload missing id")
    updated = float(payload.get("updated") or now)
    # `owner` and `version` are columns as well as payload fields. A column nothing writes is
    # worse than no column: the index exists, the query uses it, and every row answers "no owner"
    # while the payload says otherwise. (Caught by the project-listing test the moment the query
    # replaced the scan.)
    owner = payload.get("owner", "") or ""
    with _LOCK, _connect() as con:
        if expected_version is not None:
            # Inside the same lock and connection as the write, so nothing can slip between the
            # check and the update. A check in a separate transaction would be a race with a
            # longer window, which is worse than no check because it looks like one.
            row = con.execute("SELECT version FROM projects WHERE id = ?", (pid,)).fetchone()
            actual = int(row[0]) if row and row[0] is not None else 0
            if actual != expected_version:
                raise StaleWrite(pid, expected_version, actual)
        con.execute("""
        INSERT INTO projects(id, name, created, updated, target_path, payload, owner, version)
        VALUES(?, ?, ?, ?, ?, ?, ?, 1)
        ON CONFLICT(id) DO UPDATE SET
          name=excluded.name,
          created=excluded.created,
          updated=excluded.updated,
          target_path=excluded.target_path,
          payload=excluded.payload,
          owner=excluded.owner,
          version=projects.version + 1
        """, (
            pid,
            payload.get("name"),
            float(payload.get("created") or updated),
            updated,
            payload.get("target_path"),
            json.dumps(payload, ensure_ascii=False, default=str),
            owner,
        ))
        row = con.execute("SELECT version FROM projects WHERE id = ?", (pid,)).fetchone()
    return int(row[0]) if row and row[0] is not None else 1


def load_project(pid: str) -> Optional[Dict[str, Any]]:
    init()
    with _LOCK, _connect() as con:
        row = con.execute("SELECT payload FROM projects WHERE id=?", (pid,)).fetchone()
    if not row:
        return None
    try:
        return json.loads(row["payload"])
    except Exception:
        return None


def list_projects_owned_by(subjects: List[str], *, include_ownerless: bool = True,
                           limit: int = 500) -> List[Dict[str, Any]]:
    """Project summaries visible to these subjects, as a query rather than a scan.

    `SessionStore.list_projects_for()` resolved ownership by loading and parsing every project.
    Correct, and the wrong shape - it is a `WHERE` clause, which is what the `owner` column added
    by migration 1 makes possible.

    `include_ownerless` covers projects created before ownership existed: they stay visible, the
    alternative being to lock analysts out of their own history on upgrade.
    """
    init()
    if not subjects and not include_ownerless:
        return []
    clauses, params = [], []
    if subjects:
        clauses.append("owner IN (%s)" % ",".join("?" * len(subjects)))
        params.extend(subjects)
    if include_ownerless:
        clauses.append("(owner IS NULL OR owner = '')")
    where = " OR ".join(clauses) or "1=0"
    with _LOCK, _connect() as con:
        rows = con.execute(
            f"SELECT payload FROM projects WHERE ({where}) AND deleted_at IS NULL "
            f"ORDER BY updated DESC LIMIT ?", (*params, limit)).fetchall()
    return [_summary(row[0]) for row in rows]


def _summary(payload: str) -> Dict[str, Any]:
    d = json.loads(payload)
    return {"id": d.get("id"), "name": d.get("name"), "created": d.get("created"),
            "updated": d.get("updated"), "owner": d.get("owner", ""),
            "findings": len(d.get("findings", [])), "messages": len(d.get("messages", [])),
            "usage": d.get("llm_usage", [])}


def list_projects() -> List[Dict[str, Any]]:
    init()
    out: List[Dict[str, Any]] = []
    with _LOCK, _connect() as con:
        rows = con.execute("SELECT id, name, created, updated, payload FROM projects ORDER BY updated DESC").fetchall()
    for row in rows:
        try:
            payload = json.loads(row["payload"])
        except Exception:
            payload = {}
        out.append({
            "id": row["id"],
            "name": row["name"],
            "created": row["created"],
            "updated": row["updated"],
            "findings": len(payload.get("findings", []) or []),
            "messages": len(payload.get("messages", []) or []),
            "usage": payload.get("llm_usage", []) or [],
        })
    return out


def delete_project(pid: str) -> bool:
    init()
    with _LOCK, _connect() as con:
        cur = con.execute("DELETE FROM projects WHERE id=?", (pid,))
        return cur.rowcount > 0


def migrate_json_projects(projects_dir: Path | None = None) -> int:
    """Import the JSON project mirrors the database does not hold yet. Returns how many.

    Only the missing ones. This used to re-save every mirror on every start, which rewrote every
    row, bumped its version each time the server came up, and let a stale mirror overwrite the
    database it was supposed to mirror. SQLite is the authoritative store (module docstring);
    the mirrors are the fallback for a database that is absent or unreadable.
    """
    init()
    root = projects_dir or config.PROJECTS_DIR
    with _LOCK, _connect() as con:
        known = {row[0] for row in con.execute("SELECT id FROM projects")}
    n = 0
    for path in root.glob("*.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            pid = payload.get("id") or path.stem
            if pid in known:
                continue
            payload["id"] = pid
            save_project(payload)
            n += 1
        except Exception:
            continue
    return n


# --------------------------------------------------------------------------- retention
def sweep_expired(retention_days: Optional[int] = None, *, now: Optional[float] = None) -> Dict[str, Any]:
    """Mark projects past their retention window as deleted. Reversible by design.

    **Soft-delete.** The row stays, `deleted_at` is set, and the project disappears from listings.
    Automatically destroying an engagement's findings on a timer is not something a tool should
    do: a retention policy is usually set once, by someone who was estimating, and the first time
    it fires on real work it must be recoverable. `purge_expired()` is the separate, deliberate
    step that actually removes them.

    `retention_days = 0` keeps everything, and is the default.
    """
    days = config.RETENTION_DAYS if retention_days is None else retention_days
    if not days:
        return {"enabled": False, "marked": 0}
    cutoff = (now or time.time()) - days * 86400
    init()
    with _LOCK, _connect() as con:
        rows = con.execute(
            "SELECT id FROM projects WHERE deleted_at IS NULL AND updated < ?",
            (cutoff,)).fetchall()
        for row in rows:
            con.execute("UPDATE projects SET deleted_at = ? WHERE id = ?",
                        (now or time.time(), row[0]))
    marked = [row[0] for row in rows]
    if marked:
        import logging

        logging.getLogger("reforge.db").warning(
            "retention: %d project(s) past %d days marked for deletion and hidden. They are "
            "recoverable with restore_project(); purge_expired() removes them for good.",
            len(marked), days)
    return {"enabled": True, "marked": len(marked), "ids": marked, "retention_days": days}


def restore_project(pid: str) -> bool:
    """Un-delete a soft-deleted project. The reason soft-delete is worth having."""
    init()
    with _LOCK, _connect() as con:
        cur = con.execute("UPDATE projects SET deleted_at = NULL WHERE id = ?", (pid,))
    return cur.rowcount > 0


def purge_expired(*, grace_days: int = 30, now: Optional[float] = None,
                  confirm: bool = False) -> Dict[str, Any]:
    """Permanently remove projects soft-deleted longer than `grace_days` ago.

    `confirm=False` reports what WOULD go without touching anything. Irreversible destruction of
    customer findings should take two steps, and the first one should show you the list.
    """
    cutoff = (now or time.time()) - grace_days * 86400
    init()
    with _LOCK, _connect() as con:
        rows = con.execute(
            "SELECT id, name FROM projects WHERE deleted_at IS NOT NULL AND deleted_at < ?",
            (cutoff,)).fetchall()
        candidates = [{"id": r[0], "name": r[1]} for r in rows]
        if confirm:
            for row in rows:
                con.execute("DELETE FROM projects WHERE id = ?", (row[0],))
    return {"purged": len(candidates) if confirm else 0,
            "would_purge": 0 if confirm else len(candidates),
            "projects": candidates, "grace_days": grace_days, "confirmed": confirm}
