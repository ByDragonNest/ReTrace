"""Versioned, reversible schema migrations with a mandatory backup (slice P2-S5, ADR 0005).

The schema was created by `CREATE TABLE IF NOT EXISTS` and never changed. That works exactly once:
the first time a column has to be added to a database that already holds a customer's engagements,
there is no path from what they have to what the code expects, and the options are "lose the data"
or "never change the schema".

Three rules, each because the alternative has bitten someone:

1. **A backup before every migration, or the migration does not run.** Not "we recommend a
   backup" - the code takes one, verifies it exists and is non-empty, and refuses to proceed if it
   could not. An upgrade that destroys an engagement is not recoverable by apology.
2. **Every migration declares a `down`.** Writing the reverse while the forward is fresh in mind
   is the only time it is cheap. A migration whose author could not describe the reverse usually
   should not be a migration.
3. **Applied migrations are recorded in the database itself**, so the version travels with the
   data rather than with the install.
"""
from __future__ import annotations

import logging
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional

log = logging.getLogger("reforge.migrations")


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    up: Callable[[sqlite3.Connection], None]
    down: Callable[[sqlite3.Connection], None]
    description: str = ""


class MigrationError(RuntimeError):
    """A migration could not be applied, or could not be backed up first."""


# --------------------------------------------------------------------------- the migrations
def _m001_up(con: sqlite3.Connection) -> None:
    """Ownership as a column.

    It lived only inside the JSON payload, so answering "which projects may this user see" meant
    loading every project and parsing it. Correct, and the wrong shape: it is a `WHERE` clause.
    """
    columns = {row[1] for row in con.execute("PRAGMA table_info(projects)")}
    if "owner" not in columns:
        con.execute("ALTER TABLE projects ADD COLUMN owner TEXT DEFAULT ''")
    con.execute("CREATE INDEX IF NOT EXISTS idx_projects_owner ON projects(owner)")
    # Backfill from the payload that already holds it.
    import json

    for pid, payload in con.execute("SELECT id, payload FROM projects").fetchall():
        try:
            owner = (json.loads(payload) or {}).get("owner", "")
        except (ValueError, TypeError):
            continue
        if owner:
            con.execute("UPDATE projects SET owner = ? WHERE id = ?", (owner, pid))


def _m001_down(con: sqlite3.Connection) -> None:
    # SQLite cannot drop a column before 3.35; the index is the part that matters and the column
    # is harmless. Dropping the index is the honest reverse of what this migration added.
    con.execute("DROP INDEX IF EXISTS idx_projects_owner")


def _m002_up(con: sqlite3.Connection) -> None:
    """A row version, for optimistic locking.

    Two analysts with the same project open both save; the second write silently discards the
    first one's findings. A version column turns that into a detectable conflict instead of a
    quiet loss.
    """
    columns = {row[1] for row in con.execute("PRAGMA table_info(projects)")}
    if "version" not in columns:
        con.execute("ALTER TABLE projects ADD COLUMN version INTEGER DEFAULT 1")


def _m002_down(con: sqlite3.Connection) -> None:
    pass            # the column is inert when nothing reads it


def _m003_up(con: sqlite3.Connection) -> None:
    """Retention: when a project may be deleted, and whether it has been."""
    columns = {row[1] for row in con.execute("PRAGMA table_info(projects)")}
    for column, ddl in (("retain_until", "REAL"), ("deleted_at", "REAL")):
        if column not in columns:
            con.execute(f"ALTER TABLE projects ADD COLUMN {column} {ddl}")
    con.execute("CREATE INDEX IF NOT EXISTS idx_projects_retain ON projects(retain_until)")


def _m003_down(con: sqlite3.Connection) -> None:
    con.execute("DROP INDEX IF EXISTS idx_projects_retain")


MIGRATIONS: List[Migration] = [
    Migration(1, "project_owner", _m001_up, _m001_down,
              "Ownership as a column and an index, backfilled from the payload."),
    Migration(2, "project_version", _m002_up, _m002_down,
              "Row version for optimistic locking."),
    Migration(3, "project_retention", _m003_up, _m003_down,
              "Retention deadline and soft-delete marker."),
]


# --------------------------------------------------------------------------- machinery
def _ensure_table(con: sqlite3.Connection) -> None:
    con.execute("""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at REAL NOT NULL
        )
    """)


def applied(con: sqlite3.Connection) -> List[int]:
    _ensure_table(con)
    return [row[0] for row in con.execute(
        "SELECT version FROM schema_migrations ORDER BY version")]


def current_version(con: sqlite3.Connection) -> int:
    versions = applied(con)
    return versions[-1] if versions else 0


def target_version() -> int:
    return max((m.version for m in MIGRATIONS), default=0)


def backup(db_path: Path) -> Optional[Path]:
    """Copy the database beside itself with a timestamp. Returns the copy, or None if there is
    nothing to back up (a database that does not exist yet cannot be lost)."""
    source = Path(db_path)
    if not source.is_file() or source.stat().st_size == 0:
        return None
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    target = source.with_name(f"{source.name}.backup-{stamp}")
    # sqlite3's own backup API rather than a file copy: a copy taken while a write is in flight
    # can be torn, and this is the one moment that must not produce a corrupt rescue copy.
    with sqlite3.connect(str(source)) as src, sqlite3.connect(str(target)) as dst:
        src.backup(dst)
    if not target.is_file() or target.stat().st_size == 0:
        raise MigrationError(f"the backup at {target} is missing or empty; refusing to migrate")
    prune_backups(source)
    return target


def prune_backups(db_path: Path, keep: Optional[int] = None) -> List[Path]:
    """Keep the most recent `keep` backups, delete the rest. Never the newest.

    They accumulate beside the database, one full copy each, and an unbounded series of them
    eventually fills the disk the product is trying to protect. Returns what was removed.
    """
    from . import config

    limit = int(keep if keep is not None else getattr(config, "BACKUP_RETENTION_COUNT", 10))
    source = Path(db_path)
    backups = sorted(source.parent.glob(f"{source.name}.backup-*"),
                     key=lambda p: p.stat().st_mtime, reverse=True)
    removed = []
    for stale in backups[max(1, limit):]:          # max(1, …): never prune the newest
        try:
            stale.unlink()
            removed.append(stale)
        except OSError as exc:
            log.warning("could not prune the backup %s: %s", stale, exc)
    if removed:
        log.info("pruned %d old backup(s), keeping the %d most recent", len(removed), limit)
    return removed


def migrate(db_path: Path, *, to: Optional[int] = None) -> Dict[str, object]:
    """Apply pending migrations, backing the database up first. Returns what happened."""
    db_path = Path(db_path)
    goal = target_version() if to is None else to
    with sqlite3.connect(str(db_path)) as probe:
        start = current_version(probe)
    if start >= goal:
        return {"from": start, "to": start, "applied": [], "backup": None,
                "note": "already at or beyond the target version"}

    try:
        backup_path = backup(db_path)
    except (OSError, sqlite3.Error) as exc:
        raise MigrationError(f"could not back up {db_path} before migrating: {exc}") from exc

    done: List[str] = []
    con = sqlite3.connect(str(db_path))
    try:
        _ensure_table(con)
        for migration in sorted(MIGRATIONS, key=lambda m: m.version):
            if migration.version <= start or migration.version > goal:
                continue
            log.info("applying migration %d (%s)", migration.version, migration.name)
            try:
                migration.up(con)
                con.execute(
                    "INSERT OR REPLACE INTO schema_migrations (version, name, applied_at) "
                    "VALUES (?, ?, ?)", (migration.version, migration.name, time.time()))
                con.commit()
            except Exception as exc:
                con.rollback()
                raise MigrationError(
                    f"migration {migration.version} ({migration.name}) failed: {exc}. "
                    f"The database is unchanged from before this migration; a backup taken "
                    f"beforehand is at {backup_path}.") from exc
            done.append(f"{migration.version}:{migration.name}")
    finally:
        con.close()
    return {"from": start, "to": goal, "applied": done,
            "backup": str(backup_path) if backup_path else None}


def rollback(db_path: Path, *, to: int) -> Dict[str, object]:
    """Reverse migrations down to `to`. Backs up first, same as forward."""
    db_path = Path(db_path)
    with sqlite3.connect(str(db_path)) as probe:
        start = current_version(probe)
    if start <= to:
        return {"from": start, "to": start, "reverted": [], "backup": None}

    backup_path = backup(db_path)
    reverted: List[str] = []
    con = sqlite3.connect(str(db_path))
    try:
        for migration in sorted(MIGRATIONS, key=lambda m: m.version, reverse=True):
            if migration.version <= to or migration.version > start:
                continue
            log.info("reverting migration %d (%s)", migration.version, migration.name)
            migration.down(con)
            con.execute("DELETE FROM schema_migrations WHERE version = ?", (migration.version,))
            con.commit()
            reverted.append(f"{migration.version}:{migration.name}")
    finally:
        con.close()
    return {"from": start, "to": to, "reverted": reverted,
            "backup": str(backup_path) if backup_path else None}


def status(db_path: Path) -> Dict[str, object]:
    db_path = Path(db_path)
    if not db_path.is_file():
        return {"exists": False, "current": 0, "target": target_version(), "pending": []}
    with sqlite3.connect(str(db_path)) as con:
        have = set(applied(con))
    return {
        "exists": True,
        "current": max(have) if have else 0,
        "target": target_version(),
        "pending": [f"{m.version}:{m.name}" for m in MIGRATIONS if m.version not in have],
    }
