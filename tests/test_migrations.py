"""Versioned schema migrations with a mandatory backup (slice P2-S5, ADR 0005).

The schema was created by `CREATE TABLE IF NOT EXISTS` and never changed. That works exactly
once: the first time a column has to be added to a database already holding a customer's
engagements, there is no path from what they have to what the code expects, and the options are
"lose the data" or "never change the schema".
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

import pytest

from reforge import migrations
from reforge.migrations import MigrationError


def _legacy_database(path: Path, projects=()) -> Path:
    """A database on the original schema: no owner, no version, no migration table."""
    con = sqlite3.connect(str(path))
    con.execute("""CREATE TABLE projects (id TEXT PRIMARY KEY, name TEXT, created REAL,
                   updated REAL, target_path TEXT, payload TEXT NOT NULL)""")
    for pid, name, owner in projects:
        payload = json.dumps({"id": pid, "name": name, "owner": owner, "findings": []})
        con.execute("INSERT INTO projects VALUES (?,?,?,?,?,?)",
                    (pid, name, time.time(), time.time(), None, payload))
    con.commit()
    con.close()
    return path


# --------------------------------------------------------------------------- the machinery
def test_a_fresh_database_reaches_the_target_version(tmp_path):
    db = _legacy_database(tmp_path / "p.db")
    result = migrations.migrate(db)
    assert result["from"] == 0
    assert result["to"] == migrations.target_version()
    assert len(result["applied"]) == len(migrations.MIGRATIONS)


def test_migrating_twice_is_a_no_op(tmp_path):
    db = _legacy_database(tmp_path / "p.db")
    migrations.migrate(db)
    again = migrations.migrate(db)
    assert again["applied"] == []


def test_the_version_travels_with_the_data_not_the_install(tmp_path):
    db = _legacy_database(tmp_path / "p.db")
    migrations.migrate(db)
    with sqlite3.connect(str(db)) as con:
        assert migrations.current_version(con) == migrations.target_version()


def test_status_reports_what_is_pending(tmp_path):
    db = _legacy_database(tmp_path / "p.db")
    before = migrations.status(db)
    assert before["current"] == 0 and len(before["pending"]) == len(migrations.MIGRATIONS)
    migrations.migrate(db)
    assert migrations.status(db)["pending"] == []


def test_a_database_that_does_not_exist_yet_is_not_an_error(tmp_path):
    assert migrations.status(tmp_path / "absent.db")["exists"] is False


# --------------------------------------------------------------------------- the backup rule
def test_a_backup_is_taken_before_migrating(tmp_path):
    """Not "we recommend a backup" - the code takes one, or it does not migrate."""
    db = _legacy_database(tmp_path / "p.db", [("p1", "engagement", "alice")])
    result = migrations.migrate(db)
    backup = Path(result["backup"])
    assert backup.is_file() and backup.stat().st_size > 0


def test_the_backup_contains_the_data_as_it_was(tmp_path):
    """A rescue copy that cannot be restored from is not a backup."""
    db = _legacy_database(tmp_path / "p.db", [("p1", "engagement", "alice")])
    backup = Path(migrations.migrate(db)["backup"])
    with sqlite3.connect(str(backup)) as con:
        rows = con.execute("SELECT id, name FROM projects").fetchall()
    assert rows == [("p1", "engagement")]


def test_an_empty_database_needs_no_backup(tmp_path):
    """Nothing to lose; demanding one would block the very first start."""
    db = tmp_path / "new.db"
    db.touch()
    assert migrations.backup(db) is None


def test_migration_refuses_when_it_cannot_back_up(tmp_path, monkeypatch):
    db = _legacy_database(tmp_path / "p.db", [("p1", "x", "alice")])

    def _fail(path):
        raise OSError("read-only filesystem")

    monkeypatch.setattr(migrations, "backup", _fail)
    with pytest.raises(MigrationError) as exc:
        migrations.migrate(db)
    assert "could not back up" in str(exc.value)


def test_a_failing_migration_leaves_the_database_unchanged(tmp_path, monkeypatch):
    """And says where the backup is, because that is what the operator needs next."""
    db = _legacy_database(tmp_path / "p.db", [("p1", "x", "alice")])

    def _broken(con):
        con.execute("ALTER TABLE projects ADD COLUMN owner TEXT")
        raise RuntimeError("something went wrong halfway")

    monkeypatch.setattr(migrations, "MIGRATIONS",
                        [migrations.Migration(1, "broken", _broken, lambda c: None)])
    with pytest.raises(MigrationError) as exc:
        migrations.migrate(db)
    assert "backup" in str(exc.value)
    with sqlite3.connect(str(db)) as con:
        assert migrations.current_version(con) == 0, "a failed migration was recorded as applied"


# --------------------------------------------------------------------------- reversibility
def test_every_migration_declares_a_reverse():
    """Writing the reverse while the forward is fresh is the only time it is cheap."""
    for migration in migrations.MIGRATIONS:
        assert callable(migration.down), f"migration {migration.version} has no down()"
        assert migration.description, f"migration {migration.version} is undocumented"


def test_migrations_are_uniquely_numbered_and_contiguous():
    versions = sorted(m.version for m in migrations.MIGRATIONS)
    assert len(versions) == len(set(versions))
    assert versions == list(range(1, len(versions) + 1))


def test_rolling_back_restores_the_earlier_version(tmp_path):
    db = _legacy_database(tmp_path / "p.db", [("p1", "x", "alice")])
    migrations.migrate(db)
    result = migrations.rollback(db, to=1)
    assert result["reverted"]
    with sqlite3.connect(str(db)) as con:
        assert migrations.current_version(con) == 1


def test_a_rollback_also_backs_up_first(tmp_path):
    db = _legacy_database(tmp_path / "p.db", [("p1", "x", "alice")])
    migrations.migrate(db)
    assert Path(migrations.rollback(db, to=0)["backup"]).is_file()


# --------------------------------------------------------------------------- what they do
def test_ownership_is_backfilled_from_the_payload(tmp_path):
    """An existing engagement must not lose its owner on upgrade."""
    db = _legacy_database(tmp_path / "p.db",
                          [("p1", "alice-work", "alice"), ("p2", "old", "")])
    migrations.migrate(db)
    with sqlite3.connect(str(db)) as con:
        owners = dict(con.execute("SELECT id, owner FROM projects").fetchall())
    assert owners["p1"] == "alice"
    assert owners["p2"] in ("", None), "a project with no owner must stay ownerless"


def test_the_owner_column_is_indexed(tmp_path):
    """The point of the column is that visibility becomes a WHERE clause, not a scan."""
    db = _legacy_database(tmp_path / "p.db")
    migrations.migrate(db)
    with sqlite3.connect(str(db)) as con:
        indexes = {row[1] for row in con.execute("PRAGMA index_list(projects)")}
    assert "idx_projects_owner" in indexes


def test_a_row_version_exists_for_optimistic_locking(tmp_path):
    db = _legacy_database(tmp_path / "p.db")
    migrations.migrate(db)
    with sqlite3.connect(str(db)) as con:
        columns = {row[1] for row in con.execute("PRAGMA table_info(projects)")}
    assert {"version", "retain_until", "deleted_at"} <= columns


# --------------------------------------------------------------------------- integration
def test_the_listing_query_replaces_the_scan(tmp_path, monkeypatch):
    from reforge import config, db as dbmod

    monkeypatch.setattr(config, "PROJECTS_DB", tmp_path / "p.db")
    dbmod.init()
    for pid, owner in (("p1", "alice"), ("p2", "bob"), ("p3", "")):
        dbmod.save_project({"id": pid, "name": pid, "owner": owner,
                            "created": time.time(), "updated": time.time()})
    visible = {row["id"] for row in dbmod.list_projects_owned_by(["alice"])}
    assert visible == {"p1", "p3"}, "the query returned the wrong set"
    assert "p2" not in visible


def test_a_saved_project_maintains_the_owner_column(tmp_path, monkeypatch):
    """A column nothing writes is worse than no column: the query would answer 'no owner' for
    every row while the payload said otherwise."""
    from reforge import config, db as dbmod

    monkeypatch.setattr(config, "PROJECTS_DB", tmp_path / "p.db")
    dbmod.init()
    dbmod.save_project({"id": "p1", "name": "x", "owner": "alice",
                        "created": time.time(), "updated": time.time()})
    with sqlite3.connect(str(tmp_path / "p.db")) as con:
        assert con.execute("SELECT owner FROM projects WHERE id='p1'").fetchone()[0] == "alice"


def test_the_row_version_increments_on_each_save(tmp_path, monkeypatch):
    """What optimistic locking is built on: a write that did not see the previous one is visible."""
    from reforge import config, db as dbmod

    monkeypatch.setattr(config, "PROJECTS_DB", tmp_path / "p.db")
    dbmod.init()
    payload = {"id": "p1", "name": "x", "owner": "alice",
               "created": time.time(), "updated": time.time()}
    dbmod.save_project(payload)
    dbmod.save_project(payload)
    with sqlite3.connect(str(tmp_path / "p.db")) as con:
        assert con.execute("SELECT version FROM projects WHERE id='p1'").fetchone()[0] == 2
