"""Optimistic locking, retention and backup pruning — the last three closeable residuals.

* **Optimistic locking.** The `version` column existed from migration 2 and nothing checked it,
  which made it a record of how many times a row had been overwritten rather than a guard against
  overwriting. Two analysts with the same project open both save; the second silently discarded
  the first one's findings.
* **Retention.** `retain_until` and `deleted_at` were recorded and nothing acted on them.
* **Backups.** They accumulated beside the database, one full copy each, until the disk the
  product is trying to protect filled up.
"""
from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import pytest

from reforge import config, db as dbmod, migrations
from reforge.db import StaleWrite


@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "PROJECTS_DB", tmp_path / "p.db")
    monkeypatch.setattr(config, "PROJECTS_DIR", tmp_path / "projects")
    (tmp_path / "projects").mkdir()
    dbmod.init()
    return tmp_path


def _payload(pid="p1", owner="alice", **extra):
    return {"id": pid, "name": pid, "owner": owner, "created": time.time(),
            "updated": time.time(), **extra}


# --------------------------------------------------------------------------- optimistic locking
def test_the_version_is_returned_so_a_caller_can_hold_it(store):
    assert dbmod.save_project(_payload()) == 1
    assert dbmod.save_project(_payload()) == 2


def test_a_write_on_the_current_version_succeeds(store):
    version = dbmod.save_project(_payload())
    assert dbmod.save_project(_payload(), expected_version=version) == version + 1


def test_a_write_on_a_stale_version_is_refused(store):
    """The whole point: the second writer must not silently discard the first one's work."""
    first = dbmod.save_project(_payload())
    dbmod.save_project(_payload(name="changed by someone else"))      # another writer
    with pytest.raises(StaleWrite) as exc:
        dbmod.save_project(_payload(name="mine"), expected_version=first)
    assert exc.value.expected == first
    assert exc.value.actual == first + 1


def test_the_refusal_says_what_to_do(store):
    first = dbmod.save_project(_payload())
    dbmod.save_project(_payload())
    with pytest.raises(StaleWrite) as exc:
        dbmod.save_project(_payload(), expected_version=first)
    assert "Reload it" in str(exc.value)
    assert "would discard" in str(exc.value)


def test_a_refused_write_changes_nothing(store):
    dbmod.save_project(_payload(name="original"))
    dbmod.save_project(_payload(name="second writer"))
    with pytest.raises(StaleWrite):
        dbmod.save_project(_payload(name="should not land"), expected_version=1)
    assert dbmod.load_project("p1")["name"] == "second writer"


def test_a_brand_new_project_does_not_collide_with_itself(store):
    """Version 0 means "not stored yet", which must not read as a conflict on the first write."""
    assert dbmod.project_version("new") == 0
    assert dbmod.save_project(_payload("new"), expected_version=0) == 1


def test_two_sessions_that_loaded_the_same_row_cannot_both_write(store):
    from reforge.session import Session, SessionStore

    SessionStore()
    session = Session("shared", "shared")
    session.owner = "alice"
    session.persist()

    stale = Session.from_dict(session.to_dict())      # a second instance, same row
    session.add_finding({"title": "found by the first writer"})
    session.persist()

    stale.add_finding({"title": "found by the second writer"})
    with pytest.raises(StaleWrite):
        stale.persist()


def test_a_caller_can_decide_to_win(store):
    """An argument, not a separate method, so the decision is visible at the call site."""
    from reforge.session import Session

    session = Session("shared", "shared")
    session.persist()
    stale = Session.from_dict(session.to_dict())
    session.persist()
    stale.persist(check_version=False)                # no raise
    assert dbmod.project_version("shared") >= 3


# --------------------------------------------------------------------------- retention
def test_retention_is_off_by_default(store):
    assert config.RETENTION_DAYS == 0
    assert dbmod.sweep_expired()["enabled"] is False


def test_an_expired_project_is_hidden_not_erased(store):
    """Automatically destroying findings on a timer is not something a tool should do."""
    old = _payload("old")
    old["updated"] = time.time() - 100 * 86400
    dbmod.save_project(old)
    dbmod.save_project(_payload("recent"))

    result = dbmod.sweep_expired(retention_days=30)
    assert result["marked"] == 1 and result["ids"] == ["old"]
    with sqlite3.connect(str(store / "p.db")) as con:
        assert con.execute("SELECT COUNT(*) FROM projects").fetchone()[0] == 2, "a row was erased"


def test_a_hidden_project_disappears_from_listings(store):
    old = _payload("old", owner="alice")
    old["updated"] = time.time() - 100 * 86400
    dbmod.save_project(old)
    dbmod.sweep_expired(retention_days=30)
    assert [r["id"] for r in dbmod.list_projects_owned_by(["alice"])] == []


def test_a_hidden_project_can_be_restored(store):
    """The reason soft-delete is worth having."""
    old = _payload("old", owner="alice")
    old["updated"] = time.time() - 100 * 86400
    dbmod.save_project(old)
    dbmod.sweep_expired(retention_days=30)
    assert dbmod.restore_project("old") is True
    assert [r["id"] for r in dbmod.list_projects_owned_by(["alice"])] == ["old"]


def test_purging_reports_before_it_destroys(store):
    """Irreversible destruction takes two steps, and the first shows you the list."""
    old = _payload("old")
    old["updated"] = time.time() - 100 * 86400
    dbmod.save_project(old)
    dbmod.sweep_expired(retention_days=30, now=time.time() - 60 * 86400)

    dry = dbmod.purge_expired(grace_days=30, confirm=False)
    assert dry["would_purge"] == 1 and dry["purged"] == 0
    assert dbmod.load_project("old") is not None, "a dry run deleted something"

    done = dbmod.purge_expired(grace_days=30, confirm=True)
    assert done["purged"] == 1
    assert dbmod.load_project("old") is None


def test_a_project_inside_its_grace_period_is_not_purged(store):
    old = _payload("old")
    old["updated"] = time.time() - 100 * 86400
    dbmod.save_project(old)
    dbmod.sweep_expired(retention_days=30)                 # deleted just now
    assert dbmod.purge_expired(grace_days=30, confirm=True)["purged"] == 0


# --------------------------------------------------------------------------- backup pruning
def test_old_backups_are_pruned(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "BACKUP_RETENTION_COUNT", 3)
    db = tmp_path / "p.db"
    db.write_bytes(b"x")
    for i in range(8):
        backup = tmp_path / f"p.db.backup-2026010{i}-000000"
        backup.write_bytes(b"x")
        import os
        os.utime(backup, (time.time() - (8 - i) * 60,) * 2)
    removed = migrations.prune_backups(db)
    remaining = sorted(tmp_path.glob("p.db.backup-*"))
    assert len(remaining) == 3
    assert len(removed) == 5


def test_the_newest_backup_is_never_pruned(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "BACKUP_RETENTION_COUNT", 1)
    db = tmp_path / "p.db"
    db.write_bytes(b"x")
    newest = tmp_path / "p.db.backup-20260102-000000"
    oldest = tmp_path / "p.db.backup-20260101-000000"
    for path, age in ((oldest, 600), (newest, 1)):
        path.write_bytes(b"x")
        import os
        os.utime(path, (time.time() - age,) * 2)
    migrations.prune_backups(db)
    assert newest.exists() and not oldest.exists()


def test_a_migration_prunes_as_it_backs_up(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "BACKUP_RETENTION_COUNT", 2)
    db = tmp_path / "p.db"
    con = sqlite3.connect(str(db))
    con.execute("""CREATE TABLE projects (id TEXT PRIMARY KEY, name TEXT, created REAL,
                   updated REAL, target_path TEXT, payload TEXT NOT NULL)""")
    con.execute("INSERT INTO projects VALUES ('p1','n',0,0,NULL,'{}')")
    con.commit()
    con.close()
    for i in range(5):
        stale = tmp_path / f"p.db.backup-2025010{i}-000000"
        stale.write_bytes(b"old")
        import os
        os.utime(stale, (time.time() - 10_000 + i,) * 2)
    migrations.migrate(db)
    assert len(list(tmp_path.glob("p.db.backup-*"))) <= 2


def test_pruning_survives_a_file_it_cannot_remove(tmp_path, monkeypatch):
    """A failure to prune must not fail the migration it is attached to."""
    monkeypatch.setattr(config, "BACKUP_RETENTION_COUNT", 1)
    db = tmp_path / "p.db"
    db.write_bytes(b"x")
    for i in range(3):
        (tmp_path / f"p.db.backup-2026010{i}-000000").write_bytes(b"x")

    real_unlink = Path.unlink

    def _stubborn(self, *a, **k):
        raise OSError("in use")

    monkeypatch.setattr(Path, "unlink", _stubborn)
    migrations.prune_backups(db)                  # must not raise
    monkeypatch.setattr(Path, "unlink", real_unlink)
