"""The JSON project mirrors are a fallback for the database, not a source that overrides it."""
from __future__ import annotations

import json


def test_json_mirrors_are_imported_only_when_the_database_lacks_them(tmp_path, monkeypatch):
    """`migrate_json_projects()` used to re-save every mirror on every start: each row was
    rewritten and its version bumped whenever the server came up, and a stale mirror overwrote the
    database it was mirroring. SQLite is the authoritative store; only the missing ones come in."""
    from reforge import config, db

    monkeypatch.setattr(config, "PROJECTS_DB", tmp_path / "reforge.db")
    mirrors = tmp_path / "projects"
    mirrors.mkdir()
    db.save_project({"id": "known", "name": "in the database", "findings": []})
    version_before = db.project_version("known")
    (mirrors / "known.json").write_text(json.dumps({"id": "known", "name": "stale mirror"}),
                                        encoding="utf-8")
    (mirrors / "fresh.json").write_text(json.dumps({"id": "fresh", "name": "only on disk"}),
                                        encoding="utf-8")

    assert db.migrate_json_projects(mirrors) == 1
    assert db.project_version("known") == version_before
    assert db.load_project("known")["name"] == "in the database"
    assert db.load_project("fresh")["name"] == "only on disk"
    assert db.migrate_json_projects(mirrors) == 0, "a second start imports nothing"
