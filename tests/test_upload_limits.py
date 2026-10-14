"""Upload limits, magic-byte typing, archive policy and XML entity guard (slice P0-S3).

Closes P0-5 and threat T-2.

Before this slice both upload endpoints streamed to disk with no bound of any kind: no size cap,
no file-count limit, no per-project quota, no free-space check, no cleanup of a partial write, and
type detection ran only *after* the whole file had landed. `POST /api/projects/{pid}/upload` had
its own separate inline `while True: out.write(chunk)` loop, so even a limit added to the artifact
path could have been bypassed by picking the other endpoint.

Two parsers (`artifact_overview`, `heuristics`) run automatically on upload, both on
`xml.etree.ElementTree`, which expands internal entities - so an uploaded XML file was enough to
exhaust memory with no human in the loop.
"""
from __future__ import annotations

import io
import os
from pathlib import Path

import pytest

from reforge import artifacts as A
from reforge import config, safe_xml
from reforge.session import Session

PROCMON_XML = (b'<?xml version="1.0" encoding="UTF-8"?><procmon><eventlist>'
               b'<event><Process_Name>x.exe</Process_Name><Operation>ReadFile</Operation>'
               b'<Path>C:\\t</Path><Result>SUCCESS</Result></event></eventlist></procmon>')


@pytest.fixture()
def project(tmp_path, monkeypatch):
    """An isolated project whose workspace is a throwaway directory."""
    monkeypatch.setattr(config, "WORKSPACE_DIR", tmp_path)
    return Session(name="uploads")


def _limits(monkeypatch, **kw):
    for name, value in kw.items():
        monkeypatch.setattr(config, name, value)


# --------------------------------------------------------------------------- size limit
def test_an_oversized_upload_is_refused(project, monkeypatch):
    _limits(monkeypatch, MAX_UPLOAD_BYTES=1024)
    with pytest.raises(A.UploadRejected) as exc:
        A.store_stream(project.id, "big.bin", io.BytesIO(b"x" * 5000))
    assert exc.value.status == 413
    assert exc.value.reason == "too_large"


def test_a_rejected_upload_leaves_nothing_on_disk(project, monkeypatch):
    """A refusal that still wrote 4 GB would be a disk-filling primitive by itself."""
    _limits(monkeypatch, MAX_UPLOAD_BYTES=1024)
    with pytest.raises(A.UploadRejected):
        A.store_stream(project.id, "big.bin", io.BytesIO(b"x" * 500_000))
    leftovers = list(A.artifacts_dir(project.id).iterdir())
    assert leftovers == [], f"partial upload left behind: {leftovers}"


def test_the_limit_is_enforced_on_the_bytes_that_arrive_not_the_declared_size(project, monkeypatch):
    """Content-Length is a hint from an untrusted client; the real count is what counts."""
    _limits(monkeypatch, MAX_UPLOAD_BYTES=1024)
    with pytest.raises(A.UploadRejected) as exc:
        A.store_stream(project.id, "liar.bin", io.BytesIO(b"x" * 50_000), declared_size=10)
    assert exc.value.status == 413
    assert list(A.artifacts_dir(project.id).iterdir()) == []


def test_an_upload_within_the_limit_is_stored_whole(project, monkeypatch):
    _limits(monkeypatch, MAX_UPLOAD_BYTES=1 << 20)
    payload = b"y" * 4096
    rec = A.store_stream(project.id, "ok.bin", io.BytesIO(payload))
    assert rec["size"] == len(payload)
    assert Path(rec["path"]).read_bytes() == payload


def test_a_zero_byte_upload_is_accepted_and_typed(project):
    rec = A.store_stream(project.id, "empty.bin", io.BytesIO(b""))
    assert rec["size"] == 0
    assert rec["type"] == A.TYPE_BINARY
    assert Path(rec["path"]).is_file()


# --------------------------------------------------------------------------- quotas
def test_the_file_count_limit_is_enforced(project, monkeypatch):
    _limits(monkeypatch, MAX_ARTIFACTS_PER_PROJECT=2)
    for i in range(2):
        A.store_stream(project.id, f"f{i}.bin", io.BytesIO(b"a"))
    with pytest.raises(A.UploadRejected) as exc:
        A.store_stream(project.id, "f3.bin", io.BytesIO(b"a"))
    assert exc.value.status == 409 and exc.value.reason == "too_many_files"


def test_the_project_byte_quota_is_enforced(project, monkeypatch):
    _limits(monkeypatch, MAX_PROJECT_BYTES=10_000, MAX_UPLOAD_BYTES=1 << 20)
    A.store_stream(project.id, "a.bin", io.BytesIO(b"x" * 8000))
    with pytest.raises(A.UploadRejected) as exc:
        A.store_stream(project.id, "b.bin", io.BytesIO(b"x" * 8000))
    assert exc.value.status == 409 and exc.value.reason == "project_quota"


def test_free_disk_headroom_is_respected(project, monkeypatch):
    """Refused before the first byte: filling the disk must not take the host down with it."""
    _limits(monkeypatch, MIN_FREE_DISK_BYTES=1 << 62)
    with pytest.raises(A.UploadRejected) as exc:
        A.store_stream(project.id, "a.bin", io.BytesIO(b"x"))
    assert exc.value.status == 507 and exc.value.reason == "no_space"


def test_project_usage_ignores_in_flight_temporary_files(project):
    A.store_stream(project.id, "a.bin", io.BytesIO(b"x" * 100))
    (A.artifacts_dir(project.id) / ".tmp-inflight").write_bytes(b"z" * 999)
    count, total = A.project_usage(project.id)
    assert count == 1 and total == 100


# --------------------------------------------------------------------------- naming and typing
def test_the_stored_name_is_generated_not_taken_from_the_uploader(project):
    """A filename is attacker-controlled and must not reach the filesystem verbatim."""
    rec = A.store_stream(project.id, "../../../etc/passwd", io.BytesIO(b"data"))
    stored = Path(rec["path"])
    # The extension comes from the DETECTED type, so it is not asserted literally here;
    # what matters is that the stem is the generated id and nothing of the uploader's survives.
    assert stored.name == rec["name"]
    assert stored.stem == rec["id"]
    assert "passwd" not in str(stored)
    assert stored.parent == A.artifacts_dir(project.id)
    assert rec["original_name"] == "../../../etc/passwd"   # kept as metadata, for the analyst


def test_two_uploads_with_the_same_name_do_not_collide(project):
    a = A.store_stream(project.id, "same.bin", io.BytesIO(b"first"))
    b = A.store_stream(project.id, "same.bin", io.BytesIO(b"second"))
    assert a["path"] != b["path"]
    assert Path(a["path"]).read_bytes() == b"first"
    assert Path(b["path"]).read_bytes() == b"second"


def test_type_comes_from_the_content_not_the_extension(project):
    """A PE uploaded as notes.txt is a PE."""
    rec = A.store_stream(project.id, "notes.txt", io.BytesIO(b"MZ\x90\x00" + b"\x00" * 200))
    assert rec["type"] == A.TYPE_PE
    assert rec["type_mismatch"] is True
    assert rec["declared_ext"] == ".txt"


def test_a_matching_extension_is_not_flagged(project):
    rec = A.store_stream(project.id, "trace.xml", io.BytesIO(PROCMON_XML))
    assert rec["type"] == A.TYPE_PROCMON_XML
    assert rec["type_mismatch"] is False


@pytest.mark.parametrize("magic,label", [
    (b"PK\x03\x04", "zip"), (b"\x1f\x8b\x08", "gzip"), (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07\x00", "rar"), (b"\xfd7zXZ\x00", "xz"), (b"BZh9", "bzip2"),
    (b"MSCF\x00", "cab"), (b"\x28\xb5\x2f\xfd", "zstd"),
])
def test_archives_are_recognised_by_magic_bytes(project, magic, label):
    rec = A.store_stream(project.id, f"payload.{label}", io.BytesIO(magic + b"\x00" * 64))
    assert rec["type"] == A.TYPE_ARCHIVE, label


def test_an_archive_is_stored_opaque_and_never_expanded(project):
    """The no-extraction policy is the mitigation for zip bombs, entry traversal and nesting."""
    rec = A.store_stream(project.id, "evil.zip", io.BytesIO(b"PK\x03\x04" + b"\x00" * 64))
    assert rec["expandable"] is False
    assert "does not expand archives" in rec["note"]
    # Exactly one file on disk: the container itself, nothing extracted beside it.
    assert [p.name for p in A.artifacts_dir(project.id).iterdir()] == [rec["name"]]


def test_the_product_contains_no_archive_extraction_code():
    """Structural guard: the policy above is only true while nothing learns to extract.

    The hazard is *reading* an untrusted archive - that is where zip bombs, entry traversal,
    symlink entries and nesting amplification live. *Writing* one is not the same thing, and the
    support bundle (reforge/support_bundle.py) legitimately creates a zip of our own data. So the
    guard looks for extraction verbs and for an archive opened in read mode, rather than for the
    class name, which matched both.
    """
    root = Path(__file__).resolve().parent.parent
    extraction_markers = ("extractall", ".extract(", "py7zr", "rarfile",
                          "tarfile.open", "ZipFile(", "getmembers", "infolist")
    write_only = ('ZipFile(buffer, "w"', "ZipFile(buffer, 'w'")
    hits = []
    for src in list((root / "reforge").rglob("*.py")) + list((root / "servers").rglob("*.py")):
        if "__pycache__" in src.parts:
            continue
        body = src.read_text(encoding="utf-8", errors="replace")
        for marker in extraction_markers:
            if marker not in body:
                continue
            if marker == "ZipFile(" and any(w in body for w in write_only) \
                    and body.count("ZipFile(") == 1:
                continue            # creating our own archive, not opening someone else's
            hits.append(f"{src.relative_to(root)}: {marker}")
    assert not hits, ("archive extraction appeared; it needs bomb, traversal, symlink and "
                      f"nesting defences before it can ship: {hits}")


def test_the_support_bundle_only_ever_writes_an_archive():
    """The one place that touches zipfile must not grow a read path."""
    root = Path(__file__).resolve().parent.parent
    body = (root / "reforge" / "support_bundle.py").read_text(encoding="utf-8")
    assert 'ZipFile(buffer, "w"' in body
    for forbidden in ("extractall", ".extract(", "ZipFile(path", "ZipFile(source"):
        assert forbidden not in body


# --------------------------------------------------------------------------- stored file safety
def test_stored_files_are_not_executable_and_not_world_readable(project):
    rec = A.store_stream(project.id, "sample.bin", io.BytesIO(b"MZ\x90\x00"))
    mode = os.stat(rec["path"]).st_mode & 0o777
    assert mode & 0o111 == 0, f"stored sample is executable (mode {mode:o})"
    assert mode & 0o077 == 0, f"stored sample is readable by others (mode {mode:o})"


def test_the_sha256_is_the_hash_of_what_was_actually_stored(project):
    import hashlib
    payload = b"content to hash" * 100
    rec = A.store_stream(project.id, "x.bin", io.BytesIO(payload))
    assert rec["sha256"] == hashlib.sha256(payload).hexdigest()
    assert rec["sha256"] == hashlib.sha256(Path(rec["path"]).read_bytes()).hexdigest()


# --------------------------------------------------------------------------- XML entity guard
BILLION_LAUGHS = (b'<?xml version="1.0"?>\n<!DOCTYPE lolz [\n'
                  b' <!ENTITY lol "lol">\n'
                  b' <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">\n'
                  b' <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">\n'
                  b']>\n<lolz>&lol3;</lolz>')


def test_an_entity_bomb_is_refused_before_parsing(tmp_path):
    bomb = tmp_path / "bomb.xml"
    bomb.write_bytes(BILLION_LAUGHS)
    with pytest.raises(safe_xml.UnsafeXMLError):
        list(safe_xml.iterparse(bomb))


def test_an_external_entity_declaration_is_refused(tmp_path):
    xxe = tmp_path / "xxe.xml"
    xxe.write_bytes(b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
                    b'<r>&e;</r>')
    with pytest.raises(safe_xml.UnsafeXMLError):
        list(safe_xml.iterparse(xxe))


def test_a_legitimate_procmon_export_still_parses(tmp_path):
    good = tmp_path / "trace.xml"
    good.write_bytes(PROCMON_XML)
    assert len(list(safe_xml.iterparse(good))) > 0


def test_the_upload_time_parsers_use_the_guard():
    """These two run automatically on upload, with no human in the loop. They must be guarded."""
    root = Path(__file__).resolve().parent.parent
    for module in ("artifact_overview.py", "heuristics.py"):
        body = (root / "reforge" / module).read_text(encoding="utf-8")
        assert "safe_xml.iterparse" in body, f"{module} parses untrusted XML unguarded"
        assert "ET.iterparse" not in body, f"{module} still has a raw ET.iterparse call"


def test_the_standalone_procmon_server_guards_too():
    root = Path(__file__).resolve().parent.parent
    body = (root / "servers" / "procmon_mcp.py").read_text(encoding="utf-8")
    assert "_assert_safe_xml(path)" in body


def test_an_uploaded_entity_bomb_does_not_take_the_overview_down(project):
    """End to end: the upload is stored, and the automatic overview declines it cleanly."""
    from reforge import artifact_overview

    rec = A.store_stream(project.id, "bomb.xml", io.BytesIO(BILLION_LAUGHS))
    assert Path(rec["path"]).is_file(), "the file is still stored for the analyst to inspect"
    ov = artifact_overview.build_overview(rec)
    assert isinstance(ov, dict)          # a refusal, not a crash and not an OOM


# --------------------------------------------------------------------------- the HTTP contract
# Both endpoints must refuse with a status the UI can act on, and - importantly - neither may be
# the lax one. `POST /upload` used to have its own unguarded write loop.
@pytest.fixture()
def api(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from reforge.server import app, store
    monkeypatch.setattr(config, "WORKSPACE_DIR", tmp_path)
    with TestClient(app) as c:
        c.headers.update({"X-Reforge-Token": config.AUTH_TOKEN})
        pid = store.create().id
        yield c, pid


@pytest.mark.parametrize("endpoint", ["artifacts", "upload"])
def test_both_upload_endpoints_refuse_an_oversized_file(api, monkeypatch, endpoint):
    client, pid = api
    monkeypatch.setattr(config, "MAX_UPLOAD_BYTES", 2048)
    r = client.post(f"/api/projects/{pid}/{endpoint}",
                    files={"file": ("big.bin", io.BytesIO(b"x" * 50_000), "application/octet-stream")})
    assert r.status_code == 413, r.text


@pytest.mark.parametrize("endpoint", ["artifacts", "upload"])
def test_both_upload_endpoints_refuse_when_the_project_quota_is_full(api, monkeypatch, endpoint):
    client, pid = api
    monkeypatch.setattr(config, "MAX_ARTIFACTS_PER_PROJECT", 1)
    first = client.post(f"/api/projects/{pid}/{endpoint}",
                        files={"file": ("a.bin", io.BytesIO(b"a" * 10), "application/octet-stream")})
    assert first.status_code == 200, first.text
    second = client.post(f"/api/projects/{pid}/{endpoint}",
                         files={"file": ("b.bin", io.BytesIO(b"b" * 10), "application/octet-stream")})
    assert second.status_code == 409, second.text


@pytest.mark.parametrize("endpoint", ["artifacts", "upload"])
def test_both_upload_endpoints_refuse_without_free_disk(api, monkeypatch, endpoint):
    client, pid = api
    monkeypatch.setattr(config, "MIN_FREE_DISK_BYTES", 1 << 62)
    r = client.post(f"/api/projects/{pid}/{endpoint}",
                    files={"file": ("a.bin", io.BytesIO(b"a"), "application/octet-stream")})
    assert r.status_code == 507, r.text


def test_the_sample_endpoint_reports_the_detected_type_and_any_mismatch(api):
    client, pid = api
    r = client.post(f"/api/projects/{pid}/upload",
                    files={"file": ("harmless.txt", io.BytesIO(b"MZ\x90\x00" + b"\x00" * 64),
                                    "text/plain")})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["type"] == A.TYPE_PE
    assert body["type_mismatch"] is True
    assert body["original_name"] == "harmless.txt"
    assert "harmless" not in body["path"]
    assert len(body["sha256"]) == 64


def test_a_refused_upload_leaves_the_project_empty_over_http(api, monkeypatch):
    client, pid = api
    monkeypatch.setattr(config, "MAX_UPLOAD_BYTES", 1024)
    client.post(f"/api/projects/{pid}/artifacts",
                files={"file": ("big.bin", io.BytesIO(b"x" * 80_000), "application/octet-stream")})
    listed = client.get(f"/api/projects/{pid}/artifacts").json()["artifacts"]
    assert listed == []
    assert list(A.artifacts_dir(pid).iterdir()) == []
