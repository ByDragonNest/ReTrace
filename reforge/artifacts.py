"""Artifact subsystem: upload, registry, type detection, and safe id→path resolution.

WHY THIS EXISTS
---------------
Before this module, an uploaded file was written to disk and its path returned, but nothing
connected it to the analysis: the Procmon MCP server received no path (hence "0 events"), the
LLM never saw the content, and the graph had no artifact nodes. This module is the bridge.

Pipeline:
  1. store_upload()   -> sanitized filename, confined under the project's artifacts/ dir, sha256,
                         type sniffing. Returns an Artifact record.
  2. register()       -> appends the record to session.artifacts (persisted).
  3. resolve_path()   -> artifact_id -> absolute on-disk path, re-validated through workspace
                         path-safety (no traversal, confined). This is what gets injected into
                         MCP tool calls such as procmon__procmon_load_xml(path=...).
  4. summarize_for_llm() -> a compact, truncated, text summary safe to hand to an LLM that has no
                         file-attachment channel (fallback for providers without native uploads).

SECURITY
--------
Everything an artifact carries (filename, content, detected type) is UNTRUSTED. Filenames are
sanitized to a basename; stored paths are confined to the project artifact dir; resolution goes
back through workspace.safe_resolve so traversal is impossible even if the registry is tampered.
Files are NEVER executed.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from . import config, workspace

log = logging.getLogger("reforge.artifacts")


class UploadRejected(ValueError):
    """An upload was refused by policy. `status` is the HTTP status the API should answer with."""

    def __init__(self, message: str, *, status: int = 400, reason: str = "rejected"):
        super().__init__(message)
        self.status = status
        self.reason = reason


# --------------------------------------------------------------------------- storage layout
def artifacts_dir(project_id: str) -> Path:
    """Per-project artifact directory: <workspace>/<pid>/artifacts/ (created on demand)."""
    d = workspace.project_dir(project_id) / "artifacts"
    d.mkdir(parents=True, exist_ok=True)
    return d


# --------------------------------------------------------------------------- type detection
# Detected types drive which MCP tool/parser an artifact is routed to.
TYPE_PROCMON_XML = "procmon_xml"
TYPE_PCAP = "pcap"
TYPE_PE = "pe_binary"
TYPE_ELF = "elf_binary"
TYPE_XML = "xml"
TYPE_JSON = "json"
TYPE_TEXT = "text"
TYPE_BINARY = "binary"
TYPE_ARCHIVE = "archive"
TYPE_MACHO = "macho_binary"

# Containers are recognised so they can be labelled and left alone.
#
# ReTrace does not expand archives, and this is a deliberate design decision rather than a missing
# feature: an extractor is where zip bombs, path traversal through entry names ("../../.ssh/..."),
# symlink entries and nested-archive amplification all live. Nothing in the product has ever
# extracted an archive, and nothing added here starts. An uploaded archive is stored, hashed and
# labelled; the analyst extracts it themselves, outside the tool, and uploads what they want
# analysed. See docs/threat-model.md T-2.
_ARCHIVE_MAGIC: Tuple[Tuple[bytes, str], ...] = (
    (b"PK\x03\x04", "zip"), (b"PK\x05\x06", "zip"), (b"PK\x07\x08", "zip"),
    (b"\x1f\x8b", "gzip"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"BZh", "bzip2"),
    (b"MSCF", "cab"),
    (b"\x04\x22\x4d\x18", "lz4"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
)

# Extension a stored file gets, derived from the DETECTED type. The declared extension is kept as
# metadata only - it is attacker-controlled and must not decide how anything is handled.
_EXT_FOR_TYPE = {
    TYPE_PROCMON_XML: ".xml", TYPE_XML: ".xml", TYPE_JSON: ".json", TYPE_TEXT: ".txt",
    TYPE_PCAP: ".pcap", TYPE_PE: ".bin", TYPE_ELF: ".bin", TYPE_MACHO: ".bin",
    TYPE_ARCHIVE: ".archive", TYPE_BINARY: ".bin",
}

_PROCMON_HINT = re.compile(rb"<\s*procmon\b|<\s*eventlist\b|Process_Name|Time_of_Day", re.I)


def detect_type(path: Path, declared_name: str = "") -> str:
    """Sniff an artifact's type from a small header read + extension hints. Cheap and bounded.

    Procmon XML is detected by structural markers (<procmon>/<eventlist>/Process_Name), not just
    the .xml extension, because that is the artifact we must route to the Procmon MCP server.
    """
    name = (declared_name or path.name).lower()
    try:
        with open(path, "rb") as fh:
            head = fh.read(8192)
    except OSError:
        head = b""

    # Magic bytes first.
    if head[:2] == b"MZ":
        return TYPE_PE
    if head[:4] == b"\x7fELF":
        return TYPE_ELF
    if head[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4") or head[:4] == b"\x0a\x0d\x0d\x0a":
        return TYPE_PCAP  # pcap / pcapng
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe",
                    b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return TYPE_MACHO
    for magic, _fmt in _ARCHIVE_MAGIC:
        if head.startswith(magic):
            return TYPE_ARCHIVE
    if name.endswith((".pcap", ".pcapng", ".cap")):
        return TYPE_PCAP

    # Strip a UTF-8 BOM for text sniffing.
    sniff = head[3:] if head[:3] == b"\xef\xbb\xbf" else head
    stripped = sniff.lstrip()

    if _PROCMON_HINT.search(head):
        return TYPE_PROCMON_XML
    if stripped[:5].lower() == b"<?xml" or stripped[:1] == b"<":
        return TYPE_XML
    if stripped[:1] in (b"{", b"["):
        return TYPE_JSON

    # Printable-ratio heuristic -> text vs binary.
    if head:
        printable = sum(1 for b in head if 9 <= b <= 13 or 32 <= b <= 126)
        if printable / len(head) > 0.85:
            return TYPE_TEXT
        return TYPE_BINARY
    return TYPE_BINARY


# Maps a detected type to a suggested MCP tool + the argument that should carry the path.
_TOOL_ROUTING: Dict[str, Dict[str, Any]] = {
    TYPE_PROCMON_XML: {"server": "procmon", "tool": "procmon_load_xml", "path_arg": "path"},
    TYPE_PCAP:        {"server": "tshark",  "tool": None,                "path_arg": "path"},
    TYPE_PE:          {"server": None,      "tool": None,                "path_arg": "path"},
    TYPE_ELF:         {"server": None,      "tool": None,                "path_arg": "path"},
}


def routing_for(artifact_type: str) -> Dict[str, Any]:
    """Suggested MCP routing for an artifact type (server/tool/path_arg). Empty dict if none."""
    return dict(_TOOL_ROUTING.get(artifact_type, {}))


# --------------------------------------------------------------------------- store / register
def _sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def project_usage(project_id: str) -> Tuple[int, int]:
    """(file count, total bytes) currently stored for a project. Cheap: one directory scan."""
    d = artifacts_dir(project_id)
    count = 0
    total = 0
    for entry in d.iterdir():
        if entry.is_file() and not entry.name.startswith(".tmp-"):
            count += 1
            try:
                total += entry.stat().st_size
            except OSError:
                pass
    return count, total


def _free_bytes(path: Path) -> int:
    try:
        return shutil.disk_usage(path).free
    except OSError:
        return 1 << 62          # unknown: do not block the upload on a failed stat


def check_can_accept(project_id: str, declared_size: Optional[int] = None) -> None:
    """Refuse an upload *before* the first byte is written. Raises UploadRejected.

    Everything checkable up front is checked up front: a request that cannot possibly succeed
    should not get to write half a gigabyte first.
    """
    max_bytes = int(getattr(config, "MAX_UPLOAD_BYTES", 1 << 30))
    if declared_size is not None and declared_size > max_bytes:
        raise UploadRejected(
            f"upload is {declared_size} bytes; the limit is {max_bytes} "
            "(raise max_upload_bytes if this is expected)",
            status=413, reason="too_large")

    count, total = project_usage(project_id)
    max_files = int(getattr(config, "MAX_ARTIFACTS_PER_PROJECT", 500))
    if count >= max_files:
        raise UploadRejected(
            f"project already holds {count} artifacts; the limit is {max_files}",
            status=409, reason="too_many_files")

    max_project = int(getattr(config, "MAX_PROJECT_BYTES", 20 * (1 << 30)))
    incoming = declared_size or 0
    if total + incoming > max_project:
        raise UploadRejected(
            f"project would hold {total + incoming} bytes; the limit is {max_project}",
            status=409, reason="project_quota")

    reserve = int(getattr(config, "MIN_FREE_DISK_BYTES", 1 << 30))
    free = _free_bytes(artifacts_dir(project_id))
    if free - incoming < reserve:
        raise UploadRejected(
            f"not enough free disk: {free} bytes available, {reserve} must stay free",
            status=507, reason="no_space")


def _stream_to_temp(project_id: str, fileobj, chunk: int = 1 << 20) -> Tuple[Path, int]:
    """Stream an upload to a temporary file, enforcing the size cap as the bytes arrive.

    Written to a `.tmp-` name and only renamed once it is complete and within policy, so a partial
    or rejected upload never appears as an artifact. On any failure the partial file is removed -
    the previous implementation left it on disk, which turned a rejected upload into a disk-filling
    primitive all by itself.
    """
    max_bytes = int(getattr(config, "MAX_UPLOAD_BYTES", 1 << 30))
    reserve = int(getattr(config, "MIN_FREE_DISK_BYTES", 1 << 30))
    dest_dir = artifacts_dir(project_id)
    tmp = dest_dir / f".tmp-{uuid.uuid4().hex}"
    size = 0
    checked_at = 0
    try:
        # 0o600: owner read/write, never executable, never group/world readable. An uploaded
        # sample is untrusted input, not a program, and not something other local users should see.
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as out:
            while True:
                block = fileobj.read(chunk)
                if not block:
                    break
                if isinstance(block, str):
                    block = block.encode("utf-8", "replace")
                size += len(block)
                if size > max_bytes:
                    raise UploadRejected(
                        f"upload exceeds the {max_bytes} byte limit "
                        "(raise max_upload_bytes if this is expected)",
                        status=413, reason="too_large")
                out.write(block)
                # Re-check free space periodically: `declared_size` is a client-supplied hint and
                # a chunked upload may not declare one at all.
                if size - checked_at >= (64 << 20):
                    checked_at = size
                    if _free_bytes(dest_dir) < reserve:
                        raise UploadRejected(
                            f"ran out of disk while receiving: {reserve} bytes must stay free",
                            status=507, reason="no_space")
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return tmp, size


def _finalize(tmp: Path, project_id: str, original_name: str, size: int) -> Dict[str, Any]:
    """Name the stored file from its DETECTED type and build the artifact record.

    The stored name is generated (`<artifact-id><ext>`), never derived from what the uploader
    called the file. A filename is attacker-controlled: generating it removes collision handling,
    unicode and case-folding surprises, and any chance of an extension steering later behaviour.
    The original name is kept as metadata, for the analyst to read.
    """
    atype = detect_type(tmp, declared_name=original_name)
    artifact_id = "A-" + uuid.uuid4().hex[:10]
    stored_name = artifact_id + _EXT_FOR_TYPE.get(atype, ".bin")
    dest = artifacts_dir(project_id) / stored_name
    try:
        tmp.replace(dest)
    except OSError:
        tmp.unlink(missing_ok=True)
        raise
    declared_ext = Path(str(original_name or "")).suffix.lower()
    expected_ext = _EXT_FOR_TYPE.get(atype, ".bin")
    rec: Dict[str, Any] = {
        "id": artifact_id,
        "name": stored_name,
        "original_name": original_name or stored_name,
        "path": str(dest),
        "size": size,
        "sha256": _sha256_file(dest),
        "type": atype,
        "declared_ext": declared_ext,
        # Surfaced to the analyst rather than acted on: a PE uploaded as "notes.txt" is a fact
        # worth seeing, not by itself a reason to refuse the file.
        "type_mismatch": bool(declared_ext) and declared_ext != expected_ext,
        "expandable": False,          # ReTrace never expands archives; see _ARCHIVE_MAGIC
        "routing": routing_for(atype),
        "uploaded_at": time.time(),
        "source": "user_upload",
    }
    if atype == TYPE_ARCHIVE:
        rec["note"] = ("Stored as an opaque container. ReTrace does not expand archives; "
                       "extract it yourself and upload the files you want analysed.")
    log.info("stored artifact %s type=%s size=%d sha256=%s… (original name: %r)",
             artifact_id, atype, size, rec["sha256"][:12], original_name)
    return rec


def store_stream(project_id: str, filename: str, fileobj, chunk: int = 1 << 20,
                 declared_size: Optional[int] = None) -> Dict[str, Any]:
    """Stream an upload to disk under policy, and return its Artifact record.

    Raises UploadRejected (carrying the HTTP status the API should answer with) when a limit is
    hit. Nothing partial survives a rejection.
    """
    check_can_accept(project_id, declared_size)
    tmp, size = _stream_to_temp(project_id, fileobj, chunk)
    try:
        # Re-check against the real size now that it is known; a client may understate it.
        count, total = project_usage(project_id)
        max_project = int(getattr(config, "MAX_PROJECT_BYTES", 20 * (1 << 30)))
        if total + size > max_project:
            raise UploadRejected(
                f"project would hold {total + size} bytes; the limit is {max_project}",
                status=409, reason="project_quota")
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return _finalize(tmp, project_id, filename or "artifact.bin", size)


def store_upload(project_id: str, filename: str, data: bytes) -> Dict[str, Any]:
    """Persist uploaded bytes under the same policy as the streaming path.

    Kept because callers already hold the bytes; it is not a second, laxer code path.
    """
    import io

    return store_stream(project_id, filename, io.BytesIO(data), declared_size=len(data))


def register(session, rec: Dict[str, Any]) -> Dict[str, Any]:
    """Attach an artifact record to the session (idempotent on id) and persist."""
    store = getattr(session, "artifacts", None)
    if store is None:
        session.artifacts = []
        store = session.artifacts
    if not any(a.get("id") == rec.get("id") for a in store):
        store.append(rec)
        if hasattr(session, "persist"):
            session.persist()
    return rec


def get(session, artifact_id: str) -> Optional[Dict[str, Any]]:
    for a in getattr(session, "artifacts", []) or []:
        if a.get("id") == artifact_id:
            return a
    return None


def resolve_path(session, artifact_id: str) -> str:
    """Resolve artifact_id -> absolute path, re-validated through workspace path-safety.

    Raises KeyError if unknown, workspace.UnsafePathError if the stored path is unsafe.
    """
    rec = get(session, artifact_id)
    if not rec:
        raise KeyError(f"unknown artifact: {artifact_id}")
    return str(workspace.safe_resolve(rec["path"]))


# --------------------------------------------------------------------------- LLM-facing summary
def summarize_for_llm(rec: Dict[str, Any], max_chars: int = 4000) -> str:
    """A compact textual summary of an artifact, safe to hand to an LLM with no file channel.

    For huge files (e.g. a 500MB Procmon XML) this reads only a bounded head so it never loads
    the whole file. The structured Procmon summary should come from the MCP server; this is the
    generic fallback so the model at least knows what the artifact is.
    """
    lines = [
        f"Artifact {rec.get('id')}: {rec.get('name')}",
        f"  type={rec.get('type')} size={rec.get('size')} bytes sha256={(rec.get('sha256') or '')[:16]}…",
    ]
    routing = rec.get("routing") or {}
    if routing.get("tool"):
        lines.append(f"  suggested MCP tool: {routing.get('server')}__{routing.get('tool')}"
                     f"({routing.get('path_arg')}=<resolved path>)")
    # Bounded content peek for text-like artifacts.
    if rec.get("type") in (TYPE_TEXT, TYPE_XML, TYPE_JSON, TYPE_PROCMON_XML):
        try:
            with open(rec["path"], "rb") as fh:
                head = fh.read(max_chars * 2)
            text = head.decode("utf-8", errors="replace")
            text = text[:max_chars]
            lines.append("  --- content head (truncated) ---")
            lines.append(text)
        except OSError as e:
            lines.append(f"  (could not read the content: {e})")
    return "\n".join(lines)
