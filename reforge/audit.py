"""Append-only audit trail for sensitive actions (slices P2-S1, P2-S6).

Who approved running code against a customer's binary, who exported the unredacted dump, who
deleted a project. None of it was recorded. A customer asking "who did this" had no answer, and
neither did we.

Three properties, each for a reason:

* **Append-only, one JSON object per line.** A log you can edit in place is not evidence. JSONL
  survives a truncated write (one bad line, not a corrupt file) and is greppable without tooling.
* **Hash-chained.** Each entry carries the hash of the previous one, so removing or altering an
  entry breaks the chain from that point on. This is tamper-*evident*, not tamper-proof: someone
  with write access can rewrite the whole file and recompute the chain. Making it tamper-proof
  needs an external witness - a WORM store or a remote collector - which is P2-S6 proper.
* **Separate from the operational log and from customer content.** It records *that* a project was
  exported, never the bytes exported. Mixing the two is how an audit trail becomes the thing you
  have to redact before you can hand it over.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

log = logging.getLogger("reforge.audit")

GENESIS = "0" * 64
_lock = threading.Lock()


def _log_path() -> Path:
    from . import config

    directory = Path(config.STATE_ROOT) / "audit"
    directory.mkdir(parents=True, exist_ok=True)
    return directory / "audit.jsonl"


def _entry_hash(entry: Dict[str, Any]) -> str:
    """Hash over the entry WITHOUT its own hash field, with keys sorted so it is reproducible."""
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _last_hash(path: Path) -> str:
    if not path.is_file():
        return GENESIS
    try:
        with open(path, "rb") as fh:
            # Read the tail rather than the file: an audit log is append-only and grows forever.
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - 8192))
            tail = fh.read().decode("utf-8", "replace").strip().splitlines()
        for line in reversed(tail):
            if line.strip():
                return json.loads(line).get("hash", GENESIS)
    except (OSError, json.JSONDecodeError):
        pass
    return GENESIS


def record(action: str, *, principal: Optional[Any] = None, project_id: str = "",
           outcome: str = "ok", **detail: Any) -> Dict[str, Any]:
    """Append one entry. Never raises: an audit failure must not take down the action it records.

    It is logged at ERROR instead, because an audit trail that silently stopped being written is
    worse than one that is loudly broken.
    """
    entry = {
        "ts": time.time(),
        "iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "action": action,
        "outcome": outcome,
        "project_id": project_id,
        "actor": (principal.describe() if principal is not None and hasattr(principal, "describe")
                  else {"subject": "system"}),
        "detail": detail,
    }
    try:
        path = _log_path()
        with _lock:
            entry["prev"] = _last_hash(path)
            entry["hash"] = _entry_hash(entry)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, sort_keys=True, default=str) + "\n")
                fh.flush()
                os.fsync(fh.fileno())
    except OSError as exc:
        log.error("AUDIT WRITE FAILED for %s: %s - the action proceeded but is not recorded",
                  action, exc)
    return entry


def read(limit: int = 200, action: str = "", project_id: str = "") -> List[Dict[str, Any]]:
    """Most recent entries first. Filtering is exact-match, not a query language."""
    out: List[Dict[str, Any]] = []
    for entry in reversed(list(_iter_entries())):
        if action and entry.get("action") != action:
            continue
        if project_id and entry.get("project_id") != project_id:
            continue
        out.append(entry)
        if len(out) >= limit:
            break
    return out


def _iter_entries() -> Iterator[Dict[str, Any]]:
    path = _log_path()
    if not path.is_file():
        return
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def verify() -> Dict[str, Any]:
    """Walk the chain and report the first break. Tamper-EVIDENT, not tamper-proof."""
    previous = GENESIS
    count = 0
    for index, entry in enumerate(_iter_entries()):
        count += 1
        if entry.get("prev") != previous:
            return {"ok": False, "entries": count, "broken_at": index,
                    "reason": "an entry was removed or reordered"}
        if _entry_hash(entry) != entry.get("hash"):
            return {"ok": False, "entries": count, "broken_at": index,
                    "reason": "an entry's contents were altered after it was written"}
        previous = entry["hash"]
    return {"ok": True, "entries": count, "head": previous}
