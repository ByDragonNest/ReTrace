"""Cache for deterministic model requests (slice P1-S4).

Only safe when the key covers everything that could change the answer. A cache keyed on the input
alone will happily serve a result produced by a different model, or by a prompt that has since
been rewritten - which turns an upgrade into a silent behaviour change that no test catches
because the model is never actually called.

The key therefore covers: provider, model, prompt version, schema name and version, and the input.
Any of them moving is a miss.

Two deliberate limits:

* **Only deterministic requests.** A cached sample from a temperature>0 request would present one
  draw from a distribution as if it were the answer. The caller decides; `enabled` is off unless
  asked for.
* **Entries live under STATE_ROOT**, next to the projects, never in the source tree. They can
  contain customer-derived text, so they inherit the state directory's handling: deleting the
  project directory deletes them, and nothing here is written to a report or a log.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Optional

log = logging.getLogger("reforge.llm_cache")

#: Cap on the number of entries. Small on purpose: this is a cache for repeated deterministic work
#: inside one investigation, not a model-output archive.
DEFAULT_MAX_ENTRIES = 2000


class LLMCache:
    def __init__(self, directory: Path, *, enabled: bool = True,
                 max_entries: int = DEFAULT_MAX_ENTRIES):
        self.dir = Path(directory)
        self.enabled = enabled
        self.max_entries = max_entries
        if self.enabled:
            self.dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ key
    @staticmethod
    def key(*, provider: str, model: str, prompt_version: str, schema: str, payload: str) -> str:
        """Everything that could change the answer goes into the hash. Nothing else does."""
        h = hashlib.sha256()
        for part in (provider, model, prompt_version, schema, payload):
            h.update(str(part).encode("utf-8"))
            h.update(b"\x1f")                 # separator: "ab"+"c" must not collide with "a"+"bc"
        return h.hexdigest()

    def _path(self, key: str) -> Path:
        return self.dir / f"{key}.json"

    # ------------------------------------------------------------------ access
    def get(self, key: str) -> Optional[Any]:
        if not self.enabled:
            return None
        path = self._path(key)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return payload.get("value")

    def put(self, key: str, value: Any) -> None:
        """Write atomically: a half-written entry read by another process is a wrong answer."""
        if not self.enabled:
            return
        record = {"value": value, "stored_at": time.time()}
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=str(self.dir), suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(record, fh)
            os.replace(tmp, self._path(key))
        except OSError as exc:
            log.debug("could not cache %s: %s", key[:12], exc)
            return
        self._evict_if_needed()

    def delete(self, key: str) -> None:
        try:
            self._path(key).unlink(missing_ok=True)
        except OSError:
            pass

    def clear(self) -> int:
        removed = 0
        for entry in self.dir.glob("*.json"):
            try:
                entry.unlink()
                removed += 1
            except OSError:
                pass
        return removed

    def stats(self) -> Dict[str, Any]:
        entries = list(self.dir.glob("*.json")) if self.dir.is_dir() else []
        return {"enabled": self.enabled, "entries": len(entries),
                "bytes": sum(e.stat().st_size for e in entries if e.is_file()),
                "directory": str(self.dir)}

    def _evict_if_needed(self) -> None:
        """Oldest-first eviction. Crude, and right for this: entries are equal-cost to recompute."""
        try:
            entries = sorted(self.dir.glob("*.json"), key=lambda p: p.stat().st_mtime)
        except OSError:
            return
        for stale in entries[:max(0, len(entries) - self.max_entries)]:
            try:
                stale.unlink()
            except OSError:
                pass


_default: Optional[LLMCache] = None


def default() -> LLMCache:
    """The process-wide cache, under STATE_ROOT/cache/llm."""
    global _default
    if _default is None:
        from . import config
        _default = LLMCache(Path(config.STATE_ROOT) / "cache" / "llm")
    return _default
