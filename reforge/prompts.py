"""Versioned prompt registry (slice P1-S4).

A prompt is part of the product's behaviour, so it needs a version for the same reasons code does:
a result is only reproducible if you know which prompt produced it, a cache entry is only valid
while the prompt that produced it is unchanged, and a benchmark number is only comparable across
releases if the prompt is part of what was compared.

The version is the content hash. Nothing to remember to bump, and it cannot drift from the text it
describes: edit the prompt and the version changes, which invalidates its cache entries and shows
up in the evidence attached to anything that used it.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"


@dataclass(frozen=True)
class Prompt:
    name: str
    text: str
    version: str          # sha256 of the text, truncated - stable and self-maintaining

    def __str__(self) -> str:                     # so it drops into an f-string as the text
        return self.text


def _version_of(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


def inline(name: str, text: str) -> Prompt:
    """Version a prompt defined in code rather than in a file."""
    return Prompt(name=name, text=text, version=_version_of(text))


def _read(name: str) -> str:
    path = PROMPTS_DIR / f"{name}.md"
    if not path.is_file():
        raise FileNotFoundError(f"no prompt named {name!r} in {PROMPTS_DIR}")
    return path.read_text(encoding="utf-8")


def get(name: str) -> Prompt:
    """Load a prompt from reforge/prompts/<name>.md with its content version.

    Deliberately not cached: these are a few kilobytes read at most once per turn, and caching
    would mean an edited prompt kept serving the old text until a restart - exactly the kind of
    stale behaviour the version exists to prevent.
    """
    text = _read(name)
    return Prompt(name=name, text=text, version=_version_of(text))


def available() -> List[str]:
    return sorted(p.stem for p in PROMPTS_DIR.glob("*.md"))


def versions() -> Dict[str, str]:
    """Every shipped prompt and its version. Goes into the report's reproducibility section."""
    return {name: get(name).version for name in available()}
