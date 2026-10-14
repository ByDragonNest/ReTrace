"""Secret redaction for anything that could end up in logs, tool outputs, the UI, or reports.

Treat all of those surfaces as potentially observable. We mask (a) the concrete secrets we
know about from config (API keys, auth token) and (b) common secret-looking patterns, so a
leaked key in a tool output / LLM message / exception never reaches the screen verbatim.
"""
import re
from typing import Iterable

_MASK = "«redatto»"

# Generic high-confidence secret patterns (provider keys, bearer tokens, long hex/base64 blobs).
_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9\-_]{16,}"),                 # OpenAI / Anthropic style
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-_\.=]{16,}"),  # Authorization: Bearer ...
    re.compile(r"\b[A-Fa-f0-9]{40,}\b"),                   # long hex (sha/tokens)
    re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[=:]\s*['\"]?[A-Za-z0-9\-_\.]{12,}"),
]


def _known_secrets() -> Iterable[str]:
    # Imported lazily to avoid a circular import with config.
    try:
        from . import config
    except Exception:  # noqa: BLE001
        return []
    out = []
    for name in ("ANTHROPIC_API_KEY", "NVD_API_KEY", "LOCAL_API_KEY", "AUTH_TOKEN"):
        v = getattr(config, name, "")
        if isinstance(v, str) and len(v) >= 6 and v.lower() not in ("ollama", ""):
            out.append(v)
    return out


def redact(text: str) -> str:
    """Return text with known secrets and secret-looking tokens masked."""
    if not text or not isinstance(text, str):
        return text
    out = text
    for sec in _known_secrets():
        if sec:
            out = out.replace(sec, _MASK)
    for pat in _PATTERNS:
        out = pat.sub(_MASK, out)
    return out


def mask(value: str, keep: int = 4) -> str:
    """Mask a value for display: keep the last few chars, hide the rest. Empty stays empty."""
    if not value:
        return ""
    v = str(value)
    if len(v) <= keep:
        return "•" * len(v)
    return "•" * (len(v) - keep) + v[-keep:]
