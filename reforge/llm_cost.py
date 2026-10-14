"""Lightweight Claude API token-cost estimation.

The Anthropic API returns token usage, not a final invoice line. This module converts the usage
object into an operator-facing estimate using a small local price table. Keep the table updated when
Anthropic changes prices or when you use a negotiated/marketplace plan.
"""
from __future__ import annotations

import time
from typing import Any, Dict, Optional

MTOK = 1_000_000

# USD per million tokens. Mirrors the public first-party Claude API table at the time this build was
# made. Cache prices are included because the API can return cache_* token counters.
_MODEL_PRICES = {
    "fable-5": {"input": 10.00, "cache_write_5m": 12.50, "cache_write_1h": 20.00, "cache_read": 1.00, "output": 50.00},
    "mythos-5": {"input": 10.00, "cache_write_5m": 12.50, "cache_write_1h": 20.00, "cache_read": 1.00, "output": 50.00},
    "opus-4.8": {"input": 5.00, "cache_write_5m": 6.25, "cache_write_1h": 10.00, "cache_read": 0.50, "output": 25.00},
    "opus-4.7": {"input": 5.00, "cache_write_5m": 6.25, "cache_write_1h": 10.00, "cache_read": 0.50, "output": 25.00},
    "opus-4.6": {"input": 5.00, "cache_write_5m": 6.25, "cache_write_1h": 10.00, "cache_read": 0.50, "output": 25.00},
    "opus-4.5": {"input": 5.00, "cache_write_5m": 6.25, "cache_write_1h": 10.00, "cache_read": 0.50, "output": 25.00},
    "opus-4.1": {"input": 15.00, "cache_write_5m": 18.75, "cache_write_1h": 30.00, "cache_read": 1.50, "output": 75.00},
    "opus-4": {"input": 15.00, "cache_write_5m": 18.75, "cache_write_1h": 30.00, "cache_read": 1.50, "output": 75.00},
    "sonnet-4.6": {"input": 3.00, "cache_write_5m": 3.75, "cache_write_1h": 6.00, "cache_read": 0.30, "output": 15.00},
    "sonnet-4.5": {"input": 3.00, "cache_write_5m": 3.75, "cache_write_1h": 6.00, "cache_read": 0.30, "output": 15.00},
    "sonnet-4": {"input": 3.00, "cache_write_5m": 3.75, "cache_write_1h": 6.00, "cache_read": 0.30, "output": 15.00},
    "haiku-4.5": {"input": 1.00, "cache_write_5m": 1.25, "cache_write_1h": 2.00, "cache_read": 0.10, "output": 5.00},
    "haiku-3.5": {"input": 0.80, "cache_write_5m": 1.00, "cache_write_1h": 1.60, "cache_read": 0.08, "output": 4.00},
}


def _num(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def price_for_model(model: str) -> Optional[Dict[str, float]]:
    """Return the closest first-party Claude API price row for a model id."""
    m = (model or "").lower().replace("_", "-")
    # Prefer the most specific keys first, e.g. opus-4.8 before opus-4.
    for key in sorted(_MODEL_PRICES, key=len, reverse=True):
        if key in m:
            return _MODEL_PRICES[key]
    return None


def estimate_usd(model: str, usage: Dict[str, Any]) -> Optional[float]:
    """Estimate first-party Claude API token cost in USD, or None for unknown models."""
    price = price_for_model(model)
    if not price:
        return None
    input_tokens = _num(usage.get("input_tokens"))
    output_tokens = _num(usage.get("output_tokens"))
    cache_write = _num(usage.get("cache_creation_input_tokens"))
    cache_read = _num(usage.get("cache_read_input_tokens"))
    total = (
        input_tokens * price["input"]
        + output_tokens * price["output"]
        + cache_write * price["cache_write_5m"]
        + cache_read * price["cache_read"]
    ) / MTOK
    return round(total, 8)


def usage_entry(provider: str, model: str, usage: Dict[str, Any], step: int | None = None) -> Dict[str, Any]:
    """Build a persistable usage row for the current model call."""
    usage = dict(usage or {})
    cost = estimate_usd(model, usage) if provider == "anthropic" else None
    return {
        "ts": time.time(),
        "provider": provider,
        "model": model,
        "step": step,
        "usage": usage,
        "estimated_cost_usd": cost,
        "cost_note": "first_party_token_estimate" if cost is not None else "no_price_table_match",
    }


def summarize(entries: list[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate usage rows for display in the UI."""
    entries = entries or []
    input_tokens = output_tokens = cache_write = cache_read = 0
    cost = 0.0
    has_cost = False
    for e in entries:
        u = e.get("usage") or {}
        input_tokens += _num(u.get("input_tokens"))
        output_tokens += _num(u.get("output_tokens"))
        cache_write += _num(u.get("cache_creation_input_tokens"))
        cache_read += _num(u.get("cache_read_input_tokens"))
        c = e.get("estimated_cost_usd")
        if c is not None:
            has_cost = True
            try:
                cost += float(c)
            except (TypeError, ValueError):
                pass
    return {
        "calls": len(entries),
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cache_creation_input_tokens": cache_write,
        "cache_read_input_tokens": cache_read,
        "estimated_cost_usd": round(cost, 6) if has_cost else None,
    }
