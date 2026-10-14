"""Correlation, structured logging and metrics (slice P2-S6, prompt §12).

**What was missing.** Logs were unstructured lines with no correlation: a failed analysis produced
output from the API, the agent, the MCP host and the LLM layer interleaved with every other
request, and nothing tied them together. There were no metrics at all, so "is this deployment
healthy" and "did that change make anything slower" had no answer but anecdote. The one thing that
did exist — the hash-chained audit trail from P2-S1 — covers *who did what*, not *what the system
is doing*.

Three pieces, deliberately small and dependency-free:

1. **A correlation id per request**, carried in a `contextvars` so it reaches every log line from
   every module without being threaded through a hundred signatures, and returned as a response
   header so a user reporting a problem can quote it.
2. **A structured formatter** (opt-in) emitting one JSON object per line, with the correlation id,
   actor and project alongside the message — greppable, and parseable by whatever collects it.
3. **An in-process metric registry** with counters and histograms, exposed in Prometheus text
   format. In-process because a workstation install must not need a metrics backend to be
   observable; the same numbers scrape into one when there is a fleet.

**Operational logs are not the audit trail and are not customer content.** The audit trail is
`reforge/audit.py`, tamper-evident and deliberately separate. Customer content — decompiled code,
strings, findings — must never reach an operational log, because a log you have to redact before
handing it to support is a log nobody will hand to support. `scrub()` is the guard.
"""
from __future__ import annotations

import contextvars
import json
import logging
import math
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# --------------------------------------------------------------------------- correlation
_correlation: contextvars.ContextVar[str] = contextvars.ContextVar("correlation_id", default="")
_actor: contextvars.ContextVar[str] = contextvars.ContextVar("actor", default="")
_project: contextvars.ContextVar[str] = contextvars.ContextVar("project", default="")


def new_correlation_id() -> str:
    return uuid.uuid4().hex[:16]


def set_context(*, correlation_id: str = "", actor: str = "", project: str = "") -> None:
    if correlation_id:
        _correlation.set(correlation_id)
    if actor:
        _actor.set(actor)
    if project:
        _project.set(project)


def context() -> Dict[str, str]:
    return {"correlation_id": _correlation.get(), "actor": _actor.get(),
            "project": _project.get()}


class CorrelationFilter(logging.Filter):
    """Attaches the current correlation context to every record.

    A filter rather than an adapter so it applies to records from modules that know nothing about
    any of this - which is all of them.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        ctx = context()
        record.correlation_id = ctx["correlation_id"] or "-"
        record.actor = ctx["actor"] or "-"
        record.project = ctx["project"] or "-"
        return True


# --------------------------------------------------------------------------- customer content
#: Markers of material that belongs in the Evidence Graph, not in an operational log.
_CUSTOMER_CONTENT = (
    re.compile(r"\b(?:FUN_|LAB_|DAT_)[0-9a-f]{4,}\b"),
    re.compile(r"(?:[0-9a-fA-F]{2}[ \-]){8,}"),           # hex dump
    re.compile(r"\bundefined[0-9]\b"),
)
SCRUBBED = "«content removed»"
#: Beyond this, a log line is carrying data rather than describing an event.
MAX_LOG_FIELD = 2000


def scrub_identifiers(text: str, identifiers: Any) -> str:
    """Remove specific known strings - project names and ids - from a log line.

    Pattern matching cannot find these: a project is called whatever the analyst called it, and
    what they called it is usually the customer. So they are removed by name, which means the
    caller has to supply the list. Longest first, so "acme-corp-2024" does not leave "-2024"
    behind after "acme-corp" is removed.
    """
    out = str(text)
    for identifier in sorted({str(i) for i in (identifiers or []) if i and len(str(i)) >= 3},
                             key=len, reverse=True):
        out = out.replace(identifier, SCRUBBED)
    return out


def scrub(text: Any) -> str:
    """Remove customer-derived content and bound the length.

    Operational logs get handed to support. One that has to be redacted first is one nobody hands
    over, so the redaction happens on the way in.
    """
    value = str(text)
    for marker in _CUSTOMER_CONTENT:
        value = marker.sub(SCRUBBED, value)
    if len(value) > MAX_LOG_FIELD:
        value = value[:MAX_LOG_FIELD] + f"…(+{len(value) - MAX_LOG_FIELD} chars)"
    return value


class JSONFormatter(logging.Formatter):
    """One JSON object per line. Opt-in via `log_format = "json"`."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": scrub(record.getMessage()),
            "correlation_id": getattr(record, "correlation_id", "-"),
            "actor": getattr(record, "actor", "-"),
            "project": getattr(record, "project", "-"),
        }
        if record.exc_info:
            payload["exception"] = scrub(self.formatException(record.exc_info))
        return json.dumps(payload, default=str)


# --------------------------------------------------------------------------- metrics
@dataclass
class Histogram:
    """Counts and a bounded reservoir, enough for percentiles without a metrics backend."""

    name: str
    help: str = ""
    count: int = 0
    total: float = 0.0
    samples: List[float] = field(default_factory=list)
    max_samples: int = 2048

    def observe(self, value: float) -> None:
        self.count += 1
        self.total += value
        if len(self.samples) < self.max_samples:
            self.samples.append(value)
        else:
            # Keep the tail: for latency, the recent and the slow are what matter.
            self.samples[self.count % self.max_samples] = value

    def percentile(self, pct: float) -> float:
        """Nearest-rank, the same definition `benchmarks/metrics.py` uses.

        Duplicated rather than imported: `benchmarks/` is a development corpus and is excluded
        from the wheel, so importing it here would make the shipped product depend on something it
        does not ship. Six lines of duplication beat that.
        """
        if not self.samples:
            return 0.0
        ordered = sorted(self.samples)
        rank = math.ceil(pct / 100.0 * len(ordered))
        return ordered[max(1, min(len(ordered), rank)) - 1]


class Metrics:
    """Counters and histograms, in-process and thread-safe."""

    def __init__(self):
        self._lock = threading.Lock()
        self._counters: Dict[str, float] = {}
        self._help: Dict[str, str] = {}
        self._histograms: Dict[str, Histogram] = {}
        self.started_at = time.time()

    @staticmethod
    def _key(name: str, labels: Optional[Dict[str, str]]) -> str:
        if not labels:
            return name
        rendered = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()))
        return f"{name}{{{rendered}}}"

    def increment(self, name: str, value: float = 1.0, *, help: str = "",
                  **labels: str) -> None:
        with self._lock:
            self._counters[self._key(name, labels)] = \
                self._counters.get(self._key(name, labels), 0.0) + value
            if help:
                self._help.setdefault(name, help)

    def observe(self, name: str, value: float, *, help: str = "", **labels: str) -> None:
        key = self._key(name, labels)
        with self._lock:
            hist = self._histograms.get(key)
            if hist is None:
                hist = self._histograms[key] = Histogram(name=key, help=help)
            hist.observe(value)
            if help:
                self._help.setdefault(name, help)

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "uptime_seconds": round(time.time() - self.started_at, 1),
                "counters": dict(self._counters),
                "histograms": {
                    key: {"count": h.count, "sum": round(h.total, 4),
                          "mean": round(h.total / h.count, 4) if h.count else 0.0,
                          "p50": round(h.percentile(50), 4),
                          "p95": round(h.percentile(95), 4),
                          "p99": round(h.percentile(99), 4)}
                    for key, h in self._histograms.items()},
            }

    def prometheus(self) -> str:
        """Prometheus text exposition. The same numbers scrape into a backend when one exists."""
        lines: List[str] = []
        snap = self.snapshot()
        lines.append("# HELP retrace_uptime_seconds Seconds since this process started.")
        lines.append("# TYPE retrace_uptime_seconds gauge")
        lines.append(f"retrace_uptime_seconds {snap['uptime_seconds']}")
        # HELP/TYPE once per metric NAME, not per series: repeating them for every label set is
        # not what the exposition format says, and some scrapers reject it.
        emitted: set = set()
        for key, value in sorted(snap["counters"].items()):
            base = key.split("{")[0]
            if base not in emitted:
                emitted.add(base)
                if base in self._help:
                    lines.append(f"# HELP {base} {self._help[base]}")
                lines.append(f"# TYPE {base} counter")
            lines.append(f"{key} {value}")
        for key, stats in sorted(snap["histograms"].items()):
            base = key.split("{")[0]
            labels = key[len(base):]
            inner = labels.strip("{}")
            prefix = inner + "," if inner else ""
            if base not in emitted:
                emitted.add(base)
                if base in self._help:
                    lines.append("# HELP " + base + " " + self._help[base])
                lines.append("# TYPE " + base + " summary")
            for quantile, field in (("0.5", "p50"), ("0.95", "p95"), ("0.99", "p99")):
                series = base + "{" + prefix + 'quantile="' + quantile + '"}'
                lines.append(series + " " + str(stats[field]))
            lines.append(base + "_sum" + labels + " " + str(stats["sum"]))
            lines.append(base + "_count" + labels + " " + str(stats["count"]))
        return "\n".join(lines) + "\n"

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()
            self._histograms.clear()


METRICS = Metrics()


# --------------------------------------------------------------------------- SLI
def service_level_indicators() -> Dict[str, Any]:
    """The four SLIs defined in docs/observability-and-slo.md, computed from live counters.

    Reported as `null` rather than a flattering default when there is no traffic: an availability
    of 100% derived from zero requests is a number that means nothing and reads like one that does.
    """
    snap = METRICS.snapshot()
    counters = snap["counters"]

    def total(prefix: str) -> float:
        return sum(v for k, v in counters.items() if k.startswith(prefix))

    requests = total("retrace_http_requests_total")
    errors = sum(v for k, v in counters.items()
                 if k.startswith("retrace_http_requests_total") and 'status="5' in k)
    jobs_done = total("retrace_jobs_total{")
    jobs_failed = sum(v for k, v in counters.items()
                      if k.startswith("retrace_jobs_total") and 'status="failed"' in k)
    latency = snap["histograms"].get("retrace_http_request_seconds", {})

    return {
        "api_availability": round(1 - errors / requests, 4) if requests else None,
        "api_latency_p95_seconds": latency.get("p95") if latency else None,
        "job_success_rate": round(1 - jobs_failed / jobs_done, 4) if jobs_done else None,
        "tool_call_success_rate": _ratio(counters, "retrace_tool_calls_total", 'outcome="ok"'),
        "sample_sizes": {"http_requests": requests, "jobs": jobs_done},
    }


def _ratio(counters: Dict[str, float], prefix: str, good_label: str) -> Optional[float]:
    total = sum(v for k, v in counters.items() if k.startswith(prefix))
    good = sum(v for k, v in counters.items() if k.startswith(prefix) and good_label in k)
    return round(good / total, 4) if total else None
