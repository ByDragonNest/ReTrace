"""Correlation, metrics, SLIs and the support bundle (slice P2-S6, prompt §12).

**What was missing.** Logs were unstructured lines with no correlation: output from the API, the
agent, the MCP host and the LLM layer interleaved with every other request and nothing tied them
together. There were no metrics, so "is this deployment healthy" had no answer but anecdote. And
there was no way to ask a customer for diagnostics without asking them to send material they are
under NDA to protect.
"""
from __future__ import annotations

import io
import json
import logging
import zipfile

import pytest

from reforge import config, observability
from reforge.observability import METRICS, JSONFormatter, scrub


@pytest.fixture(autouse=True)
def clean_metrics():
    METRICS.reset()
    yield
    METRICS.reset()


# --------------------------------------------------------------------------- correlation
def test_a_correlation_id_reaches_every_log_line():
    """Via contextvars, so it does not have to be threaded through a hundred signatures."""
    observability.set_context(correlation_id="abc123", actor="alice", project="p1")
    record = logging.LogRecord("reforge.somewhere", logging.INFO, __file__, 1, "msg", (), None)
    assert observability.CorrelationFilter().filter(record) is True
    assert record.correlation_id == "abc123"
    assert record.actor == "alice" and record.project == "p1"


def test_a_record_with_no_context_is_still_well_formed():
    observability.set_context(correlation_id="-", actor="-", project="-")
    record = logging.LogRecord("x", logging.INFO, __file__, 1, "msg", (), None)
    observability.CorrelationFilter().filter(record)
    assert record.correlation_id and record.actor and record.project


def test_correlation_ids_are_unique():
    assert len({observability.new_correlation_id() for _ in range(500)}) == 500


# --------------------------------------------------------------------------- log hygiene
@pytest.mark.parametrize("content", [
    "decompiled FUN_00401250 into something",
    "undefined4 result = 0",
    "bytes: 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00",
])
def test_customer_content_is_removed_from_operational_logs(content):
    """A log you must redact before handing it to support is one nobody hands to support."""
    cleaned = scrub(content)
    assert observability.SCRUBBED in cleaned
    assert "FUN_00401250" not in cleaned and "undefined4" not in cleaned


def test_an_oversized_log_line_is_bounded():
    cleaned = scrub("x" * 50_000)
    assert len(cleaned) < observability.MAX_LOG_FIELD + 100
    assert "+47" in cleaned or "chars" in cleaned


def test_an_ordinary_message_survives_untouched():
    """Over-scrubbing makes logs useless, which is its own failure."""
    message = "MCP server 'hardening' unavailable: FileNotFoundError"
    assert scrub(message) == message


def test_the_json_formatter_emits_one_object_per_line():
    observability.set_context(correlation_id="cid", actor="bob", project="p2")
    record = logging.LogRecord("reforge.api", logging.WARNING, __file__, 1,
                               "decompiled FUN_00401250", (), None)
    observability.CorrelationFilter().filter(record)
    payload = json.loads(JSONFormatter().format(record))
    assert payload["level"] == "WARNING" and payload["correlation_id"] == "cid"
    assert "FUN_00401250" not in payload["message"], "the formatter must scrub too"


# --------------------------------------------------------------------------- metrics
def test_counters_and_labels():
    METRICS.increment("retrace_x_total", method="GET", status="200")
    METRICS.increment("retrace_x_total", method="GET", status="200")
    METRICS.increment("retrace_x_total", method="GET", status="500")
    counters = METRICS.snapshot()["counters"]
    assert counters['retrace_x_total{method="GET",status="200"}'] == 2
    assert counters['retrace_x_total{method="GET",status="500"}'] == 1


def test_histograms_report_percentiles():
    for value in range(1, 101):
        METRICS.observe("retrace_latency_seconds", float(value))
    stats = METRICS.snapshot()["histograms"]["retrace_latency_seconds"]
    assert stats["count"] == 100
    assert stats["p50"] == 50.0 and stats["p95"] == 95.0 and stats["p99"] == 99.0


def test_the_histogram_reservoir_is_bounded():
    """Unbounded sample retention in a long-running process is a leak."""
    for value in range(10_000):
        METRICS.observe("retrace_bounded_seconds", float(value))
    histogram = METRICS._histograms["retrace_bounded_seconds"]
    assert histogram.count == 10_000
    assert len(histogram.samples) <= histogram.max_samples


def test_the_exposition_format_declares_each_metric_once():
    """Repeating HELP/TYPE per label set is not the format, and some scrapers reject it."""
    METRICS.increment("retrace_y_total", help="A counter.", route="/a")
    METRICS.increment("retrace_y_total", route="/b")
    METRICS.observe("retrace_z_seconds", 0.5, help="A histogram.", route="/a")
    text = METRICS.prometheus()
    assert text.count("# TYPE retrace_y_total") == 1
    assert text.count("# HELP retrace_y_total") == 1
    assert text.count("# TYPE retrace_z_seconds") == 1
    assert 'retrace_y_total{route="/a"} 1.0' in text
    assert 'retrace_z_seconds{route="/a",quantile="0.5"}' in text


def test_the_exposition_output_parses_as_prometheus_text():
    METRICS.increment("retrace_parse_total", help="x", route="/a")
    METRICS.observe("retrace_parse_seconds", 1.0, route="/a")
    for line in METRICS.prometheus().splitlines():
        if not line or line.startswith("#"):
            continue
        name, _, value = line.rpartition(" ")
        assert name, line
        float(value)                       # every sample line ends in a number


# --------------------------------------------------------------------------- SLIs
def test_slis_report_nothing_rather_than_a_flattering_default():
    """100% availability derived from zero requests reads like a number that means something."""
    sli = observability.service_level_indicators()
    assert sli["api_availability"] is None
    assert sli["job_success_rate"] is None


def test_availability_is_computed_from_real_traffic():
    for _ in range(9):
        METRICS.increment("retrace_http_requests_total", route="/a", method="GET", status="200")
    METRICS.increment("retrace_http_requests_total", route="/a", method="GET", status="500")
    sli = observability.service_level_indicators()
    assert sli["api_availability"] == 0.9
    assert sli["sample_sizes"]["http_requests"] == 10


def test_job_success_rate_counts_failures():
    for _ in range(3):
        METRICS.increment("retrace_jobs_total", kind="static", status="completed")
    METRICS.increment("retrace_jobs_total", kind="static", status="failed")
    assert observability.service_level_indicators()["job_success_rate"] == 0.75


# --------------------------------------------------------------------------- support bundle
@pytest.fixture()
def bundle(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "STATE_ROOT", tmp_path)
    from reforge import support_bundle

    return support_bundle.build(recent_logs=[
        "INFO reforge | decompiled FUN_00401250 for project acme-corp",
        "WARNING reforge | MCP server 'ghidra' unavailable",
    ])


def _entries(data: bytes) -> dict:
    archive = zipfile.ZipFile(io.BytesIO(data))
    return {name: archive.read(name) for name in archive.namelist()}


def _decompressed_text(data: bytes) -> str:
    """Every entry's content, concatenated.

    Grepping the raw zip bytes is unsound in both directions - the payload is DEFLATE-compressed,
    so a secret that IS present may not appear literally, and a marker that is absent may appear
    by coincidence. The only honest check decompresses first. (My first version of these tests got
    this wrong and passed for the wrong reason.)
    """
    return "\n".join(body.decode("utf-8", "replace") for body in _entries(data).values())


def test_the_bundle_carries_what_diagnoses_a_problem(bundle):
    names = set(_entries(bundle))
    for expected in ("README.txt", "environment.json", "dependencies.json",
                     "security-posture.json", "configuration.json", "mcp-servers.json",
                     "metrics.json", "sli.json", "audit-integrity.json"):
        assert expected in names


def test_the_bundle_contains_no_customer_content(bundle):
    """Symbols a pattern can find, and project names it cannot."""
    text = _decompressed_text(bundle)
    for forbidden in ("FUN_00401250", "undefined4"):
        assert forbidden not in text, f"{forbidden} reached the support bundle"


def test_a_project_name_in_a_log_line_does_not_reach_the_bundle(monkeypatch, tmp_path):
    """A project is named after the customer. The README promises these are absent."""
    from reforge import support_bundle
    from reforge.session import SessionStore

    monkeypatch.setattr(config, "STATE_ROOT", tmp_path)
    monkeypatch.setattr(config, "PROJECTS_DIR", tmp_path / "projects")
    monkeypatch.setattr(SessionStore, "list_projects",
                        lambda self: [{"id": "abc123def", "name": "acme-corp-engagement"}])
    data = support_bundle.build(recent_logs=[
        "INFO reforge | loaded project acme-corp-engagement (abc123def)"])
    text = _decompressed_text(data)
    assert "acme-corp-engagement" not in text
    assert "abc123def" not in text


def test_identifier_scrubbing_removes_the_longest_match_first():
    """Otherwise "acme-corp" is removed and "-2024" is left behind."""
    cleaned = observability.scrub_identifiers(
        "project acme-corp-2024 failed", ["acme-corp", "acme-corp-2024"])
    assert "acme" not in cleaned and "2024" not in cleaned


def test_identifier_scrubbing_ignores_values_too_short_to_be_meaningful():
    """Removing every two-character string would destroy the log to protect nothing."""
    assert observability.scrub_identifiers("the job ok ran", ["ok"]) == "the job ok ran"


def test_the_bundle_contains_no_credential(monkeypatch, tmp_path):
    from reforge import support_bundle

    monkeypatch.setattr(config, "STATE_ROOT", tmp_path)
    sentinel = "sk-ant-SENTINEL-not-a-real-key"
    monkeypatch.setattr(config, "ANTHROPIC_API_KEY", sentinel)
    data = support_bundle.build()
    text = _decompressed_text(data)
    assert sentinel not in text, "a credential reached the support bundle"
    # The bundle still says one EXISTS, which is diagnostic; its value never is.
    configuration = json.loads(_entries(data)["configuration.json"])
    assert configuration["_has_anthropic_key"] is True


def test_the_bundle_says_whether_a_credential_exists_without_revealing_it(bundle):
    configuration = json.loads(_entries(bundle)["configuration.json"])
    assert "_has_auth_token" in configuration
    assert isinstance(configuration["_has_auth_token"], bool)
    for key, value in configuration.items():
        if any(m in key.lower() for m in ("key", "token", "secret", "password")):
            assert value in (True, False, "«present»", "«not set»"), f"{key} leaked a value"


def test_the_bundle_carries_the_audit_verdict_not_the_entries(bundle):
    integrity = json.loads(_entries(bundle)["audit-integrity.json"])
    assert set(integrity) <= {"ok", "entries", "head", "broken_at", "reason", "error"}


def test_the_bundle_explains_what_it_excludes(bundle):
    readme = _entries(bundle)["README.txt"].decode("utf-8")
    for promise in ("findings", "project names", "API key", "sendable without review"):
        assert promise in readme


def test_the_bundle_does_not_carry_server_command_lines(bundle):
    """A command line carries a sample path, and a sample path carries a customer name."""
    servers = json.loads(_entries(bundle)["mcp-servers.json"])
    assert set(servers) == {"configured", "manifested", "manifest_errors", "unmanifested"}
    assert all(isinstance(name, str) for name in servers["configured"])
