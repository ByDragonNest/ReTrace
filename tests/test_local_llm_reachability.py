"""A configured local model that is not running must be visible as such (not "available").

Ollama installed and not started looks exactly like Ollama running from the configuration alone.
The status endpoint probes; the turn names the cause.
"""
from __future__ import annotations

import asyncio

import pytest

from reforge import config, llm


@pytest.fixture
def local_on_a_closed_port(monkeypatch):
    monkeypatch.setattr(config, "LLM_PROVIDER", "local")
    monkeypatch.setattr(config, "LOCAL_BASE_URL", "http://127.0.0.1:1/v1")   # port 1: refused at once
    monkeypatch.setattr(config, "LOCAL_MODEL", "qwen-test:1b")
    llm._PROBE_CACHE.update(at=0.0, url="", ok=None, error="")
    yield
    llm._PROBE_CACHE.update(at=0.0, url="", ok=None, error="")


def test_a_closed_local_port_is_reported_unreachable(local_on_a_closed_port):
    ok, err = asyncio.run(llm.local_reachable(timeout=1.0))
    assert ok is False and err


def test_the_probe_does_not_apply_to_other_providers(monkeypatch):
    monkeypatch.setattr(config, "LLM_PROVIDER", "anthropic")
    assert asyncio.run(llm.local_reachable()) == (None, "")
    monkeypatch.setattr(config, "LLM_PROVIDER", "none")
    assert asyncio.run(llm.local_reachable()) == (None, "")


def test_the_probe_is_cached_between_status_polls(local_on_a_closed_port, monkeypatch):
    calls = []
    monkeypatch.setattr(llm, "_probe_url", lambda url, timeout: (calls.append(url), (False, "refused"))[1])
    asyncio.run(llm.local_reachable()); asyncio.run(llm.local_reachable())
    assert len(calls) == 1


def test_status_endpoint_carries_reachability(local_on_a_closed_port):
    from fastapi.testclient import TestClient
    from reforge import server as s
    with TestClient(s.app) as c:
        c.headers.update({"X-Reforge-Token": config.AUTH_TOKEN})
        body = c.get("/api/status").json()
    assert body["llm_available"] is True          # configured...
    assert body["llm_reachable"] is False         # ...but nobody is listening
    assert body["llm_base_url"] == "http://127.0.0.1:1/v1"


def test_a_connection_error_is_explained_with_the_url_and_the_fix(local_on_a_closed_port):
    class APIConnectionError(Exception):
        pass
    text = llm.explain_error(APIConnectionError("Connection error."), "local")
    assert "http://127.0.0.1:1/v1" in text and "ollama serve" in text and "qwen-test:1b" in text


def test_a_timeout_names_the_ceiling(local_on_a_closed_port):
    class APITimeoutError(Exception):
        pass
    text = llm.explain_error(APITimeoutError("timed out"), "local")
    assert str(config.LOCAL_TIMEOUT_S) in text and "local_timeout_s" in text


def test_an_unknown_model_says_to_pull_it(local_on_a_closed_port):
    class NotFoundError(Exception):
        pass
    text = llm.explain_error(NotFoundError("model 'qwen-test:1b' not found"), "local")
    assert "ollama pull qwen-test:1b" in text


def test_other_errors_keep_their_class_and_message():
    assert llm.explain_error(ValueError("bad json"), "local") == "ValueError: bad json"


# --------------------------------------------------------------------------- model present?
def test_a_pulled_model_is_fine():
    assert llm.model_missing_message("qwen3:30b", {"data": [{"id": "qwen3:30b"}, {"id": "llama3:8b"}]}) == ""


def test_an_untagged_name_matches_any_tag():
    assert llm.model_missing_message("qwen3", {"data": [{"id": "qwen3:30b"}]}) == ""


def test_an_empty_server_names_the_pull_command():
    msg = llm.model_missing_message("qwen3:30b", {"data": []})
    assert "ollama pull qwen3:30b" in msg and "available: none" in msg


def test_a_different_model_lists_what_is_there():
    msg = llm.model_missing_message("qwen3:30b", {"data": [{"id": "llama3:8b"}]})
    assert "llama3:8b" in msg and "qwen3:30b" in msg


def test_a_listing_that_is_not_openai_shaped_says_nothing():
    assert llm.model_missing_message("qwen3:30b", ["not", "a", "dict"]) == ""


def test_status_reports_a_reachable_server_without_the_model(local_on_a_closed_port, monkeypatch):
    # The SDK problem outranks the probe (its own test below); here the provider is assumed built,
    # so the test does not depend on whether `openai` happens to be installed where it runs.
    monkeypatch.setattr(llm, "provider_problem", lambda: "")
    monkeypatch.setattr(llm, "_probe_url", lambda url, timeout: (True, "model 'qwen-test:1b' is not on the server (available: none). Pull it with `ollama pull qwen-test:1b` or set `local_model` to one of the available ones."))
    from fastapi.testclient import TestClient
    from reforge import server as s
    with TestClient(s.app) as c:
        c.headers.update({"X-Reforge-Token": config.AUTH_TOKEN})
        body = c.get("/api/status").json()
    assert body["llm_reachable"] is True and "ollama pull qwen-test:1b" in body["llm_error"]


def test_ollama_with_nothing_pulled_answers_data_null():
    """Seen live: `{"object":"list","data":null}`. Iterating None reported the server unreachable."""
    msg = llm.model_missing_message("qwen3:30b", {"object": "list", "data": None})
    assert "ollama pull qwen3:30b" in msg and "available: none" in msg


# --------------------------------------------------------------------------- SDK missing
def test_a_missing_sdk_is_named_with_the_extra_that_installs_it():
    msg = llm.provider_install_hint("local", "No module named 'openai'")
    assert 'retrace[local]' in msg and "openai" in msg
    msg = llm.provider_install_hint("anthropic", "No module named 'anthropic'")
    assert 'retrace[cloud]' in msg


def test_a_no_llm_stand_in_reports_its_reason_through_status(local_on_a_closed_port, monkeypatch):
    monkeypatch.setattr(llm, "get_llm", lambda provider=None: llm.NoLLM(reason="No module named 'openai'", provider="local"))
    monkeypatch.setattr(llm, "_probe_url", lambda url, timeout: (True, ""))
    from fastapi.testclient import TestClient
    from reforge import server as s
    with TestClient(s.app) as c:
        c.headers.update({"X-Reforge-Token": config.AUTH_TOKEN})
        body = c.get("/api/status").json()
    assert 'retrace[local]' in body["llm_error"]


def test_an_unconfigured_provider_still_says_so():
    assert "No LLM configured" in llm.NoLLM().problem()


def test_check_reports_llm_readiness(capsys, monkeypatch):
    from reforge import __main__ as cli
    monkeypatch.setattr(config, "LLM_PROVIDER", "local")
    monkeypatch.setattr(llm, "get_llm", lambda provider=None: llm.NoLLM(reason="No module named 'openai'", provider="local"))
    assert cli.main(["check"]) == 0
    assert "NOT READY" in capsys.readouterr().out
