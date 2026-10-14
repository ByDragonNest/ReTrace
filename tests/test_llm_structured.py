"""Schema-validated, fail-closed model output (slice P1-S4).

Structured output used to be *parsed*: `_first_json_object()` scraped the first brace-balanced
object out of whatever the model said, and `complete_json()` returned `{}` when nothing parsed -
indistinguishable from "the model answered with an empty object". For the local provider that
best-effort path was the primary one, not a fallback.

Separately, `salvage_tool_calls()` recovered tool calls from free text with no restriction on
which tool, so a sentence the model was only *discussing* could be scraped into an `add_finding`
call: a fabricated claim with a real title on it.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from pydantic import BaseModel, ConfigDict, Field

from reforge import llm, llm_cache, llm_schema, prompts

ROOT = Path(__file__).resolve().parent.parent


class Verdict(BaseModel):
    model_config = ConfigDict(extra="forbid")
    exploitable: bool
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str = ""


class _FakeLLM:
    """A model that answers with a scripted sequence of payloads."""

    def __init__(self, *payloads):
        self.payloads = list(payloads)
        self.prompts_seen = []

    async def complete_json(self, system, user):
        self.prompts_seen.append(user)
        value = self.payloads.pop(0) if self.payloads else {}
        if isinstance(value, Exception):
            raise value
        return value


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


# --------------------------------------------------------------------------- happy path
def test_a_valid_response_is_returned_as_a_typed_object():
    client = _FakeLLM({"exploitable": True, "confidence": 0.9, "reason": "reachable sink"})
    out = run(llm_schema.structured(client, Verdict, system="s", user="u"))
    assert isinstance(out, Verdict)
    assert out.exploitable is True and out.confidence == 0.9


def test_the_schema_is_sent_to_the_model_verbatim():
    """The instruction and the validation must be the same artefact, or they drift."""
    client = _FakeLLM({"exploitable": False, "confidence": 0.1})
    run(llm_schema.structured(client, Verdict, system="s", user="u"))
    assert "JSON Schema" in client.prompts_seen[0]
    assert "exploitable" in client.prompts_seen[0]


# --------------------------------------------------------------------------- fail closed
def test_an_unparseable_response_raises_instead_of_returning_empty():
    """The defect this slice exists for: `{}` used to flow on as if it were an answer."""
    client = _FakeLLM({}, {})
    with pytest.raises(llm_schema.StructuredOutputError):
        run(llm_schema.structured(client, Verdict, system="s", user="u"))


def test_a_wrong_shape_raises_and_is_never_coerced():
    client = _FakeLLM({"exploitable": "yes please", "confidence": 42},
                      {"exploitable": "still wrong", "confidence": 42})
    with pytest.raises(llm_schema.StructuredOutputError) as exc:
        run(llm_schema.structured(client, Verdict, system="s", user="u"))
    assert "confidence" in exc.value.last_error or "exploitable" in exc.value.last_error


def test_a_value_outside_its_declared_range_is_rejected():
    client = _FakeLLM({"exploitable": True, "confidence": 1.7},
                      {"exploitable": True, "confidence": 1.7})
    with pytest.raises(llm_schema.StructuredOutputError):
        run(llm_schema.structured(client, Verdict, system="s", user="u"))


def test_an_extra_field_is_rejected_when_the_schema_forbids_it():
    client = _FakeLLM({"exploitable": True, "confidence": 0.5, "severity": "CRITICAL"},
                      {"exploitable": True, "confidence": 0.5, "severity": "CRITICAL"})
    with pytest.raises(llm_schema.StructuredOutputError):
        run(llm_schema.structured(client, Verdict, system="s", user="u"))


def test_a_transport_failure_also_fails_closed():
    client = _FakeLLM(RuntimeError("connection reset"), RuntimeError("connection reset"))
    with pytest.raises(llm_schema.StructuredOutputError) as exc:
        run(llm_schema.structured(client, Verdict, system="s", user="u"))
    assert "connection reset" in exc.value.last_error


# --------------------------------------------------------------------------- bounded retry
def test_the_model_gets_one_corrective_attempt_with_the_actual_error():
    """A generic 'try again' teaches the model nothing; the specific failure does."""
    client = _FakeLLM({"exploitable": "maybe"},
                      {"exploitable": True, "confidence": 0.7, "reason": "fixed"})
    out = run(llm_schema.structured(client, Verdict, system="s", user="u"))
    assert out.reason == "fixed"
    assert len(client.prompts_seen) == 2
    assert "rejected" in client.prompts_seen[1]
    assert "exploitable" in client.prompts_seen[1]


def test_retries_are_bounded():
    client = _FakeLLM(*[{"bad": True}] * 10)
    with pytest.raises(llm_schema.StructuredOutputError) as exc:
        run(llm_schema.structured(client, Verdict, system="s", user="u", max_attempts=3))
    assert exc.value.attempts == 3
    assert len(client.prompts_seen) == 3


def test_the_raw_reply_is_truncated_on_the_error():
    """An error carrying a whole decompilation into a log is its own problem."""
    client = _FakeLLM({"junk": "x" * 50_000}, {"junk": "x" * 50_000})
    with pytest.raises(llm_schema.StructuredOutputError) as exc:
        run(llm_schema.structured(client, Verdict, system="s", user="u"))
    assert len(exc.value.raw) <= 2000


# --------------------------------------------------------------------------- cache keying
def test_the_cache_key_covers_everything_that_changes_the_answer(tmp_path):
    cache = llm_cache.LLMCache(tmp_path)
    base = dict(provider="local", model="m", prompt_version="v1", schema="S@1", payload="p")
    key = cache.key(**base)
    for field, other in [("provider", "anthropic"), ("model", "m2"),
                         ("prompt_version", "v2"), ("schema", "S@2"), ("payload", "q")]:
        assert cache.key(**{**base, field: other}) != key, f"{field} is not in the cache key"


def test_the_cache_key_cannot_be_confused_by_field_boundaries(tmp_path):
    """Without a separator, ('ab','c') and ('a','bc') hash identically."""
    cache = llm_cache.LLMCache(tmp_path)
    a = cache.key(provider="ab", model="c", prompt_version="v", schema="s", payload="p")
    b = cache.key(provider="a", model="bc", prompt_version="v", schema="s", payload="p")
    assert a != b


def test_a_cached_answer_is_reused_and_the_model_is_not_called_again(tmp_path):
    cache = llm_cache.LLMCache(tmp_path)
    client = _FakeLLM({"exploitable": True, "confidence": 0.8})
    kwargs = dict(system="s", user="u", cache=cache, provider="local",
                  model_name="m", prompt_version="v1")
    first = run(llm_schema.structured(client, Verdict, **kwargs))
    second = run(llm_schema.structured(client, Verdict, **kwargs))
    assert first.confidence == second.confidence == 0.8
    assert len(client.prompts_seen) == 1, "the second call should have been a cache hit"


def test_editing_the_prompt_invalidates_the_cache(tmp_path):
    """An upgraded prompt must not keep serving answers produced by the old one."""
    cache = llm_cache.LLMCache(tmp_path)
    client = _FakeLLM({"exploitable": True, "confidence": 0.8},
                      {"exploitable": False, "confidence": 0.2})
    run(llm_schema.structured(client, Verdict, system="s", user="u", cache=cache,
                              provider="local", model_name="m", prompt_version="v1"))
    out = run(llm_schema.structured(client, Verdict, system="s", user="u", cache=cache,
                                    provider="local", model_name="m", prompt_version="v2"))
    assert out.exploitable is False
    assert len(client.prompts_seen) == 2


def test_the_cache_can_be_disabled(tmp_path):
    cache = llm_cache.LLMCache(tmp_path, enabled=False)
    cache.put(cache.key(provider="a", model="b", prompt_version="c", schema="d", payload="e"), 1)
    assert cache.get(cache.key(provider="a", model="b", prompt_version="c",
                               schema="d", payload="e")) is None


def test_the_cache_evicts_oldest_entries(tmp_path):
    cache = llm_cache.LLMCache(tmp_path, max_entries=5)
    for i in range(12):
        cache.put(cache.key(provider="p", model="m", prompt_version="v",
                            schema="s", payload=str(i)), {"i": i})
    assert cache.stats()["entries"] <= 5


# --------------------------------------------------------------------------- prompt versioning
def test_every_shipped_prompt_has_a_version():
    versions = prompts.versions()
    assert versions, "no prompts were found"
    assert all(len(v) == 12 for v in versions.values())


def test_the_version_is_the_content_so_it_cannot_drift():
    a = prompts.inline("p", "hello")
    b = prompts.inline("p", "hello")
    c = prompts.inline("p", "hello!")
    assert a.version == b.version and a.version != c.version


def test_a_prompt_stringifies_to_its_text():
    assert str(prompts.inline("p", "the text")) == "the text"


def test_an_unknown_prompt_is_an_error_not_an_empty_string():
    with pytest.raises(FileNotFoundError):
        prompts.get("definitely-not-a-prompt")


# --------------------------------------------------------------------------- salvage restriction
def test_a_salvaged_call_may_not_create_a_finding():
    """ADR 0002: best-effort parsing may never produce a finding."""
    text = ('I should record this: {"name":"add_finding","arguments":'
            '{"title":"Buffer overflow","severity":"CRITICAL"}}')
    assert llm.salvage_tool_calls(text, {"add_finding"}) == []


def test_a_salvaged_call_may_not_change_state():
    text = '{"name":"x64dbg__MemoryWrite","arguments":{"addr":"0x1000","data":"90"}}'
    assert llm.salvage_tool_calls(text, {"x64dbg__MemoryWrite"}) == []


def test_a_salvaged_read_only_call_still_works():
    """The fallback exists because small models describe calls instead of emitting them."""
    text = '{"name":"ghidra__decompile_function","arguments":{"name":"main"}}'
    got = llm.salvage_tool_calls(text, {"ghidra__decompile_function"})
    assert [c["name"] for c in got] == ["ghidra__decompile_function"]


def test_salvage_keeps_the_reads_and_drops_the_rest_from_one_reply():
    text = ('{"name":"add_finding","arguments":{"title":"x"}} '
            '{"name":"ghidra__list_imports","arguments":{}} '
            '{"name":"x64dbg__DebugRun","arguments":{}}')
    valid = {"add_finding", "ghidra__list_imports", "x64dbg__DebugRun"}
    assert [c["name"] for c in llm.salvage_tool_calls(text, valid)] == ["ghidra__list_imports"]


@pytest.mark.parametrize("tool", ["add_finding", "approve", "deny", "parse_artifact",
                                  "x64dbg__MemoryWrite", "x64dbg__ExecCommand",
                                  "ghidra__patch_bytes"])
def test_state_changing_tools_are_not_salvageable(tool):
    assert llm.salvageable(tool) is False


@pytest.mark.parametrize("tool", ["ghidra__decompile_function", "ghidra__list_imports",
                                  "ghidra__get_xrefs", "workflow_status"])
def test_read_only_tools_are_salvageable(tool):
    assert llm.salvageable(tool) is True
