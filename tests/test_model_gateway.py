"""Model egress: operating profiles, classification, redaction, ledger (slice P2-S4, T-10).

**The defect.** Whether a customer's decompiled code reached a cloud provider was decided by one
setting and nothing else. No classification of what was about to be sent, no redaction on the
outbound path, no egress allow-list, and no record of what had been sent, to whom, or why. An
operator could not answer "did any of this customer's binary reach Anthropic" - which, for a
product handling material under NDA, is the question.
"""
from __future__ import annotations

import pytest

from reforge import config, model_gateway as mg
from reforge.model_gateway import DataClass, EgressDenied, Profile


class _Cfg:
    def __init__(self, profile):
        self.OPERATING_PROFILE = profile


DECOMPILED = """
undefined4 FUN_00401250(char *param_1)
{
  char local_108 [256];
  strcpy(local_108, param_1);
  return 0;
}
"""
DISASM = "00401250:  55              push ebp\n00401251:  8b ec           mov ebp, esp\n"
HEXDUMP = " ".join(f"{b:02x}" for b in range(64))
FINDING = "Weak crypto: RC4 is used for the session key (CWE-327), seen at FUN_401000."
METADATA = "sha256=abc123, 14 imports, 3 findings"


# --------------------------------------------------------------------------- classification
@pytest.mark.parametrize("text,expected", [
    (DECOMPILED, DataClass.DERIVED_ANALYSIS),
    (DISASM, DataClass.DERIVED_ANALYSIS),
    (HEXDUMP, DataClass.ARTIFACT_BYTES),
    ("x" * (mg.BULK_EXTRACT_CHARS + 1), DataClass.ARTIFACT_BYTES),
    (METADATA, DataClass.FINDINGS),
    ("", DataClass.METADATA),
])
def test_payloads_are_classified_by_what_they_carry(text, expected):
    assert mg.classify(text) is expected


def test_a_caller_that_knows_may_declare_the_class():
    assert mg.classify(METADATA, declared=DataClass.ARTIFACT_BYTES) is DataClass.ARTIFACT_BYTES


def test_a_finding_citing_a_function_name_is_not_treated_as_code():
    """Otherwise `hybrid` refuses almost every finding, which is useless rather than strict."""
    assert mg.classify(FINDING) is DataClass.FINDINGS
    assert mg.classify("Buffer overflow in FUN_00401250, reached from argv[1].") is DataClass.FINDINGS


def test_a_decompiled_function_is_caught():
    """Two independent markers, or one plus C-like block structure."""
    assert mg.classify(DECOMPILED) is DataClass.DERIVED_ANALYSIS


# --------------------------------------------------------------------------- the profiles
def test_offline_deterministic_calls_no_model_at_all():
    with pytest.raises(EgressDenied):
        mg.guard(METADATA, provider="anthropic", model="m", purpose="t",
                 cfg=_Cfg("offline_deterministic"))


def test_local_only_lets_nothing_leave():
    for payload in (METADATA, FINDING, DECOMPILED, HEXDUMP):
        with pytest.raises(EgressDenied):
            mg.guard(payload, provider="anthropic", model="m", purpose="t",
                     cfg=_Cfg("local_only"))


def test_local_only_still_allows_a_local_model():
    sent, decision = mg.guard(DECOMPILED, provider="local", model="qwen", purpose="t",
                              cfg=_Cfg("local_only"))
    assert decision.allowed and sent == DECOMPILED
    assert "nothing leaves" in decision.reason


def test_hybrid_keeps_code_and_bytes_local_but_lets_context_through():
    """The line prompt §9.1 draws, and the default on a shared install."""
    cfg = _Cfg("hybrid")
    for allowed in (METADATA, FINDING):
        sent, decision = mg.guard(allowed, provider="anthropic", model="m", purpose="t", cfg=cfg)
        assert decision.allowed
    for refused in (DECOMPILED, DISASM, HEXDUMP):
        with pytest.raises(EgressDenied) as exc:
            mg.guard(refused, provider="anthropic", model="m", purpose="t", cfg=cfg)
        assert "may not leave the host" in str(exc.value)


def test_frontier_permits_everything_but_still_classifies_and_records():
    sent, decision = mg.guard(DECOMPILED, provider="anthropic", model="m", purpose="t",
                              cfg=_Cfg("frontier"))
    assert decision.allowed
    assert decision.data_class is DataClass.DERIVED_ANALYSIS, "permitted is not the same as unexamined"


def test_an_unknown_profile_falls_back_to_the_stricter_usable_one():
    assert mg.active_profile(_Cfg("whatever")) is Profile.HYBRID


def test_a_shared_install_forces_hybrid():
    """§9.1: a shared install must not let a client's decompiled code reach a provider."""
    from reforge.settings import Settings

    assert Settings(deployment_profile="workstation").operating_profile == "frontier"
    for shared in ("team",):
        assert Settings(deployment_profile=shared,
                        operating_profile="frontier").operating_profile == "hybrid"


# --------------------------------------------------------------------------- redaction
def test_secrets_are_redacted_on_the_way_out(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "STATE_ROOT", tmp_path)
    payload = "The config contains sk-ant-api03-REDACTME0123456789 and a token."
    sent, decision = mg.guard(payload, provider="anthropic", model="m", purpose="t",
                              cfg=_Cfg("frontier"))
    assert "REDACTME" not in sent
    assert decision.extra.get("redactions", 0) >= 1


def test_a_local_call_is_not_redacted():
    """Redaction is a cost paid for leaving the host; a local model gets the real text."""
    payload = "sk-ant-api03-REDACTME0123456789"
    sent, _ = mg.guard(payload, provider="local", model="m", purpose="t", cfg=_Cfg("frontier"))
    assert sent == payload


# --------------------------------------------------------------------------- the ledger
@pytest.fixture()
def ledger_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "STATE_ROOT", tmp_path)
    return tmp_path


def test_every_send_is_recorded(ledger_dir):
    mg.guard(FINDING, provider="anthropic", model="claude-x", purpose="enrichment",
             cfg=_Cfg("frontier"))
    entry = mg.ledger()[0]
    assert entry["action"] == "llm.egress"
    assert entry["detail"]["provider"] == "anthropic"
    assert entry["detail"]["model"] == "claude-x"
    assert entry["detail"]["purpose"] == "enrichment"
    assert entry["detail"]["data_class"] == "findings"


def test_every_refusal_is_recorded_too(ledger_dir):
    """A ledger of only successes cannot answer "did we ever try"."""
    with pytest.raises(EgressDenied):
        mg.guard(DECOMPILED, provider="anthropic", model="m", purpose="t", cfg=_Cfg("hybrid"))
    entry = mg.ledger()[0]
    assert entry["action"] == "llm.egress_denied"
    assert entry["detail"]["allowed"] is False


def test_the_ledger_records_the_shape_not_the_payload(ledger_dir):
    """A ledger you must redact before showing it is not evidence of anything."""
    secret_text = "FUN_00401250 proprietary customer routine"
    mg.guard(secret_text, provider="anthropic", model="m", purpose="t", cfg=_Cfg("frontier"))
    body = str(mg.ledger()[0])
    assert "proprietary customer routine" not in body
    assert "FUN_00401250" not in body
    assert mg.ledger()[0]["detail"]["payload_chars"] == len(secret_text)


def test_the_summary_answers_whether_anything_left_the_host(ledger_dir):
    assert mg.summary()["nothing_has_left_this_host"] is True
    mg.guard(FINDING, provider="anthropic", model="m", purpose="t", cfg=_Cfg("frontier"))
    summary = mg.summary()
    assert summary["nothing_has_left_this_host"] is False
    assert summary["requests_sent"] == 1
    assert summary["by_provider"]["anthropic"] == 1


def test_a_local_only_deployment_can_prove_nothing_left(ledger_dir):
    """The claim air-gapped operation rests on, made checkable."""
    for payload in (METADATA, FINDING, DECOMPILED):
        mg.guard(payload, provider="local", model="qwen", purpose="t", cfg=_Cfg("local_only"))
    assert mg.summary()["nothing_has_left_this_host"] is True


# --------------------------------------------------------------------------- enforcement point
def test_every_remote_provider_declares_itself():
    """The gate keys on `is_remote`; a provider that forgets it would bypass the gate entirely."""
    import inspect

    from reforge import llm

    for name, obj in vars(llm).items():
        if not (inspect.isclass(obj) and issubclass(obj, llm.BaseLLM) and obj is not llm.BaseLLM):
            continue
        assert isinstance(obj.is_remote, bool), name
        if obj.provider_name in ("anthropic", "openai"):
            assert obj.is_remote is True, f"{name} is a cloud provider but is_remote is False"
        else:
            assert obj.is_remote is False, f"{name} claims to be remote without naming a provider"


def test_the_remote_provider_guards_every_outbound_method():
    """A method that reaches the network without calling _guard would bypass the whole slice."""
    import inspect

    from reforge import llm

    source = inspect.getsource(llm.AnthropicLLM)
    for method in ("async def run", "async def complete"):
        start = source.index(method)
        body = source[start:start + 1200]
        assert "_guard(" in body, f"AnthropicLLM.{method} does not pass through the egress gate"


def test_the_whole_conversation_is_classified_together():
    """A request is only as safe as its most sensitive part."""
    from reforge.llm import _payload_text

    text = _payload_text("system prompt", [
        {"role": "user", "content": "a harmless question"},
        {"role": "assistant", "content": DECOMPILED},
    ])
    assert mg.classify(text) is DataClass.DERIVED_ANALYSIS


# --------------------------------------------------------------------------- §9.2 resilience
def test_provider_clients_carry_an_explicit_timeout_and_retry_budget():
    """A provider that stops answering must fail the turn, not hang it for the SDK's 10-minute
    default. Both clients are built with the configured ceiling."""
    import pytest as _pytest
    from reforge import config, llm
    from reforge.settings import Settings

    s = Settings()
    assert 5 <= s.llm_timeout_s <= 600 and s.llm_max_retries <= 10
    assert config.LLM_TIMEOUT_S == s.llm_timeout_s
    anthropic = _pytest.importorskip("anthropic")
    openai = _pytest.importorskip("openai")
    a = llm.AnthropicLLM() if hasattr(llm, "AnthropicLLM") else None
    local = llm.LocalLLM() if hasattr(llm, "LocalLLM") else None
    for client, ceiling in ((getattr(a, "_c", None), config.LLM_TIMEOUT_S),
                            (getattr(local, "_c", None), config.LOCAL_TIMEOUT_S)):
        if client is None:
            continue
        assert float(client.timeout) == float(ceiling)
        assert client.max_retries == config.LLM_MAX_RETRIES
    # a local model gets more rope than a cloud one, by design, never less
    assert config.LOCAL_TIMEOUT_S >= config.LLM_TIMEOUT_S
