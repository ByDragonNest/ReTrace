"""Write-time finding admission (slices P1-S1, P1-S2, P1-S3).

The canonical model in `reforge/engine/` was only applied when a report was rendered, over data
that had been stored unvalidated. `engine/pipeline.py` - the documented A..H pipeline - had zero
callers, and `engine/llm_safety.sanitize_enrichment()`, the guard that stops a model raising a
severity, was never invoked anywhere in the product.

These tests pin the three properties that change makes true: nothing is stored without passing
the evidence gate, an LLM can only touch prose, and an invalid record is refused rather than
repaired.
"""
from __future__ import annotations

import pytest

from reforge.engine import intake, status as st
from reforge.session import Session


# --------------------------------------------------------------------------- validation
@pytest.mark.parametrize("candidate,field", [
    ({}, "title"),
    ({"title": "   "}, "title"),
    ({"title": "x" * 400}, "title"),
    ({"title": "x", "severity": "APOCALYPTIC"}, "severity"),
    ({"title": "x", "potential_severity": "NOPE"}, "potential_severity"),
    ({"title": "x", "confidence": 1.5}, "confidence"),
    ({"title": "x", "confidence": "high"}, "confidence"),
    ({"title": "x", "cwe": "120"}, "cwe"),
    ({"title": "x", "evidence_refs": "E-1"}, "evidence_refs"),
])
def test_structurally_invalid_candidates_are_rejected(candidate, field):
    with pytest.raises(intake.FindingRejected) as exc:
        intake.validate(candidate)
    assert exc.value.field == field


def test_a_non_object_is_rejected():
    for junk in ("a string", 42, None, ["list"]):
        with pytest.raises(intake.FindingRejected):
            intake.validate(junk)


def test_validation_does_not_repair():
    """Silently fixing a malformed finding is how an unsupported claim acquires a valid shape."""
    with pytest.raises(intake.FindingRejected):
        intake.admit({"title": "x", "severity": "critical!!"}, origin=intake.ORIGIN_HUMAN)


def test_an_unknown_origin_is_rejected():
    with pytest.raises(intake.FindingRejected):
        intake.admit({"title": "x"}, origin="somewhere")


# --------------------------------------------------------------------------- the evidence gate
def test_a_confirmation_backed_only_by_an_import_is_capped():
    admitted, _ = intake.admit(
        {"title": "Command injection", "status": "CONFIRMED_STATIC", "severity": "CRITICAL",
         "cwe": "CWE-78", "evidence": "present in the import table"},
        origin=intake.ORIGIN_STATIC)
    assert admitted["declared_status"] == st.CONFIRMED_STATIC
    assert not st.is_confirmed(admitted["status"])
    assert admitted["status_capped_note"]


def test_no_cvss_is_emitted_for_an_unconfirmed_finding():
    admitted, _ = intake.admit(
        {"title": "Buffer overflow", "status": "HYPOTHESIS", "severity": "HIGH",
         "cwe": "CWE-120", "evidence": "strcpy in the import table"},
        origin=intake.ORIGIN_STATIC)
    assert admitted["cvss_score"] is None
    assert admitted["confirmed_severity"] is None
    assert admitted["potential_severity"] == "HIGH", "worst-case is still recorded, separately"


def test_runtime_observation_is_allowed_to_confirm():
    """The gate must not be a blanket refusal: real evidence has to be able to promote a finding."""
    admitted, _ = intake.admit(
        {"title": "Command injection", "status": "CONFIRMED_DYNAMIC", "severity": "HIGH",
         "cwe": "CWE-78", "evidence_source": "x64dbg",
         "evidence": "observed at runtime; reproduced with a crafted argument"},
        origin=intake.ORIGIN_DYNAMIC)
    assert st.is_confirmed(admitted["status"])


def test_severity_is_split_into_potential_and_confirmed():
    admitted, _ = intake.admit(
        {"title": "Weak cipher", "status": "HYPOTHESIS", "severity": "HIGH", "cwe": "CWE-327"},
        origin=intake.ORIGIN_STATIC)
    assert admitted["potential_severity"] == "HIGH"
    assert admitted["confirmed_severity"] is None
    assert admitted["remediation_priority"].startswith("P")


# --------------------------------------------------------------------------- provenance
def test_every_admitted_finding_carries_its_provenance():
    admitted, _ = intake.admit({"title": "x", "status": "HYPOTHESIS"},
                               origin=intake.ORIGIN_STATIC,
                               tool="static_analysis", tool_version="9.9.9")
    assert admitted["schema_version"] == intake.SCHEMA_VERSION
    assert admitted["origin"] == intake.ORIGIN_STATIC
    assert admitted["produced_by_tool"] == "static_analysis"
    assert admitted["produced_by_tool_version"] == "9.9.9"
    assert admitted["admitted_at"] and admitted["updated_at"]


def test_admission_is_detectable_and_idempotent():
    admitted, _ = intake.admit({"title": "x"}, origin=intake.ORIGIN_HUMAN)
    assert intake.is_admitted(admitted)
    assert intake.admit_legacy(admitted) is admitted, "an admitted finding is not re-admitted"


# --------------------------------------------------------------------------- the LLM guard
def test_an_llm_may_change_prose():
    prior, _ = intake.admit({"title": "Weak hash", "status": "HYPOTHESIS", "severity": "LOW"},
                            origin=intake.ORIGIN_STATIC)
    merged, blocked = intake.admit(
        {"title": "Weak hash", "description": "MD5 is used for password storage.",
         "recommendation": "Move to Argon2id."},
        origin=intake.ORIGIN_LLM, prior=prior)
    assert merged["description"].startswith("MD5 is used")
    assert merged["recommendation"].startswith("Move to Argon2id")
    assert not blocked


@pytest.mark.parametrize("field,value", [
    ("status", "CONFIRMED_DYNAMIC"),
    ("severity", "CRITICAL"),
    ("cvss_score", 9.8),
    ("confidence", 0.99),
    ("cwe", "CWE-1337"),
])
def test_an_llm_may_not_change_a_deterministic_field(field, value):
    prior, _ = intake.admit(
        {"title": "Weak hash", "status": "HYPOTHESIS", "severity": "LOW", "cwe": "CWE-328"},
        origin=intake.ORIGIN_STATIC)
    before = prior.get(field)
    merged, blocked = intake.admit({"title": "Weak hash", field: value},
                                   origin=intake.ORIGIN_LLM, prior=prior)
    assert merged.get(field) == before, f"the model changed {field}"
    assert blocked, f"the blocked attempt on {field} was not recorded"
    assert merged["blocked_enrichment"]


def test_a_non_llm_origin_merges_normally():
    """Deterministic analyzers and humans are trusted to supply risk fields; the gate still applies."""
    prior, _ = intake.admit({"title": "Weak hash", "status": "HYPOTHESIS", "severity": "LOW"},
                            origin=intake.ORIGIN_STATIC)
    merged, blocked = intake.admit(
        {"title": "Weak hash", "status": "CONFIRMED_DYNAMIC", "severity": "HIGH",
         "evidence_source": "x64dbg", "evidence": "observed at runtime, reproduced"},
        origin=intake.ORIGIN_DYNAMIC, prior=prior)
    assert not blocked
    assert st.is_confirmed(merged["status"])


# --------------------------------------------------------------------------- legacy migration
def test_a_legacy_finding_is_upgraded_on_load():
    legacy = {"title": "Old finding", "status": "confirmed", "severity": "HIGH",
              "location": "0x401000", "evidence": "import table"}
    upgraded = intake.admit_legacy(legacy)
    assert upgraded["schema_version"] == intake.SCHEMA_VERSION
    assert upgraded["migrated_from_legacy"] is True
    assert not st.is_confirmed(upgraded["status"]), "the gate applies to migrated findings too"


def test_an_unupgradeable_legacy_finding_is_kept_and_flagged():
    """Refusing to open an old project would be worse than one visibly-marked finding."""
    broken = {"title": "", "severity": "WHATEVER"}
    out = intake.admit_legacy(broken)
    assert out["admission_error"]
    assert out["schema_version"] == 0


def test_loading_a_project_upgrades_its_findings(tmp_path, monkeypatch):
    from reforge import config
    monkeypatch.setattr(config, "PROJECTS_DIR", tmp_path)
    payload = {
        "id": "legacy1", "name": "legacy",
        "findings": [{"title": "Old", "status": "confirmed", "severity": "HIGH",
                      "location": "0x1", "evidence": "import table"}],
    }
    session = Session.from_dict(payload)
    stored = session.findings[0]
    assert stored["schema_version"] == intake.SCHEMA_VERSION
    assert stored["declared_status"] == st.CONFIRMED_STATIC
    assert not st.is_confirmed(stored["status"])


def test_a_non_dict_entry_in_a_stored_project_is_dropped_not_fatal():
    session = Session.from_dict({"id": "x", "name": "x",
                                 "findings": [{"title": "ok"}, "corrupt", None]})
    assert len(session.findings) == 1


# --------------------------------------------------------------------------- reproducibility (P1-S7)
# Acceptance criterion 9 - same artifact, tools, versions and configuration produce the same
# result - is only a checkable claim if the report records what those were.
def test_the_report_records_what_it_was_produced_from():
    from reforge import report_pt

    session = Session("r", "r")
    session.target_profile = {"sha256": "b" * 64, "size": 1024}
    session.add_finding({"title": "Weak crypto: RC4", "status": "HYPOTHESIS", "severity": "HIGH",
                         "cwe": "CWE-327", "evidence": "RC4_set_key symbol"},
                        origin=intake.ORIGIN_STATIC, tool="static_analysis", tool_version="0.1.0")
    data = report_pt.reproducibility(session)

    assert data["artifact_sha256"] == "b" * 64
    assert data["tools"]["static_analysis"] == "0.1.0"
    assert data["tools"]["finding_schema"] == str(intake.SCHEMA_VERSION)
    assert data["prompts"], "the prompt versions must be recorded"
    assert len(data["analysis_config"]["fingerprint"]) == 12


def test_the_config_fingerprint_moves_only_for_settings_that_change_a_result():
    from reforge import config, report_pt

    before = report_pt._analysis_config_fingerprint()["fingerprint"]

    original_port = config.PORT
    config.PORT = 9999                       # cosmetic: must not look like a different analysis
    try:
        assert report_pt._analysis_config_fingerprint()["fingerprint"] == before
    finally:
        config.PORT = original_port

    original_mode = config.SAFETY_MODE
    config.SAFETY_MODE = "autonomous"        # changes what the agent may do, so it counts
    try:
        assert report_pt._analysis_config_fingerprint()["fingerprint"] != before
    finally:
        config.SAFETY_MODE = original_mode


def test_the_reproducibility_section_carries_no_secret():
    from reforge import config, report_pt

    session = Session("r", "r")
    sentinel = "sk-ant-sentinel-value-not-real"
    original = config.ANTHROPIC_API_KEY
    config.ANTHROPIC_API_KEY = sentinel
    try:
        rendered = "\n".join(report_pt._reproducibility_section(session))
    finally:
        config.ANTHROPIC_API_KEY = original
    assert sentinel not in rendered
    assert "api_key" not in rendered.lower()


def test_the_section_appears_in_the_generated_report():
    from reforge import report_pt

    session = Session("r", "r")
    session.target_profile = {"sha256": "c" * 64}
    body = report_pt._deterministic(session)
    assert "## Reproducibility" in body
    assert "Prompt versions" in body
