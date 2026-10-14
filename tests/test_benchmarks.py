"""The benchmark harness itself must be trustworthy (slice P0-S6).

A benchmark nobody can trust is worse than no benchmark: it launders unverified claims. These
tests check the harness, not the product - that the corpus is well-formed, that scoring punishes
noise as well as misses, that results are reproducible, and that the committed baseline is not
silently stale.

The product numbers live in `benchmarks/baseline.json` and are produced by
`python -m benchmarks.run`.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks import corpus, metrics, synth

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / "benchmarks" / "baseline.json"


# --------------------------------------------------------------------------- corpus integrity
def test_every_fixture_builds_deterministically(tmp_path):
    """Byte-identical across runs, or cross-release comparison means nothing."""
    for fixture in corpus.fixtures():
        first, second = fixture.build(), fixture.build()
        assert first == second, f"{fixture.name} is not reproducible"


def test_fixture_names_are_unique():
    names = [f.name for f in corpus.fixtures()]
    assert len(names) == len(set(names))


def test_every_fixture_states_why_its_ground_truth_is_what_it_is():
    """Ground truth without a rationale is a snapshot, and a snapshot measures nothing."""
    for fixture in corpus.fixtures():
        assert len(fixture.rationale) > 40, f"{fixture.name} has no usable rationale"


def test_the_corpus_covers_positives_negatives_and_malformed_input():
    tags = {tag for f in corpus.fixtures() for tag in f.tags}
    for required in ("negative", "malformed", "anti-fp", "mitigations", "crypto", "packing", "elf"):
        assert required in tags, f"the corpus has no {required} fixture"


def test_negative_and_malformed_fixtures_expect_no_invented_findings():
    for fixture in corpus.fixtures():
        if "malformed" in fixture.tags or "robustness" in fixture.tags:
            if "mitigations" not in fixture.tags:
                assert not fixture.expected, \
                    f"{fixture.name} is malformed input; nothing should be derived from it"


def test_the_synthetic_pe_is_actually_parseable():
    """If pefile cannot read the fixtures, the corpus is measuring the wrong thing."""
    pefile = pytest.importorskip("pefile")
    data = synth.build_pe(synth.PESpec(
        dll_characteristics=synth.FULLY_HARDENED,
        imports={"kernel32.dll": ["CreateFileW"], "msvcrt.dll": ["strcpy"]},
        sections=[synth.Section(".text", b"\x90" * 600, 0x60000020)]))
    pe = pefile.PE(data=data)
    pe.parse_data_directories()
    names = {i.name.decode() for e in pe.DIRECTORY_ENTRY_IMPORT for i in e.imports if i.name}
    assert names == {"CreateFileW", "strcpy"}
    assert pe.OPTIONAL_HEADER.DllCharacteristics == synth.FULLY_HARDENED


def test_mitigation_flags_actually_change_what_the_analyzer_sees(tmp_path):
    """The fixtures must discriminate; otherwise precision and recall are measuring nothing."""
    from reforge import hardening
    common = dict(imports={"kernel32.dll": ["CreateFileW"]},
                  sections=[synth.Section(".text", b"\x90" * 600, 0x60000020)])
    hardened = tmp_path / "h.exe"
    hardened.write_bytes(synth.build_pe(synth.PESpec(
        dll_characteristics=synth.FULLY_HARDENED, **common)))
    weak = tmp_path / "w.exe"
    weak.write_bytes(synth.build_pe(synth.PESpec(
        dll_characteristics=synth.UNHARDENED, **common)))

    keys = lambda p: {metrics.finding_key(f) for f in hardening.audit(str(p)).get("findings", [])}
    assert "hardening/dep-nx" not in keys(hardened)
    assert "hardening/dep-nx" in keys(weak)
    assert keys(hardened) < keys(weak), "the hardened fixture must be a strict subset"


# --------------------------------------------------------------------------- scoring
def test_scoring_counts_unexpected_findings_against_precision():
    """Noise is the cost of this product category; a harness that ignores it is useless."""
    sc = metrics.score({"a/x"}, {"a/x", "a/noise"})
    assert sc.precision == 0.5 and sc.recall == 1.0
    assert sc.false_positives == {"a/noise"}


def test_scoring_counts_misses_against_recall():
    sc = metrics.score({"a/x", "a/y"}, {"a/x"})
    assert sc.recall == 0.5 and sc.precision == 1.0


def test_a_perfect_silence_on_a_negative_fixture_scores_perfectly():
    sc = metrics.score(set(), set())
    assert sc.precision == 1.0 and sc.recall == 1.0 and sc.f1 == 0.0 or sc.f1 == 1.0


def test_finding_key_is_stable_against_prefix_rewording():
    a = metrics.finding_key({"vuln_type": "hardening", "title": "Missing mitigation: DEP / NX"})
    b = metrics.finding_key({"vuln_type": "hardening", "title": "Mitigation absent: DEP / NX"})
    assert a == b == "hardening/dep-nx"


def test_finding_key_distinguishes_different_mitigations_sharing_one_cwe():
    """Six missing mitigations all map to CWE-693; scoring on CWE alone would hide five of them."""
    keys = {metrics.finding_key({"vuln_type": "hardening", "title": f"Missing mitigation: {m}"})
            for m in ("DEP / NX", "ASLR (DYNAMICBASE)", "Control Flow Guard", "Stack canary (/GS)")}
    assert len(keys) == 4


def test_percentiles_are_computed_the_same_way_every_time():
    values = [float(v) for v in range(1, 101)]
    assert metrics.percentile(values, 50) == 50.0
    assert metrics.percentile(values, 95) == 95.0
    assert metrics.percentile(values, 99) == 99.0


# --------------------------------------------------------------------------- the baseline
def test_a_baseline_is_committed():
    assert BASELINE.is_file(), "no baseline: release-over-release comparison is impossible"


def test_the_committed_baseline_is_complete():
    data = json.loads(BASELINE.read_text(encoding="utf-8"))
    summary = data["summary"]
    for field in ("precision", "recall", "f1", "false_positives", "false_negatives", "crashes",
                  "false_positives_per_artifact", "evidence_completeness", "latency_ms", "llm"):
        assert field in summary, f"the baseline does not record {field}"
    for pct in ("p50", "p95", "p99"):
        assert pct in summary["latency_ms"]
    assert data["stability"]["deterministic"] is True


def test_the_baseline_covers_the_current_corpus():
    """A fixture added without re-recording the baseline would silently go unmeasured."""
    data = json.loads(BASELINE.read_text(encoding="utf-8"))
    recorded = {row["fixture"] for row in data["fixtures"]}
    current = {f.name for f in corpus.fixtures()}
    assert recorded == current, (
        "baseline and corpus disagree; re-run `python -m benchmarks.run --write-baseline`. "
        f"only in baseline: {sorted(recorded - current)}; only in corpus: {sorted(current - recorded)}"
    )


def test_the_product_has_not_regressed_against_the_committed_baseline():
    """The gate. Runs the real corpus through the real analyzers."""
    import tempfile

    from benchmarks import run as runner

    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        result = {
            "summary": runner.aggregate(runner.run_once(directory)),
            "stability": runner.stability(directory, repeats=2),
        }
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    problems = runner.compare(result, baseline)
    assert not problems, "regression against benchmarks/baseline.json: " + "; ".join(problems)


def test_results_are_reproducible_across_identical_runs():
    """Acceptance criterion 9: same artifact, same tools, same configuration, same result."""
    import tempfile

    from benchmarks import run as runner

    with tempfile.TemporaryDirectory() as tmp:
        assert runner.stability(Path(tmp), repeats=3)["deterministic"] is True


# --------------------------------------------------------------------------- source→sink (P1-S5/S6)
# The engine used to emit the full cartesian product of sources x sinks. On an ordinary Windows
# program - 4 sources, 8 sinks - that was 32 "chains" at confidence 0.40-0.55, including
# `recv -> LoadLibraryW`, with no call site and no dataflow behind any of them.
def test_an_ordinary_program_yields_capability_rows_not_leads():
    from reforge import sinks, source_to_sink as s2s

    imports = ["CreateFileW", "ReadFile", "WriteFile", "CloseHandle", "GetCommandLineW",
               "getenv", "recv", "memcpy", "strncpy", "sprintf", "CreateProcessW",
               "LoadLibraryW", "malloc", "fopen"]
    inventory = sinks.inventory(imports)
    sink_names = [a for apis in inventory["sinks"].values() for a in apis]
    source_names = list(inventory["sources"].keys())
    emitted = s2s.build_candidate_chains(source_names, sink_names, all_symbols=imports)
    rows = [c for c in emitted if not c.get("_meta")]
    meta = next(c for c in emitted if c.get("_meta"))

    assert meta["pairings_considered"] == len(source_names) * len(sink_names)
    assert len(rows) < meta["pairings_considered"], "aggregation did nothing"
    assert all(r["tier"] == s2s.TIER_CAPABILITY for r in rows)
    assert all(r["confidence"] <= 0.20 for r in rows), \
        "a chain with no call site must not reach the confidence band that reads as a lead"


def test_no_symbol_is_lost_by_the_aggregation():
    """Grouping must reduce rows, not information."""
    from reforge import sinks, source_to_sink as s2s

    imports = ["GetCommandLineW", "getenv", "recv", "memcpy", "sprintf", "CreateProcessW"]
    inventory = sinks.inventory(imports)
    sink_names = [a for apis in inventory["sinks"].values() for a in apis]
    source_names = list(inventory["sources"].keys())
    rows = [c for c in s2s.build_candidate_chains(source_names, sink_names, all_symbols=imports)
            if not c.get("_meta")]
    named_sinks = {s.strip() for r in rows for s in r["sink"].split(",")}
    named_sources = {s.strip() for r in rows for s in r["source"].split(",")}
    assert set(sink_names) <= named_sinks
    assert set(source_names) <= named_sources


def test_a_call_site_promotes_a_chain_out_of_capability_tier():
    """The cap must not become a ceiling on real evidence."""
    from reforge import source_to_sink as s2s

    rows = [c for c in s2s.build_candidate_chains(["GetCommandLineW"], ["CreateProcessW"])
            if not c.get("_meta")]
    assert rows[0]["tier"] == s2s.TIER_CAPABILITY

    refined = s2s.refine_chain(rows[0], function="FUN_401200", callsite="0x4012af",
                               argument="lpCommandLine", validation_seen=False)
    assert refined["tier"] == s2s.TIER_PATH
    assert refined["confidence"] > rows[0]["confidence"]

    traced = s2s.refine_chain(refined, dataflow_traced=True)
    assert traced["tier"] == s2s.TIER_DATAFLOW
    confirmed = s2s.confirm_chain(traced, "E-0001")
    assert confirmed["tier"] == s2s.TIER_CONFIRMED
    assert confirmed["confidence"] > traced["confidence"]


def test_absence_of_validation_only_counts_once_someone_has_looked():
    """`validation_seen=False` meant "nobody looked", and it was being scored as evidence."""
    from reforge import source_to_sink as s2s

    no_callsite = s2s.Chain(source="getenv", sink="system", validation_seen=False)
    with_callsite = s2s.Chain(source="getenv", sink="system", validation_seen=False,
                              callsite="0x401000")
    assert s2s.compute_confidence(no_callsite) <= 0.20
    assert s2s.compute_confidence(with_callsite) > s2s.compute_confidence(no_callsite)


def test_a_bounded_counterpart_is_recorded_and_lowers_confidence():
    from reforge import source_to_sink as s2s

    plain = [c for c in s2s.build_candidate_chains(
        ["GetCommandLineW"], ["strcpy"], all_symbols=["GetCommandLineW", "strcpy"])
        if not c.get("_meta")][0]
    mitigated = [c for c in s2s.build_candidate_chains(
        ["GetCommandLineW"], ["strcpy"],
        all_symbols=["GetCommandLineW", "strcpy", "strcpy_s", "strncpy_s"])
        if not c.get("_meta")][0]

    assert mitigated["mitigating_symbols"] == ["strcpy_s", "strncpy_s"]
    assert not plain["mitigating_symbols"]
    assert mitigated["confidence"] <= plain["confidence"]
    assert "strcpy_s" in mitigated["notes"]


def test_a_pairing_needing_a_conversion_is_labelled_and_costs_confidence():
    """Network bytes really can become a DLL path - so it is labelled, not dropped."""
    from reforge import source_to_sink as s2s

    direct = [c for c in s2s.build_candidate_chains(["GetCommandLineW"], ["LoadLibraryW"])
              if not c.get("_meta")][0]
    converted = [c for c in s2s.build_candidate_chains(["recv"], ["LoadLibraryW"])
                 if not c.get("_meta")][0]
    assert direct["linkage"] == "direct"
    assert converted["linkage"] == "conversion"
    assert "parsed or reinterpreted" in converted["notes"]


def test_the_benchmark_detects_a_source_to_sink_regression():
    """The guard must actually fail when the engine gets noisier again."""
    from benchmarks import corpus
    from benchmarks import run as runner

    fixture = next(f for f in corpus.fixtures() if f.name == "pe_ordinary_program.exe")
    imports = ["GetCommandLineW", "getenv", "recv", "memcpy", "sprintf", "CreateProcessW",
               "LoadLibraryW", "fopen"]

    tight = runner._score_chains(fixture, {"imports": imports})
    assert tight["chain_violations"] == []

    fixture.chains = corpus.ChainExpectation(max_rows=1, max_confidence=0.20)
    try:
        loose = runner._score_chains(fixture, {"imports": imports})
        assert loose["chain_violations"], "an over-ceiling row count was not reported"
    finally:
        fixture.chains = corpus.ChainExpectation(max_rows=12, max_confidence=0.20)


def test_the_benchmark_detects_an_unjustified_confidence_claim():
    from benchmarks import corpus
    from benchmarks import run as runner

    fixture = next(f for f in corpus.fixtures() if f.name == "pe_ordinary_program.exe")
    fixture.chains = corpus.ChainExpectation(max_rows=99, max_confidence=0.01)
    try:
        report = runner._score_chains(fixture, {"imports": ["GetCommandLineW", "CreateProcessW"]})
        assert any("confidence" in v for v in report["chain_violations"])
    finally:
        fixture.chains = corpus.ChainExpectation(max_rows=12, max_confidence=0.20)
