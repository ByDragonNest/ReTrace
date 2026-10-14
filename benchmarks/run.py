#!/usr/bin/env python3
"""Run the ReTrace benchmark corpus and report precision, recall, cost and timing.

    python -m benchmarks.run                      # run and print
    python -m benchmarks.run --json out.json      # also write the machine-readable result
    python -m benchmarks.run --baseline benchmarks/baseline.json   # compare, non-zero on regression
    python -m benchmarks.run --write-baseline     # record a new baseline (deliberate act)

Scope, stated plainly so the numbers are not read as more than they are:

* This measures the **deterministic** analysis path - `static_analysis.analyze()` and everything
  under it. No LLM, no MCP server, no network. That path is the one that must be reproducible, and
  it is the one the product's precision claims rest on.
* The corpus is synthetic (`benchmarks/corpus.py`). It exercises header mitigations, component
  fingerprinting, crypto markers, packing heuristics and parser robustness. It does **not**
  exercise decompilation, call-graph reachability or source-to-sink, because those need a real
  compiled program and a live Ghidra. Those numbers do not exist yet and are not implied here.
* Token, latency and cost per model are not measured: nothing in this path calls a model.
  The columns exist in the schema so the LLM-orchestrated path can be added without changing the
  report format.
"""
from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List

if __package__:                                   # python -m benchmarks.run
    from . import corpus, metrics
else:                                             # python benchmarks/run.py
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from benchmarks import corpus, metrics

ROOT = Path(__file__).resolve().parent.parent
REPEATS_FOR_STABILITY = 3


def _peak_rss_mb() -> float:
    """Peak resident set size. 0.0 on Windows, where `resource` does not exist.

    Imported here rather than at module level: `tests/test_benchmarks.py` imports this module,
    and a top-level `import resource` failed every one of those tests on the Windows runner.
    """
    try:
        import resource
    except ImportError:
        return 0.0
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux reports kilobytes, macOS bytes.
    return usage / (1024 * 1024) if sys.platform == "darwin" else usage / 1024


def run_once(directory: Path) -> Dict[str, Any]:
    from reforge import static_analysis

    per_fixture: List[Dict[str, Any]] = []
    for fixture in corpus.fixtures():
        path = fixture.write(directory)
        started = time.perf_counter()
        try:
            result = static_analysis.analyze(str(path))
            crashed = False
            error = result.get("error") or ""
        except Exception as exc:               # a crash is a result, not an excuse to stop
            result, crashed, error = {"findings": []}, True, f"{type(exc).__name__}: {exc}"
        elapsed_ms = (time.perf_counter() - started) * 1000

        findings = result.get("findings") or []
        actual = {metrics.finding_key(f) for f in findings}
        sc = metrics.score(fixture.expected, actual)
        chain_report = _score_chains(fixture, result)
        per_fixture.append({
            "fixture": fixture.name,
            "tags": fixture.tags,
            "bytes": path.stat().st_size,
            "crashed": crashed,
            "error": error,
            "elapsed_ms": round(elapsed_ms, 3),
            "findings": len(findings),
            "evidence_completeness": round(metrics.evidence_completeness(findings), 4),
            **sc.as_dict(),
            **chain_report,
        })
    return {"fixtures": per_fixture}


def _score_chains(fixture, result: Dict[str, Any]) -> Dict[str, Any]:
    """Measure the source→sink output: how many rows, at what tier, at what confidence.

    Separate from finding precision on purpose. Candidate chains are not findings - they are where
    to look - so counting them as false positives would be wrong. But their volume *is* the cost
    the analyst pays, so it is measured in its own right instead of going unmeasured because it did
    not fit the existing metric.
    """
    from reforge import sinks as _sinks
    from reforge import source_to_sink as _s2s

    expectation = getattr(fixture, "chains", None)
    if expectation is None:
        return {}
    imports = result.get("imports") or []
    if not imports:
        return {"chain_rows": 0, "chain_violations": []}

    inventory = _sinks.inventory(imports)
    sink_names = [api for apis in (inventory.get("sinks") or {}).values() for api in apis]
    source_names = list((inventory.get("sources") or {}).keys())
    if not sink_names or not source_names:
        return {"chain_rows": 0, "chain_violations": []}

    emitted = _s2s.build_candidate_chains(source_names, sink_names, all_symbols=imports)
    rows = [c for c in emitted if not c.get("_meta")]
    meta = next((c for c in emitted if c.get("_meta")), {})

    violations = []
    if len(rows) > expectation.max_rows:
        violations.append(f"{len(rows)} rows exceeds the ceiling of {expectation.max_rows}")
    ceiling = _s2s.TIER_ORDER.index(expectation.max_tier)
    for row in rows:
        if _s2s.TIER_ORDER.index(row.get("tier", "capability")) > ceiling:
            violations.append(f"{row['sink_class']} claimed tier {row['tier']} with no call site")
            break
    worst = max((row.get("confidence", 0.0) for row in rows), default=0.0)
    if worst > expectation.max_confidence + 1e-9:
        violations.append(f"confidence {worst} exceeds the cap {expectation.max_confidence}")
    if expectation.expect_mitigations and not any(row.get("mitigating_symbols") for row in rows):
        violations.append("bounded counterparts are imported but were not recorded")

    return {
        "chain_rows": len(rows),
        "chain_pairings_considered": meta.get("pairings_considered", 0),
        "chain_max_confidence": round(worst, 3),
        "chain_violations": violations,
    }


def aggregate(run: Dict[str, Any]) -> Dict[str, Any]:
    rows = run["fixtures"]
    total = metrics.Score()
    for row in rows:
        total = total.merge(metrics.Score(
            true_positives={f"{row['fixture']}::{k}" for k in range(row["tp"])},
            false_positives={f"{row['fixture']}::{k}" for k in row["false_positives"]},
            false_negatives={f"{row['fixture']}::{k}" for k in row["false_negatives"]},
        ))
    timings = [row["elapsed_ms"] for row in rows]
    negatives = [row for row in rows if "negative" in row["tags"] or "malformed" in row["tags"]]
    fp_on_negatives = sum(len(row["false_positives"]) for row in negatives)
    return {
        "precision": round(total.precision, 4),
        "recall": round(total.recall, 4),
        "f1": round(total.f1, 4),
        "true_positives": len(total.true_positives),
        "false_positives": len(total.false_positives),
        "false_negatives": len(total.false_negatives),
        "false_positives_per_artifact": round(
            len(total.false_positives) / len(rows), 4) if rows else 0.0,
        "false_positives_on_negative_fixtures": fp_on_negatives,
        "crashes": sum(1 for row in rows if row["crashed"]),
        "chain_rows_total": sum(row.get("chain_rows", 0) for row in rows),
        "chain_pairings_considered": sum(row.get("chain_pairings_considered", 0) for row in rows),
        "chain_violations": [f"{row['fixture']}: {v}"
                             for row in rows for v in row.get("chain_violations", [])],
        "evidence_completeness": round(
            statistics.fmean([row["evidence_completeness"] for row in rows]), 4) if rows else 1.0,
        "latency_ms": {
            "total": round(sum(timings), 2),
            "mean": round(statistics.fmean(timings), 3) if timings else 0.0,
            "p50": round(metrics.percentile(timings, 50), 3),
            "p95": round(metrics.percentile(timings, 95), 3),
            "p99": round(metrics.percentile(timings, 99), 3),
            "max": round(max(timings), 3) if timings else 0.0,
        },
        # Deterministic path: no model is called, so these are structurally zero rather than
        # unmeasured. Stated explicitly so the absence is not mistaken for an omission.
        "llm": {"calls": 0, "input_tokens": 0, "output_tokens": 0, "estimated_cost_usd": 0.0},
    }


def stability(directory: Path, repeats: int = REPEATS_FOR_STABILITY) -> Dict[str, Any]:
    """Identical input, identical configuration, N runs. Any variation is a defect."""
    signatures = []
    for _ in range(repeats):
        run = run_once(directory)
        signatures.append(json.dumps(
            [[row["fixture"], sorted(row["false_positives"]), sorted(row["false_negatives"]),
              row["findings"]] for row in run["fixtures"]], sort_keys=True))
    return {"repeats": repeats, "deterministic": len(set(signatures)) == 1}


def compare(current: Dict[str, Any], baseline: Dict[str, Any]) -> List[str]:
    """Regressions only. An improvement is reported but never fails the build."""
    problems = []
    cur, base = current["summary"], baseline["summary"]
    for metric in ("precision", "recall", "f1"):
        if cur[metric] < base[metric] - 1e-9:
            problems.append(f"{metric} regressed: {base[metric]} -> {cur[metric]}")
    if cur["false_positives"] > base["false_positives"]:
        problems.append(f"false positives rose: {base['false_positives']} -> {cur['false_positives']}")
    if cur["crashes"] > base["crashes"]:
        problems.append(f"crashes rose: {base['crashes']} -> {cur['crashes']}")
    if cur.get("chain_violations"):
        problems.extend(f"source->sink: {v}" for v in cur["chain_violations"])
    if cur.get("chain_rows_total", 0) > base.get("chain_rows_total", 10 ** 9):
        problems.append(f"source->sink rows rose: {base['chain_rows_total']} -> "
                        f"{cur['chain_rows_total']}")
    if not current["stability"]["deterministic"]:
        problems.append("results are no longer reproducible across identical runs")
    # Latency is a property of the machine as much as of the code: the committed baseline was
    # recorded on a laptop, and a CI runner on the same commit measured 4x its p95 (35 -> 143 ms)
    # with nothing changed. A 3x threshold therefore failed the build on hardware, not on a
    # regression. Precision, recall, false positives, crashes and reproducibility are the gate;
    # latency fails only for a catastrophic move (an accidental quadratic path), and is otherwise
    # reported so a real drift is visible in the artifact.
    p95_base, p95_cur = base["latency_ms"]["p95"], cur["latency_ms"]["p95"]
    if p95_cur > max(p95_base * 20, 500):
        problems.append(f"p95 latency regressed catastrophically: {p95_base} -> {p95_cur} ms")
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", type=Path, help="write the full result here")
    ap.add_argument("--baseline", type=Path, help="compare against this baseline and fail on regression")
    ap.add_argument("--write-baseline", action="store_true",
                    help="record the current result as benchmarks/baseline.json")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    with tempfile.TemporaryDirectory(prefix="retrace-bench-") as tmp:
        directory = Path(tmp)
        run = run_once(directory)
        result = {
            "schema": 1,
            "summary": aggregate(run),
            "stability": stability(directory),
            "fixtures": run["fixtures"],
            "environment": {
                "python": platform.python_version(),
                "platform": platform.system(),
                "peak_rss_mb": round(_peak_rss_mb(), 1),
            },
        }

    if not args.quiet:
        _print(result)

    if args.json:
        args.json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.write_baseline:
        target = ROOT / "benchmarks" / "baseline.json"
        target.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"\nbaseline written: {target}")
    if args.baseline:
        base = json.loads(args.baseline.read_text(encoding="utf-8"))
        problems = compare(result, base)
        if problems:
            print("\nREGRESSION:", file=sys.stderr)
            for p in problems:
                print(f"  - {p}", file=sys.stderr)
            return 1
        print("\nno regression against the baseline")
    return 0


def _print(result: Dict[str, Any]) -> None:
    s = result["summary"]
    print(f"{'fixture':<34} {'find':>4} {'tp':>3} {'fp':>3} {'fn':>3} {'ms':>8}  notes")
    print("-" * 86)
    for row in result["fixtures"]:
        notes = []
        if row["crashed"]:
            notes.append("CRASH " + row["error"][:40])
        if row["false_positives"]:
            notes.append("FP: " + ", ".join(row["false_positives"])[:46])
        if row["false_negatives"]:
            notes.append("FN: " + ", ".join(row["false_negatives"])[:46])
        print(f"{row['fixture']:<34} {row['findings']:>4} {row['tp']:>3} {row['fp']:>3} "
              f"{row['fn']:>3} {row['elapsed_ms']:>8.2f}  {' | '.join(notes)}")
    print("-" * 86)
    print(f"precision {s['precision']:.3f}   recall {s['recall']:.3f}   F1 {s['f1']:.3f}   "
          f"FP/artifact {s['false_positives_per_artifact']:.3f}")
    print(f"crashes {s['crashes']}   FP on negative fixtures {s['false_positives_on_negative_fixtures']}"
          f"   evidence completeness {s['evidence_completeness']:.3f}")
    print(f"source->sink  {s.get('chain_rows_total', 0)} rows from "
          f"{s.get('chain_pairings_considered', 0)} pairings   "
          f"violations {len(s.get('chain_violations', []))}")
    lat = s["latency_ms"]
    print(f"latency  total {lat['total']:.1f} ms   p50 {lat['p50']:.2f}   p95 {lat['p95']:.2f}   "
          f"p99 {lat['p99']:.2f}   max {lat['max']:.2f}")
    print(f"peak RSS {result['environment']['peak_rss_mb']:.1f} MB   "
          f"reproducible across {result['stability']['repeats']} runs: "
          f"{result['stability']['deterministic']}")


if __name__ == "__main__":
    raise SystemExit(main())
