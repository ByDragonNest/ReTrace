#!/usr/bin/env python3
"""Build a release artifact and prove it carries nothing it should not (slice P0-S4).

    python scripts/build_release.py [--out dist] [--check-only]

The working tree of this product routinely contains a populated project database, uploaded
samples, a secrets store and per-analyst state. None of it may reach a customer. This script
builds the sdist and wheel and then *verifies* their contents against an allow-list, because a
.gitignore and good intentions are not an acceptance criterion - a file list that a machine checks
is. See docs/gap-analysis.md P0-6.

Exit codes: 0 clean · 1 contaminated or build failure.
"""
from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Iterable, List

ROOT = Path(__file__).resolve().parent.parent

# Anything matching these is a release-blocking defect, not a warning.
FORBIDDEN_NAMES = {
    ".reforge_secrets.json", ".env", ".env.local", "servers_state.json",
    "reforge.db", "reforge.db-wal", "reforge.db-shm", ".DS_Store", "Thumbs.db",
}
FORBIDDEN_SUFFIXES = (".pem", ".key", ".pyc", ".pyo", ".db", ".sqlite", ".sqlite3", ".wal")
FORBIDDEN_PARTS = (
    ".git", ".pytest_cache", ".ruff_cache", ".mypy_cache", "__pycache__",
    "projects", "sessions", "jobs", "workspace", "uploads", ".venv", "venv",
    "benchmarks", "mcp_servers",
)
# A wheel must be able to serve the UI on its own.
REQUIRED_IN_WHEEL = (
    "reforge/server.py", "reforge/settings.py", "reforge/web/index.html",
    "reforge/web/app.js", "reforge/web/styles.css", "reforge/prompts/reforge_system.md",
    "reforge/mcp.servers.default.json",
)


def _members(path: Path) -> List[str]:
    if path.suffixes[-2:] == [".tar", ".gz"] or path.suffix == ".gz":
        with tarfile.open(path) as tf:
            return tf.getnames()
    with zipfile.ZipFile(path) as zf:
        return zf.namelist()


def _strip_root(name: str) -> str:
    """sdist entries are prefixed with `<project>-<version>/`; compare on the inner path."""
    parts = name.split("/", 1)
    return parts[1] if len(parts) == 2 and parts[0].startswith("retrace-") else name


def inspect(path: Path) -> List[str]:
    problems: List[str] = []
    names = _members(path)
    for name in names:
        inner = _strip_root(name)
        leaf = inner.rsplit("/", 1)[-1]
        if leaf in FORBIDDEN_NAMES:
            problems.append(f"{path.name}: forbidden file {inner}")
        elif inner.endswith(FORBIDDEN_SUFFIXES):
            problems.append(f"{path.name}: forbidden suffix {inner}")
        else:
            for part in inner.split("/")[:-1]:
                if part in FORBIDDEN_PARTS:
                    problems.append(f"{path.name}: forbidden directory {inner}")
                    break
    if path.suffix == ".whl":
        present = {_strip_root(n) for n in names}
        for required in REQUIRED_IN_WHEEL:
            if required not in present:
                problems.append(f"{path.name}: MISSING {required} - the wheel cannot run alone")
    return problems


def build(out: Path) -> List[Path]:
    subprocess.run([sys.executable, "-m", "build", "--outdir", str(out)],
                   cwd=str(ROOT), check=True)
    return sorted(p for p in out.iterdir() if p.suffix in (".whl", ".gz"))


def checksums(paths: Iterable[Path], out: Path) -> Path:
    lines = []
    for p in sorted(paths):
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        lines.append(f"{digest}  {p.name}")
    target = out / "SHA256SUMS"
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return target


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="dist", help="output directory (default: dist)")
    ap.add_argument("--check-only", action="store_true",
                    help="verify artifacts already in --out instead of building")
    args = ap.parse_args()

    out = (ROOT / args.out).resolve()
    if args.check_only:
        artifacts = sorted(p for p in out.iterdir() if p.suffix in (".whl", ".gz"))
        if not artifacts:
            print(f"no artifacts in {out}", file=sys.stderr)
            return 1
    else:
        out.mkdir(parents=True, exist_ok=True)
        for stale in out.glob("retrace-*"):
            stale.unlink()
        artifacts = build(out)

    problems: List[str] = []
    for art in artifacts:
        found = inspect(art)
        status = "CONTAMINATED" if found else "clean"
        print(f"  {art.name:<44} {len(_members(art)):>4} entries  {status}")
        problems.extend(found)

    if problems:
        print("\nrelease blocked:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1

    sums = checksums(artifacts, out)
    print(f"\n{len(artifacts)} artifact(s) verified. Checksums: {sums}")
    print(sums.read_text(encoding="utf-8").rstrip())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
