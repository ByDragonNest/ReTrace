#!/usr/bin/env python3
"""Build an installation bundle for a machine with no network (slice P2-S7).

    python scripts/build_offline_bundle.py --out offline-bundle [--extras cloud,local]
    python scripts/build_offline_bundle.py --verify offline-bundle

An air-gapped install was documented as "build the bundle on a connected machine with
`pip download`" — an instruction, not a deliverable, and one whose failure mode is discovered on
the far side of the air gap where nothing can be fixed. This produces the bundle and, more
importantly, **verifies it installs with the index switched off**, which is the only way to know
it is complete before carrying it across.

The check that matters is `--no-index`: pip is forbidden to reach PyPI, so a dependency missing
from the bundle fails here rather than on the isolated machine.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parent.parent


def _run(cmd: List[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, text=True, **kw)


def build(out: Path, extras: str) -> dict:
    out.mkdir(parents=True, exist_ok=True)
    wheels = out / "wheels"
    if wheels.exists():
        shutil.rmtree(wheels)
    wheels.mkdir()

    spec = f".[{extras}]" if extras else "."
    print(f"building the project wheel from {spec} …")
    _run([sys.executable, "-m", "build", "--wheel", "--outdir", str(wheels)], cwd=str(ROOT))

    print(f"downloading the dependency closure for {spec} …")
    _run([sys.executable, "-m", "pip", "download", spec, "--dest", str(wheels)], cwd=str(ROOT))

    (out / "install.sh").write_text(_install_sh(), encoding="utf-8")
    (out / "install.ps1").write_text(_install_ps1(), encoding="utf-8")
    (out / "install.sh").chmod(0o755)

    manifest = {
        "built_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "built_on": {"python": platform.python_version(), "platform": platform.platform(),
                     "machine": platform.machine()},
        "extras": extras,
        "wheels": sorted(p.name for p in wheels.iterdir()),
        "sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in sorted(wheels.iterdir())},
    }
    (out / "MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (out / "README.txt").write_text(_readme(manifest), encoding="utf-8")
    return manifest


def verify(bundle: Path) -> bool:
    """Install the bundle into a throwaway environment **with the index switched off**.

    This is the whole point. A bundle that has not been installed with `--no-index` is a bundle
    whose completeness is a guess, and the place that guess gets tested is the far side of the
    air gap.
    """
    import tempfile
    import venv

    wheels = bundle / "wheels"
    if not wheels.is_dir() or not any(wheels.iterdir()):
        print(f"no wheels in {wheels}", file=sys.stderr)
        return False

    manifest = json.loads((bundle / "MANIFEST.json").read_text(encoding="utf-8"))
    print("checking the recorded checksums …")
    for name, digest in manifest["sha256"].items():
        actual = hashlib.sha256((wheels / name).read_bytes()).hexdigest()
        if actual != digest:
            print(f"  {name}: checksum mismatch", file=sys.stderr)
            return False
    print(f"  {len(manifest['sha256'])} file(s) match")

    with tempfile.TemporaryDirectory(prefix="retrace-offline-") as tmp:
        env = Path(tmp) / "venv"
        venv.create(env, with_pip=True)
        python = env / ("Scripts" if sys.platform == "win32" else "bin") / "python"
        project = next((w for w in wheels.iterdir() if w.name.startswith("retrace-")), None)
        if project is None:
            print("the bundle has no retrace wheel", file=sys.stderr)
            return False

        print("installing with the index DISABLED …")
        result = subprocess.run(
            [str(python), "-m", "pip", "install", "--no-index",
             "--find-links", str(wheels), str(project)],
            capture_output=True, text=True)
        if result.returncode != 0:
            print("the bundle is INCOMPLETE - this would have failed on the isolated machine:",
                  file=sys.stderr)
            print(result.stderr[-1500:], file=sys.stderr)
            return False

        print("checking it runs with no network …")
        check = subprocess.run(
            [str(python), "-c",
             "import reforge.server as s; print('routes', len(s.app.routes))"],
            capture_output=True, text=True, cwd=tmp,
            env={"PATH": "/usr/bin:/bin", "REFORGE_STATE_DIR": str(Path(tmp) / "state"),
                 "HOME": tmp})
        if check.returncode != 0:
            print("the installed package does not import:", file=sys.stderr)
            print(check.stderr[-1500:], file=sys.stderr)
            return False
        print(f"  {check.stdout.strip()}")
    return True


def _install_sh() -> str:
    return """#!/bin/sh
# ReTrace offline install. No network is used or required.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
TARGET=${1:-$HOME/retrace}
echo "Installing ReTrace into $TARGET"
python3 -m venv "$TARGET"
# --no-index: pip must not reach for an index. If something is missing from the bundle, this
# fails here rather than appearing to work and failing later.
"$TARGET/bin/pip" install --no-index --find-links "$HERE/wheels" \\
    "$(ls "$HERE"/wheels/retrace-*.whl | head -1)"
echo
echo "Done. Start it with:"
echo "  REFORGE_STATE_DIR=\\$HOME/.local/share/retrace $TARGET/bin/retrace"
"""


def _install_ps1() -> str:
    return """# ReTrace offline install. No network is used or required.
$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Target = if ($args[0]) { $args[0] } else { "$env:LOCALAPPDATA\\ReTrace" }
Write-Host "Installing ReTrace into $Target"
python -m venv $Target
$wheel = Get-ChildItem "$Here\\wheels\\retrace-*.whl" | Select-Object -First 1
& "$Target\\Scripts\\pip.exe" install --no-index --find-links "$Here\\wheels" $wheel.FullName
Write-Host ""
Write-Host "Done. Start it with:"
Write-Host "  `$env:REFORGE_STATE_DIR='$env:LOCALAPPDATA\\ReTrace\\state'; $Target\\Scripts\\retrace.exe"
"""


def _readme(manifest: dict) -> str:
    return f"""ReTrace offline installation bundle
===================================

Built {manifest['built_at']} on {manifest['built_on']['platform']},
Python {manifest['built_on']['python']} ({manifest['built_on']['machine']}).
Extras included: {manifest['extras'] or '(core only)'}

Contents: {len(manifest['wheels'])} wheels, an install script for POSIX and Windows, and
MANIFEST.json with a SHA-256 for every file.

INSTALL (no network is used):
    ./install.sh [target-directory]            # POSIX
    .\\install.ps1 [target-directory]           # Windows

Both pass --no-index to pip, so nothing is fetched. If a dependency were missing from this
bundle the install would fail here rather than appearing to work.

VERIFY BEFORE CARRYING IT ACROSS (on the machine that built it):
    python scripts/build_offline_bundle.py --verify <this directory>

IMPORTANT - a bundle is built for one platform and one Python minor version. Wheels for
Linux/x86_64 and CPython 3.12 will not install on Windows or on 3.10. Build the bundle on a
machine matching the target, or build one per target.

This bundle contains no customer data, no samples and no credentials.
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=ROOT / "offline-bundle")
    ap.add_argument("--extras", default="", help="comma-separated extras, e.g. cloud,local")
    ap.add_argument("--verify", type=Path, help="verify an existing bundle instead of building")
    args = ap.parse_args()

    if args.verify:
        ok = verify(args.verify)
        print("\nBUNDLE OK - it installs with no network." if ok
              else "\nBUNDLE INCOMPLETE.", file=sys.stderr if not ok else sys.stdout)
        return 0 if ok else 1

    manifest = build(args.out, args.extras)
    print(f"\n{len(manifest['wheels'])} wheels in {args.out}")
    print(f"Now verify it:  python {Path(__file__).name} --verify {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
