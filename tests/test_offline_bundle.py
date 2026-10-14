"""The air-gapped installation bundle (slice P2-S7).

Air-gapped installation was documented as "build the bundle on a connected machine with
`pip download`" — an instruction, not a deliverable, and one whose failure mode is discovered on
the far side of the air gap, where nothing can be fixed.

The expensive part (building a bundle and installing it) is exercised by
`python scripts/build_offline_bundle.py --verify`, not by the unit suite: it downloads ~38 wheels
and creates a virtualenv, which is minutes, not milliseconds. What is asserted here is that the
script's contract holds — above all that verification really does forbid the index, because a
verifier that quietly allows a download proves nothing.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "build_offline_bundle.py"


@pytest.fixture(scope="module")
def bundler():
    spec = importlib.util.spec_from_file_location("build_offline_bundle", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SOURCE = SCRIPT.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- the no-index rule
def test_verification_forbids_the_package_index():
    """The whole point. A verifier that allows a download proves nothing about the bundle."""
    import inspect
    import importlib.util as _ilu

    spec = _ilu.spec_from_file_location("b", SCRIPT)
    module = _ilu.module_from_spec(spec)
    spec.loader.exec_module(module)
    verify_source = inspect.getsource(module.verify)
    assert '"--no-index"' in verify_source
    assert '"--find-links"' in verify_source


def test_both_install_scripts_forbid_the_index(bundler):
    """An install that silently reached PyPI would work on the connected machine and nowhere else."""
    assert "--no-index" in bundler._install_sh()
    assert "--no-index" in bundler._install_ps1()


def test_the_posix_installer_is_not_bash_specific(bundler):
    """An air-gapped appliance may not have bash."""
    assert bundler._install_sh().startswith("#!/bin/sh")


# --------------------------------------------------------------------------- the manifest
def test_the_readme_states_the_platform_constraint(bundler):
    """A bundle is per platform and per Python minor version, and finding that out after
    carrying it across is the expensive way."""
    readme = bundler._readme({"built_at": "x", "built_on": {"platform": "p", "python": "3.12",
                                                            "machine": "x86_64"},
                              "extras": "", "wheels": [], "sha256": {}})
    assert "one platform and one Python minor version" in readme
    assert "no customer data" in readme


def test_the_readme_tells_the_operator_to_verify_before_carrying_it(bundler):
    readme = bundler._readme({"built_at": "x", "built_on": {"platform": "p", "python": "3",
                                                            "machine": "m"},
                              "extras": "", "wheels": [], "sha256": {}})
    assert "--verify" in readme


def test_verification_checks_checksums_before_installing():
    assert "checksum mismatch" in SOURCE
    assert SOURCE.index("checking the recorded checksums") < SOURCE.index("index DISABLED")


# --------------------------------------------------------------------------- an existing bundle
def test_a_bundle_missing_its_wheels_is_reported_not_assumed_good(bundler, tmp_path):
    bundle = tmp_path / "bundle"
    (bundle / "wheels").mkdir(parents=True)
    (bundle / "MANIFEST.json").write_text(json.dumps({"sha256": {}}), encoding="utf-8")
    assert bundler.verify(bundle) is False


def test_a_tampered_wheel_fails_verification(bundler, tmp_path):
    """The checksums exist so a bundle that changed in transit is caught before it is installed."""
    bundle = tmp_path / "bundle"
    wheels = bundle / "wheels"
    wheels.mkdir(parents=True)
    (wheels / "retrace-0.0.0-py3-none-any.whl").write_bytes(b"original")
    (bundle / "MANIFEST.json").write_text(
        json.dumps({"sha256": {"retrace-0.0.0-py3-none-any.whl": "0" * 64}}), encoding="utf-8")
    assert bundler.verify(bundle) is False


# --------------------------------------------------------------------------- air-gapped claims
def test_the_documentation_does_not_overclaim():
    """Egress is prevented by configuration and recorded, not enforced at the network level.
    Saying more than that would be the kind of unverified claim this work has avoided."""
    doc = (ROOT / "docs" / "installation.md").read_text(encoding="utf-8")
    section = doc[doc.index("## Air-gapped use"):]
    assert "not enforced at the process or network level" in section


def test_offline_operation_is_a_supported_profile():
    from reforge.settings import Settings

    assert Settings(operating_profile="offline_deterministic").operating_profile == \
        "offline_deterministic"
    assert Settings(operating_profile="local_only").operating_profile == "local_only"
