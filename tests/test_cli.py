"""The `retrace` command line (prompt §13: a CLI for automation).

`retrace config set` is the documented way to switch a shared install to the `team` profile. It
goes through the same `Settings` model as the file and the environment, so what it refuses and
what it hardens is exactly what the server would refuse and harden.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from reforge import __main__ as cli  # noqa: E402
from reforge import config  # noqa: E402


def test_no_subcommand_means_serve(monkeypatch):
    called = {}
    monkeypatch.setattr(cli, "cmd_serve", lambda args: called.setdefault("serve", True) and 0)
    assert cli.main([]) == 0 and called["serve"]


def test_config_show_masks_secrets(capsys, monkeypatch):
    monkeypatch.setattr(config, "SETTINGS", config.SETTINGS.model_copy(update={"local_api_key": "sk-very-secret"}))
    assert cli.main(["config", "show"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["local_api_key"] == "***"
    assert "sk-very-secret" not in json.dumps(out)
    assert out["deployment_profile"] in ("workstation", "team")


def test_config_set_persists_a_validated_value(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(config, "STATE_ROOT", tmp_path)
    assert cli.main(["config", "set", "max_agent_steps", "12"]) == 0
    saved = json.loads((tmp_path / "settings.json").read_text())
    assert saved["max_agent_steps"] == 12
    assert "max_agent_steps = 12" in capsys.readouterr().out


def test_config_set_refuses_an_invalid_value(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(config, "STATE_ROOT", tmp_path)
    assert cli.main(["config", "set", "safety_mode", "yolo"]) == 2
    assert not (tmp_path / "settings.json").exists()
    assert "rejected" in capsys.readouterr().err


def test_config_set_refuses_an_unknown_key(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(config, "STATE_ROOT", tmp_path)
    assert cli.main(["config", "set", "no_such_setting", "1"]) == 2
    assert "unknown setting" in capsys.readouterr().err


def test_config_set_never_stores_a_secret(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(config, "STATE_ROOT", tmp_path)
    assert cli.main(["config", "set", "anthropic_api_key", "sk-x"]) == 2
    assert not (tmp_path / "settings.json").exists()
    assert "secrets store" in capsys.readouterr().err


def test_switching_to_team_hardens_and_says_so(tmp_path, capsys, monkeypatch):
    """The documented command for a shared install. The hardening is the model's, not the CLI's:
    the file it writes already carries the forced values, so a start-up that reads it cannot
    come up relaxed."""
    monkeypatch.setattr(config, "STATE_ROOT", tmp_path)
    assert cli.main(["config", "set", "deployment_profile", "team"]) == 0
    saved = json.loads((tmp_path / "settings.json").read_text())
    assert saved["deployment_profile"] == "team"
    assert saved["auth_trust_localhost"] is False
    assert saved["allow_unisolated_execution"] is False
    assert saved["operating_profile"] == "hybrid"


def test_a_value_the_profile_forces_back_is_reported(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(config, "STATE_ROOT", tmp_path)
    monkeypatch.setattr(config, "SETTINGS", config.SETTINGS.model_copy(update={"deployment_profile": "team"}))
    assert cli.main(["config", "set", "auth_trust_localhost", "true"]) == 0
    out = capsys.readouterr().out
    assert "auth_trust_localhost = False" in out and "forced" in out


def test_check_reports_profile_and_state_dir(capsys):
    assert cli.main(["check"]) == 0
    out = capsys.readouterr().out
    assert "profile:" in out and "state dir:" in out and "routes:" in out
