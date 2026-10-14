"""Spawning a catalogue entry has to fail with a reason the operator can act on.

The catalogue ships `"command": "python"`. On a macOS or Linux box that usually means "not
found", and the resulting `FileNotFoundError: [Errno 2] No such file or directory` named neither
the command nor the fix - and took every bundled server down at once.
"""
from __future__ import annotations

import sys

import pytest

from reforge import mcp_host


def test_a_bare_python_that_is_not_on_the_path_resolves_to_this_interpreter(monkeypatch, tmp_path):
    script = tmp_path / "srv.py"; script.write_text("")
    monkeypatch.setattr(mcp_host.shutil, "which", lambda c: None)
    command, args = mcp_host.resolve_stdio_command({"command": "python", "args": [str(script)]})
    assert command == sys.executable and args == [str(script)]


def test_a_python_that_is_on_the_path_is_left_alone(monkeypatch, tmp_path):
    script = tmp_path / "srv.py"; script.write_text("")
    monkeypatch.setattr(mcp_host.shutil, "which", lambda c: "/usr/bin/python")
    command, _ = mcp_host.resolve_stdio_command({"command": "python", "args": [str(script)]})
    assert command == "python"


def test_an_absolute_interpreter_is_never_rewritten(tmp_path):
    script = tmp_path / "srv.py"; script.write_text("")
    command, _ = mcp_host.resolve_stdio_command({"command": sys.executable, "args": [str(script)]})
    assert command == sys.executable


def test_another_missing_command_is_refused_by_name(monkeypatch):
    monkeypatch.setattr(mcp_host.shutil, "which", lambda c: None)
    with pytest.raises(mcp_host.ServerSpecError, match="'node' is not on the PATH"):
        mcp_host.resolve_stdio_command({"command": "node", "args": ["x.js"]})


def test_the_placeholder_script_path_is_named_as_such():
    with pytest.raises(mcp_host.ServerSpecError, match="still the placeholder"):
        mcp_host.resolve_stdio_command({"command": sys.executable,
                                        "args": ["PATH/TO/GhidraMCP/bridge_mcp_ghidra.py"]})


def test_a_missing_script_is_reported_before_spawning(tmp_path):
    with pytest.raises(mcp_host.ServerSpecError, match="script not found"):
        mcp_host.resolve_stdio_command({"command": sys.executable, "args": [str(tmp_path / "gone.py")]})


def test_every_bundled_server_in_the_shipped_catalogue_resolves(monkeypatch):
    """With `python` absent from the PATH - the macOS/Linux case - every entry that points at a
    bundled server must still resolve, and only the Ghidra placeholder may be refused."""
    import json
    from pathlib import Path
    from reforge import config
    cat = json.loads(Path(config.__file__).with_name("mcp.servers.default.json").read_text())
    servers = cat.get("mcpServers", cat)
    monkeypatch.setattr(mcp_host.shutil, "which", lambda c: None)
    refused = {}
    for name, spec in servers.items():
        if spec.get("transport", "stdio") != "stdio":
            continue
        try:
            mcp_host.resolve_stdio_command(spec)
        except mcp_host.ServerSpecError as exc:
            refused[name] = str(exc)
    assert set(refused) <= {"ghidra"}, refused
