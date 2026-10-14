"""Test isolation for ReTrace state.

The tool keeps its mutable run-time state (project DB `reforge.db`, project/session JSON, jobs,
analyzed samples) under the repo root by default. Importing the package and creating sessions in a
test therefore used to write real projects into the *shipped* `reforge.db` — which is why a freshly
downloaded build appeared with dozens of phantom projects.

This conftest points `REFORGE_STATE_DIR` at a throwaway temp directory BEFORE `reforge.config` is
imported anywhere, so the whole suite reads code from the repo but writes state into the sandbox.
Nothing under the repo (reforge.db, projects/, sessions/, jobs/, workspace/) is touched.
"""
import os
import tempfile

# Must run at import time, before any test module imports reforge.config.
_STATE_DIR = tempfile.mkdtemp(prefix="retrace-tests-")
os.environ.setdefault("REFORGE_STATE_DIR", _STATE_DIR)

# No MCP server is started by the suite. The app's lifespan connects every *enabled* server in
# the catalogue, and "enabled" defaults to true for a name with no entry in servers_state.json.
# Once `python` resolved to a real interpreter (mcp_host.resolve_stdio_command) that meant eight
# subprocesses per TestClient start-up, ~0.4 s each, across ~100 tests: the suite went from 8 s to
# 49 s and started depending on what the machine had installed. The state file below disables
# every catalogued server for the sandbox; tests that want a server start it themselves.
import json as _json
from pathlib import Path as _Path
_ROOT = _Path(__file__).resolve().parent.parent
for _cat in (_ROOT / "mcp.servers.json", _ROOT / "reforge" / "mcp.servers.default.json"):
    if _cat.is_file():
        try:
            _names = _json.loads(_cat.read_text(encoding="utf-8"))
            _names = _names.get("mcpServers", _names)
            (_Path(os.environ["REFORGE_STATE_DIR"]) / "servers_state.json").write_text(
                _json.dumps({n: False for n in _names}), encoding="utf-8")
        except (OSError, ValueError):
            pass
        break
