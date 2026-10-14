"""Typed configuration and fail-closed defaults (slice P0-S2, ADR 0001).

Closes two defects:

P0-3  configuration was the source file. `config.persist_to_file()` regex-rewrote
      `reforge/config.py` at runtime, so every install became a divergent fork, an upgrade
      overwrote customer settings, and a packaged or read-only install could not accept a change.

P0-4  shipped defaults were fail-open and contradicted both the comment above them and the README:
      `SAFETY_MODE = "autonomous"` (which makes `policy.requires_approval()` return False for every
      call, i.e. the product's central safety gate was off), `ALLOW_OUTSIDE_WORKSPACE = True`,
      `AUTH_TRUST_LOCALHOST = True`.

The point of these tests is that a future edit cannot quietly reopen either one.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from reforge import policy
from reforge.settings import NEVER_MIGRATED, Settings, env_overrides, load, read_legacy_block

ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------- shipped defaults
def test_shipped_defaults_are_fail_closed():
    """The posture a customer gets before touching anything."""
    s = Settings()
    assert s.safety_mode == "assisted", "the approval gate must be on by default"
    assert s.require_approval is True
    assert s.allow_outside_workspace is False, "confinement must be on by default"
    assert s.auth_required is True
    # auth_trust_localhost is profile-dependent, not blanket-closed: see
    # test_loopback_trust_is_allowed_on_a_workstation_and_forced_off_elsewhere below.
    assert s.nvd_online_lookup is False, "no egress unless explicitly enabled"
    assert s.report_use_llm_enrichment is False, "the report is deterministic by default"


def test_the_default_posture_actually_gates_dangerous_tools():
    """A default-valued setting is worthless if nothing consumes it. Check the gate end to end."""
    mode = Settings().safety_mode
    for tool in ("x64dbg__MemoryWrite", "x64dbg__DebugRun", "x64dbg__ExecCommand",
                 "ghidra__patch_bytes", "libs__nvd_online_lookup"):
        requires, rclass, _reason = policy.requires_approval(tool, mode)
        assert requires is True, f"{tool} ({rclass}) runs unattended under the default posture"
    # ...and read-only analysis is still frictionless.
    requires, _rc, _r = policy.requires_approval("ghidra__decompile_function", mode)
    assert requires is False


def test_autonomous_mode_remains_available_but_must_be_asked_for():
    """Fail-closed is a default, not a prohibition: the analyst can still opt out explicitly."""
    s = Settings(safety_mode="autonomous")
    assert s.require_approval is False
    assert policy.requires_approval("x64dbg__MemoryWrite", s.safety_mode)[0] is False


# --------------------------------------------------------------------------- validation
@pytest.mark.parametrize("kwargs", [
    {"safety_mode": "yolo"},
    {"llm_provider": "openai"},
    {"port": 0},
    {"port": 70000},
    {"local_base_url": "ftp://host/v1"},
    {"local_temperature": 9.0},
    {"tool_call_timeout": 0},
    {"ui_lang": "fr"},
    {"unknown_setting": True},
])
def test_invalid_settings_are_rejected(kwargs):
    with pytest.raises(Exception):
        Settings(**kwargs)


def test_a_broken_settings_file_falls_back_to_safe_defaults_instead_of_crashing(tmp_path):
    (tmp_path / "settings.json").write_text("{not json", encoding="utf-8")
    s, notes = load(tmp_path)
    assert s.safety_mode == "assisted" and s.allow_outside_workspace is False
    assert any("unreadable" in n for n in notes)


def test_an_out_of_range_value_in_the_file_falls_back_to_safe_defaults(tmp_path):
    (tmp_path / "settings.json").write_text(json.dumps({"safety_mode": "autonomous",
                                                        "port": 999999}), encoding="utf-8")
    s, notes = load(tmp_path)
    assert s.safety_mode == "assisted", "a rejected file must not leave a partial relaxation applied"
    assert any("invalid configuration" in n for n in notes)


def test_unknown_keys_from_an_older_version_are_ignored_not_fatal(tmp_path):
    (tmp_path / "settings.json").write_text(
        json.dumps({"local_model": "m", "setting_removed_in_v2": 1}), encoding="utf-8")
    s, notes = load(tmp_path)
    assert s.local_model == "m"
    assert any("unknown settings" in n for n in notes)


# --------------------------------------------------------------------------- layering
def test_precedence_is_defaults_then_file_then_environment(tmp_path):
    (tmp_path / "settings.json").write_text(
        json.dumps({"local_model": "from-file", "max_agent_steps": 11}), encoding="utf-8")
    s, _ = load(tmp_path, environ={"REFORGE_LOCAL_MODEL": "from-env"})
    assert s.local_model == "from-env", "environment must win over the file"
    assert s.max_agent_steps == 11, "the file must win over the default"
    assert s.anthropic_model == Settings().anthropic_model, "untouched keys keep their default"


def test_environment_values_are_typed_not_strings():
    values, problems = env_overrides({
        "REFORGE_PORT": "9000", "REFORGE_VERBOSE": "true",
        "REFORGE_LOCAL_TEMPERATURE": "0.7",
        "REFORGE_PRELOAD_QUERIES": "strings, imports",
    })
    assert not problems
    assert values == {"port": 9000, "verbose": True, "local_temperature": 0.7,
                      "preload_queries": ["strings", "imports"]}


def test_a_malformed_environment_value_is_reported_and_does_not_crash():
    values, problems = env_overrides({"REFORGE_VERBOSE": "maybe"})
    assert "verbose" not in values
    assert problems and "REFORGE_VERBOSE" in problems[0]


# --------------------------------------------------------------------------- profiles
@pytest.mark.parametrize("profile", ["team"])
def test_a_non_workstation_profile_cannot_be_relaxed(profile):
    """The hardening pass can only tighten. This is the control an administrator relies on."""
    s = Settings(deployment_profile=profile, safety_mode="autonomous",
                 allow_outside_workspace=True, auth_trust_localhost=True, auth_required=False)
    assert s.safety_mode == "assisted"
    assert s.allow_outside_workspace is False
    assert s.auth_trust_localhost is False
    assert s.auth_required is True


def test_hardening_also_applies_to_a_later_assignment():
    """validate_assignment re-runs the profile pass, so the gate cannot be opened after the fact."""
    s = Settings(deployment_profile="team")
    s.safety_mode = "autonomous"
    assert s.safety_mode == "assisted"


def test_the_workstation_profile_still_allows_an_explicit_opt_out():
    s = Settings(deployment_profile="workstation", safety_mode="autonomous",
                 allow_outside_workspace=True)
    assert s.safety_mode == "autonomous" and s.allow_outside_workspace is True


# --------------------------------------------------------------------------- legacy migration
_LEGACY_SOURCE = '''
# ==================== USER SETTINGS (LEGACY) ====================
LLM_PROVIDER = "local"
LOCAL_MODEL = "qwen3:30b"
SAFETY_MODE = "autonomous"
ALLOW_OUTSIDE_WORKSPACE = True
AUTH_TRUST_LOCALHOST = True
MAX_AGENT_STEPS = 60
# ========================== END USER SETTINGS =========================
'''


def test_legacy_block_is_parsed_without_importing_or_executing_it(tmp_path):
    legacy = tmp_path / "config.py"
    legacy.write_text(_LEGACY_SOURCE, encoding="utf-8")
    parsed = read_legacy_block(legacy)
    assert parsed["llm_provider"] == "local"
    assert parsed["local_model"] == "qwen3:30b"
    assert parsed["max_agent_steps"] == 60


def test_safety_settings_are_never_carried_forward_by_the_migration(tmp_path):
    """The whole point of the slice: an upgrade must not preserve a fail-open posture.

    An install running `autonomous` with no workspace confinement goes back to the fail-closed
    default and the operator re-grants deliberately. Everything else migrates.
    """
    legacy = tmp_path / "config.py"
    legacy.write_text(_LEGACY_SOURCE, encoding="utf-8")
    parsed = read_legacy_block(legacy)
    for field in NEVER_MIGRATED:
        assert field not in parsed, f"{field} must never migrate"

    s, notes = load(tmp_path / "state", legacy_config=legacy)
    assert s.llm_provider == "local" and s.local_model == "qwen3:30b", "usable settings migrate"
    assert s.safety_mode == "assisted"
    assert s.allow_outside_workspace is False
    # Not carried over means "back to the default", which for this field is profile-dependent -
    # the point is that the legacy file's value had no influence, whatever it was.
    assert s.auth_trust_localhost is Settings().auth_trust_localhost
    assert any("Safety settings were NOT carried over" in n for n in notes)


def test_the_legacy_block_is_ignored_once_a_settings_file_exists(tmp_path):
    legacy = tmp_path / "config.py"
    legacy.write_text(_LEGACY_SOURCE, encoding="utf-8")
    state = tmp_path / "state"
    state.mkdir()
    (state / "settings.json").write_text(json.dumps({"local_model": "chosen-later"}),
                                         encoding="utf-8")
    s, _ = load(state, legacy_config=legacy)
    assert s.local_model == "chosen-later"


def test_the_shipped_config_py_legacy_block_carries_no_fail_open_safety_value():
    """Defence in depth: even if the migration changed, the shipped literals must not be fail-open."""
    parsed = read_legacy_block(ROOT / "reforge" / "config.py")
    for field in NEVER_MIGRATED:
        assert field not in parsed


# --------------------------------------------------------------------------- persistence
def test_persisting_settings_writes_to_the_state_dir_and_never_to_source(tmp_path):
    """P0-3: the replacement for persist_to_file() must not touch reforge/config.py."""
    config_py = ROOT / "reforge" / "config.py"
    before = hashlib.sha256(config_py.read_bytes()).hexdigest()

    env = dict(os.environ)
    env["REFORGE_STATE_DIR"] = str(tmp_path / "state")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    code = (
        "from reforge import config;"
        "p = config.persist_settings({'local_model': 'persisted-model', 'safety_mode': 'safe'});"
        "print(p)"
    )
    proc = subprocess.run([sys.executable, "-c", code], cwd=str(ROOT), env=env,
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    written = Path(proc.stdout.strip().splitlines()[-1])

    assert hashlib.sha256(config_py.read_bytes()).hexdigest() == before, \
        "persisting settings rewrote reforge/config.py"
    assert written.is_relative_to((tmp_path / "state").resolve())
    saved = json.loads(written.read_text(encoding="utf-8"))
    assert saved["local_model"] == "persisted-model" and saved["safety_mode"] == "safe"


def test_a_persisted_setting_is_read_back_on_the_next_start(tmp_path):
    state = tmp_path / "state"
    env = dict(os.environ)
    env["REFORGE_STATE_DIR"] = str(state)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    subprocess.run([sys.executable, "-c",
                    "from reforge import config; config.persist_settings({'local_model': 'round-trip'})"],
                   cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=120, check=True)
    proc = subprocess.run([sys.executable, "-c",
                           "from reforge import config; print(config.LOCAL_MODEL)"],
                          cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip().splitlines()[-1] == "round-trip"


def test_no_secret_is_ever_written_into_the_settings_file(tmp_path):
    """Settings files get copied, diffed and attached to support bundles. Keys must not be in them."""
    state = tmp_path / "state"
    env = dict(os.environ)
    env["REFORGE_STATE_DIR"] = str(state)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    sentinel = "sk-ant-sentinel-not-a-real-key"
    subprocess.run(
        [sys.executable, "-c",
         "from reforge import config; config.persist_settings("
         f"{{'anthropic_api_key': '{sentinel}', 'local_model': 'm'}})"],
        cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=120, check=True)
    body = (state / "settings.json").read_text(encoding="utf-8")
    assert sentinel not in body
    assert "anthropic_api_key" not in body


def test_settings_model_declares_no_secret_fields():
    """Structural guard: a future field named like a credential would leak into settings.json."""
    # `local_api_key` is exempt: it is the placeholder string local servers ignore ("ollama"),
    # not a credential. `max_tokens` is a generation limit, hence the suffix match on `_token`.
    def looks_like_a_credential(field: str) -> bool:
        if field == "local_api_key":
            return False
        return ("password" in field or "secret" in field
                or field.endswith(("_token", "_api_key", "_key", "token")) and field != "max_tokens")

    suspicious = [f for f in Settings.model_fields if looks_like_a_credential(f)]
    assert not suspicious, f"these belong in the secrets store, not in settings.json: {suspicious}"


# --------------------------------------------------------------------------- facade integrity
def test_the_facade_exposes_every_setting_and_stays_in_sync():
    """config.X is what 40 modules read. It must never drift from the object it mirrors."""
    from reforge import config
    assert config.SAFETY_MODE == config.SETTINGS.safety_mode
    assert config.ALLOW_OUTSIDE_WORKSPACE == config.SETTINGS.allow_outside_workspace
    assert config.REQUIRE_APPROVAL == config.SETTINGS.require_approval

    original = config.SETTINGS.safety_mode
    try:
        config.apply_runtime(safety_mode="safe")
        assert config.SAFETY_MODE == "safe" and config.SETTINGS.safety_mode == "safe"
        assert config.REQUIRE_APPROVAL is True
    finally:
        config.apply_runtime(safety_mode=original)
    assert config.SAFETY_MODE == original


def test_the_legacy_require_approval_toggle_can_only_tighten():
    """An old client payload of {"require_approval": false} must not disable the gate."""
    from reforge import config
    original = config.SETTINGS.safety_mode
    try:
        config.apply_runtime(safety_mode="assisted")
        config.apply_runtime(require_approval=False)
        assert config.REQUIRE_APPROVAL is True, "the gate was switched off by the legacy toggle"
        config.apply_runtime(safety_mode="autonomous")
        config.apply_runtime(require_approval=True)
        assert config.REQUIRE_APPROVAL is True, "the legacy toggle must still be able to tighten"
    finally:
        config.apply_runtime(safety_mode=original)


def test_an_invalid_runtime_change_leaves_the_running_settings_untouched():
    from reforge import config
    before = config.SETTINGS.safety_mode
    with pytest.raises(Exception):
        config.apply_runtime(safety_mode="definitely-not-a-mode")
    assert config.SETTINGS.safety_mode == before
    assert config.SAFETY_MODE == before


# --------------------------------------------------------------------------- auth bootstrap
# The token used to be left in the URL and stored in a JS-readable cookie, and the API accepted it
# from the query string. A credential in a URL reaches access logs, shell history, browser history
# and Referer headers; a non-HttpOnly cookie reaches any script on the page. (It was also simply
# broken for remote use: nothing ever set the cookie the middleware read, so the SPA's own fetch()
# and EventSource calls had no credential after the first page load.)
@pytest.fixture()
def client():
    from fastapi.testclient import TestClient
    from reforge.server import app
    with TestClient(app, follow_redirects=False) as c:
        yield c


def test_api_rejects_a_token_in_the_query_string(client):
    from reforge import config
    r = client.get(f"/api/status?token={config.AUTH_TOKEN}")
    assert r.status_code == 401, "a credential in a URL must not authenticate an API call"


def test_api_accepts_the_token_in_the_header(client):
    from reforge import config
    r = client.get("/api/status", headers={"X-Reforge-Token": config.AUTH_TOKEN})
    assert r.status_code == 200


def test_bootstrap_link_exchanges_the_token_for_a_hardened_cookie_and_clears_the_url(client):
    from reforge import config
    r = client.get(f"/?token={config.AUTH_TOKEN}")
    assert r.status_code == 303, "the bootstrap link must redirect so the token leaves the URL"
    assert r.headers["location"] == "/"

    cookie = r.headers.get("set-cookie", "")
    assert "reforge_token=" in cookie
    assert "httponly" in cookie.lower(), "the session cookie must not be readable by page scripts"
    assert "samesite=strict" in cookie.lower(), "the cookie must not ride cross-site requests"
    assert "max-age=" in cookie.lower(), "the browser session must expire"

    # The exchanged cookie is what authenticates subsequent API calls.
    assert client.get("/api/status").status_code == 200


def test_a_wrong_bootstrap_token_just_serves_the_page_and_sets_nothing(client):
    """The SPA loads for anyone - it is not secret - but an unauthenticated caller gets no cookie.

    `GET /` issues the session cookie to a caller that *would* have been allowed to call the API.
    An unauthorised one must get the page and nothing else: the auth middleware lets every
    non-/api path through, so "reached the index route" is not evidence of anything.
    """
    r = client.get("/?token=not-the-token")
    assert r.status_code == 200
    assert "reforge_token=" not in r.headers.get("set-cookie", ""), \
        "the session credential was handed to an unauthenticated caller"
    assert client.get("/api/status").status_code == 401


def test_loopback_trust_is_allowed_on_a_workstation_and_forced_off_elsewhere():
    """§10.1: the workstation profile may be simpler, but must be clearly distinct.

    Shipping this closed for every profile broke the bundled SPA, which carries no token: the page
    loaded and every API call 401'd, with nothing on screen to say why.
    """
    assert Settings(deployment_profile="workstation").auth_trust_localhost is True
    for shared in ("team",):
        assert Settings(deployment_profile=shared,
                        auth_trust_localhost=True).auth_trust_localhost is False


def test_an_authorised_caller_receives_a_hardened_session_cookie(client):
    """The cookie - not the reason the caller was let in - is the durable credential."""
    from reforge import config

    r = client.get("/", headers={"X-Reforge-Token": config.AUTH_TOKEN})
    cookie = r.headers.get("set-cookie", "")
    assert "reforge_token=" in cookie
    assert "httponly" in cookie.lower() and "samesite=strict" in cookie.lower()


def test_static_assets_stay_open(client):
    assert client.get("/styles.css").status_code == 200
