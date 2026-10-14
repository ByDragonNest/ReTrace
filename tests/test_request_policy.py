"""Cross-origin, rate-limit and path-confinement policy (slices P1-S8, P1-S9).

Two gaps this closes.

**T-5, the drive-by.** A page the analyst visits could issue `POST multipart/form-data` at
`http://127.0.0.1:8000/api/...`. That is a "simple" request, so no preflight stands in the way,
and with loopback trusted no credential is needed. The attacker cannot read the reply, but
`/api/projects/{pid}/upload` and `/artifacts` are write endpoints and the write happened.

**P1-12, the deny-list.** Path confinement outside the workspace was a list of locations to
refuse - /etc, /root, /proc, /sys, /boot, /dev, Windows system dirs, ~/.ssh - which misses
~/.aws, ~/.config, ~/Library/Keychains, ~/.docker and /var. A deny-list at a security boundary can
only enumerate what someone thought of.
"""
from __future__ import annotations

import io
import tempfile
from pathlib import Path

import pytest

from reforge import config, workspace
from reforge.workspace import UnsafePathError


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient
    from reforge.server import app
    with TestClient(app) as c:
        c.headers.update({"X-Reforge-Token": config.AUTH_TOKEN})
        yield c


# --------------------------------------------------------------------------- cross-origin
def test_a_state_changing_call_from_another_site_is_refused(client):
    """The exact shape of T-5: a simple cross-origin POST, no preflight to stop it."""
    r = client.post("/api/projects", json={"name": "drive-by"},
                    headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "cross_origin_denied"


def test_a_multipart_upload_from_another_site_is_refused(client):
    """multipart/form-data is the content type that makes this a *simple* request."""
    r = client.post("/api/projects/whatever/artifacts",
                    files={"file": ("x.bin", io.BytesIO(b"x"), "application/octet-stream")},
                    headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_the_same_origin_ui_is_unaffected(client):
    r = client.post("/api/projects", json={"name": "legit"},
                    headers={"Origin": "http://testserver"})
    assert r.status_code != 403


def test_a_cross_origin_read_is_not_blocked_by_this_control(client):
    """Reads are left to the browser's own same-origin policy; this control is about writes."""
    r = client.get("/api/status", headers={"Origin": "https://evil.example"})
    assert r.status_code == 200


def test_a_client_with_no_origin_header_is_allowed(client):
    """curl, the CLI and automation send no Origin - and cannot be driven by a web page."""
    assert client.post("/api/projects", json={"name": "cli"}).status_code != 403


def test_sec_fetch_site_is_honoured_as_an_independent_signal(client):
    r = client.post("/api/projects", json={"name": "x"},
                    headers={"Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403


def test_an_explicitly_allowed_origin_is_accepted(client, monkeypatch):
    monkeypatch.setattr(config, "CORS_ALLOW_ORIGINS", ["https://ui.internal"])
    r = client.post("/api/projects", json={"name": "x"},
                    headers={"Origin": "https://ui.internal"})
    assert r.status_code != 403


def test_cors_is_not_enabled_by_default():
    """With no CORS headers a browser already refuses to read a cross-origin reply."""
    assert config.CORS_ALLOW_ORIGINS == []


# --------------------------------------------------------------------------- rate limiting
def test_requests_beyond_the_limit_are_refused(client, monkeypatch):
    from reforge import server

    monkeypatch.setattr(config, "RATE_LIMIT_PER_MINUTE", 5)
    server._rate_limiter._hits.clear()
    codes = [client.get("/api/status").status_code for _ in range(8)]
    assert 429 in codes
    assert codes.count(200) == 5
    refused = client.get("/api/status")
    assert refused.json()["error"]["code"] == "rate_limited"


def test_the_rate_limit_can_be_disabled(client, monkeypatch):
    from reforge import server

    monkeypatch.setattr(config, "RATE_LIMIT_PER_MINUTE", 0)
    server._rate_limiter._hits.clear()
    assert all(client.get("/api/status").status_code == 200 for _ in range(30))


def test_the_limiter_does_not_grow_without_bound():
    """One integer per client per minute, cleared on window change - not a leak over a long run."""
    from reforge.server import _RateLimiter

    limiter = _RateLimiter()
    for i in range(500):
        limiter.allow(f"10.0.0.{i}", 1000)
    assert len(limiter._hits) == 500
    limiter._window = -1                      # force a window roll
    limiter.allow("10.0.0.1", 1000)
    assert len(limiter._hits) == 1


# --------------------------------------------------------------------------- path confinement
@pytest.fixture()
def sample_dirs():
    allowed = Path(tempfile.mkdtemp())
    (allowed / "sample.bin").write_bytes(b"MZ\x90\x00")
    elsewhere = Path(tempfile.mkdtemp())
    (elsewhere / "credentials").write_bytes(b"secret")
    return allowed, elsewhere


def test_without_an_allow_list_nothing_outside_the_workspace_is_reachable(sample_dirs, monkeypatch):
    allowed, _ = sample_dirs
    monkeypatch.setattr(config, "EXTERNAL_ROOTS", [])
    monkeypatch.setattr(config, "ALLOW_OUTSIDE_WORKSPACE", False)
    with pytest.raises(UnsafePathError):
        workspace.safe_resolve(str(allowed / "sample.bin"))


def test_a_named_root_is_reachable_and_nothing_else_is(sample_dirs, monkeypatch):
    allowed, elsewhere = sample_dirs
    monkeypatch.setattr(config, "EXTERNAL_ROOTS", [str(allowed)])
    monkeypatch.setattr(config, "ALLOW_OUTSIDE_WORKSPACE", False)
    assert workspace.safe_resolve(str(allowed / "sample.bin")).is_file()
    with pytest.raises(UnsafePathError):
        workspace.safe_resolve(str(elsewhere / "credentials"))


def test_the_allow_list_closes_what_the_deny_list_missed(monkeypatch):
    """~/.aws and friends were never on the deny-list; under an allow-list they need no entry."""
    monkeypatch.setattr(config, "EXTERNAL_ROOTS", [])
    monkeypatch.setattr(config, "ALLOW_OUTSIDE_WORKSPACE", False)
    for never_denied in ("~/.aws/credentials", "~/.config/gh/hosts.yml",
                         "~/Library/Keychains/login.keychain-db", "/var/db/anything"):
        with pytest.raises(UnsafePathError):
            workspace.safe_resolve(str(Path(never_denied).expanduser()))


def test_traversal_out_of_an_allowed_root_is_still_refused(sample_dirs, monkeypatch):
    allowed, elsewhere = sample_dirs
    monkeypatch.setattr(config, "EXTERNAL_ROOTS", [str(allowed)])
    monkeypatch.setattr(config, "ALLOW_OUTSIDE_WORKSPACE", False)
    with pytest.raises(UnsafePathError):
        workspace.safe_resolve(f"{allowed}/../{elsewhere.name}/credentials")


def test_a_relative_external_root_is_ignored(monkeypatch):
    """A relative root would mean something different depending on the working directory."""
    monkeypatch.setattr(config, "EXTERNAL_ROOTS", ["samples", "./cases", ""])
    assert workspace.allowed_roots() == []


def test_the_refusal_says_how_to_fix_it(sample_dirs, monkeypatch):
    allowed, _ = sample_dirs
    monkeypatch.setattr(config, "EXTERNAL_ROOTS", [])
    monkeypatch.setattr(config, "ALLOW_OUTSIDE_WORKSPACE", False)
    with pytest.raises(UnsafePathError) as exc:
        workspace.safe_resolve(str(allowed / "sample.bin"))
    assert "external_roots" in str(exc.value)


def test_permissive_mode_still_refuses_the_obvious_targets(monkeypatch):
    """The deny-list survives as a secondary net for the legacy permissive mode."""
    monkeypatch.setattr(config, "ALLOW_OUTSIDE_WORKSPACE", True)
    monkeypatch.setattr(config, "EXTERNAL_ROOTS", [])
    for target in ("/etc/passwd", str(Path("~/.ssh/id_rsa").expanduser())):
        with pytest.raises(UnsafePathError):
            workspace.safe_resolve(target)
