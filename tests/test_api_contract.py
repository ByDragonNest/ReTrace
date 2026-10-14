"""API versioning and the uniform error contract (slice P0-S5).

~70 routes were served from an unversioned `/api/...` prefix, and errors came back as whatever
`HTTPException` had been handed - a human sentence, sometimes Italian, sometimes English, with no
machine-readable code. A client could only react to an error by matching prose, and there was no
way to ship a breaking change without breaking every caller at once.
"""
from __future__ import annotations

import pytest

from reforge import config
from reforge.server import API_PREFIX, API_VERSION, app


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient
    with TestClient(app) as c:
        c.headers.update({"X-Reforge-Token": config.AUTH_TOKEN})
        yield c


# --------------------------------------------------------------------------- versioning
def test_the_versioned_prefix_serves_the_api(client):
    assert client.get(f"{API_PREFIX}/status").status_code == 200


def test_the_unversioned_prefix_still_works_for_existing_clients(client):
    """The bundled SPA and any existing automation must not break on this change."""
    assert client.get("/api/status").status_code == 200


def test_both_prefixes_return_the_same_payload(client):
    versioned = client.get(f"{API_PREFIX}/status").json()
    legacy = client.get("/api/status").json()
    # `uptime`-style fields would differ; compare the stable posture fields.
    for key in ("safety_mode", "deployment_profile", "require_approval"):
        assert versioned.get(key) == legacy.get(key)


def test_every_api_response_declares_the_api_version(client):
    for path in (f"{API_PREFIX}/status", "/api/status", f"{API_PREFIX}/nope"):
        assert client.get(path).headers.get("X-API-Version") == API_VERSION


def test_a_versioned_path_that_does_not_exist_is_a_clean_404(client):
    r = client.get(f"{API_PREFIX}/definitely-not-a-route")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "not_found"


def test_the_spa_is_not_behind_the_api_prefix(client):
    """Versioning the API must not version the UI."""
    assert client.get("/").status_code == 200
    assert client.get("/app.js").status_code == 200


# --------------------------------------------------------------------------- error envelope
def _envelope(response):
    body = response.json()
    assert set(body) == {"error"}, f"not the uniform envelope: {body}"
    err = body["error"]
    assert {"code", "message", "status"} <= set(err)
    assert err["status"] == response.status_code
    assert isinstance(err["code"], str) and err["code"]
    return err


def test_a_404_uses_the_envelope(client):
    err = _envelope(client.get(f"{API_PREFIX}/projects/nonexistent"))
    assert err["code"] == "not_found"


def test_a_validation_failure_uses_the_envelope_and_names_the_fields(client):
    r = client.post(f"{API_PREFIX}/message", json={"wrong": "shape"})
    err = _envelope(r)
    assert err["code"] == "validation_error"
    assert err["context"]["fields"], "a 422 must say which fields were wrong"


def test_an_unauthenticated_call_uses_the_envelope():
    from fastapi.testclient import TestClient
    with TestClient(app) as anon:
        r = anon.get(f"{API_PREFIX}/status")
        assert r.status_code == 401
        assert r.json()["error"]["code"] == "unauthorized"


def test_upload_refusals_carry_their_own_machine_readable_status(client, tmp_path, monkeypatch):
    """The upload policy statuses must survive the envelope, since a UI acts on them."""
    import io

    from reforge.server import store
    monkeypatch.setattr(config, "WORKSPACE_DIR", tmp_path)
    monkeypatch.setattr(config, "MAX_UPLOAD_BYTES", 512)
    pid = store.create().id
    r = client.post(f"{API_PREFIX}/projects/{pid}/artifacts",
                    files={"file": ("big.bin", io.BytesIO(b"x" * 9000), "application/octet-stream")})
    err = _envelope(r)
    assert r.status_code == 413 and err["code"] == "payload_too_large"


def test_the_error_codes_are_stable_identifiers_not_prose():
    """A client reacts to `code`; it must never be a sentence."""
    from reforge.server import _CODE_FOR_STATUS
    for status, code in _CODE_FOR_STATUS.items():
        assert code.replace("_", "").isalnum(), f"{status} -> {code!r} is not an identifier"
        assert code.islower() and " " not in code


# --------------------------------------------------------------------------- openapi
def test_the_openapi_document_is_generated_and_describes_the_version(client):
    spec = client.get("/openapi.json").json()
    assert spec["info"]["title"] == "ReTrace API"
    assert spec["info"]["version"]
    assert API_PREFIX in spec["info"]["description"]
    assert len(spec["paths"]) > 50, "the documented surface looks truncated"


# --------------------------------------------------------------------------- SPA assets
def test_spa_assets_answer_revalidation_with_304(client):
    """`Cache-Control: no-cache` means "revalidate before use", not "never cache" - but a plain
    FileResponse never answered the revalidation, so every reload re-sent the whole bundle."""
    first = client.get("/app.js")
    assert first.status_code == 200
    assert "no-cache" in first.headers.get("cache-control", "")
    tag = first.headers.get("etag")
    assert tag, "the asset carries no ETag, so a browser cannot revalidate it"
    again = client.get("/app.js", headers={"If-None-Match": tag})
    assert again.status_code == 304
    assert again.content == b""
    assert again.headers.get("etag") == tag
    stale = client.get("/app.js", headers={"If-None-Match": '"not-the-current-tag"'})
    assert stale.status_code == 200 and stale.content == first.content
