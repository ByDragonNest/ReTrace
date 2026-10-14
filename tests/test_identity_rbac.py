"""Identity, RBAC, project isolation and the audit trail (slice P2-S1).

Before this there was one process-wide shared token. Anyone who could reach the API could read,
modify, export or delete every project of every customer, and nothing recorded who did.
`DELETE /api/projects/{pid}` required only the ability to reach the endpoint.
"""
from __future__ import annotations

import os
import tempfile

import pytest

from reforge import audit, config
from reforge.identity import (ANONYMOUS, LOCAL_OPERATOR, AccessDenied, Permission, Principal,
                              Role, ROLE_PERMISSIONS, parse_roles, require)
from reforge import identity_providers as idp
from reforge.session import Session, can_access


def who(role: Role, subject: str = "u1") -> Principal:
    return Principal(subject=subject, roles=frozenset({role}))


# --------------------------------------------------------------------------- the role model
def test_read_only_cannot_change_anything():
    p = who(Role.READ_ONLY)
    assert p.can(Permission.PROJECT_READ)
    for forbidden in (Permission.PROJECT_WRITE, Permission.PROJECT_DELETE,
                      Permission.ANALYSIS_RUN, Permission.APPROVAL_GRANT,
                      Permission.FINDING_WRITE, Permission.SETTINGS_WRITE):
        assert not p.can(forbidden), forbidden


def test_a_reviewer_signs_off_but_does_not_run_the_analysis():
    """Someone approving a finding should not also be able to re-run what produced it."""
    p = who(Role.REVIEWER)
    assert p.can(Permission.FINDING_REVIEW)
    assert p.can(Permission.REPORT_EXPORT)
    assert not p.can(Permission.ANALYSIS_RUN)
    assert not p.can(Permission.FINDING_WRITE)


def test_an_analyst_works_but_does_not_administer():
    p = who(Role.ANALYST)
    for allowed in (Permission.ANALYSIS_RUN, Permission.ARTIFACT_UPLOAD,
                    Permission.FINDING_WRITE, Permission.APPROVAL_GRANT,
                    Permission.REPORT_EXPORT):
        assert p.can(allowed), allowed
    for forbidden in (Permission.RAW_EXPORT, Permission.SETTINGS_WRITE,
                      Permission.SERVER_MANAGE, Permission.USER_MANAGE,
                      Permission.PROJECT_DELETE, Permission.AUDIT_READ):
        assert not p.can(forbidden), forbidden


def test_running_an_engagement_is_not_administering_the_platform():
    """A security manager must not be able to turn off the controls they operate under."""
    p = who(Role.SECURITY_MANAGER)
    assert p.can(Permission.PROJECT_DELETE) and p.can(Permission.AUDIT_READ)
    assert not p.can(Permission.SETTINGS_WRITE)
    assert not p.can(Permission.SERVER_MANAGE)
    assert not p.can(Permission.USER_MANAGE)


def test_only_the_administrator_holds_every_permission():
    assert ROLE_PERMISSIONS[Role.ADMINISTRATOR] == frozenset(Permission)
    for role in Role:
        if role is not Role.ADMINISTRATOR:
            assert ROLE_PERMISSIONS[role] != frozenset(Permission)


def test_an_anonymous_principal_can_do_nothing():
    assert ANONYMOUS.is_anonymous()
    for permission in Permission:
        assert not ANONYMOUS.can(permission)


def test_require_raises_with_enough_to_audit_the_refusal():
    with pytest.raises(AccessDenied) as exc:
        require(who(Role.ANALYST), Permission.RAW_EXPORT, "proj-1")
    assert exc.value.permission is Permission.RAW_EXPORT
    assert exc.value.project_id == "proj-1"


# --------------------------------------------------------------------------- per-project roles
def test_a_project_role_grants_only_within_that_project():
    p = Principal("u1", roles=frozenset({Role.READ_ONLY}), project_roles={"p1": Role.ANALYST})
    assert p.can(Permission.ANALYSIS_RUN, "p1")
    assert not p.can(Permission.ANALYSIS_RUN, "p2")
    assert not p.can(Permission.ANALYSIS_RUN)


def test_a_project_role_cannot_take_away_a_global_permission():
    """Additive by design: a narrower project role must not silently demote someone."""
    p = Principal("u1", roles=frozenset({Role.SECURITY_MANAGER}),
                  project_roles={"p1": Role.READ_ONLY})
    assert p.can(Permission.PROJECT_DELETE, "p1")


# --------------------------------------------------------------------------- project isolation
def _project(owner: str = "", members=None) -> Session:
    s = Session("p1", "p")
    s.owner = owner
    s.members = members or {}
    return s


def test_an_owner_sees_their_project():
    assert can_access(who(Role.ANALYST, "alice"), _project(owner="alice"))


def test_another_analyst_does_not_see_someone_elses_project():
    assert not can_access(who(Role.ANALYST, "bob"), _project(owner="alice"))


def test_a_named_member_sees_it():
    assert can_access(who(Role.ANALYST, "bob"), _project(owner="alice", members={"bob": "analyst"}))


def test_a_cross_project_permission_implies_visibility():
    """Deleting or sharing any project implies being able to see it."""
    assert can_access(who(Role.SECURITY_MANAGER, "carol"), _project(owner="alice"))


def test_a_project_from_before_ownership_stays_visible():
    """Locking analysts out of their own history on upgrade would be the wrong failure."""
    assert can_access(who(Role.ANALYST, "bob"), _project(owner=""))


def test_no_project_is_visible_without_project_read():
    assert not can_access(ANONYMOUS, _project(owner=""))


# --------------------------------------------------------------------------- authentication
def test_the_local_operator_exists_only_on_the_workstation_profile(monkeypatch):
    """A misconfigured team deployment must fail closed, not hand everyone administrator."""
    class _Req:
        headers = {}

    monkeypatch.setattr(config, "IDENTITY_PROVIDER", "local")
    monkeypatch.setattr(config, "DEPLOYMENT_PROFILE", "workstation")
    assert idp.resolve(_Req(), config) is LOCAL_OPERATOR

    for shared in ("team",):
        monkeypatch.setattr(config, "DEPLOYMENT_PROFILE", shared)
        assert idp.resolve(_Req(), config).is_anonymous()


def test_claims_map_onto_roles_through_explicit_configuration():
    claims = {"sub": "abc", "name": "Alice", "email": "a@x.test",
              "realm_access": {"roles": ["sec-team", "offline_access"]}}
    p = idp.principal_from_claims(claims, roles_claim="realm_access.roles",
                                  role_map={"sec-team": "security_manager"})
    assert p.subject == "abc" and p.email == "a@x.test"
    assert p.roles == frozenset({Role.SECURITY_MANAGER})


def test_an_unmapped_group_grants_nothing():
    """Inferring a role from a group name is how someone gets permissions nobody granted."""
    p = idp.principal_from_claims({"sub": "x", "roles": ["wizards", "admins-ish"]})
    assert p.roles == frozenset()
    assert not p.can(Permission.PROJECT_READ)


def test_a_default_role_applies_only_when_nothing_mapped():
    assert idp.principal_from_claims({"sub": "x"}, default_role="read_only").roles == \
        frozenset({Role.READ_ONLY})
    mapped = idp.principal_from_claims({"sub": "x", "roles": ["analyst"]}, default_role="read_only")
    assert mapped.roles == frozenset({Role.ANALYST})


def test_an_empty_bearer_is_not_an_identity(monkeypatch):
    class _Req:
        headers = {"authorization": "Bearer "}

    monkeypatch.setattr(config, "IDENTITY_PROVIDER", "oidc_bearer")
    assert idp.resolve(_Req(), config).is_anonymous()


def test_a_malformed_token_is_rejected_without_calling_the_identity_provider(monkeypatch):
    """A typo must not become a round trip to the IdP, nor an outage-shaped error."""
    monkeypatch.setattr(config, "IDENTITY_PROVIDER", "oidc_bearer")
    monkeypatch.setattr(config, "OIDC_ISSUER", "https://issuer.test")

    def _must_not_be_called(issuer):
        raise AssertionError("the identity provider was contacted for a malformed token")

    monkeypatch.setattr(idp, "_discover_jwks_url", _must_not_be_called)

    class _Req:
        headers = {"authorization": "Bearer not-a-jwt"}

    with pytest.raises(idp.AuthenticationError):
        idp.resolve(_Req(), config)


def test_the_rejection_reason_is_not_handed_back_to_the_caller(monkeypatch):
    monkeypatch.setattr(config, "IDENTITY_PROVIDER", "oidc_bearer")
    monkeypatch.setattr(config, "OIDC_ISSUER", "https://issuer.test")

    class _Req:
        headers = {"authorization": "Bearer aaa.bbb.ccc"}

    monkeypatch.setattr(idp, "_discover_jwks_url", lambda issuer: "https://issuer.test/jwks")
    with pytest.raises(idp.AuthenticationError) as exc:
        idp.resolve(_Req(), config)
    assert "not valid" in str(exc.value)
    assert "jwks" not in str(exc.value).lower()


def test_an_unreachable_identity_provider_is_not_reported_as_a_bad_credential(monkeypatch):
    """503, not 401. Otherwise an IdP outage looks like every user's login breaking at once."""
    monkeypatch.setattr(config, "IDENTITY_PROVIDER", "oidc_bearer")
    monkeypatch.setattr(config, "OIDC_ISSUER", "https://unreachable.invalid")

    class _Req:
        headers = {"authorization": "Bearer aaa.bbb.ccc"}

    with pytest.raises(idp.IdentityProviderUnavailable):
        idp.resolve(_Req(), config)


def test_unknown_role_names_are_ignored_not_guessed():
    assert parse_roles(["analyst", "sorcerer", ""]) == frozenset({Role.ANALYST})


def test_describe_never_leaks_a_credential():
    """`auth_method` names how they authenticated; it must not carry what they authenticated with."""
    p = Principal("s", "Name", "e@x.test", frozenset({Role.ANALYST}), auth_method="oidc_bearer")
    described = p.describe()
    assert set(described) == {"subject", "display_name", "email", "roles",
                              "auth_method", "is_local_operator"}
    assert described["auth_method"] == "oidc_bearer"      # the method, not a token
    rendered = str(described)
    for forbidden in ("eyj", "secret", "password", "api_key"):   # eyJ = a JWT's first bytes
        assert forbidden not in rendered.lower()


# --------------------------------------------------------------------------- audit trail
@pytest.fixture()
def audit_dir(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "STATE_ROOT", tmp_path)
    return tmp_path


def test_sensitive_actions_are_recorded_with_who_did_them(audit_dir):
    actor = who(Role.SECURITY_MANAGER, "alice")
    audit.record("project.delete", principal=actor, project_id="p1", name="engagement")
    entries = audit.read()
    assert entries[0]["action"] == "project.delete"
    assert entries[0]["actor"]["subject"] == "alice"
    assert entries[0]["detail"]["name"] == "engagement"


def test_refusals_are_recorded_too(audit_dir):
    """Recording only successes makes the trail a record of what went right."""
    audit.record("authz.denied", principal=who(Role.ANALYST, "bob"),
                 outcome="denied", permission="raw:export")
    assert audit.read()[0]["outcome"] == "denied"


def test_the_chain_detects_an_altered_entry(audit_dir):
    import json

    for i in range(3):
        audit.record("x", principal=who(Role.ANALYST), project_id=str(i))
    assert audit.verify()["ok"] is True

    path = audit._log_path()
    lines = path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[1])
    tampered["detail"] = {"changed": True}
    lines[1] = json.dumps(tampered, sort_keys=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    result = audit.verify()
    assert result["ok"] is False and result["broken_at"] == 1


def test_the_chain_detects_a_removed_entry(audit_dir):
    for i in range(4):
        audit.record("x", principal=who(Role.ANALYST), project_id=str(i))
    path = audit._log_path()
    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[2]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert audit.verify()["ok"] is False


def test_an_audit_write_failure_does_not_break_the_action(monkeypatch, tmp_path):
    """An audit failure must be loud, not fatal to the thing it was recording."""
    monkeypatch.setattr(config, "STATE_ROOT", tmp_path / "nonexistent" / "deep")

    def _boom(*a, **k):
        raise OSError("read-only filesystem")

    monkeypatch.setattr(audit, "_log_path", _boom)
    entry = audit.record("project.delete", principal=who(Role.ANALYST))
    assert entry["action"] == "project.delete"       # returned, not raised


def test_the_audit_records_the_action_not_the_customer_content(audit_dir):
    audit.record("raw.export", principal=who(Role.SECURITY_MANAGER), project_id="p1")
    body = str(audit.read()[0])
    assert "p1" in body
    assert "findings" not in body and "evidence" not in body


# --------------------------------------------------------------------------- enforcement at the API
# The model above is worthless if a route forgets to consult it. These exercise the real app.
@pytest.fixture()
def api(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from reforge.server import app
    monkeypatch.setattr(config, "WORKSPACE_DIR", tmp_path)
    monkeypatch.setattr(config, "STATE_ROOT", tmp_path)
    with TestClient(app) as c:
        c.headers.update({"X-Reforge-Token": config.AUTH_TOKEN})
        yield c


def _as(client, role: Role, subject: str = "u1"):
    """Force the principal the server will see, leaving the rest of the stack real."""
    from reforge import server

    original = server.principal_of
    server.principal_of = lambda request: Principal(subject=subject, roles=frozenset({role}))
    client.addfinalizer = getattr(client, "addfinalizer", None)
    return original


def test_whoami_reports_the_caller_and_never_a_credential(api):
    body = api.get("/api/whoami").json()
    assert body["subject"] == "local-operator"
    assert "administrator" in body["roles"]
    assert "token" not in str(body).lower()


def test_a_created_project_belongs_to_its_creator(api):
    body = api.post("/api/projects", json={"name": "mine"}).json()
    assert body["owner"] == "local-operator"


def test_an_analyst_cannot_delete_a_project(api):
    from reforge import server

    created = api.post("/api/projects", json={"name": "x"}).json()
    original = server.principal_of
    server.principal_of = lambda request: Principal("bob", roles=frozenset({Role.ANALYST}))
    try:
        r = api.delete(f"/api/projects/{created['id']}")
        # Either forbidden (lacks the permission) or not-found (cannot see someone else's project);
        # both are correct refusals, and neither is a deletion.
        assert r.status_code in (403, 404), r.text
        assert r.json()["error"]["code"] in ("forbidden", "not_found")
    finally:
        server.principal_of = original
    assert api.get(f"/api/projects/{created['id']}").status_code == 200, "it was deleted anyway"


def test_an_analyst_cannot_change_the_security_posture(api):
    from reforge import server

    original = server.principal_of
    server.principal_of = lambda request: Principal("bob", roles=frozenset({Role.ANALYST}))
    try:
        r = api.post("/api/settings", json={"safety_mode": "autonomous"})
        assert r.status_code == 403
        assert r.json()["error"]["context"]["permission"] == "settings:write"
    finally:
        server.principal_of = original
    assert config.SAFETY_MODE != "autonomous", "the posture changed despite the refusal"


def test_an_analyst_cannot_take_the_unredacted_dump(api):
    from reforge import server

    created = api.post("/api/projects", json={"name": "x"}).json()
    original = server.principal_of
    server.principal_of = lambda request: Principal(
        "bob", roles=frozenset({Role.ANALYST}), project_roles={created["id"]: Role.ANALYST})
    try:
        r = api.get(f"/api/projects/{created['id']}/raw-export")
        assert r.status_code in (403, 404)
    finally:
        server.principal_of = original


def test_a_project_listing_is_filtered_to_what_the_caller_may_see(api):
    from reforge import server

    api.post("/api/projects", json={"name": "alice-project"})
    original = server.principal_of
    server.principal_of = lambda request: Principal("bob", roles=frozenset({Role.ANALYST}))
    try:
        listed = api.get("/api/projects").json()["projects"]
        assert all(p.get("name") != "alice-project" for p in listed), \
            "another analyst's project appeared in the listing"
    finally:
        server.principal_of = original


def test_a_refusal_is_audited(api):
    from reforge import server

    original = server.principal_of
    server.principal_of = lambda request: Principal("bob", roles=frozenset({Role.ANALYST}))
    try:
        api.post("/api/settings", json={"safety_mode": "autonomous"})
    finally:
        server.principal_of = original
    denials = [e for e in audit.read(limit=50) if e["action"] == "authz.denied"]
    assert denials and denials[0]["actor"]["subject"] == "bob"
    assert denials[0]["detail"]["permission"] == "settings:write"


def test_the_audit_endpoint_needs_the_audit_permission(api):
    from reforge import server

    original = server.principal_of
    server.principal_of = lambda request: Principal("bob", roles=frozenset({Role.ANALYST}))
    try:
        assert api.get("/api/audit").status_code == 403
    finally:
        server.principal_of = original
    assert api.get("/api/audit").status_code == 200


def test_no_route_returns_the_unfiltered_project_list():
    """A listing route that skips the ownership filter would undo project isolation entirely."""
    from pathlib import Path

    source = (Path(__file__).resolve().parent.parent / "reforge" / "server.py").read_text(
        encoding="utf-8")
    assert "store.list_projects()" not in source, \
        "a route calls the unfiltered listing; use store.list_projects_for(principal)"
