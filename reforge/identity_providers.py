"""Authentication: proving who is calling (slice P2-S1).

Separated from `identity.py` on purpose. Authorization must be the same code whichever way the
caller authenticated, or the simpler path quietly becomes the weaker one.

Two providers:

* **local** - the workstation profile's single implicit operator. Frictionless, and refused
  outright on any other profile so a misconfigured team deployment fails closed instead of
  handing everyone administrator.
* **oidc_bearer** - validates an `Authorization: Bearer <jwt>` against the issuer's JWKS and maps
  its claims onto roles. This is the enforcement half of OIDC and the half an API needs.

**Not implemented, and it fails closed rather than pretending:** the interactive authorization-code
flow (redirect, PKCE, callback, session establishment). A browser reaching a deployment configured
for `oidc_bearer` with no bearer token is refused, not waved through. Deploy behind an
authenticating proxy that performs the flow and forwards the token, or wait for P2-S1b.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from .identity import ANONYMOUS, LOCAL_OPERATOR, Principal, parse_roles

log = logging.getLogger("reforge.identity")

class AuthenticationError(RuntimeError):
    """The caller presented a credential and it was not valid."""


class IdentityProviderUnavailable(RuntimeError):
    """The identity provider could not be reached, so the caller could not be authenticated.

    Distinct from AuthenticationError on purpose: "your token is invalid" (401, the caller's
    problem) and "we cannot check your token right now" (503, ours) are different answers, and
    collapsing them tells an operator their users' credentials broke when the IdP is simply down.
    """


def _bearer(headers) -> str:
    value = headers.get("authorization") or ""
    scheme, _, token = value.partition(" ")
    return token.strip() if scheme.lower() == "bearer" else ""


# --------------------------------------------------------------------------- OIDC
def _discover_jwks_url(issuer: str) -> str:
    import httpx

    well_known = issuer.rstrip("/") + "/.well-known/openid-configuration"
    try:
        response = httpx.get(well_known, timeout=10.0)
        response.raise_for_status()
        url = response.json().get("jwks_uri")
    except Exception as exc:
        raise IdentityProviderUnavailable(
            f"could not reach the identity provider at {well_known}: {exc}") from exc
    if not url:
        raise IdentityProviderUnavailable(f"{well_known} does not advertise a jwks_uri")
    return url


def _looks_like_a_jwt(token: str) -> bool:
    """Three dot-separated non-empty segments. Checked before any network call.

    A malformed token is the caller's problem and needs no key set to establish. Going to the
    identity provider first would make every junk request a round trip, and would turn a
    typo into an outage-shaped error.
    """
    parts = token.split(".")
    return len(parts) == 3 and all(parts)


def validate_bearer(token: str, *, issuer: str, audience: str,
                    jwks_url: str = "") -> Dict[str, Any]:
    """Verify a JWT's signature, issuer, audience and expiry. Returns its claims.

    Everything here is a hard failure. A token that cannot be verified is not a token with fewer
    privileges, it is an unauthenticated request.
    """
    try:
        import jwt
        from jwt import PyJWKClient
    except ImportError as exc:                 # pragma: no cover - dependency is declared
        raise AuthenticationError(
            "OIDC is configured but PyJWT is not installed; install retrace[oidc]") from exc

    if not token:
        raise AuthenticationError("no bearer token")
    if not _looks_like_a_jwt(token):
        raise AuthenticationError("the bearer token is not valid")
    if not issuer:
        raise IdentityProviderUnavailable("oidc_issuer is not configured")

    url = jwks_url or _discover_jwks_url(issuer)
    try:
        signing_key = PyJWKClient(url, cache_keys=True).get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token, signing_key.key,
            algorithms=["RS256", "RS384", "RS512", "ES256", "ES384"],
            audience=audience or None,
            issuer=issuer,
            options={"require": ["exp", "iss", "sub"], "verify_aud": bool(audience)},
        )
    except Exception as exc:
        # The reason is logged, never returned: telling an unauthenticated caller *why* their
        # token failed helps them craft a better one.
        log.warning("bearer token rejected: %s: %s", type(exc).__name__, exc)
        raise AuthenticationError("the bearer token is not valid") from exc
    return claims


def principal_from_claims(claims: Dict[str, Any], *, roles_claim: str = "roles",
                          role_map: Optional[Dict[str, str]] = None,
                          default_role: str = "") -> Principal:
    """Map verified claims onto a Principal.

    Unmapped group names are ignored rather than guessed: an identity provider that sends
    `security-team` must be told what that means here, because inferring it is how someone ends up
    with permissions nobody granted.
    """
    raw = claims.get(roles_claim)
    if raw is None and "." in roles_claim:               # nested, e.g. "realm_access.roles"
        node: Any = claims
        for part in roles_claim.split("."):
            node = (node or {}).get(part) if isinstance(node, dict) else None
        raw = node

    values: List[str] = []
    if isinstance(raw, str):
        values = [raw]
    elif isinstance(raw, (list, tuple)):
        values = [str(v) for v in raw]

    mapping = {k.lower(): v for k, v in (role_map or {}).items()}
    mapped = [mapping.get(str(v).lower(), v) for v in values]
    roles = parse_roles(mapped)
    if not roles and default_role:
        roles = parse_roles([default_role])

    return Principal(
        subject=str(claims.get("sub") or ""),
        display_name=str(claims.get("name") or claims.get("preferred_username") or ""),
        email=str(claims.get("email") or ""),
        roles=roles,
        auth_method="oidc_bearer",
    )


# --------------------------------------------------------------------------- resolution
def resolve(request, cfg) -> Principal:
    """Who is calling. Returns ANONYMOUS when nobody proved anything.

    `cfg` is the config facade, passed in so this module stays importable and testable without
    pulling the whole application in behind it.
    """
    profile = getattr(cfg, "DEPLOYMENT_PROFILE", "workstation")
    mode = getattr(cfg, "IDENTITY_PROVIDER", "local")

    if mode == "oidc_bearer":
        token = _bearer(request.headers)
        if not token:
            return ANONYMOUS
        claims = validate_bearer(
            token,
            issuer=getattr(cfg, "OIDC_ISSUER", ""),
            audience=getattr(cfg, "OIDC_AUDIENCE", ""),
            jwks_url=getattr(cfg, "OIDC_JWKS_URL", ""),
        )
        return principal_from_claims(
            claims,
            roles_claim=getattr(cfg, "OIDC_ROLES_CLAIM", "roles"),
            role_map=getattr(cfg, "OIDC_ROLE_MAP", None),
            default_role=getattr(cfg, "OIDC_DEFAULT_ROLE", ""),
        )

    # Local operator. Only the workstation profile may have one: on any other profile this would
    # mean "whoever holds the shared token is an administrator", which is the model being replaced.
    if profile == "workstation":
        return LOCAL_OPERATOR
    log.error("identity_provider=local is not allowed on profile %r; refusing the request. "
              "Configure identity_provider=oidc_bearer.", profile)
    return ANONYMOUS
