"""Centralized, pure authorization decision for the local API.

Kept dependency-free and side-effect-free so it is trivially unit-testable. The HTTP middleware
in server.py extracts the request fields and delegates the decision here.
"""
LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def authorize(path: str, method: str, client_host: str, *,
              token_provided: str, token_expected: str,
              auth_required: bool, trust_localhost: bool) -> bool:
    """Return True if the request is allowed.

    Rules: non-/api paths and OPTIONS are always allowed (static assets, preflight). When auth is
    required, loopback clients may be trusted; otherwise the provided token must equal the expected
    token (which must be non-empty).
    """
    if not auth_required:
        return True
    if not path.startswith("/api/"):
        return True
    if method == "OPTIONS":
        return True
    if trust_localhost and (client_host or "") in LOOPBACK:
        return True
    return bool(token_expected) and token_provided == token_expected
