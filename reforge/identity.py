"""Identity, roles and permissions (slice P2-S1).

Before this there was one process-wide shared token and nothing else. Anyone who could reach the
API could read, modify, export or delete every project of every customer, and no record said who
did. `DELETE /api/projects/{pid}` required only the ability to reach the endpoint. For a product
sold to a team that is not a missing feature, it is a missing security model.

Two things are deliberately kept apart:

* **Authentication** - who is calling - is pluggable (`providers.py`). The workstation profile has
  a single implicit local operator and stays frictionless; a team deployment validates a bearer
  token from its own identity provider.
* **Authorization** - what they may do - is this module, and it is the same code in both cases.
  A permission check must not depend on how the caller proved who they were, or the two paths
  drift and the simpler one quietly becomes the weaker one.

Permissions are explicit per role rather than hierarchical. A hierarchy ("manager implies
analyst") reads well and then surprises you: the moment one role needs an ability a notionally
lower one must not have, the ladder is wrong and every check built on it is wrong with it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, Optional


class Role(str, Enum):
    ADMINISTRATOR = "administrator"
    SECURITY_MANAGER = "security_manager"
    ANALYST = "analyst"
    REVIEWER = "reviewer"
    READ_ONLY = "read_only"


class Permission(str, Enum):
    # --- projects
    PROJECT_READ = "project:read"
    PROJECT_CREATE = "project:create"
    PROJECT_WRITE = "project:write"
    PROJECT_DELETE = "project:delete"
    PROJECT_SHARE = "project:share"
    # --- analysis
    ANALYSIS_RUN = "analysis:run"
    ARTIFACT_UPLOAD = "artifact:upload"
    # --- findings
    FINDING_WRITE = "finding:write"
    FINDING_REVIEW = "finding:review"          # accept risk, suppress, sign off
    # --- gated actions
    APPROVAL_GRANT = "approval:grant"          # authorise a dynamic/write/network tool call
    # --- data out
    REPORT_EXPORT = "report:export"
    RAW_EXPORT = "raw:export"                  # the unredacted dump
    # --- administration
    SETTINGS_READ = "settings:read"
    SETTINGS_WRITE = "settings:write"
    SERVER_MANAGE = "server:manage"            # enable/disable MCP servers
    AUDIT_READ = "audit:read"
    USER_MANAGE = "user:manage"


_READ_ONLY: FrozenSet[Permission] = frozenset({
    Permission.PROJECT_READ,
    Permission.SETTINGS_READ,
})

#: Reviewer: can read everything in a project and make review decisions, but cannot run analysis
#: or change the target. Someone signing off on a finding should not also be able to re-run the
#: analysis that produced it.
_REVIEWER: FrozenSet[Permission] = _READ_ONLY | frozenset({
    Permission.FINDING_REVIEW,
    Permission.REPORT_EXPORT,
})

#: Analyst: the working role. Runs analysis, uploads samples, records findings, exports reports.
#: Notably NOT: raw export (the unredacted dump), settings, or user management.
_ANALYST: FrozenSet[Permission] = _READ_ONLY | frozenset({
    Permission.PROJECT_CREATE,
    Permission.PROJECT_WRITE,
    Permission.ANALYSIS_RUN,
    Permission.ARTIFACT_UPLOAD,
    Permission.FINDING_WRITE,
    Permission.APPROVAL_GRANT,
    Permission.REPORT_EXPORT,
})

#: Security manager: an analyst who can also review, delete, share and read the audit trail.
#: Still not settings or user management - running an engagement and administering the platform
#: are different jobs, and the person doing the first should not be able to turn off the controls
#: on the second.
_SECURITY_MANAGER: FrozenSet[Permission] = _ANALYST | frozenset({
    Permission.FINDING_REVIEW,
    Permission.PROJECT_DELETE,
    Permission.PROJECT_SHARE,
    Permission.RAW_EXPORT,
    Permission.AUDIT_READ,
})

_ADMINISTRATOR: FrozenSet[Permission] = frozenset(Permission)

ROLE_PERMISSIONS: Dict[Role, FrozenSet[Permission]] = {
    Role.READ_ONLY: _READ_ONLY,
    Role.REVIEWER: _REVIEWER,
    Role.ANALYST: _ANALYST,
    Role.SECURITY_MANAGER: _SECURITY_MANAGER,
    Role.ADMINISTRATOR: _ADMINISTRATOR,
}


@dataclass(frozen=True)
class Principal:
    """Who is calling, and what they are allowed to do.

    `subject` is the stable identifier from the identity provider - never the email, which people
    change and which providers reuse.
    """
    subject: str
    display_name: str = ""
    email: str = ""
    roles: FrozenSet[Role] = field(default_factory=frozenset)
    #: Per-project role overrides: {project_id: Role}. A grant here is additive to the global role
    #: and cannot take away a permission the global role confers.
    project_roles: Dict[str, Role] = field(default_factory=dict)
    is_local_operator: bool = False
    auth_method: str = "none"

    # ---------------------------------------------------------------- permissions
    def global_permissions(self) -> FrozenSet[Permission]:
        out: FrozenSet[Permission] = frozenset()
        for role in self.roles:
            out = out | ROLE_PERMISSIONS.get(role, frozenset())
        return out

    def permissions_for(self, project_id: Optional[str] = None) -> FrozenSet[Permission]:
        out = self.global_permissions()
        if project_id:
            role = self.project_roles.get(project_id)
            if role:
                out = out | ROLE_PERMISSIONS.get(role, frozenset())
        return out

    def can(self, permission: Permission, project_id: Optional[str] = None) -> bool:
        return permission in self.permissions_for(project_id)

    def is_anonymous(self) -> bool:
        return not self.subject

    def describe(self) -> Dict[str, Any]:
        """For the audit log and /api/whoami. Never includes a credential."""
        return {
            "subject": self.subject,
            "display_name": self.display_name,
            "email": self.email,
            "roles": sorted(r.value for r in self.roles),
            "auth_method": self.auth_method,
            "is_local_operator": self.is_local_operator,
        }


class AccessDenied(PermissionError):
    """A principal lacks a permission. Carries enough to audit the refusal, never the credential."""

    def __init__(self, principal: Principal, permission: Permission,
                 project_id: Optional[str] = None):
        target = f" on project {project_id}" if project_id else ""
        super().__init__(f"{principal.subject or 'anonymous'} lacks {permission.value}{target}")
        self.principal = principal
        self.permission = permission
        self.project_id = project_id


def require(principal: Principal, permission: Permission,
            project_id: Optional[str] = None) -> None:
    """Raise AccessDenied unless `principal` holds `permission`."""
    if not principal.can(permission, project_id):
        raise AccessDenied(principal, permission, project_id)


# --------------------------------------------------------------------------- the local operator
#: The single implicit user of the workstation profile.
#:
#: It is an administrator because on a single-user workstation there is nobody to separate duties
#: *from*: pretending otherwise would add friction without adding a boundary. What it is NOT is a
#: fallback for the other profiles - `providers.resolve()` refuses to mint it outside
#: `workstation`, so a misconfigured shared deployment fails closed rather than silently
#: handing everyone administrator.
LOCAL_OPERATOR = Principal(
    subject="local-operator",
    display_name="Local operator",
    roles=frozenset({Role.ADMINISTRATOR}),
    is_local_operator=True,
    auth_method="local",
)

ANONYMOUS = Principal(subject="", display_name="anonymous", roles=frozenset(), auth_method="none")


def parse_roles(values: Any) -> FrozenSet[Role]:
    """Map arbitrary claim values onto known roles. Unknown values are ignored, never guessed."""
    if isinstance(values, str):
        values = [values]
    out = set()
    for value in (values or []):
        try:
            out.add(Role(str(value).strip().lower()))
        except ValueError:
            continue
    return frozenset(out)
