"""Workspace + safe path handling.

Analyzed-file paths come from the UI/API and must be treated as untrusted. `safe_resolve`
rejects path traversal, resolves symlinks, and (when confinement is on) ensures the file lives
inside the configured workspace. Filenames for uploads are sanitized to a safe basename.

Confinement is governed by config.ALLOW_OUTSIDE_WORKSPACE:
  * False  -> strict: only files inside the workspace can be analyzed (recommended for shared/exposed setups)
  * True   -> permissive: absolute paths anywhere are allowed (preserves the analyst's existing
              workflow of pointing at binaries already on the RE machine). Traversal is STILL rejected
              and the path is still resolved; only the workspace-confinement check is relaxed.
"""
import logging
import re
from pathlib import Path

from . import config

log = logging.getLogger("reforge.workspace")


class UnsafePathError(ValueError):
    """Raised when a requested path is rejected by the sandbox policy."""


_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")

# Sensitive locations rejected even in permissive (ALLOW_OUTSIDE_WORKSPACE) mode.
_DENY_PARTS = [
    ["etc"], ["root"], ["proc"], ["sys"], ["boot"], ["dev"],
    ["windows", "system32"], ["windows"], ["program files"], ["program files (x86)"],
]
_DENY_NAMES = {"passwd", "shadow", "sudoers", "id_rsa", "id_ed25519"}


def sanitize_filename(name: str) -> str:
    """Reduce an arbitrary user-provided filename to a safe basename (no dirs, no traversal)."""
    base = Path(str(name or "")).name            # strip any directory components
    base = base.replace("\x00", "")
    base = _SAFE_NAME.sub("_", base).strip("._") or "sample.bin"
    return base[:128]


def workspace_dir() -> Path:
    d = Path(getattr(config, "WORKSPACE_DIR", config.ROOT / "workspace"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def project_dir(project_id: str) -> Path:
    pid = sanitize_filename(project_id) or "default"
    d = workspace_dir() / pid
    d.mkdir(parents=True, exist_ok=True)
    return d


def allowed_roots() -> list:
    """Absolute, resolved directories outside the workspace that may be analyzed."""
    out = []
    for entry in (getattr(config, "EXTERNAL_ROOTS", None) or []):
        raw = str(entry or "").strip()
        if not raw:
            continue
        expanded = Path(raw).expanduser()
        # Absoluteness is checked BEFORE resolving. `Path("samples").resolve()` silently becomes
        # cwd-relative, so a relative entry would make the allow-list mean something different
        # depending on where the server happened to be started - the one thing an allow-list at a
        # security boundary must never do. `~` is expanded first because it names a fixed location.
        if not expanded.is_absolute():
            log.warning("ignoring relative external_roots entry %r: name an absolute directory", raw)
            continue
        try:
            out.append(expanded.resolve())
        except (OSError, RuntimeError):
            continue
    return out


def _within_allowed_root(resolved: Path) -> bool:
    return any(_is_within(resolved, root) for root in allowed_roots())


def _reject_if_deny_listed(resolved: Path) -> None:
    """Secondary net for permissive mode. Enumerating what to protect can never be complete."""
    parts = [part.lower() for part in resolved.parts]
    if resolved.name.lower() in _DENY_NAMES:
        raise UnsafePathError("access to a sensitive system file denied")
    for seq in _DENY_PARTS:
        n = len(seq)
        if any(parts[i:i + n] == seq for i in range(len(parts) - n + 1)):
            raise UnsafePathError("access to a sensitive system directory denied")
    if ".ssh" in parts:
        raise UnsafePathError("access to a sensitive directory (.ssh) denied")


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def safe_resolve(path: str, *, must_exist: bool = True) -> Path:
    """Resolve a user-supplied path safely.

    - Rejects empty paths and raw traversal sequences.
    - Resolves symlinks/relatives via Path.resolve().
    - Enforces workspace confinement unless config.ALLOW_OUTSIDE_WORKSPACE is True.
    Raises UnsafePathError on any violation.
    """
    raw = (path or "").strip()
    if not raw:
        raise UnsafePathError("empty path")
    # Obvious traversal markers (checked on the raw input before resolution).
    if ".." in raw.replace("\\", "/").split("/"):
        raise UnsafePathError("traversal (..) not allowed")

    ws = workspace_dir().resolve()
    p = Path(raw)
    if not p.is_absolute():
        p = ws / p                                # relative paths are relative to the workspace
    try:
        resolved = p.resolve()
    except (OSError, RuntimeError) as exc:        # e.g. symlink loop
        raise UnsafePathError(f"path cannot be resolved: {exc}") from exc

    # Allow-list first: the workspace, plus any root the operator has explicitly named.
    #
    # A deny-list at a security boundary can only enumerate what someone thought of. The one below
    # misses ~/.aws, ~/.config, ~/Library/Keychains, ~/.docker and /var, among others. Naming the
    # directories where samples actually live inverts that: everything not named is refused, and
    # the list of what to protect no longer has to be complete.
    if _is_within(resolved, ws) or _within_allowed_root(resolved):
        if must_exist and not resolved.is_file():
            raise UnsafePathError("file does not exist or is not a regular file")
        return resolved

    confined = not getattr(config, "ALLOW_OUTSIDE_WORKSPACE", False)
    if confined:
        roots = allowed_roots()
        extra = (" or one of the allowed roots: " + ", ".join(str(r) for r in roots)) if roots else ""
        raise UnsafePathError(
            f"the file must be inside the workspace ({ws}){extra}. "
            "Add its directory to `external_roots`, or move the sample into the workspace.")

    # Permissive mode (allow_outside_workspace=true, no allow-list): fall back to the deny-list.
    # Kept for the existing workflow of pointing at binaries already on the RE machine, and
    # structurally incomplete by nature - which is why it is no longer the default.
    _reject_if_deny_listed(resolved)

    if must_exist and not resolved.is_file():
        raise UnsafePathError("file does not exist or is not a regular file")
    return resolved
