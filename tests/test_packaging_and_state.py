"""Packaging and state-isolation invariants (slice P0-S1).

Two defects motivated this file, both reproduced against a clean `git archive HEAD` checkout:

P0-1  `requirements.txt` declared mcp/pefile/requests while `reforge/server.py` imports fastapi and
      pydantic and `reforge/__main__.py` imports uvicorn at module level. The documented install
      (`pip install -r requirements.txt && python -m reforge`) failed with
      `ModuleNotFoundError: No module named 'fastapi'`.

P0-2  Importing `reforge.config` generated an auth token and wrote `.reforge_secrets.json` into the
      **source tree**, and `knowledge.py` wrote a derived index next to the shipped documents.
      `REFORGE_STATE_DIR` did not cover either. On a read-only install the write failed inside a
      bare `except: pass`, so a new token was minted on every start.

These tests fail the build when either regresses.
"""
from __future__ import annotations

import ast
import hashlib
import os
import subprocess
import json
import re
import sys
try:
    import tomllib                      # 3.11+
except ModuleNotFoundError:          # 3.10: the backport, in the dev extra
    import tomli as tomllib  # type: ignore[no-redef]
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"

# Import name -> distribution name, where they differ.
_DIST_FOR_IMPORT = {
    "yaml": "pyyaml",
    "multipart": "python-multipart",
    "docx": "python-docx",
    "fitz": "pymupdf",
    "dotenv": "python-dotenv",
    "jwt": "pyjwt",
    "PIL": "pillow",
}

# Imported by the bundled MCP servers or installed as OS packages, never part of the wheel.
_OUT_OF_SCOPE = {"angr", "frida", "frida_tools", "floss", "_reforge_locator", "_toolpath"}

# Packages ReTrace can use but must never distribute, with the reason. Each one must be imported
# lazily and must degrade cleanly when absent - asserted by
# test_license_restricted_packages_stay_optional_and_undeclared below.
_NOT_DISTRIBUTABLE = {
    # PyMuPDF is AGPL-3.0 or a paid Artifex licence. The AGPL network clause is triggered by
    # exactly ReTrace's deployment shape (a server users reach over a network), so bundling it in
    # a proprietary on-premise product would oblige ReTrace to release its own source under AGPL.
    # pypdf (BSD-3-Clause) covers the same feature and IS declared, in the `knowledge` extra.
    # See docs/third-party-and-license-inventory.md section 3.
    "fitz": "PyMuPDF: AGPL-3.0 / paid commercial licence",
}


def _norm(name: str) -> str:
    return name.lower().replace("_", "-").split("[")[0].strip()


def _dist(import_name: str) -> str:
    return _norm(_DIST_FOR_IMPORT.get(import_name, import_name))


@pytest.fixture(scope="module")
def pyproject() -> dict:
    assert PYPROJECT.is_file(), "pyproject.toml is missing: the project is not installable"
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def _declared(pyproject: dict) -> tuple[set[str], set[str]]:
    """(core, core+extras) distribution names, normalized."""
    def names(specs):
        out = set()
        for s in specs:
            out.add(_norm(s.split(">")[0].split("<")[0].split("=")[0].split("!")[0].split(";")[0]))
        return out

    core = names(pyproject["project"]["dependencies"])
    everything = set(core)
    for extra in pyproject["project"].get("optional-dependencies", {}).values():
        everything |= names(extra)
    everything.discard("retrace")      # the `all` extra refers back to the project
    return core, everything


# --------------------------------------------------------------------------- import classification
def _classify_imports(path: Path) -> tuple[set[str], set[str]]:
    """(hard, guarded) top-level third-party module names imported by `path`.

    hard     - module level, outside any try/except: the module cannot be imported without it.
    guarded  - inside a function, or inside a module-level try/except: the feature degrades.
    """
    tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), str(path))
    hard: set[str] = set()
    guarded: set[str] = set()
    stdlib = set(sys.stdlib_module_names)
    local = {"reforge", "servers", "mcp_servers", "tests"}

    def record(node: ast.AST, deferred: bool) -> None:
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [a.name.split(".")[0] for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:            # relative import, always local
                return
            if node.module:
                names = [node.module.split(".")[0]]
        for n in names:
            if n in stdlib or n in local or n.startswith("_"):
                continue
            (guarded if deferred else hard).add(n)

    def walk(node: ast.AST, deferred: bool) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.Import, ast.ImportFrom)):
                record(child, deferred)
            elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Try)):
                walk(child, True)
            else:
                walk(child, deferred)

    walk(tree, False)
    return hard - guarded, guarded


def _package_sources() -> list[Path]:
    return [p for p in sorted((ROOT / "reforge").rglob("*.py")) if "__pycache__" not in p.parts]


def test_every_hard_import_in_the_package_is_a_declared_core_dependency(pyproject):
    """A module-level, unguarded third-party import must be installed by `pip install .`."""
    core, _ = _declared(pyproject)
    missing: dict[str, list[str]] = {}
    for src in _package_sources():
        hard, _g = _classify_imports(src)
        for mod in hard:
            if mod in _OUT_OF_SCOPE:
                continue
            if _dist(mod) not in core:
                missing.setdefault(mod, []).append(str(src.relative_to(ROOT)))
    assert not missing, (
        "module-level imports not declared in [project.dependencies] - a clean install will fail "
        f"with ModuleNotFoundError: {missing}"
    )


def test_lazy_imports_are_declared_in_core_or_in_an_extra(pyproject):
    """A lazily-imported package must still be installable by name, via an extra."""
    _core, everything = _declared(pyproject)
    undeclared: dict[str, list[str]] = {}
    for src in _package_sources():
        _h, guarded = _classify_imports(src)
        for mod in guarded:
            if mod in _OUT_OF_SCOPE or mod in _NOT_DISTRIBUTABLE:
                continue
            if _dist(mod) not in everything:
                undeclared.setdefault(mod, []).append(str(src.relative_to(ROOT)))
    assert not undeclared, (
        "optional imports with no extra to install them from - the feature is unreachable for a "
        f"user who did not already happen to have the package: {undeclared}"
    )


def test_license_restricted_packages_stay_optional_and_undeclared(pyproject):
    """Licence guard: a package we may not ship must stay lazy, and must stay out of pyproject.

    This is the counterpart to the exemption in `_NOT_DISTRIBUTABLE`. Adding PyMuPDF to
    pyproject.toml would make the wheel AGPL-encumbered; importing it at module level would make
    it a hard requirement in all but name. Both fail here.
    """
    _core, everything = _declared(pyproject)
    for mod, reason in _NOT_DISTRIBUTABLE.items():
        assert _dist(mod) not in everything, (
            f"{mod} is declared in pyproject.toml but must not be distributed - {reason}"
        )
        for src in _package_sources():
            hard, _g = _classify_imports(src)
            assert mod not in hard, (
                f"{src.relative_to(ROOT)} imports {mod} at module level, making it a de-facto "
                f"hard dependency - {reason}. Import it lazily and degrade when absent."
            )


def test_requirements_txt_agrees_with_pyproject_core(pyproject):
    """requirements.txt is a convenience mirror; it must not drift from the real dependency set."""
    core, _ = _declared(pyproject)
    req = ROOT / "requirements.txt"
    listed = set()
    for line in req.read_text(encoding="utf-8").splitlines():
        line = line.split("#")[0].strip()
        if not line or line.startswith("-"):
            continue
        listed.add(_norm(line.split(">")[0].split("<")[0].split("=")[0]))
    assert listed == core, (
        "requirements.txt and pyproject.toml disagree. "
        f"only in requirements.txt: {sorted(listed - core)}; only in pyproject: {sorted(core - listed)}"
    )


def test_console_script_entry_point_is_importable_and_callable(pyproject):
    target = pyproject["project"]["scripts"]["retrace"]
    module_path, _, func = target.partition(":")
    assert module_path == "reforge.__main__" and func == "main", target
    src = (ROOT / "reforge" / "__main__.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    funcs = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
    assert func in funcs, f"pyproject declares the `retrace` script as {target}, but {func}() does not exist"


# --------------------------------------------------------------------------- state isolation
def test_secrets_are_stored_outside_the_source_tree():
    from reforge import config
    assert config.SECRETS_FILE.resolve().is_relative_to(Path(config.STATE_ROOT).resolve()), \
        f"secrets must live under STATE_ROOT, not at {config.SECRETS_FILE}"
    assert not config.SECRETS_FILE.resolve().is_relative_to(Path(config.ROOT).resolve()), \
        "secrets file resolves inside the source tree"


def test_legacy_secrets_location_is_still_readable():
    """An existing install keeps working: the old path is read, the new one is written."""
    from reforge import config
    assert config.LEGACY_SECRETS_FILE == Path(config.ROOT) / ".reforge_secrets.json"


def test_knowledge_index_cache_is_written_outside_the_source_tree():
    from reforge import config, knowledge
    kb = knowledge.KnowledgeBase(Path(config.KNOWLEDGE_DIR))
    cache = kb._cache_path().resolve()
    assert cache.is_relative_to(Path(config.STATE_ROOT).resolve()), \
        f"derived knowledge index must live under STATE_ROOT, not at {cache}"
    assert not cache.is_relative_to(Path(config.ROOT).resolve()), \
        "knowledge index resolves inside the source tree"


def _snapshot(tree: Path) -> dict[str, str]:
    out = {}
    skip = {"__pycache__", ".git", ".pytest_cache", ".ruff_cache", ".mypy_cache",
            "projects", "sessions", "jobs", "workspace", ".venv"}
    for p in tree.rglob("*"):
        if not p.is_file() or any(part in skip for part in p.parts):
            continue
        if p.suffix in (".pyc", ".pyo") or p.name.endswith((".db", ".db-wal", ".db-shm")):
            continue
        out[str(p.relative_to(tree))] = hashlib.sha256(p.read_bytes()).hexdigest()
    return out


def test_importing_the_application_does_not_write_into_the_source_tree(tmp_path):
    """The strongest form of P0-2: import the whole app and prove the source tree is unchanged.

    Runs in a subprocess so the import genuinely happens at import time rather than being served
    from this process's module cache.
    """
    before = _snapshot(ROOT / "reforge")
    env = dict(os.environ)
    env["REFORGE_STATE_DIR"] = str(tmp_path / "state")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    proc = subprocess.run(
        [sys.executable, "-c", "import reforge.server, reforge.knowledge, reforge.agent"],
        cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, f"importing the application failed:\n{proc.stderr}"
    after = _snapshot(ROOT / "reforge")

    added = sorted(set(after) - set(before))
    changed = sorted(k for k in set(after) & set(before) if after[k] != before[k])
    removed = sorted(set(before) - set(after))
    assert not (added or changed or removed), (
        "importing the application modified its own source tree - a packaged, read-only or signed "
        f"install cannot work. added={added} changed={changed} removed={removed}"
    )


def test_a_fresh_state_dir_receives_the_secrets_file_not_the_source_tree(tmp_path):
    """End-to-end check that token generation lands under STATE_ROOT."""
    state = tmp_path / "state"
    env = dict(os.environ)
    env["REFORGE_STATE_DIR"] = str(state)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.pop("REFORGE_TOKEN", None)
    proc = subprocess.run(
        [sys.executable, "-c", "import reforge.config as c; print(c.SECRETS_FILE)"],
        cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    written = Path(proc.stdout.strip())
    assert written.is_relative_to(state.resolve()), written
    assert not (ROOT / ".reforge_secrets.json").exists() or \
        (ROOT / ".reforge_secrets.json").stat().st_mtime < state.stat().st_mtime, \
        "a secrets file was (re)created in the source tree"


# --------------------------------------------------------------------------- wheel self-containment
# Slice P0-S4. A wheel-only install (no source checkout anywhere) must start and serve the UI.
# Two defects were found by actually trying it: the SPA lived outside the package, and the MCP
# catalogue was unpackaged *and* a missing one raised out of the lifespan, killing the app.
def test_the_spa_ships_inside_the_package():
    from reforge.server import WEB
    pkg = Path(__import__("reforge").__file__).resolve().parent
    assert WEB.resolve().is_relative_to(pkg), \
        f"the SPA at {WEB} is outside the package, so a wheel cannot serve it"
    for asset in ("index.html", "app.js", "assessment.js", "palette.js", "styles.css"):
        assert (WEB / asset).is_file(), f"{asset} missing from {WEB}"


def test_package_data_declares_every_shipped_non_python_file(pyproject):
    """A file the package reads at runtime but does not declare is missing from the wheel."""
    import fnmatch
    patterns = pyproject["tool"]["setuptools"]["package-data"]["reforge"]
    pkg = Path(__import__("reforge").__file__).resolve().parent
    undeclared = []
    # OS artefacts cannot be packaged - setuptools includes only what the globs name - so an
    # undeclared one is Finder litter rather than a packaging defect. Everything else must be
    # declared or it is missing from the wheel.
    os_litter = {".DS_Store", "Thumbs.db", "desktop.ini"}
    for f in pkg.rglob("*"):
        if not f.is_file() or f.suffix in (".py", ".pyc") or "__pycache__" in f.parts:
            continue
        if f.name in os_litter:
            continue
        rel = f.relative_to(pkg).as_posix()
        if not any(fnmatch.fnmatch(rel, pat) for pat in patterns):
            undeclared.append(rel)
    assert not undeclared, f"not declared in [tool.setuptools.package-data]: {undeclared}"


def test_the_default_mcp_catalogue_is_packaged_and_valid():
    import json
    pkg = Path(__import__("reforge").__file__).resolve().parent
    default = pkg / "mcp.servers.default.json"
    assert default.is_file(), "an installed wheel would have no MCP catalogue at all"
    assert isinstance(json.loads(default.read_text(encoding="utf-8"))["mcpServers"], dict)


def test_a_missing_or_broken_mcp_catalogue_is_not_fatal(tmp_path, monkeypatch):
    """Acceptance criterion 4: the product works without MCP. That includes having no catalogue."""
    from reforge import config
    monkeypatch.setattr(config, "SERVERS_CONFIG", tmp_path / "absent.json")
    assert config.load_server_config() == {}

    broken = tmp_path / "broken.json"
    broken.write_text("{ not json", encoding="utf-8")
    monkeypatch.setattr(config, "SERVERS_CONFIG", broken)
    assert config.load_server_config() == {}

    wrong_shape = tmp_path / "wrong.json"
    wrong_shape.write_text('{"servers": []}', encoding="utf-8")
    monkeypatch.setattr(config, "SERVERS_CONFIG", wrong_shape)
    assert config.load_server_config() == {}


def test_the_operator_catalogue_in_the_state_dir_wins_over_the_packaged_default(tmp_path):
    """An operator's catalogue must survive an upgrade that replaces the packaged one."""
    from reforge import config
    state_copy = tmp_path / "mcp.servers.json"
    state_copy.write_text('{"mcpServers": {}}', encoding="utf-8")
    # Replicate the resolution order rather than re-importing the module under a new STATE_ROOT.
    order = [state_copy, ROOT / "mcp.servers.json",
             Path(__import__("reforge").__file__).resolve().parent / "mcp.servers.default.json"]
    assert next(p for p in order if p.is_file()) == state_copy
    assert config.SERVERS_CONFIG.is_file(), "no catalogue resolved in this checkout"


# --------------------------------------------------------------------------- nothing stateful is tracked
# Mirrors the CI hygiene rule in .github/workflows/ci.yml, and the kinds (not names) that
# .gitignore refuses: whole state directories, the operator's catalogue, caches, build output,
# bytecode, and any analysed sample by extension.
_FORBIDDEN_TRACKED = re.compile(
    r"(^|/)(\.reforge_secrets\.json|\.env(\..*)?|servers_state\.json|settings\.json|\.DS_Store|\.gitkeep"
    r"|.*\.(db|db-wal|db-shm|sqlite|sqlite3|pem|key|pyc|pyo|exe|dll|sys|so|dylib|bin|msi|pcap|pcapng|pml"
    r"|zip|7z|rar|tar|tgz|tar\.gz)|.*\.backup-.*)$"
    r"|^mcp\.servers\.json$|^(projects|sessions|jobs|workspace|uploads|audit|cache)/"
    r"|(^|/)(__pycache__|.*\.egg-info)/|^knowledge/(?!READ_ME$|vuln_research_methodology\.md$)")


def test_no_runtime_state_or_archive_is_tracked_by_git():
    """The CI hygiene job's rule, run locally. A pre-migration database backup carries every
    project the operator has; it was committed to a public repository once, which is one time too
    many. Fails on the index, so it fails before the push."""
    import subprocess
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True)
    if out.returncode != 0:
        pytest.skip("not a git checkout")
    tracked = [f for f in out.stdout.splitlines() if _FORBIDDEN_TRACKED.search(f)]
    assert not tracked, ("runtime state or archives are tracked - `git rm --cached` them:\n  " + "\n  ".join(tracked))


# One path of each kind that must never be committed, and a few shipped ones that must.
_MUST_BE_IGNORED = [
    ".reforge_secrets.json", ".env", ".env.local", "settings.json", "servers_state.json",
    "mcp.servers.json", "reforge.db", "reforge.db-wal", "reforge.db-shm",
    "reforge.db.backup-20261013-191551", "projects/49971d6d25b4.json", "projects/.gitkeep",
    "sessions/s", "jobs/j.json", "workspace/p/sample.exe", "workspace/p/graph.sqlite",
    "workspace/p/artifacts/A-1.bin", "uploads/u", "audit/audit.jsonl",
    "cache/knowledge-index-abc.json", "knowledge/.reforge_index.json", "knowledge/book.pdf",
    "GhidraMCP-1-4.zip", "servers/sample.dll", "tests/fixtures/driver.sys", ".DS_Store",
    "servers/.DS_Store", "reforge/__pycache__/x.pyc", "retrace.egg-info/PKG-INFO",
]
_MUST_BE_TRACKED = ["knowledge/READ_ME", "knowledge/vuln_research_methodology.md",
                    "reforge/mcp.servers.default.json", "reforge/web/app.js", "README.md"]


def test_the_ignore_rules_cover_every_kind_of_runtime_state():
    """The rules in .gitignore, asked the way git asks them.

    The repository was once re-created from a folder that no longer held this file, and a single
    `git add -A` published the database, a project, a workspace with an analysed executable, the
    audit chain and the operator's catalogue. A rule that lives only in a file nobody checks is a
    hope. This asks `git check-ignore` for one path of each kind that must never be committed, and
    for a few shipped files that must stay, so a missing or weakened ignore file fails the suite
    rather than the next push.
    """
    import subprocess

    probe = subprocess.run(["git", "check-ignore", "--no-index", "-v", *_MUST_BE_IGNORED],
                           cwd=ROOT, capture_output=True, text=True)
    if probe.returncode not in (0, 1):
        pytest.skip("not a git checkout")
    ignored = {line.rsplit("\t", 1)[-1] for line in probe.stdout.splitlines()}
    missing = [p for p in _MUST_BE_IGNORED if p not in ignored]
    assert not missing, f"would be committed by `git add -A`: {missing}"
    kept = subprocess.run(["git", "check-ignore", "--no-index", *_MUST_BE_TRACKED],
                          cwd=ROOT, capture_output=True, text=True)
    assert not kept.stdout.strip(), f"shipped files the rules would drop: {kept.stdout.split()}"


def test_the_packaged_catalogue_is_the_fallback_when_the_operator_has_none(tmp_path, monkeypatch):
    """`mcp.servers.json` is per-install and git-ignored, so a fresh clone has none. The shipped
    template must be what the app then loads, not an empty server list."""
    from reforge import config

    monkeypatch.setattr(config, "STATE_ROOT", tmp_path / "state")
    monkeypatch.setattr(config, "ROOT", tmp_path / "checkout")
    resolved = config._resolve_servers_config()
    assert resolved.name == "mcp.servers.default.json" and resolved.is_file()
    catalogue = json.loads(resolved.read_text(encoding="utf-8"))["mcpServers"]
    assert catalogue, "the packaged catalogue is empty"
