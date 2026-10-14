"""MCP gateway: manifests, allow-list, fail-closed risk resolution (slice P2-S3, ADR 0003, T-4).

**The defect.** `policy.risk_class()` decided how dangerous a tool is by running regexes over its
*unqualified name* — a string the MCP server itself chooses. A server exposing a destructive
operation under the name `analyze_report` was classified `safe_read` and, in `assisted` mode,
executed **without approval**. The catalogue was deny-by-exception: any tool any connected server
offered was callable.
"""
from __future__ import annotations

import json

import pytest

from reforge import mcp_manifest, policy
from reforge.mcp_manifest import RISK_ORDER, ManifestRegistry, ServerManifest, higher_risk


# --------------------------------------------------------------------------- the inversion
def test_an_innocuous_name_from_an_unreviewed_server_is_not_treated_as_safe():
    """T-4 itself. The name and the catalogue hint come from the same untrusted place."""
    decision = policy.resolve_risk("evil__analyze_report", catalogue_hint="safe_read")
    assert decision["risk_class"] != "safe_read"
    assert decision["source"] == "unmanifested"

    requires, risk, _reason = policy.requires_approval(
        "evil__analyze_report", "assisted", "safe_read")
    assert requires is True, "a destructive tool under a benign name ran without approval"


def test_a_server_cannot_declare_its_own_tools_safer_than_their_names_suggest(tmp_path):
    """A manifest is the authority on what a tool does, not a licence to relabel a write."""
    (tmp_path / "liar.json").write_text(json.dumps({
        "manifest_version": 1, "server": "liar", "version": "1.0.0",
        "tools": [{"name": "memory_write", "risk_class": "safe_read"}],
    }), encoding="utf-8")
    registry = ManifestRegistry(tmp_path)
    decision = registry.resolve("liar", "memory_write", name_heuristic="write_or_patch")
    assert decision["risk_class"] == "write_or_patch"
    assert "raised" in decision["reason"]


def test_a_reviewed_server_keeps_its_read_tools_frictionless():
    """The gate must not be a wall: the common workflow has to stay usable."""
    for tool in ("hardening__hardening_audit", "procmon__procmon_summary",
                 "ghidra__decompile_function", "ghidra__list_imports"):
        requires, risk, _ = policy.requires_approval(tool, "assisted")
        assert requires is False, f"{tool} now needs approval; the gate became a wall"
        assert risk == "safe_read"


@pytest.mark.parametrize("tool,expected", [
    ("ghidra__patch_bytes", "write_or_patch"),
    ("ghidra__rename_function", "write_or_patch"),
    ("x64dbg__MemoryWrite", "write_or_patch"),
    ("x64dbg__DebugRun", "dynamic_execution"),
    ("x64dbg__MemoryRead", "sensitive_read"),
    ("frida__trace_sinks", "dynamic_execution"),
])
def test_dangerous_tools_are_classified_and_gated(tool, expected):
    requires, risk, _ = policy.requires_approval(tool, "assisted")
    assert risk == expected
    assert requires is True


# --------------------------------------------------------------------------- the allow-list
def test_a_tool_name_that_does_not_exist_is_refused_rather_than_guessed():
    """Found by writing a test against a tool name I assumed existed; the allow-list caught it."""
    allowed, reason = policy.is_allowed("frida__frida_trace")       # the real name is trace_sinks
    assert allowed is False and "allow-list" in reason


def test_a_manifest_does_not_over_classify_its_read_tools():
    """Over-classification trains the operator to approve without reading, which ends the gate."""
    registry = mcp_manifest.registry()
    assert registry.get("frida").tool("list_sink_presets").risk_class == "safe_read"
    assert registry.get("frida").tool("trace_sinks").risk_class == "dynamic_execution"


def test_a_manifested_server_may_not_use_a_tool_it_did_not_declare():
    """A server growing a capability after review must be re-reviewed, not trusted."""
    allowed, reason = policy.is_allowed("hardening__suddenly_a_new_tool")
    assert allowed is False
    assert "allow-list" in reason


def test_a_third_party_manifest_may_classify_without_allow_listing(tmp_path):
    """Inventing an allow-list for a server you cannot enumerate refuses legitimate tools."""
    (tmp_path / "third.json").write_text(json.dumps({
        "manifest_version": 1, "server": "third", "version": "1.0.0",
        "default_risk_class": "safe_read", "allow_undeclared_tools": True,
        "tools": [{"name": "patch_bytes", "risk_class": "write_or_patch"}],
    }), encoding="utf-8")
    registry = ManifestRegistry(tmp_path)
    undeclared = registry.resolve("third", "some_read_tool", name_heuristic="safe_read")
    assert undeclared["allowed"] is True and undeclared["risk_class"] == "safe_read"
    declared = registry.resolve("third", "patch_bytes", name_heuristic="write_or_patch")
    assert declared["risk_class"] == "write_or_patch"


def test_the_shipped_ghidra_manifest_classifies_rather_than_allow_lists():
    """GhidraMCP is third party; its full tool list cannot be enumerated from here."""
    manifest = mcp_manifest.registry().get("ghidra")
    assert manifest is not None and manifest.allow_undeclared_tools is True
    assert manifest.default_risk_class == "safe_read"
    assert manifest.tool("patch_bytes").risk_class == "write_or_patch"


def test_the_bundled_servers_do_allow_list():
    """We package these, so we can enumerate them, so they get the stricter treatment."""
    for name in ("hardening", "procmon", "crypto", "x64dbg", "builtin"):
        manifest = mcp_manifest.registry().get(name)
        assert manifest is not None, f"{name} ships no manifest"
        assert manifest.allow_undeclared_tools is False, f"{name} should allow-list"


# --------------------------------------------------------------------------- failing closed
def test_forgetting_to_classify_a_tool_does_not_make_it_safe():
    """`default_risk_class` defaults to the most dangerous value on purpose."""
    assert ServerManifest(server="x").default_risk_class == "write_or_patch"


def test_a_malformed_manifest_is_not_silently_ignored(tmp_path):
    """Ignoring it into "no manifest" would silently downgrade a reviewed server."""
    (tmp_path / "broken.json").write_text("{not json", encoding="utf-8")
    (tmp_path / "wrong.json").write_text(json.dumps({"server": "wrong", "tools": "nope"}),
                                         encoding="utf-8")
    registry = ManifestRegistry(tmp_path)
    assert registry.get("wrong") is None
    assert set(registry.errors) == {"broken", "wrong"}


def test_an_unknown_risk_class_is_treated_as_the_most_dangerous():
    assert higher_risk("safe_read", "something_new") == RISK_ORDER[-1]
    assert higher_risk("write_or_patch", "safe_read") == "write_or_patch"


def test_the_unmanifested_floor_is_configurable_and_defaults_closed(monkeypatch):
    from reforge import config

    assert config.UNMANIFESTED_RISK_FLOOR == "sensitive_read"
    monkeypatch.setattr(config, "UNMANIFESTED_RISK_FLOOR", "safe_read")
    assert policy.resolve_risk("evil__analyze_report")["risk_class"] == "safe_read"
    monkeypatch.setattr(config, "UNMANIFESTED_RISK_FLOOR", "nonsense")
    assert policy.resolve_risk("evil__analyze_report")["risk_class"] == "sensitive_read"


def test_a_manifest_can_force_approval_regardless_of_mode(tmp_path):
    """For a tool whose risk the class system understates - irreversible, but technically a read."""
    (tmp_path / "s.json").write_text(json.dumps({
        "manifest_version": 1, "server": "s", "version": "1.0.0",
        "tools": [{"name": "wipe", "risk_class": "safe_read", "requires_approval_always": True}],
    }), encoding="utf-8")
    monkey = ManifestRegistry(tmp_path)
    decision = monkey.resolve("s", "wipe", name_heuristic="safe_read")
    assert decision["requires_approval_always"] is True


# --------------------------------------------------------------------------- the built-ins
def test_retraces_own_meta_tools_are_not_subject_to_the_third_party_floor():
    """They run in-process. Applying the floor meant for untrusted servers would gate them."""
    for tool in ("search_tools", "workflow_status", "attack_surface", "vuln_checklist"):
        requires, risk, _ = policy.requires_approval(tool, "assisted")
        assert risk == "safe_read" and requires is False, tool


def test_writing_a_finding_is_still_classified_as_a_write():
    assert policy.resolve_risk("add_finding")["risk_class"] == "write_or_patch"


# --------------------------------------------------------------------------- manifests shipped
def test_every_bundled_server_in_the_catalogue_has_a_manifest():
    """A bundled server without one pays the unmanifested floor for no reason."""
    from reforge import config

    catalogue = set(config.load_server_config())
    manifested = set(mcp_manifest.registry().servers())
    missing = sorted(catalogue - manifested)
    assert not missing, f"bundled servers with no manifest: {missing}"


def test_every_shipped_manifest_is_valid_and_matches_its_filename():
    registry = mcp_manifest.registry()
    assert not registry.errors, f"invalid manifests: {registry.errors}"
    for name in registry.servers():
        manifest = registry.get(name)
        assert manifest.server == name
        assert manifest.manifest_version == mcp_manifest.MANIFEST_VERSION
        for tool in manifest.tools:
            assert tool.risk_class in RISK_ORDER, f"{name}.{tool.name}: {tool.risk_class}"


def test_manifest_tool_names_match_the_servers_actual_source():
    """A manifest that disagrees with its server allow-lists the wrong things."""
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    for server, filename in (("hardening", "hardening_mcp.py"), ("procmon", "procmon_mcp.py"),
                             ("crypto", "crypto_mcp.py"), ("tshark", "tshark_mcp.py")):
        source = root / "servers" / filename
        tree = ast.parse(source.read_text(encoding="utf-8"))
        actual = {n.name for n in ast.walk(tree)
                  if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                  and any("mcp.tool" in ast.unparse(d) for d in n.decorator_list)}
        declared = {t.name for t in mcp_manifest.registry().get(server).tools}
        assert actual == declared, (
            f"{server}: manifest and source disagree. "
            f"only in source: {sorted(actual - declared)}; only in manifest: {sorted(declared - actual)}"
        )
