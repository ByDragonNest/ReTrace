"""Product scope: ReTrace finds vulnerabilities, it does not classify malware.

These are guard tests. The malware-analysis machinery (behavioural capability taxonomy, IOC
extraction, YARA signature matching, MITRE ATT&CK / MBC mapping, threat-intel framing) was removed
deliberately; this module fails if any of it comes back, in code or in user-facing copy.

What must NOT be caught by these tests, because it is the core of the product: dangerous sinks,
untrusted input sources, and the source->sink model (`reforge/sinks.py`).
"""
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


# --------------------------------------------------------------------------- code-level removals
def test_no_capability_taxonomy_in_static_analysis():
    from reforge import static_analysis as sa
    for gone in ("CAPABILITIES", "API_MAP", "_reg", "_capability_findings", "_iocs"):
        assert not hasattr(sa, gone), f"static_analysis.{gone} is malware-analysis machinery"


def test_static_analysis_output_has_no_iocs_or_capabilities():
    from reforge import static_analysis as sa
    res = sa.analyze(__file__)          # any readable file: we only inspect the result's shape
    assert "iocs" not in res
    assert "capabilities" not in (res.get("attack_surface") or {})


def test_ioc_engine_module_is_gone():
    with pytest.raises(ImportError):
        __import__("reforge.engine.ioc")


def test_session_has_no_ioc_field():
    from reforge.session import Session
    assert not hasattr(Session("s", "demo"), "static_iocs")


def test_yara_and_capa_servers_are_not_shipped():
    """Checked across every server tree in the working copy, not just the tracked one.

    An untracked `mcp_servers/` - a stale copy predating the removal of the malware-oriented
    content - carried `capa_mcp.py` and went unnoticed because this guard only looked at
    `servers/`. A scope boundary that only holds in the directory you remembered to check is not
    a boundary. Slice P2-S9.
    """
    for tree in ("servers", "mcp_servers", "reforge/servers"):
        for name in ("capa_mcp.py", "yara_mcp.py"):
            assert not (ROOT / tree / name).exists(), (
                f"{tree}/{name} is malware-classification tooling; ReTrace does not ship it "
                "(see the README's scope section)")


def test_there_is_exactly_one_server_tree():
    """Two trees means one of them is stale, and nothing says which.

    The untracked `mcp_servers/` was an older copy whose `x64dbg.py` still described finding "C2
    connections" - malware-analysis framing the tracked tree had already corrected to "which
    remote endpoints feed untrusted input into the process".
    """
    duplicates = [name for name in ("mcp_servers", "reforge/servers")
                  if (ROOT / name).is_dir()]
    assert not duplicates, (
        f"a second server tree exists: {duplicates}. `servers/` is the tracked, current one; "
        "remove the other so there is one source of truth."
    )


def test_yara_and_capa_are_not_configured():
    import json
    cfg = json.loads((ROOT / "mcp.servers.json").read_text())
    servers = cfg.get("mcpServers", cfg)
    assert "capa" not in servers and "yara" not in servers


def test_evidence_sources_do_not_include_malware_tools():
    from reforge import evidence
    assert "yara" not in evidence.VALID_SOURCES
    assert "capa" not in evidence.VALID_SOURCES


def test_string_categories_have_no_persistence_bucket():
    from reforge import string_signal
    assert "persistence" not in string_signal.CATEGORIES


# --------------------------------------------------------------------------- what must survive
def test_sink_and_source_model_is_intact():
    """The source->sink model is vulnerability research, not malware analysis. It must stay."""
    from reforge import sinks
    inv = sinks.inventory(["strcpy", "sprintf", "system", "LoadLibraryA", "recv", "GetCommandLineA"])
    assert inv["sinks"], "the dangerous-sink inventory is the core of the product"
    assert "mem_copy" in inv["sinks"] and "exec" in inv["sinks"]
    assert inv["sources"], "untrusted input sources must still be inventoried"
    for f in inv["findings"]:
        assert f.get("cwe"), "every sink class must map to a CWE"


def test_source_to_sink_chains_still_build():
    from reforge import source_to_sink as s2s
    chains = s2s.build_candidate_chains(["recv"], ["strcpy"])
    assert chains and chains[0]["source"] == "recv" and chains[0]["sink"] == "strcpy"


def test_assessment_attack_surface_is_sinks_and_sources():
    from reforge import assessment
    from reforge.session import Session
    s = Session("s", "demo")
    s.attack_surface = {"sinks": {"exec": ["system"]}, "sources": {"recv": "network (socket)"}}
    surf = assessment.attack_surface(s)
    assert surf["available"] and surf["sinks"] and surf["sources"]
    assert "categories" not in surf


# --------------------------------------------------------------------------- user-facing copy
_SOURCES = (
    list((ROOT / "reforge").rglob("*.py"))
    + list((ROOT / "reforge").rglob("*.yaml"))
    + list((ROOT / "servers").glob("*.py"))
    + list((ROOT / "reforge" / "web").glob("*.js"))
    + list((ROOT / "reforge" / "web").glob("*.html"))
)

# Each pattern is anchored enough not to collide with legitimate vocabulary: "RC2" (a cipher) must
# not trip the C2 rule, "job persistence" must not trip the persistence rule.
_FORBIDDEN = [
    (r"\bMITRE ATT&CK\b", "MITRE ATT&CK mapping is attacker-behaviour taxonomy"),
    (r"\bMBC\b", "Malware Behavior Catalog mapping"),
    (r"\bYARA\b", "YARA is malware signature matching"),
    (r"\bThreat Map\b", "threat-intel framing; the module is the Evidence Graph"),
    (r"\bti_cluster\b", "threat-intel cluster node type"),
    (r"indicator[s]? of compromise", "IOC extraction was removed"),
]


@pytest.mark.parametrize("pattern,why", _FORBIDDEN)
def test_malware_vocabulary_stays_out_of_the_product(pattern, why):
    rx = re.compile(pattern, re.I)
    hits = []
    for path in _SOURCES:
        if path.name == "test_scope.py":
            continue
        for n, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
            if rx.search(line):
                hits.append(f"{path.relative_to(ROOT)}:{n}: {line.strip()[:100]}")
    assert not hits, f"{why}:\n" + "\n".join(hits)


# --------------------------------------------------------------------------- SPA wiring
def test_every_nav_item_has_a_matching_view():
    """A nav button pointing at a missing <section> renders a blank screen with no error.

    This exists because removing a view block once took the two sections that followed it with it.
    """
    html = (ROOT / "reforge" / "web" / "index.html").read_text(encoding="utf-8")
    nav = set(re.findall(r'class="nav-item[^"]*"[^>]*data-view="([a-z]+)"', html))
    views = set(re.findall(r'<section id="view-([a-z]+)"', html))
    assert nav, "no nav items found — the selector is wrong, not the markup"
    missing = sorted(nav - views)
    assert not missing, f"nav items with no view section: {missing}"
    orphan = sorted(views - nav)
    assert not orphan, f"view sections no nav item reaches: {orphan}"


def test_spa_scripts_are_served_and_referenced():
    html = (ROOT / "reforge" / "web" / "index.html").read_text(encoding="utf-8")
    from reforge.server import _SPA_ASSETS
    for asset in ("app.js", "assessment.js", "palette.js", "styles.css"):
        assert asset in _SPA_ASSETS, f"{asset} is not served"
        # Resolved through the server so the assertion follows the SPA wherever it is packaged
        # (checkout or installed wheel) rather than pinning the test to one layout.
        from reforge.server import WEB
        assert (WEB / asset).exists(), f"{asset} is missing from {WEB}"
        assert asset in html, f"index.html does not reference {asset}"
