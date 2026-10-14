"""MCP server: SBOM generation and CVE matching for third-party components.

Replaces the NVD keyword search in libs_mcp, which is very noisy: a keyword query for "openssl 1.1.1"
returns CVEs for every OpenSSL version ever. Syft produces CPEs and PURLs, and Grype/OSV match them
against version ranges, so you get "this exact version is affected" instead of "this library has had
CVEs at some point".

Falls back to the OSV.dev API when Grype is unavailable.
"""
from __future__ import annotations

import json
import os
import sys
import re
import subprocess
from collections import defaultdict
from typing import Any, Dict, List

# Resolve external tools without depending on the PATH the MCP client happened to inherit.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _toolpath import resolve as _tool, missing_message as _tool_missing

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("sbom")
CAP = 14000
SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "negligible": 0, "unknown": 0}

# Version banners embedded by common C/C++ libraries. Static fallback when no SBOM tool exists.
BANNERS = [
    (r"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?(?:-[a-z0-9]+)?)", "openssl"),
    (r"zlib\s+(?:version\s+)?(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)", "zlib"),
    (r"libpng\s+(?:version\s+)?(\d+\.\d+\.\d+)", "libpng"),
    (r"libcurl[/ ](\d+\.\d+\.\d+)", "curl"),
    (r"SQLite\s+(?:version\s+)?(\d+\.\d+\.\d+(?:\.\d+)?)", "sqlite"),
    (r"mbed\s?TLS\s+(\d+\.\d+\.\d+)", "mbedtls"),
    (r"libssh2[/ ](\d+\.\d+\.\d+)", "libssh2"),
    (r"PCRE2?\s+(\d+\.\d+)", "pcre"),
    (r"libxml2?\s+(\d+\.\d+\.\d+)", "libxml2"),
    (r"expat_(\d+)_(\d+)_(\d+)", "expat"),
    (r"Lua\s+(\d+\.\d+(?:\.\d+)?)", "lua"),
    (r"FreeType\s+(\d+\.\d+\.\d+)", "freetype"),
    (r"libjpeg-turbo\s+(\d+\.\d+\.\d+)", "libjpeg-turbo"),
    (r"Boost\s+(\d+[._]\d+[._]\d+)", "boost"),
    (r"nginx/(\d+\.\d+\.\d+)", "nginx"),
    (r"OpenSSH[_ ](\d+\.\d+)", "openssh"),
]


def _cap(s: str) -> str:
    return s[:CAP] + "\n…(truncated)" if len(s) > CAP else s


def _run(cmd: List[str], timeout: int = 300) -> Dict[str, Any]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        return {"ok": p.returncode == 0, "out": p.stdout, "err": p.stderr, "rc": p.returncode}
    except FileNotFoundError:
        return {"ok": False, "err": f"not found: {cmd[0]}"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "err": f"timeout after {timeout}s"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "err": str(e)}


def _strings(path: str, min_len: int = 6, limit_mb: int = 200) -> List[str]:
    """Extract printable ASCII and UTF-16 runs without shelling out to `strings`."""
    try:
        size = os.path.getsize(path)
        if size > limit_mb * 1024 * 1024:
            return []
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return []
    out = re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)
    wide = re.findall(rb"(?:[\x20-\x7e]\x00){%d,}" % min_len, data)
    res = [b.decode("ascii", "ignore") for b in out]
    res += [b.decode("utf-16le", "ignore") for b in wide]
    return res


@mcp.tool()
def detect_components(path: str) -> str:
    """Fingerprint embedded third-party libraries and their versions from version banners in the
    binary. Works with no external tooling. Use this first: the output feeds cve_lookup.

    Statically linked libraries are the usual source of the highest-severity findings on a
    closed-source executable, because nobody patches what they forgot they bundled."""
    if not os.path.isfile(path):
        return f"file not found: {path}"
    strs = _strings(path)
    if not strs:
        return "Cannot extract strings (file too large or unreadable)."
    blob = "\n".join(strs)
    found: Dict[str, set] = defaultdict(set)
    for pattern, name in BANNERS:
        for m in re.finditer(pattern, blob, re.I):
            ver = ".".join(g for g in m.groups() if g).replace("_", ".")
            found[name].add(ver)
    if not found:
        return ("No version banner recognised.\n"
                "That does not mean there are no dependencies: many libraries leave no banner. "
                "Try `generate_sbom` (Syft), which uses more techniques, or look for the symbols "
                "in the decompiler.")
    lines = [f"# Componenti rilevati in {os.path.basename(path)}\n"]
    for name, vers in sorted(found.items()):
        for v in sorted(vers):
            lines.append(f"- **{name}** {v}")
    lines.append("\nPass each one to `cve_lookup(product, version)` for matching by "
                 "version range.")
    return _cap("\n".join(lines))


@mcp.tool()
def generate_sbom(path: str, output_path: str = "", timeout: int = 600) -> str:
    """Generate a CycloneDX SBOM with Syft. Syft detects far more than version banners: package
    metadata, .NET assemblies, Go module info, embedded archives. Requires syft on PATH
    (https://github.com/anchore/syft)."""
    if not os.path.exists(path):
        return f"path not found: {path}"
    syft = _tool("syft")
    if not syft:
        return _tool_missing("syft",
            "Download syft_<version>_windows_amd64.zip from "
            "https://github.com/anchore/syft/releases\n"
            "Without syft use `detect_components`, which needs no external tool.")
    r = _run([syft, "scan", f"file:{path}", "-o", "cyclonedx-json"], timeout)
    if not r["ok"]:
        r = _run([syft, f"file:{path}", "-o", "cyclonedx-json"], timeout)
    if not r["ok"]:
        return f"Syft: error: {r.get('err', '')[:800]}"
    try:
        sbom = json.loads(r["out"])
    except json.JSONDecodeError:
        return f"Syft: non-JSON output:\n{r['out'][:1500]}"

    comps = sbom.get("components", []) or []
    if output_path:
        try:
            with open(output_path, "w", encoding="utf-8") as fh:
                json.dump(sbom, fh, indent=2)
        except OSError as e:
            return f"error writing the SBOM: {e}"
    lines = [f"# SBOM: {os.path.basename(path)} — {len(comps)} componenti"]
    if output_path:
        lines.append(f"scritto in `{output_path}`")
    for c in comps[:100]:
        purl = c.get("purl", "")
        lines.append(f"- {c.get('name', '?')} {c.get('version', '?')}"
                     + (f"  `{purl}`" if purl else ""))
    if len(comps) > 100:
        lines.append(f"…{len(comps) - 100} more")
    lines.append("\nNow `scan_vulnerabilities` for the CVE matching.")
    return _cap("\n".join(lines))


@mcp.tool()
def scan_vulnerabilities(path: str, min_severity: str = "medium", timeout: int = 600) -> str:
    """Match the components of a binary against known CVEs using Grype, which matches on version
    RANGES rather than keywords, so the false-positive rate is far lower than an NVD keyword search.
    min_severity: negligible|low|medium|high|critical. Requires grype on PATH."""
    if not os.path.exists(path):
        return f"path not found: {path}"
    grype = _tool("grype")
    if not grype:
        return _tool_missing("grype",
            "Download grype_<version>_windows_amd64.zip from "
            "https://github.com/anchore/grype/releases\n"
            "Fallback with nothing to install: `detect_components` + `cve_lookup`.")
    r = _run([grype, f"file:{path}", "-o", "json"], timeout)
    combined = (r.get("out") or "") + (r.get("err") or "")

    # Grype fails loudly and unhelpfully when its vulnerability DB is missing or unreachable.
    # That is by far the most common setup problem, so translate it instead of dumping the log.
    if "database does not exist" in combined or "failed to load vulnerability db" in combined:
        offline = "403" in combined or "no such host" in combined or "timeout" in combined
        return ("Grype has no vulnerability database.\n\n"
                "Download it with:  `grype db update`  (the first time takes a few minutes)\n"
                "Check with:       `grype db status`\n\n"
                + ("⚠ The download was BLOCKED by the network (HTTP 403 / host unreachable). "
                   "In a corporate environment the Anchore DB endpoint is often filtered by the proxy.\n"
                   "  - behind a proxy: set HTTPS_PROXY and retry\n"
                   "  - closed network: download the DB from a machine with access and copy it into the\n"
                   "    cache (`grype db status` shows the path), then set\n"
                   "    GRYPE_DB_AUTO_UPDATE=false so it does not retry on every scan\n"
                   if offline else
                   "If the command fails, check connectivity and the proxy.\n")
                + "\nMeanwhile `detect_components` works with no network and no database.")

    if not r["ok"] and not r.get("out"):
        return f"Grype: error: {(r.get('err') or '')[:800]}"
    try:
        data = json.loads(r["out"])
    except json.JSONDecodeError:
        return f"Grype: non-JSON output:\n{(r.get('out') or r.get('err', ''))[:1500]}"

    floor = SEV_ORDER.get(min_severity.lower(), 2)
    matches = []
    for m in data.get("matches", []) or []:
        vuln = m.get("vulnerability", {})
        sev = (vuln.get("severity") or "unknown").lower()
        if SEV_ORDER.get(sev, 0) < floor:
            continue
        art = m.get("artifact", {})
        matches.append({
            "id": vuln.get("id", "?"),
            "severity": sev,
            "package": art.get("name", "?"),
            "version": art.get("version", "?"),
            "fixed_in": ", ".join((vuln.get("fix", {}) or {}).get("versions", []) or []) or "n/d",
            "cvss": next((str(c.get("metrics", {}).get("baseScore"))
                          for c in (vuln.get("cvss") or []) if c.get("metrics")), "n/d"),
            "desc": (vuln.get("description") or "")[:200],
        })
    if not matches:
        return (f"No vulnerability of severity >= {min_severity}.\n"
                "Note: Grype only finds what has an identifiable component. "
                "On a statically linked binary it may see nothing: always cross-check "
                "with `detect_components`.")
    matches.sort(key=lambda x: -SEV_ORDER.get(x["severity"], 0))
    by_pkg: Dict[str, List[dict]] = defaultdict(list)
    for m in matches:
        by_pkg[f"{m['package']} {m['version']}"].append(m)

    lines = [f"# CVE note — {len(matches)} (severity >= {min_severity})\n"]
    for pkg, items in sorted(by_pkg.items(), key=lambda kv: -SEV_ORDER.get(kv[1][0]["severity"], 0)):
        lines.append(f"## {pkg} — {len(items)} CVE")
        fixed = {i["fixed_in"] for i in items if i["fixed_in"] != "n/d"}
        if fixed:
            lines.append(f"_Remediation: update to {', '.join(sorted(fixed)[:5])}_")
        for i in items[:15]:
            lines.append(f"  - **{i['id']}** [{i['severity']}] CVSS {i['cvss']} — {i['desc']}")
        if len(items) > 15:
            lines.append(f"  …{len(items) - 15} more")
    return _cap("\n".join(lines))


@mcp.tool()
def check_sbom_setup() -> str:
    """Report whether syft and grype are installed, their versions, and the state and AGE of the
    grype vulnerability database.

    Database age matters more than it looks: grype only reports what is in its local DB, so a stale
    database silently produces false negatives. On a vulnerability assessment that means telling a
    client a component is clean when a CVE was published last week."""
    lines = ["# SBOM / CVE tooling status\n"]

    syft = _tool("syft")
    if syft:
        v = _run([syft, "version"], 30)
        ver = ""
        for line in (v.get("out") or "").splitlines():
            if line.lower().startswith("version:"):
                ver = line.split(":", 1)[1].strip()
        lines.append(f"✅ **syft** {ver or ''} — `{syft}`")
    else:
        lines.append("❌ **syft** is not installed\n"
                     "   Linux/macOS: `curl -sSfL https://raw.githubusercontent.com/anchore/syft/"
                     "main/install.sh | sh -s -- -b /usr/local/bin`\n"
                     "   Windows: download the zip from https://github.com/anchore/syft/releases")

    grype = _tool("grype")
    if not grype:
        lines.append("\n❌ **grype** is not installed\n"
                     "   Same method as syft, repo https://github.com/anchore/grype\n"
                     "   Without grype there is still `detect_components` + `cve_lookup` (OSV), which "
                     "work but cover less.")
        return _cap("\n".join(lines))

    v = _run([grype, "version"], 30)
    ver = ""
    for line in (v.get("out") or "").splitlines():
        if line.lower().startswith("version:"):
            ver = line.split(":", 1)[1].strip()
    lines.append(f"\n✅ **grype** {ver or ''} — `{grype}`")

    st = _run([grype, "db", "status"], 60)
    out = (st.get("out") or "") + (st.get("err") or "")
    lines.append("\n## Vulnerability database")
    if "does not exist" in out or "invalid" in out.lower():
        lines.append("❌ **missing or invalid** — no scan is possible.\n"
                     "   Run: `grype db update`")
        if "403" in out or "no such host" in out:
            lines.append("   ⚠ download blocked by the network: see the proxy notes in the README.")
    else:
        built = ""
        for line in out.splitlines():
            ls = line.strip()
            if ls.lower().startswith("built:"):
                built = ls.split(":", 1)[1].strip()
            if ls.lower().startswith(("path:", "schema:", "status:")):
                lines.append(f"   {ls}")
        if built:
            age_note = ""
            try:
                import datetime as _dt
                b = _dt.datetime.fromisoformat(built.replace("Z", "+00:00"))
                days = (_dt.datetime.now(_dt.timezone.utc) - b).days
                if days > 7:
                    age_note = (f"\n   ⚠ **DB is {days} days old.** Update it with "
                                "`grype db update`: a stale DB produces silent false "
                                "negatives, that is, components reported clean that are not.")
                else:
                    age_note = f"\n   ✅ up to date ({days} days ago)"
            except Exception:  # noqa: BLE001
                pass
            lines.append(f"   Built: {built}{age_note}")

    lines.append("\n---\n**A reminder of the limits.** syft and grype were built for containers and "
                 "ecosystems with a package manager. On a single statically linked Windows "
                 ".exe they may find nothing: that is a normal result, not an error. "
                 "Always cross-check with `detect_components`, which works on the version banners "
                 "inside the binary.")
    return _cap("\n".join(lines))


@mcp.tool()
def cve_lookup(product: str, version: str, ecosystem: str = "") -> str:
    """Query OSV.dev for the CVEs affecting a specific product version. Unlike an NVD keyword search
    this filters by affected version range, so the results actually apply to the version you have.

    Use it on the components returned by detect_components. ecosystem is optional
    (e.g. 'PyPI', 'npm', 'Go'); leave empty for C/C++ libraries."""
    try:
        import urllib.request
        import urllib.error
    except ImportError:
        return "urllib unavailable."
    payload: Dict[str, Any] = {"version": version, "package": {"name": product}}
    if ecosystem:
        payload["package"]["ecosystem"] = ecosystem
    req = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
    except Exception as e:  # noqa: BLE001
        return (f"OSV: query failed: {e}\n"
                "Connectivity to api.osv.dev is required. Alternatively use Grype offline "
                "with a pre-downloaded DB.")

    vulns = data.get("vulns", []) or []
    if not vulns:
        return (f"OSV: no known vulnerability for {product} {version}.\n"
                "⚠ OSV covers package-manager ecosystems well; for statically linked "
                "C/C++ libraries the coverage is partial. Cross-check with Grype and with "
                "the upstream changelog.")
    lines = [f"# {product} {version} — {len(vulns)} vulnerabilities (OSV)\n"]
    for v in vulns[:30]:
        sev = "n/a"
        for s in v.get("severity", []) or []:
            if s.get("type", "").startswith("CVSS"):
                sev = s.get("score", "n/d")
        aliases = ", ".join(v.get("aliases", [])[:4])
        lines.append(f"- **{v.get('id')}** {f'({aliases})' if aliases else ''} [{sev}]")
        summary = (v.get("summary") or v.get("details") or "")[:220]
        if summary:
            lines.append(f"    {summary}")
    if len(vulns) > 30:
        lines.append(f"\n…{len(vulns) - 30} more")
    return _cap("\n".join(lines))


if __name__ == "__main__":
    mcp.run()
