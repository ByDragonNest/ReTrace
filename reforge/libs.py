"""Third-party component fingerprinting for binary vulnerability auditing.

Detects embedded library version banners (OpenSSL, zlib, libpng, curl, SQLite, ...)
from the raw bytes of a binary. Each detected component is a lead toward *known* CVEs
(CWE-1395, dependency on a vulnerable third-party component). An optional, best-effort
NVD keyword lookup can attach candidate CVE IDs; it needs network and is off by default.

Detection is signature-based (version strings), so it's high-precision but not exhaustive:
statically-linked code with stripped banners won't be seen.
"""
import json
import re
import urllib.parse
import urllib.request
from typing import Any, Dict, List

# (display name, compiled byte-regex with a version group, NVD keyword vendor/product)
_PATTERNS = [
    ("OpenSSL",        rb"OpenSSL (\d+\.\d+\.\d+[a-z]?)", "openssl"),
    ("LibreSSL",       rb"LibreSSL (\d+\.\d+\.\d+)",      "libressl"),
    ("mbedTLS",        rb"mbed ?TLS (\d+\.\d+\.\d+)",     "mbedtls"),
    ("wolfSSL",        rb"wolfSSL (\d+\.\d+\.\d+)",       "wolfssl"),
    ("zlib",           rb"(?:in|de)flate (\d+\.\d+\.\d+) Copyright", "zlib"),
    ("zlib",           rb"zlib version (\d+\.\d+\.\d+)",  "zlib"),
    ("libpng",         rb"libpng version (\d+\.\d+\.\d+)", "libpng"),
    ("libcurl",        rb"libcurl/(\d+\.\d+\.\d+)",       "curl"),
    ("curl",           rb"\bcurl/(\d+\.\d+\.\d+)",        "curl"),
    ("SQLite",         rb"SQLite (?:version )?(\d+\.\d+\.\d+)", "sqlite"),
    ("PCRE2",          rb"PCRE2? (\d+\.\d+)",             "pcre"),
    ("libexpat",       rb"expat_(\d+\.\d+\.\d+)",         "expat"),
    ("libxml2",        rb"libxml2 (\d+\.\d+\.\d+)",       "libxml2"),
    ("bzip2",          rb"bzip2-(\d+\.\d+\.\d+)",         "bzip2"),
    ("libssh2",        rb"libssh2[_/](\d+\.\d+\.\d+)",    "libssh2"),
    ("OpenSSH",        rb"OpenSSH_(\d+\.\d+(?:p\d+)?)",   "openssh"),
    ("nginx",          rb"nginx/(\d+\.\d+\.\d+)",         "nginx"),
    ("libjpeg-turbo",  rb"libjpeg-turbo version (\d+\.\d+\.\d+)", "libjpeg-turbo"),
    ("FreeType",       rb"FreeType (\d+\.\d+\.\d+)",      "freetype"),
    ("Lua",            rb"Lua (\d+\.\d+\.\d+)",           "lua"),
    ("zstd",           rb"Zstandard v?(\d+\.\d+\.\d+)",   "zstd"),
    ("Boost",          rb"Boost (\d+\.\d+\.\d+)",         "boost"),
    ("Qt",             rb"Qt (\d+\.\d+\.\d+)",            "qt"),
    ("libtiff",        rb"LIBTIFF, Version (\d+\.\d+\.\d+)", "libtiff"),
    ("c-ares",         rb"c-ares (\d+\.\d+\.\d+)",        "c-ares"),
]
_COMPILED = [(name, re.compile(rx), kw) for name, rx, kw in _PATTERNS]

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fingerprint(data: bytes) -> List[Dict[str, Any]]:
    """Return detected components: [{library, version, keyword}], deduped."""
    seen = set()
    out = []
    for name, rx, kw in _COMPILED:
        for m in rx.finditer(data):
            ver = m.group(1).decode("ascii", "ignore")
            key = (name, ver)
            if key in seen:
                continue
            seen.add(key)
            out.append({"library": name, "version": ver, "keyword": kw})
    return out


def nvd_lookup(keyword: str, version: str, api_key: str = "", limit: int = 5,
               timeout: int = 15) -> List[Dict[str, str]]:
    """Best-effort NVD keyword search for a component+version. Returns [] on any failure
    (offline, rate-limited, parse error). Never raises."""
    try:
        q = urllib.parse.urlencode({"keywordSearch": f"{keyword} {version}",
                                    "resultsPerPage": limit})
        req = urllib.request.Request(NVD_URL + "?" + q,
                                     headers={"User-Agent": "ReTrace"})
        if api_key:
            req.add_header("apiKey", api_key)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "ignore"))
    except Exception:  # noqa: BLE001
        return []
    cves = []
    for item in data.get("vulnerabilities", [])[:limit]:
        cve = item.get("cve", {})
        cid = cve.get("id", "")
        sev = ""
        metrics = cve.get("metrics", {})
        for mk in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(mk):
                d = metrics[mk][0].get("cvssData", {})
                sev = d.get("baseSeverity") or str(d.get("baseScore", "")) or ""
                break
        if cid:
            cves.append({"id": cid, "severity": sev})
    return cves


_SEV_MAP = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}


def audit(path: str, online: bool = False, api_key: str = "") -> Dict[str, Any]:
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as e:
        return {"error": f"cannot read file: {e}"}
    components = fingerprint(data)
    findings = []
    for c in components:
        cves = nvd_lookup(c["keyword"], c["version"], api_key) if online else []
        c["cves"] = cves
        sev = "LOW"
        for cv in cves:
            if cv["severity"].upper() in ("CRITICAL", "HIGH"):
                sev = "HIGH"; break
        desc = f"Third-party component detected: {c['library']} {c['version']}."
        if cves:
            desc += " CVE candidate: " + ", ".join(
                f"{cv['id']}" + (f" ({cv['severity']})" if cv["severity"] else "") for cv in cves) + "."
        else:
            desc += (" Check known CVEs for this version (e.g. on NVD)."
                     if not online else " No CVE found via keyword search (verify manually).")
        findings.append({
            "title": f"Third-party library: {c['library']} {c['version']}",
            "severity": sev, "status": "HYPOTHESIS", "vuln_type": "third_party_component",
            "cwe": "CWE-1395", "location": "embedded version strings",
            "potential_severity": sev,
            "evidence_source": "version banner", "evidence_type": "string signature",
            "evidence": f"Version banner found in the binary: {c['library']} {c['version']}"
                        + (f" — match: '{c.get('match')}'." if c.get("match") else "."),
            "missing_validation_steps": [
                "corroborate the component with a second independent fingerprint",
                "confirm code reachability and whether untrusted input reaches the vulnerable code",
                "separate identification / version match / CVE match / exploitability",
            ],
            "plain": ("The program includes a component from other developers at an outdated version. "
                      "If security issues are known for that version, the program may 'inherit' them "
                      "even if its own code is well written — but this must be verified for this build."),
            "description": desc,
            "impact": ("If the vulnerable code is reachable from untrusted input, this dependency may "
                       "expose the binary to the component's known issues (RCE, DoS, memory disclosure "
                       "or a cryptographic bypass). A library CVE is NOT automatically an application "
                       "RCE: reachability and exploitability require validation."),
            "recommendation": "Compare the version against the latest upstream and known CVEs (NVD); "
                              "update to the fixed release or apply the vendor's patches; "
                              "if the library is statically linked, recompile with the updated version.",
        })
    res = {"components": components, "findings": findings, "online": online}
    res["text"] = render(res)
    return res


def render(res: Dict[str, Any]) -> str:
    if "error" in res:
        return f"Library fingerprint: {res['error']}"
    comps = res.get("components", [])
    if not comps:
        return ("## Third-party components\n\nNo known version banner detected "
                "(possible static linking with banners stripped).")
    L = ["## Third-party components", "", "| Library | Version | Candidate CVEs |",
         "|---|---|---|"]
    for c in comps:
        cves = c.get("cves") or []
        cve_txt = ", ".join(f"{cv['id']}" + (f" ({cv['severity']})" if cv["severity"] else "")
                            for cv in cves) if cves else ("—" if res.get("online") else "(offline lookup)")
        L.append(f"| {c['library']} | {c['version']} | {cve_txt} |")
    L += ["", f"{len(comps)} components detected. " +
          ("NVD lookup active." if res.get("online")
           else "CVE lookup disabled (offline): compare versions against NVD manually "
                "or enable NVD_ONLINE_LOOKUP."), ""]
    return "\n".join(L)
