"""Interoperable exports: SARIF 2.1.0 (findings) and CycloneDX 1.5 (component SBOM).

SARIF is the standard format for static-analysis results (consumed by GitHub code scanning,
VS Code, and others). CycloneDX is an SBOM standard for listing the third-party components
embedded in the binary, useful for a supply-chain audit.

Both are generated deterministically from the session state (findings + the components
identified by `libs.fingerprint`), with no external dependency.
"""
import json
import time
import uuid
from typing import Any, Dict, List

from . import findings as fx

# Mappa severità ReTrace -> SARIF level.
_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning",
                "LOW": "note", "INFO": "note"}
# SARIF security-severity numerica (scala 0-10, convenzione GitHub).
_SARIF_SCORE = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.0", "LOW": "3.0", "INFO": "1.0"}


def _first_cwe(f: Dict[str, Any]) -> str:
    """First CWE id as a string. `cwe` may be a list (["CWE-427", ...]) or a plain string or absent."""
    v = f.get("cwe")
    if not v:
        return ""
    if isinstance(v, (list, tuple, set)):
        for x in v:
            if str(x).strip():
                return str(x).strip()
        return ""
    return str(v).strip()


def _rule_id(f: Dict[str, Any]) -> str:
    cwe = _first_cwe(f)
    vt = (f.get("vuln_type") or "finding").strip()
    return (cwe or vt or "RF-FINDING").replace(" ", "-")


def to_sarif(session, tool_version: str = "5.5") -> Dict[str, Any]:
    """Build a SARIF 2.1.0 document from the session's findings."""
    F = getattr(session, "findings", []) or []
    rules: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    artifact = "binary"
    prof = getattr(session, "target_profile", None)
    if prof and prof.get("file"):
        artifact = prof["file"]
    elif getattr(session, "target_path", None):
        artifact = session.target_path

    for f in F:
        if fx.category(f) == "rejected":
            continue
        rid = _rule_id(f)
        sev = (f.get("severity") or "INFO").upper()
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": (f.get("vuln_type") or "finding").replace(" ", "_"),
                "shortDescription": {"text": f.get("title", rid)[:120]},
                "fullDescription": {"text": (f.get("description") or f.get("title") or "")[:1000]},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{rid.split('-')[-1]}.html"
                           if rid.upper().startswith("CWE-") and rid.split('-')[-1].isdigit() else "",
                "properties": {"security-severity": _SARIF_SCORE.get(sev, "1.0")},
            }
        status = fx.normalize_status(f.get("status"))
        loc = (f.get("location") or "").strip()
        result = {
            "ruleId": rid,
            "level": _SARIF_LEVEL.get(sev, "note"),
            "message": {"text": (f.get("title", "") + " — " +
                                 (f.get("description") or "")).strip(" —")[:1500]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": artifact},
                    "region": {"snippet": {"text": loc or "n/d"}},
                },
                "logicalLocations": [{"name": loc}] if loc else [],
            }],
            "properties": {
                "status": status,
                "confidence": fx.confidence(f),
                "evidence_refs": f.get("evidence_refs", []),
            },
        }
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "ReTrace",
                "informationUri": "https://github.com/",
                "version": tool_version,
                "rules": list(rules.values()),
            }},
            "results": results,
            "properties": {"generated": time.time(), "artifact": artifact},
        }],
    }


def _bom_ref(comp: Dict[str, Any]) -> str:
    lib = (comp.get("library") or comp.get("keyword") or "component").lower().replace(" ", "-")
    ver = (comp.get("version") or "unknown")
    return f"pkg:generic/{lib}@{ver}"


def to_cyclonedx(components: List[Dict[str, Any]], *,
                 binary_name: str = "binary",
                 online: bool = False, api_key: str = "") -> Dict[str, Any]:
    """Build a CycloneDX 1.5 SBOM from the identified components (libs.fingerprint).

    With `online=True`, each component is enriched with its candidate CVEs via NVD (best-effort),
    reported both as properties and in the document's standard `vulnerabilities` section.
    """
    comps = []
    vulns = []
    for c in components or []:
        ref = _bom_ref(c)
        entry = {
            "type": "library",
            "bom-ref": ref,
            "name": c.get("library") or c.get("keyword") or "component",
            "version": c.get("version") or "unknown",
        }
        cves = c.get("cves") or []
        if online and not cves:
            try:
                from . import libs
                cves = libs.nvd_lookup(c.get("keyword") or c.get("library") or "",
                                       c.get("version") or "", api_key)
            except Exception:  # noqa: BLE001
                cves = []
        if cves:
            entry["properties"] = [{"name": "reforge:candidate_cves",
                                    "value": ", ".join(cv.get("id", "") for cv in cves)}]
            for cv in cves:
                if not cv.get("id"):
                    continue
                vulns.append({
                    "bom-ref": f"vuln-{cv['id']}",
                    "id": cv["id"],
                    "source": {"name": "NVD",
                               "url": f"https://nvd.nist.gov/vuln/detail/{cv['id']}"},
                    "ratings": ([{"severity": _cdx_sev(cv.get("severity"))}]
                                if cv.get("severity") else []),
                    "affects": [{"ref": ref}],
                })
        comps.append(entry)

    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "tools": [{"vendor": "ReTrace", "name": "ReTrace", "version": "5.6"}],
            "component": {"type": "application", "name": binary_name, "bom-ref": binary_name},
        },
        "components": comps,
    }
    if vulns:
        doc["vulnerabilities"] = vulns
    return doc


# CycloneDX severity ammette: critical, high, medium, low, info, none, unknown.
def _cdx_sev(sev: str) -> str:
    """Map any severity expression (label or numeric CVSS) to a CycloneDX band.

    Delegates band logic to the centralized normalizer so labels like "high" and numeric
    scores like 8.1 are handled in one place and never raise.
    """
    from . import severity as _sev
    s = (sev or "").strip().lower()
    if s in ("none",):
        return "none"
    band = _sev.norm_severity(sev, default="")
    return band.lower() if band else "unknown"


def cyclonedx_from_session(session, *, online: bool = False, api_key: str = "") -> Dict[str, Any]:
    """CycloneDX SBOM derived from the session's binary (component fingerprints)."""
    from . import libs
    binary_name = "binary"
    prof = getattr(session, "target_profile", None)
    if prof and prof.get("file"):
        binary_name = prof["file"]
    components: List[Dict[str, Any]] = []
    path = getattr(session, "target_path", None)
    if path:
        try:
            with open(path, "rb") as fh:
                components = libs.fingerprint(fh.read())
        except OSError:
            components = []
    # Fallback: deriva i componenti dai finding di tipo third_party_component.
    if not components:
        for f in (getattr(session, "findings", []) or []):
            if f.get("vuln_type") == "third_party_component":
                title = f.get("title", "")
                # "Libreria di terze parti: <lib> <ver>"
                tail = title.split(":", 1)[-1].strip()
                parts = tail.rsplit(" ", 1)
                if len(parts) == 2:
                    components.append({"library": parts[0], "version": parts[1]})
    return to_cyclonedx(components, binary_name=binary_name, online=online, api_key=api_key)


def dumps(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False)
