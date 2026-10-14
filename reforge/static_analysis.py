"""Offline static triage — no LLM required.

Deterministic first pass over a target binary: hashes, printable strings, PE imports and sections,
entropy/packing corroboration, exploit-mitigation audit, third-party component fingerprinting and
weak-crypto scanning.

The attack surface this produces is expressed in one model only — **dangerous sinks and untrusted
input sources** (``reforge/sinks.py``), each tagged with the CWE it can lead to. There is no
behavioural capability taxonomy here: "does this program inject into other processes / persist /
keylog" is a malware-classification question, and ReTrace does not answer it. The question here is
"can untrusted input reach an operation that breaks this program".
"""
import hashlib
import math
import os
import re
from typing import Any, Dict, List

from . import hardening
from . import sinks
from . import libs
from . import cryptosec

try:
    import pefile  # optional; richer analysis when present
    _HAVE_PEFILE = True
except Exception:
    _HAVE_PEFILE = False

# Below this, a file is too small to contain a packed program: whatever the entropy says, there
# is not enough of it to be evidence. Chosen as one page; the smallest real packed PE is orders of
# magnitude larger.
_MIN_PACKING_EVIDENCE_BYTES = 4096


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


def _strings(data: bytes, min_len: int = 5) -> List[str]:
    out = []
    out += [m.decode("ascii", "ignore") for m in
            re.findall(rb"[\x20-\x7e]{%d,}" % min_len, data)]
    out += [m.decode("utf-16-le", "ignore") for m in
            re.findall((rb"(?:[\x20-\x7e]\x00){%d,}" % min_len), data)]
    return out


def _pe_profile(data: bytes) -> Dict[str, Any]:
    if not _HAVE_PEFILE:
        return {"pefile": False}
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    except Exception as exc:
        return {"pefile": True, "error": str(exc)}
    machine = pe.FILE_HEADER.Machine
    arch = {0x14c: "x86", 0x8664: "x86_64", 0x1c0: "ARM", 0xaa64: "ARM64"}.get(machine, hex(machine))
    sections = []
    for s in pe.sections:
        raw = s.get_data()
        sections.append({"name": s.Name.rstrip(b"\x00").decode("ascii", "ignore"),
                         "vsize": s.Misc_VirtualSize, "rawsize": s.SizeOfRawData,
                         "entropy": round(_entropy(raw), 2)})
    imports = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        for imp in entry.imports:
            if imp.name:
                imports.append(imp.name.decode("ascii", "ignore"))
    ts = getattr(pe.FILE_HEADER, "TimeDateStamp", 0)
    return {"pefile": True, "arch": arch, "sections": sections, "imports": sorted(set(imports)),
            "timestamp": ts, "import_count": len(set(imports))}


def analyze(path: str) -> Dict[str, Any]:
    if not os.path.isfile(path):
        return {"error": f"File not found: {path}"}
    with open(path, "rb") as fh:
        data = fh.read()
    md5 = hashlib.md5(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()
    is_pe = data[:2] == b"MZ"
    overall_entropy = round(_entropy(data), 2)

    pe: Dict[str, Any] = _pe_profile(data) if is_pe else {"pefile": False}
    imports: List[str] = list(pe.get("imports") or [])
    # A ReTrace finding is a *vulnerability lead*, not an inventory of which APIs a program imports.
    # "CreateFile / sprintf / LoadLibrary are present" is attack-surface mapping — it is not a
    # vulnerability and it drowns the report in noise. So the offline seed does NOT emit
    # sink-presence findings. Those live in `attack_surface` below purely as investigation targets
    # for the static/dynamic phase; only a demonstrated source→sink path (via Ghidra xrefs) or an
    # observed runtime behaviour (x64dbg/procmon) becomes an actual finding.
    findings: List[Dict[str, Any]] = []

    # packing heuristic — corroboration required (a lone high-entropy .rsrc is usually just
    # compressed media/icons, NOT packing; flagging it MEDIUM on every installer was a false
    # positive). Whole-image high entropy, or a high-entropy *code/data* (non-resource) section,
    # combined with a tiny import table, is the real signal.
    packed_signals = []
    whole_image_high = overall_entropy >= 7.2
    if whole_image_high:
        packed_signals.append(f"overall entropy {overall_entropy}")
    _RESOURCE_SECTIONS = (".rsrc", ".rdata", ".reloc", ".pdata")
    high_ent_code = [s for s in pe.get("sections", [])
                     if s["entropy"] >= 7.2 and s["name"].lower() not in _RESOURCE_SECTIONS]
    high_ent_rsrc = [s for s in pe.get("sections", [])
                     if s["entropy"] >= 7.2 and s["name"].lower() in _RESOURCE_SECTIONS]
    if high_ent_code:
        packed_signals.append("high-entropy code/data sections: "
                              + ", ".join(s["name"] for s in high_ent_code))
    tiny_imports = is_pe and pe.get("pefile") and pe.get("import_count", 99) <= 8
    if tiny_imports:
        packed_signals.append(f"only {pe.get('import_count')} imports")
    # A packing claim is a claim about a *program*. If the image could not be parsed - a truncated
    # stub, a certificate, a compressed blob that happens to start with MZ - then there is no
    # program to call packed, and high entropy says only "these bytes are dense". Reporting it
    # anyway was a measured false positive: benchmarks/corpus.py `malformed_header_only.bin`, a
    # 514-byte MZ stub, scored MEDIUM "Likely packed / obfuscated" at precision 0.975.
    parsed_image = (bool(pe.get("pefile")) and not pe.get("error")) if is_pe else True
    enough_bytes = len(data) >= _MIN_PACKING_EVIDENCE_BYTES
    can_assess_packing = parsed_image and enough_bytes

    # A packing *finding* needs at least two corroborating signals, or whole-image high entropy.
    if can_assess_packing and (whole_image_high or len(packed_signals) >= 2):
        findings.insert(0, {
            "title": "Likely packed / obfuscated", "severity": "MEDIUM", "status": "HYPOTHESIS",
            "vuln_type": "packing", "evidence_source": "static entropy/section analysis",
            "evidence_type": "byte entropy", "description": "; ".join(packed_signals)
                + ". Unpack before deeper static analysis.",
        })
    elif can_assess_packing and high_ent_rsrc:
        # lone compressed-resource entropy: keep it as a low-noise indicator, not a MEDIUM finding.
        findings.append({
            "title": "High-entropy resource section (informational)", "severity": "INFO",
            "status": "INDICATOR", "vuln_type": "packing",
            "evidence_source": "static entropy/section analysis", "evidence_type": "byte entropy",
            "evidence_bundle": {"isolated_only": True},
            "description": "High entropy in " + ", ".join(s["name"] for s in high_ent_rsrc)
                + " (typically compressed icons/media/resources). Not packing by itself; noted for "
                  "completeness. Corroborate with import-table size / entry-point stub before "
                  "concluding the binary is packed.",
        })

    target = {
        "file": os.path.basename(path), "path": path, "size": len(data),
        "format": "PE" if is_pe else "non-PE", "arch": pe.get("arch", "?"),
        "md5": md5, "sha256": sha256, "entropy": overall_entropy,
        "import_count": pe.get("import_count", 0), "pefile": pe.get("pefile", False),
    }
    hard = hardening.audit(path)
    if hard.get("findings"):
        findings = hard["findings"] + findings   # mitigation gaps first — they frame exploitability
    # Sink/source inventory: kept ONLY as attack-surface context (where to point Ghidra/x64dbg),
    # never as findings. Presence of a dangerous sink is not a vulnerability.
    attack = sinks.inventory(imports)
    from . import config as _cfg
    libsres = libs.audit(path, online=getattr(_cfg, "NVD_ONLINE_LOOKUP", False),
                         api_key=getattr(_cfg, "NVD_API_KEY", ""))
    if libsres.get("findings"):
        findings = findings + libsres["findings"]
    crypto = cryptosec.scan(data, imports)
    if crypto.get("findings"):
        findings = findings + crypto["findings"]
    report = _render_report(target, pe, findings, hard, attack, libsres, crypto)
    n_sinks = sum(len(v) for v in (attack.get("sinks") or {}).values())
    summary = (f"{target['format']} {target['arch']}, {len(findings)} findings, "
               f"{n_sinks} dangerous sinks, {len(attack.get('sources') or {})} input sources")
    raw_strings = _strings(data, min_len=6)
    attack_surface = {
        "sinks": attack.get("sinks", {}),
        "sources": attack.get("sources", {}),
        "note": "Attack surface / investigation targets — NOT vulnerabilities. Presence of these "
                "APIs only tells the analyst where to point static (Ghidra xrefs / source→sink) and "
                "dynamic (x64dbg) analysis. A finding is recorded only once a path is demonstrated.",
    }
    return {"target": target, "findings": findings, "hardening": hard,
            "attack_surface": attack_surface,
            "strings": raw_strings[:2000], "imports": pe.get("imports", []),
            "sections": pe.get("sections", []),
            "report_markdown": report, "summary": summary}


def _render_report(target, pe, findings, hard=None, attack=None, libsres=None, crypto=None) -> str:
    L = ["# Static Triage Report — " + target["file"], "",
         "*Offline analysis (no LLM).*", "",
         "## Target profile", "",
         f"- File: `{target['file']}`  ({target['size']} bytes)",
         f"- Format / Arch: {target['format']} / {target['arch']}",
         f"- MD5: `{target['md5']}`", f"- SHA256: `{target['sha256']}`",
         f"- Overall entropy: {target['entropy']}",
         f"- Imports: {target['import_count']}" if target["pefile"] else "- Imports: (pefile not installed)",
         ""]
    if hard and "text" in hard:
        L += [hard["text"], ""]
    if attack and "text" in attack:
        L += [attack["text"], ""]
    if libsres and "text" in libsres:
        L += [libsres["text"], ""]
    if crypto and "text" in crypto:
        L += [crypto["text"], ""]
    if pe.get("sections"):
        L += ["## Sections", "", "| name | vsize | raw | entropy |", "|---|---|---|---|"]
        L += [f"| {s['name']} | {s['vsize']} | {s['rawsize']} | {s['entropy']} |" for s in pe["sections"]]
        L += [""]
    L += ["## Findings", ""]
    if not findings:
        L += ["No notable static indicators detected.", ""]
    for f in findings:
        L += [f"### [{f['severity']}/{f['status']}] {f['title']}",
              f"- {f.get('description','')}",
              f"- Evidence: {f.get('evidence_source','')} ({f.get('evidence_type','')})", ""]
    L += ["## Recommendation", "",
          "The dangerous sinks and input sources above are leads, not defects. Resolve the real "
          "call sites (Ghidra xrefs) and trace each sink argument back to an untrusted source "
          "before recording a finding; confirm dynamically (x64dbg) before promoting it to "
          "CONFIRMED. If the binary is packed, unpack it first — the import table is unreliable "
          "on packed samples.", ""]
    return "\n".join(L)
