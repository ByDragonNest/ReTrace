"""Security-oriented binary diff (patch-analysis triage).

Not a full BinDiff (no basic-block graph matching). Instead it compares two binaries across the
dimensions that matter for vulnerability research and patch diffing — mitigations, imports,
dangerous sinks, third-party library versions, weak crypto, hardcoded secrets, and strings — and
flags the security-relevant deltas. Convention: A = old version, B = new version.

Deterministic and offline. Use it to triage "what changed that matters", then drill into the
specific functions (Ghidra) around the changed imports/strings.
"""
from typing import Any, Dict, List

from . import hardening, sinks, libs, cryptosec

try:
    import pefile  # noqa
    _HAVE_PEFILE = True
except Exception:  # noqa: BLE001
    _HAVE_PEFILE = False

import re as _re
_STR_RE = _re.compile(rb"[\x20-\x7e]{5,}")


def _imports(data: bytes) -> set:
    if not (_HAVE_PEFILE and data[:2] == b"MZ"):
        return set()
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        out = set()
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            for imp in entry.imports:
                if imp.name:
                    out.add(imp.name.decode("ascii", "ignore"))
        return out
    except Exception:  # noqa: BLE001
        return set()


def _strings(data: bytes, cap: int = 4000) -> set:
    out = set()
    for m in _STR_RE.finditer(data):
        out.add(m.group(0).decode("ascii", "ignore"))
        if len(out) >= cap:
            break
    return out


def _profile(path: str) -> Dict[str, Any]:
    with open(path, "rb") as fh:
        data = fh.read()
    h = hardening.audit(path)
    mit = {m["name"] for m in h.get("mitigations", []) if m.get("present")} if "mitigations" in h else set()
    imports = _imports(data)
    cs = cryptosec.scan(data, list(imports))
    return {
        "path": path, "size": len(data),
        "format": h.get("profile", {}).get("format", "?"), "arch": h.get("profile", {}).get("arch", "?"),
        "mitigations": mit,
        "imports": imports,
        "libs": {c["library"]: c["version"] for c in libs.fingerprint(data)},
        "sinks": {k: set(v) for k, v in sinks.inventory(list(imports))["sinks"].items()},
        "weak_crypto": {w["algo"] for w in cs["weak_crypto"]},
        "secrets": {s["type"] for s in cs["secrets"]},
        "strings": _strings(data),
    }


def diff(path_a: str, path_b: str) -> Dict[str, Any]:
    try:
        A = _profile(path_a)
        B = _profile(path_b)
    except OSError as e:
        return {"error": f"cannot read a file: {e}"}

    findings: List[Dict[str, Any]] = []
    delta: Dict[str, Any] = {}

    # mitigations
    mit_lost = sorted(A["mitigations"] - B["mitigations"])
    mit_gained = sorted(B["mitigations"] - A["mitigations"])
    delta["mitigations"] = {"lost_in_B": mit_lost, "gained_in_B": mit_gained}
    for m in mit_lost:
        findings.append(_f(f"Mitigation regression: {m} removed in version B", "MEDIUM",
                           "CWE-693", f"Mitigation '{m}', present in A, is absent in B."))

    # imports / sinks
    delta["imports"] = {"a_only": sorted(A["imports"] - B["imports"]),
                        "b_only": sorted(B["imports"] - A["imports"])}
    for klass, apis in B["sinks"].items():
        new = apis - A["sinks"].get(klass, set())
        if new:
            cwe = sinks._CLASS[klass][0]
            findings.append(_f(f"New sink in B: {klass} ({', '.join(sorted(new))})", "MEDIUM",
                               cwe, "Dangerous sink introduced in version B; check reachability."))

    # libs (version changes)
    libchg = []
    for lib, vb in B["libs"].items():
        va = A["libs"].get(lib)
        if va and va != vb:
            libchg.append((lib, va, vb))
            findings.append(_f(f"Library version changed: {lib} {va} → {vb}", "LOW", "CWE-1395",
                               "Third-party component updated/changed; compare known CVEs between the two versions."))
    delta["libs"] = {"changed": libchg,
                     "a_only": sorted(set(A["libs"]) - set(B["libs"])),
                     "b_only": sorted(set(B["libs"]) - set(A["libs"]))}

    # weak crypto / secrets introduced in B
    wc_new = sorted(B["weak_crypto"] - A["weak_crypto"])
    delta["weak_crypto"] = {"introduced_in_B": wc_new, "removed_in_B": sorted(A["weak_crypto"] - B["weak_crypto"])}
    for w in wc_new:
        findings.append(_f(f"Weak crypto introduced in B: {w}", "MEDIUM", "CWE-327",
                           "Weak algorithm present in B and not in A."))
    sec_new = sorted(B["secrets"] - A["secrets"])
    delta["secrets"] = {"introduced_in_B": sec_new}
    for s in sec_new:
        findings.append(_f(f"Secret introduced in B: {s}", "HIGH", "CWE-798",
                           "Possible credential/secret present in B and not in A."))

    # strings (count + sample)
    s_only_b = sorted(B["strings"] - A["strings"])
    s_only_a = sorted(A["strings"] - B["strings"])
    delta["strings"] = {"added_in_B": len(s_only_b), "removed_in_B": len(s_only_a),
                        "sample_B": s_only_b[:25], "sample_A": s_only_a[:25]}

    res = {"a": _meta(A), "b": _meta(B), "delta": delta, "findings": findings}
    res["text"] = render(res)
    return res


def _f(title, sev, cwe, desc):
    return {"title": title, "severity": sev, "status": "HYPOTHESIS", "vuln_type": "patch_diff",
            "cwe": cwe, "location": "diff A/B", "evidence_source": "binary diff",
            "evidence_type": "delta", "description": desc,
            "recommendation": "Analyze with Ghidra the functions around the change to confirm its impact."}


def _meta(p):
    return {"path": p["path"], "format": p["format"], "arch": p["arch"], "size": p["size"]}


def render(res: Dict[str, Any]) -> str:
    if "error" in res:
        return f"Diff: {res['error']}"
    d = res["delta"]
    L = ["# Security diff A → B", "",
         f"- A: `{res['a']['path']}` ({res['a']['format']} {res['a']['arch']}, {res['a']['size']} B)",
         f"- B: `{res['b']['path']}` ({res['b']['format']} {res['b']['arch']}, {res['b']['size']} B)", ""]

    def block(title, lines):
        L.append(f"## {title}")
        L.extend(lines if lines else ["- (no change)"])
        L.append("")

    m = d["mitigations"]
    block("Mitigations", ([f"- ❌ lost in B: {x}" for x in m["lost_in_B"]] +
                          [f"- ✅ gained in B: {x}" for x in m["gained_in_B"]]) or None)
    imp = d["imports"]
    il = [f"- + (B only): {', '.join(imp['b_only'][:40])}"] if imp["b_only"] else []
    il += [f"- − (A only): {', '.join(imp['a_only'][:40])}"] if imp["a_only"] else []
    block("Imports", il or None)
    lc = [f"- {lib}: {va} → {vb}" for lib, va, vb in d["libs"]["changed"]]
    lc += [f"- + (B only): {x}" for x in d["libs"]["b_only"]] + [f"- − (A only): {x}" for x in d["libs"]["a_only"]]
    block("Third-party libraries", lc or None)
    cs = [f"- weak crypto + in B: {x}" for x in d["weak_crypto"]["introduced_in_B"]]
    cs += [f"- secret + in B: {x}" for x in d["secrets"]["introduced_in_B"]]
    block("Crypto & secrets", cs or None)
    st = d["strings"]
    block("Strings", [f"- added in B: {st['added_in_B']} · removed in B: {st['removed_in_B']}"] +
          ([f"  - new: {s}" for s in st["sample_B"][:10]] if st["sample_B"] else []))
    L.append(f"**{len(res['findings'])} security-relevant deltas** (see findings).")
    return "\n".join(L)
