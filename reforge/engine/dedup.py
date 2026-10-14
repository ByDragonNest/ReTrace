"""Stable finding identity and root-cause deduplication (prompt §4).

A finding_id is derived deterministically from:

    binary SHA-256 + normalized root cause + normalized component
                   + normalized location + normalized CWE

Findings that hash to the same id are the SAME finding: they are merged, keeping the union of
their evidence_refs and the strongest status/severity. Child items of an aggregated finding do
NOT increase the total count.

Normalization is aggressive on synonyms so that, e.g.:
  * "Weak crypto RC4" and "Use of Broken Stream Cipher RC4"  -> one finding
  * every "password" variant                                 -> one finding
  * every "zlib" variant                                     -> one finding
  * the two SQL injections                                   -> one finding
  * duplicate mitigations                                    -> consolidated
  * Authenticode                                             -> appears once
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List

from . import status as st

# Root-cause synonym table: many titles/vuln_types collapse to one canonical root cause.
_ROOT_SYNONYMS = [
    (re.compile(r"rc4|arcfour|broken stream cipher", re.I), "weak-cipher-rc4"),
    (re.compile(r"\brc2\b", re.I), "weak-cipher-rc2"),
    (re.compile(r"\bdes\b|3des|triple.?des", re.I), "weak-cipher-des"),
    (re.compile(r"\bmd5\b", re.I), "weak-hash-md5"),
    (re.compile(r"sha-?1\b", re.I), "weak-hash-sha1"),
    (re.compile(r"ecb", re.I), "weak-mode-ecb"),
    (re.compile(r"password|passwd|\bpwd\b|hardcoded secret|hardcoded credential", re.I),
     "hardcoded-credential"),
    (re.compile(r"\bzlib\b|inflate|deflate", re.I), "thirdparty-zlib"),
    (re.compile(r"openssl", re.I), "thirdparty-openssl"),
    (re.compile(r"authenticode|code sign", re.I), "hardening-authenticode"),
    # Exploit-mitigation gaps: normalise the offline "Missing mitigation: X" and any LLM restatement
    # ("Missing X Protection", "No X", ...) to one canonical per mitigation, so the SAME gap merges
    # but DIFFERENT gaps stay distinct.
    (re.compile(r"\bdep\b|nx[\s_]?compat|\bnx\b|data execution prevention", re.I), "mitigation-dep"),
    (re.compile(r"aslr|dynamicbase|address space layout", re.I), "mitigation-aslr"),
    (re.compile(r"/gs\b|stack canary|stack cookie|stack (?:buffer )?protection|security cookie", re.I),
     "mitigation-gs"),
    (re.compile(r"control flow guard|\bcfg\b|guard:?cf", re.I), "mitigation-cfg"),
    (re.compile(r"safeseh|seh (?:overwrite|handler|protection)", re.I), "mitigation-safeseh"),
    (re.compile(r"sql\s*inject|sqli", re.I), "sql-injection"),
    (re.compile(r"dll\s*(search|hijack|side.?load)", re.I), "dll-hijack"),
    (re.compile(r"path\s*travers|directory\s*travers", re.I), "path-traversal"),
    (re.compile(r"format\s*string", re.I), "format-string"),
    (re.compile(r"buffer\s*overflow|stack\s*overflow|out.?of.?bounds", re.I), "buffer-overflow"),
    (re.compile(r"insecure\s*rng|weak\s*random|predictable\s*random", re.I), "insecure-rng"),
    (re.compile(r"cleartext|plaintext\s*transport|missing\s*tls", re.I), "cleartext-transport"),
]

_COMPONENT_SYNONYMS = [
    (re.compile(r"rc4|arcfour", re.I), "rc4"),
    (re.compile(r"zlib|inflate|deflate", re.I), "zlib"),
    (re.compile(r"openssl", re.I), "openssl"),
    (re.compile(r"authenticode", re.I), "authenticode"),
]


def _norm_text(s: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(s or "").strip().lower()).strip("-")


def _root_cause(f: Dict[str, Any]) -> str:
    hay = " ".join(str(f.get(k) or "") for k in ("root_cause", "title", "vuln_type", "cwe"))
    for rx, canon in _ROOT_SYNONYMS:
        if rx.search(hay):
            return canon
    # fall back to the explicit root_cause or vuln_type.
    return _norm_text(f.get("root_cause") or f.get("vuln_type") or f.get("title"))


def _component(f: Dict[str, Any]) -> str:
    hay = " ".join(str(f.get(k) or "") for k in ("component", "title", "vuln_type"))
    for rx, canon in _COMPONENT_SYNONYMS:
        if rx.search(hay):
            return canon
    return _norm_text(f.get("component") or "")


def _location(f: Dict[str, Any]) -> str:
    """Normalize location to the containing function, ignoring exact byte offsets so two hits in
    the same function collapse. 'import table' / 'strings' locations normalize to a shared token."""
    loc = str(f.get("location") or "").lower()
    m = re.search(r"(fun_[0-9a-f]+|sub_[0-9a-f]+|[a-z_][a-z0-9_]{2,}\(\))", loc)
    if m:
        return _norm_text(m.group(1))
    if any(k in loc for k in ("import", "symbol", "string", "embedded", "banner")):
        return "static-inventory"
    return _norm_text(loc) or "unknown"


def _cwe(f: Dict[str, Any]) -> str:
    cwe = f.get("cwe")
    if isinstance(cwe, (list, tuple)):
        cwe = cwe[0] if cwe else ""
    m = re.search(r"cwe-?(\d+)", str(cwe or ""), re.I)
    return f"cwe-{m.group(1)}" if m else ""


def finding_id(f: Dict[str, Any], binary_sha256: str = "") -> str:
    root = _root_cause(f)
    # Exploit-mitigation / hardening gaps are binary-wide properties uniquely identified by WHICH
    # mitigation they concern: their location ("PE headers") and CWE vary between the offline audit
    # and any LLM restatement, so keying on those spuriously kept duplicates apart. Key them on the
    # canonical root cause alone.
    # These root causes name a binary-wide property (a mitigation gap, a weak algorithm, a bundled
    # component) that different tools locate differently. Key them on the canonical root cause alone
    # so the offline audit and any LLM restatement collapse into one. NOT applied to per-instance
    # findings (e.g. hardcoded-credential), where distinct locations mean distinct findings.
    if root.startswith(("mitigation-", "hardening-", "weak-", "thirdparty-")):
        digest = hashlib.sha256("|".join([binary_sha256 or "", root]).encode("utf-8")).hexdigest()[:12]
        return "F-" + digest
    parts = [binary_sha256 or "", root, _component(f), _location(f), _cwe(f)]
    digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:12]
    return "F-" + digest


def _merge_two(base: Dict[str, Any], other: Dict[str, Any]) -> Dict[str, Any]:
    """Merge `other` into `base`: keep strongest status, union evidence/assumptions/gaps, record
    the merged children so the count logic can ignore them."""
    if st.rank(other.get("status")) > st.rank(base.get("status")):
        base["status"] = st.normalize(other.get("status"))
    # union list-ish fields
    for k in ("evidence_refs", "assumptions", "missing_validation_steps", "coverage_gaps"):
        merged = list(base.get(k) or [])
        for v in (other.get(k) or []):
            if v not in merged:
                merged.append(v)
        base[k] = merged
    # keep the worst potential severity
    from . import schema as sc
    # Normalise before ranking: `_band_rank` wants a band name and these lookups can be None,
    # which `norm_band` turns into the documented default. The line below already normalised the
    # value it stored, so only the comparison was taking the raw one.
    _other_band = sc.norm_band(other.get("potential_severity") or other.get("severity"))
    _base_band = sc.norm_band(base.get("potential_severity") or base.get("severity"))
    if sc._band_rank(_other_band) < sc._band_rank(_base_band):
        base["potential_severity"] = sc.norm_band(other.get("potential_severity") or other.get("severity"))
    # record child titles (do NOT add to totals).
    children = base.setdefault("merged_from", [])
    label = other.get("title") or other.get("id") or ""
    if label and label not in children:
        children.append(label)
    return base


def deduplicate(findings: List[Dict[str, Any]], binary_sha256: str = "") -> List[Dict[str, Any]]:
    """Collapse equivalent findings. Returns the unique list; each carries `id` and `merged_from`."""
    by_id: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    for f in findings:
        fid = finding_id(f, binary_sha256)
        f["id"] = fid
        if fid in by_id:
            _merge_two(by_id[fid], f)
        else:
            f.setdefault("merged_from", [])
            by_id[fid] = f
            order.append(fid)
    return [by_id[i] for i in order]


def unique_count(findings: List[Dict[str, Any]]) -> int:
    """Number of UNIQUE findings (aggregated children never inflate this)."""
    return len({f.get("id") for f in findings})
