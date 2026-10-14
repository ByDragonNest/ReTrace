"""Vulnerability research report — single, unified report generator (Phase: reporting).

Produces one complete, professional report structure covering the full lifecycle of a binary
vulnerability-research engagement:
  cover · definitions · classification/disclaimer · executive summary (with a plain-language
  digest) · methodology/CVSS · scope · vulnerability overview · CWE index · summary table ·
  prioritized remediation · detailed findings · conclusions · appendices (tool execution log,
  evidence, validation warnings).

The backbone is fully DETERMINISTIC — built from the structured findings and the target profile —
so a complete, well-formatted report exists even with no LLM configured. If an LLM provider is
configured AND report enrichment is explicitly enabled (`REPORT_USE_LLM_ENRICHMENT`), an optional
executive narrative and prioritized remediation plan are appended; this never changes the
deterministic numbers, tables or structure above.

Output is Markdown, consumed by report_export.py (HTML/PDF) and report_docx.py (Word). A blank
fill-in template (same structure, placeholder values) is produced by `template()`.
"""
import json
import time
from collections import Counter
from typing import Any, Dict, List

from . import findings as fx
from .session import Session

CLASSIFICATION = "INTERNAL USE — CONFIDENTIAL"

# Label pack. Kept as a dict so all display strings live in one place.
_STR = {
    "title": "Technical Report — Reverse Engineering & Vulnerability Analysis",
    "classif": CLASSIFICATION, "date": "Date", "tool": "Tool",
    "name": "Name", "role": "Role", "author": "Author", "reviewer": "Reviewer",
    "version": "Version", "changes": "Changes", "first": "First issue",
    "s1": "1. Definitions and acronyms", "term": "Term", "desc": "Description",
    "s2": "2. Classification and confidentiality", "disclaimer": "Disclaimer",
    "s3": "3. Executive Summary", "sev": "Severity", "nvuln": "Number of Vulnerabilities",
    "crit": "Critical", "high": "High", "med": "Medium", "low": "Low", "info": "Informational",
    "s4": "4. Activity description", "obj": "Objectives and methodology",
    "cvss_def": "Definition", "perimeter": "Scope definition (technical data)",
    "elem": "Item", "value": "Value",
    "s5": "5. Vulnerability overview",
    "s6": "6. Vulnerability summary and assessment sheet",
    "vuln": "Vulnerability", "reco": "Recommendation",
    "s7": "7. Detailed vulnerability analysis",
    "field": "Field", "status": "Status", "confidence": "Confidence",
    "location": "Location", "evidences": "Evidence",
    "descr_l": "Description", "impact_l": "Impact", "evid_act": "Activity evidence", "reco_l": "Recommendation",
    "s8": "8. Conclusions", "validation": "Technical validation",
    "s9": "9. Appendices", "appA": "Appendix A — Tool execution summary",
    "appB": "Appendix B — Collected evidence", "appC": "Appendix C — Limits and validation",
    "tool_h": "Tool", "calls": "Calls", "errors": "Errors",
    "id": "ID", "source": "Source", "synth": "Summary",
    "end": "End of report", "risk_low": "LOW", "risk_mid": "MEDIUM", "risk_high": "HIGH",
    "no_vuln": "No vulnerability recorded", "no_detail": "No vulnerability to detail.",
    "cwe_idx": "5.1 CWE index", "cwe_col": "CWE", "nfind": "Findings", "maxsev": "Max severity",
    "plain_h": "In plain language (executive digest)", "mitig_h": "4.1 Mitigation profile",
    "mitig_col": "Mitigation", "present": "Present", "absent": "Absent",
    "ai_h1": "10. Management summary (AI-assisted)",
    "ai_h2": "11. Prioritized remediation plan (AI-assisted)",
    "toc": "Contents", "total": "Total", "risk_overall": "Overall risk",
    "distrib": "Distribution by severity", "vulns_word": "vulnerabilities",
    "s6_1": "6.1 Remediation priorities", "prio": "Priority",
    "action": "Recommended action",
    "remediation_intro": "Actions ordered by urgency (severity and level of confirmation). "
                         "Start from the top: the leading items combine the worst impact with the "
                         "highest certainty of exploitability.",
    "no_remediation": "No remediation required: no vulnerabilities were recorded.",
}

T = _STR  # module-level shortcut (single language)

# Severity → CVSS band (deterministic mapping, v3.1 qualitative ranges).
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_SEV_LABEL = {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Informational"}
_CVSS_BAND = {"CRITICAL": "9.0 – 10.0", "HIGH": "7.0 – 8.9", "MEDIUM": "4.0 – 6.9",
              "LOW": "0.1 – 3.9", "INFO": "N/A"}
_CVSS_REPR = {"CRITICAL": "9.8", "HIGH": "8.1", "MEDIUM": "6.1", "LOW": "3.1", "INFO": "0.0"}


def _sev(f) -> int:
    return _SEV_ORDER.get((f.get("severity") or "INFO").upper(), 4)


def _cwe_str(f, default="—") -> str:
    """Normalize a finding's `cwe` (list or string or absent) to a display string."""
    v = f.get("cwe")
    if not v:
        return default
    if isinstance(v, (list, tuple, set)):
        items = [str(x).strip() for x in v if str(x).strip()]
        return ", ".join(dict.fromkeys(items)) or default
    return str(v).strip() or default


def _clip(text: str, n: int) -> str:
    """Truncate on a word boundary with an ellipsis (never mid-word)."""
    t = (text or "").replace("\n", " ").strip()
    if len(t) <= n:
        return t
    cut = t[:n].rsplit(" ", 1)[0].rstrip(",;:.")
    return (cut or t[:n]) + "…"


def _cwe_links(cwe_display: str) -> str:
    """Turn a 'CWE-121, CWE-787' display string into Markdown links to cwe.mitre.org.

    Non-CWE tokens (e.g. 'No CWE', '—') are passed through unchanged. Exporters that do not
    render links degrade gracefully to the visible link text.
    """
    import re
    def repl(m):
        num = m.group(1)
        return f"[CWE-{num}](https://cwe.mitre.org/data/definitions/{num}.html)"
    return re.sub(r"CWE-(\d+)", repl, cwe_display or "")


def _slugify(text: str) -> str:
    """GitHub-style heading slug - report_export's, so the TOC links match the heading ids.

    This used to try an import that could never succeed (report_export had no `slugify`) and fall
    back to a local copy, which meant the "kept in sync" in its docstring described an intention
    rather than a fact. One implementation now, and the HTML export emits the ids it produces.
    """
    from .report_export import slugify
    return slugify(text)


def _sev_label(f) -> str:
    return _SEV_LABEL.get((f.get("severity") or "INFO").upper(), "Informational")


def _counts(F) -> Dict[str, int]:
    """Severity distribution over UNIQUE VULNERABILITY-CANDIDATE findings.

    Aggregated children never inflate counts. Neutral observations (hardening/mitigation gaps) and
    rejected findings are excluded — they are reported in their own sections and are not
    vulnerabilities, so counting them here overstated the vulnerability totals. Prompt §4/§13/§17.
    """
    from .engine import dedup as _dd
    uniq = _dd.deduplicate([dict(f) for f in F])
    c = {k: 0 for k in _SEV_ORDER}
    for f in uniq:
        if fx.category(f) in ("observation", "rejected"):
            continue
        s = (f.get("severity") or "INFO").upper()
        c[s] = c.get(s, 0) + 1
    return c


def _risk_split(F) -> Dict[str, Any]:
    """Dual overall risk: confirmed-only vs potential-if-hypotheses-confirmed (prompt §13)."""
    from .engine import schema as _esc, dedup as _dd
    uniq = _dd.deduplicate([dict(f) for f in F])
    return _esc.overall_risk(uniq)


def _overall_risk(F) -> str:
    """Overall CONFIRMED risk only — hypotheses do not raise it (prompt §13)."""
    split = _risk_split(F)
    band = split.get("overall_confirmed_risk", "NONE")
    if band in ("CRITICAL", "HIGH"):
        return T["risk_high"]
    if band == "MEDIUM":
        return T["risk_mid"]
    return T["risk_low"]


def _cvss_score(f) -> str:
    """Numeric CVSS string, gated by confirmation (prompt §2/§13).

    CVSS is withheld ("N/A") for anything that is not CONFIRMED_STATIC/DYNAMIC — a hypothesis must
    never carry a CVSS number. For confirmed findings we prefer a fully-justified vector; failing
    that, an explicit numeric cvss field; we never invent a band-representative score.
    """
    from . import severity as _sevmod
    from .engine import status as _est, schema as _esc
    if not _est.is_confirmed(f.get("status")):
        return "N/A"
    j = _esc.justified_cvss(f)
    if j.get("score") is not None:
        return f"{j['score']:.1f}"
    raw = f.get("cvss") or f.get("cvss_score")
    score = _sevmod.cvss_score(raw, severity=f.get("severity"), allow_band_default=False)
    return f"{score:.1f}" if score else "N/A"


def _cvss_vector(f) -> str:
    return f.get("cvss_vector") or "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (estimated)"


def _profile(session: Session) -> Dict[str, Any]:
    return session.target_profile or {}


def _app_name(session: Session) -> str:
    p = _profile(session)
    return p.get("file") or session.name or session.id


def _missing_mitigations(session: Session) -> List[str]:
    return [f["title"].split(":", 1)[1].strip() for f in (session.findings or [])
            if f.get("vuln_type") == "hardening" and f.get("title", "").startswith("Missing mitigation")]


def _mitigation_rows(session: Session) -> List[Dict[str, Any]]:
    return (session.target_profile or {}).get("mitigations") or []


def _tool_summary(session: Session) -> List[str]:
    """Aggregate the investigation log into per-tool call/error counts (deterministic)."""
    log = getattr(session, "investigation_log", []) or []
    calls: Counter[str] = Counter()
    errors: Counter[str] = Counter()
    for e in log:
        tname = e.get("tool", "?")
        calls[tname] += 1
        if e.get("is_error"):
            errors[tname] += 1
    return [f"| {tname} | {n} | {errors.get(tname, 0)} |" for tname, n in calls.most_common()]


def _plain_exec_summary(F, top_label: str, miss: List[str]) -> List[str]:
    """High-level, non-technical executive digest built from the findings' plain-language
    explanations (when present). Works fully offline, no LLM needed."""
    risk_word = {"CRITICAL": "very high", "HIGH": "high", "MEDIUM": "medium",
                 "LOW": "low", "INFO": "negligible"}
    risk = risk_word.get(top_label, risk_word["INFO"])
    if not F:
        return ["> **" + T["plain_h"] + "** — No relevant security issues were found in this "
                "program. It is still good practice to keep it up to date."]
    n_crit = sum(1 for f in F if (f.get("severity") or "").upper() == "CRITICAL")
    n_high = sum(1 for f in F if (f.get("severity") or "").upper() == "HIGH")
    out = [f"> **{T['plain_h']}** — The overall risk level of this program is **{risk}**. "
           f"Here is what was found and why it matters, without jargon.", ""]
    seen, picks = set(), []
    for f in sorted(F, key=_sev):
        title = (f.get("title") or "").strip().lower()
        if f.get("plain") and title not in seen:
            seen.add(title); picks.append(f)
        if len(picks) >= 3:
            break
    out += [f"- **{f.get('title', 'Finding')}** — {f['plain']}" for f in picks]
    if picks:
        out.append("")
    if n_crit or n_high:
        cw = f"{n_crit} critical" if n_crit else ""
        hw = f"{n_high} high-severity" if n_high else ""
        parts = ", ".join(p for p in (cw, hw) if p)
        out.append(f"The most serious issues ({parts}) should be addressed first: they carry "
                   "the worst consequences if exploited.")
    if miss:
        out.append("The program also does not have some standard protections enabled ("
                   + ", ".join(sorted(miss)) + "): not vulnerabilities by themselves, but they "
                   "lower the defenses.")
    out.append("Full technical details, evidence and recommendations follow in the next sections.")
    return out


# ---------------------------------------------------------------- sections
def _cover(session: Session, app_name: str) -> List[str]:
    today = time.strftime("%d/%m/%Y")
    return [
        f"# {T['title']}",
        f"## {app_name}",
        "",
        f"> **{T['classif']}**",
        f"> **{T['date']}:** {today} · **{T['tool']}:** ReTrace",
        "",
        f"| | **{T['name']}** | **{T['role']}** |",
        "| --- | --- | --- |",
        f"| {T['author']} | _________________ | Security / Vulnerability Researcher |",
        f"| {T['reviewer']} | _________________ | Reviewer |",
        "",
        f"| {T['version']} | {T['date']} | {T['changes']} |",
        "| --- | --- | --- |",
        f"| 1.0 | {today} | {T['first']} |",
        "",
    ]


def _toc() -> List[str]:
    """Table of contents with anchor links to the always-present top-level sections."""
    keys = ["s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9"]
    L = [f"## {T['toc']}", ""]
    for k in keys:
        title = T[k]
        L.append(f"- [{title}](#{_slugify(title)})")
    return L + [""]


def _definitions() -> List[str]:
    rows = [
        ("Vulnerability", "A weakness in a system, procedure or control that can be exploited to compromise security."),
        ("Exploit", "Code or sequence designed to take advantage of a vulnerability."),
        ("CWE", "Common Weakness Enumeration: standard classification of software weaknesses."),
        ("CVSS", "Common Vulnerability Scoring System: severity score from 0 to 10."),
        ("Sink", "Function/point where untrusted data can cause a dangerous effect."),
        ("Source", "Entry point of untrusted data (arguments, files, network, environment)."),
        ("Static analysis", "Analysing the binary without running it (disassembly, decompilation, strings)."),
        ("Dynamic analysis", "Runtime analysis via a debugger (e.g. x64dbg) with breakpoints and inspection."),
    ]
    L = [f"## {T['s1']}", "", f"| **{T['term']}** | **{T['desc']}** |", "| --- | --- |"]
    L += [f"| {k} | {v} |" for k, v in rows]
    return L + [""]


def _classification() -> List[str]:
    return [
        f"## {T['s2']}", "",
        f"This document is classified as **{T['classif']}** and contains confidential information "
        "related to the authorized security analysis activities on the target application.",
        "", f"### {T['disclaimer']}",
        "The evidence, results and recommendations represent a point-in-time assessment of the "
        "security state of the analysed binary at the date of execution. These findings may no "
        "longer be current after changes to the software. Periodic repetition of the analysis is "
        "recommended, in particular upon new releases or significant changes.", "",
    ]


def _executive_summary(session: Session, app_name: str) -> List[str]:
    F = session.findings or []
    counts = _counts(F)
    risk = _overall_risk(F)
    confirmed = [f for f in F if fx.category(f) == "confirmed"]
    presence = "presence" if confirmed else "absence"
    L = [
        f"## {T['s3']}", "",
        f"A reverse-engineering and vulnerability-research activity was carried out on the application "
        f"**{app_name}**, to assess its security posture and identify exploitable defects.", "",
        f"Given the current state of technology, the risk-exposure profile of **{app_name}** is **{risk}**.", "",
        f"The **{presence}** of criticalities able to facilitate exploitation was observed. "
        f"The identified vulnerabilities are summarised below, grouped by risk level.", "",
    ]
    total = sum(counts.values())
    snapshot = (f"{counts['CRITICAL']} {T['crit']} · {counts['HIGH']} {T['high']} · "
                f"{counts['MEDIUM']} {T['med']} · {counts['LOW']} {T['low']} · "
                f"{counts['INFO']} {T['info']}")
    split = _risk_split(F)
    sc = split.get("counts", {})
    n_conf = sc.get("vulnerabilities_confirmed", 0)
    n_hyp = sc.get("hypotheses", 0)
    n_obs = sc.get("observations", 0)
    L += [f"> **{T['risk_overall']}: {risk}** — {snapshot}", "",
          f"> Of these, **{n_conf} confirmed** vulnerabilit{'y' if n_conf == 1 else 'ies'}, "
          f"**{n_hyp} to validate** (attack-surface leads from static/offline signals, not yet "
          f"proven exploitable), and **{n_obs} neutral observations** (e.g. missing exploit "
          f"mitigations). The severity distribution below counts vulnerability candidates only; "
          f"observations are detailed in the mitigation-profile section.", "",
          f"| {T['sev']} | {T['nvuln']} |", "| --- | --- |",
          f"| {T['crit']} | {counts['CRITICAL']} |",
          f"| {T['high']} | {counts['HIGH']} |",
          f"| {T['med']} | {counts['MEDIUM']} |",
          f"| {T['low']} | {counts['LOW']} |",
          f"| {T['info']} | {counts['INFO']} |",
          f"| **{T['total']}** | **{total}** |", "",
    ]
    top = min((_sev(x) for x in F), default=4)
    top_label = next((k for k, v in _SEV_ORDER.items() if v == top), "INFO")
    miss = _missing_mitigations(session)
    L += _plain_exec_summary(F, top_label, miss) + [""]
    return L


def reproducibility(session: Session) -> Dict[str, Any]:
    """Everything needed to reproduce this report, as structured data.

    Acceptance criterion 9 is that the same artifact, tools, versions and configuration produce the
    same result. That is only a checkable claim if the report records what those were. A customer
    disputing a finding, or an analyst re-running an assessment six months later, needs to know
    which prompt wrote the narrative and which analyzer version produced the evidence - otherwise
    "it says something different now" has no answer.

    Deliberately excluded: anything secret, any provider key, and the content of the analyzed
    binary. This section is identifiers and versions only.
    """
    from . import __version__
    from . import prompts as _prompts
    from .engine import intake as _intake

    prof = session.target_profile or {}
    tools: Dict[str, str] = {"retrace": __version__, "finding_schema": str(_intake.SCHEMA_VERSION)}
    for finding in (session.findings or []):
        name = finding.get("produced_by_tool")
        if name:
            tools.setdefault(str(name), str(finding.get("produced_by_tool_version") or "unknown"))

    try:
        prompt_versions = _prompts.versions()
    except OSError:
        prompt_versions = {}

    return {
        "retrace_version": __version__,
        "artifact_sha256": prof.get("sha256", ""),
        "artifact_size": prof.get("size"),
        "tools": tools,
        "prompts": prompt_versions,
        "analysis_config": _analysis_config_fingerprint(),
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
    }


def _analysis_config_fingerprint() -> Dict[str, Any]:
    """The configuration that can change a RESULT, plus a hash of it.

    Only settings that affect analysis: a different port or log level must not look like a
    different analysis. The hash is for comparing two reports at a glance; the values are listed
    so a difference can be explained rather than merely detected.
    """
    import hashlib

    from . import config

    relevant = {
        "safety_mode": getattr(config, "SAFETY_MODE", ""),
        "allow_outside_workspace": getattr(config, "ALLOW_OUTSIDE_WORKSPACE", None),
        "nvd_online_lookup": getattr(config, "NVD_ONLINE_LOOKUP", None),
        "report_use_llm_enrichment": getattr(config, "REPORT_USE_LLM_ENRICHMENT", None),
        "llm_provider": getattr(config, "LLM_PROVIDER", ""),
        "model": config.active_model() if hasattr(config, "active_model") else "",
    }
    blob = json.dumps(relevant, sort_keys=True, default=str)
    relevant["fingerprint"] = hashlib.sha256(blob.encode("utf-8")).hexdigest()[:12]
    return relevant


def _reproducibility_section(session: Session) -> List[str]:
    """Render the reproducibility data as a report section."""
    data = reproducibility(session)
    L = ["## Reproducibility", "",
         "The inputs and versions this report was produced from. Re-running with the same values "
         "on the same artifact produces the same findings; a difference here explains a difference "
         "in the result.", "",
         "| | |", "|---|---|",
         f"| ReTrace version | `{data['retrace_version']}` |"]
    if data["artifact_sha256"]:
        L.append(f"| Artifact SHA-256 | `{data['artifact_sha256']}` |")
    cfg = data["analysis_config"]
    L += [f"| Analysis configuration | `{cfg['fingerprint']}` |",
          f"| LLM provider / model | {cfg['llm_provider'] or 'none'} / {cfg['model'] or '—'} |",
          f"| LLM narrative enrichment | {'on' if cfg['report_use_llm_enrichment'] else 'off'} |",
          f"| Generated | {data['generated_at']} |", ""]
    if data["tools"]:
        L += ["**Analyzer versions**", "", "| tool | version |", "|---|---|"]
        L += [f"| `{name}` | `{ver}` |" for name, ver in sorted(data["tools"].items())]
        L.append("")
    if data["prompts"]:
        L += ["**Prompt versions** (content hashes; a changed prompt changes its version)", "",
              "| prompt | version |", "|---|---|"]
        L += [f"| `{name}` | `{ver}` |" for name, ver in sorted(data["prompts"].items())]
        L.append("")
    return L


def _methodology() -> List[str]:
    return [
        f"## {T['s4']}", "", f"### {T['obj']}",
        "The analysis aims to assess the overall security level of the binary, documenting the "
        "presence or absence of exploitable vulnerabilities. It follows a structured workflow: "
        "**Triage → Classification → Capability mapping → Attack surface → Vulnerability hunting "
        "→ Exploitability → Reporting → Validation**, combining static analysis (disassembly/"
        "decompilation, strings, imports, attack surface) and, where applicable, dynamic analysis "
        "(debugger).",
        "", "### Common Vulnerability Scoring System (CVSS)",
        "Severity is expressed via CVSS v3.1 (Base Score). The table below defines the levels and ranges.", "",
        f"| {T['sev']} | CVSS Score | {T['cvss_def']} |", "| --- | --- | --- |",
        f"| {T['crit']} | 9.0 – 10.0 | Immediate exploitation. Immediate intervention and patching. |",
        f"| {T['high']} | 7.0 – 8.9 | More complex exploitation but high impact. Prioritised patching. |",
        f"| {T['med']} | 4.0 – 6.9 | Present but not directly exploitable or with prerequisites. Planned patching. |",
        f"| {T['low']} | 0.1 – 3.9 | Not directly exploitable; increases the attack surface. |",
        f"| {T['info']} | N/A | No known vulnerability; hardening guidance. |", "",
    ]


def _mitigation_profile(session: Session) -> List[str]:
    mits = _mitigation_rows(session)
    if not mits:
        return []
    L = [f"### {T['mitig_h']}", "", f"| **{T['mitig_col']}** | **{T['status']}** |", "| --- | --- |"]
    for m in mits:
        state = T["present"] if m.get("present") else T["absent"]
        L.append(f"| {m.get('name', '?')} | {state} |")
    return L + [""]


def _scope(session: Session, app_name: str) -> List[str]:
    p = _profile(session)
    today = time.strftime("%d/%m/%Y")
    return [
        f"### {T['perimeter']}", "", f"| {T['elem']} | {T['value']} |", "| --- | --- |",
        f"| Time window | {today} |",
        "| Test mode | White box (binary analysis) |",
        "| Execution mode | Local analysis via ReTrace (offline) |",
        f"| Application | {app_name} |",
        f"| Format / Architecture | {p.get('format', 'n/a')} · {p.get('arch', 'n/a')} |",
        f"| Size | {p.get('size', 'n/a')} bytes |",
        f"| MD5 | {p.get('md5', 'n/a')} |",
        f"| SHA-256 | {p.get('sha256', 'n/a')} |", "",
    ]


def _cwe_index(session: Session) -> List[str]:
    """5.1 — findings grouped by CWE, sorted by worst severity in each group."""
    from collections import defaultdict
    F = session.findings or []
    no_cwe = "No CWE"
    by_cwe = defaultdict(list)
    for f in F:
        by_cwe[_cwe_str(f, no_cwe)].append(f)
    if not by_cwe:
        return []
    L = [f"### {T['cwe_idx']}", "",
         f"| **{T['cwe_col']}** | **{T['nfind']}** | **{T['maxsev']}** |", "| --- | --- | --- |"]
    for cwe, fs in sorted(by_cwe.items(), key=lambda item: min((_sev(x) for x in item[1]), default=4)):
        maxsev = _sev_label(sorted(fs, key=_sev)[0])
        L.append(f"| {_cwe_links(cwe)} | {len(fs)} | {maxsev} |")
    return L + [""]


def _overview(session: Session) -> List[str]:
    F = session.findings or []
    counts = _counts(F)
    intro = ("This section summarises the risk-exposure profile. The analysis, however thorough, "
             "cannot be considered exhaustive.")
    L = [f"## {T['s5']}", "", intro, "", f"**{T['distrib']}**", ""]
    total = sum(counts.values())
    maxc = max(counts.values()) if total else 0
    sevkeys = {"CRITICAL": T["crit"], "HIGH": T["high"], "MEDIUM": T["med"], "LOW": T["low"], "INFO": T["info"]}
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n = counts[sev]
        pct = round(100 * n / total) if total else 0
        bar = "█" * int(round(20 * n / maxc)) if (maxc and n) else ""
        L.append(f"- **{sevkeys[sev]}**: {n} ({pct}%) {bar}".rstrip())
    L.append("")
    L.append(f"{T['total']}: {total} {T['vulns_word']}.")
    L.append("")
    L += _cwe_index(session)
    return L


def _summary_table(session: Session) -> List[str]:
    F = sorted(session.findings or [], key=_sev)
    notitle = "(no title)"
    L = [f"## {T['s6']}", "",
         f"| # | {T['vuln']} | {T['sev']} | CVSS | CWE | {T['status']} | {T['reco']} |",
         "| --- | --- | --- | --- | --- | --- | --- |"]
    if not F:
        L.append(f"| — | {T['no_vuln']} | — | — | — | — | — |")
    for i, f in enumerate(F, 1):
        rec = _clip(f.get("recommendation") or "—", 80)
        L.append(f"| {i} | {f.get('title', notitle)} | {_sev_label(f)} | {_cvss_score(f)} "
                 f"| {_cwe_str(f)} | {fx.normalize_status(f.get('status'))} | {rec} |")
    L += [""]
    L += _remediation_plan(session)
    return L


def _remediation_plan(session: Session) -> List[str]:
    """Deterministic, always-present remediation priority list.

    Ranks findings by severity, then by confidence (more certain first) so the top rows combine
    worst impact with highest exploitability certainty. No LLM, no invented content.
    """
    F = [f for f in (session.findings or []) if fx.category(f) != "rejected"]
    L = [f"### {T['s6_1']}", ""]
    if not F:
        return L + [T["no_remediation"], ""]
    ordered = sorted(F, key=lambda f: (_sev(f),
                                       -fx.confidence_value(f.get("confidence"), fx.confidence(f))))
    L += [T["remediation_intro"], "",
          f"| {T['prio']} | {T['vuln']} | {T['sev']} | CVSS | {T['status']} | {T['action']} |",
          "| --- | --- | --- | --- | --- | --- |"]
    notitle = "(no title)"
    for i, f in enumerate(ordered, 1):
        action = _clip(f.get("recommendation") or "—", 90)
        L.append(f"| {i} | {_clip(f.get('title', notitle), 48)} | {_sev_label(f)} "
                 f"| {_cvss_score(f)} | {fx.normalize_status(f.get('status'))} | {action} |")
    return L + [""]


def _detailed(session: Session) -> List[str]:
    F = sorted(session.findings or [], key=_sev)
    notitle = "(no title)"
    L = [f"## {T['s7']}", ""]
    if not F:
        return L + [T["no_detail"], ""]
    for i, f in enumerate(F, 1):
        refs = ", ".join(f.get("evidence_refs") or []) or "—"
        conf = f.get("confidence", fx.confidence(f))
        pot = (f.get("potential_severity") or "").upper()
        cur = (f.get("severity") or "INFO").upper()
        rows = [
            f"### 7.{i} {f.get('title', notitle)}", "",
            f"| {T['field']} | {T['value']} |", "| --- | --- |",
            f"| CWE | {_cwe_str(f)} |",
            f"| {T['sev']} | {_sev_label(f)} |",
        ]
        # If the finding is a lead whose worst case is higher than its presence severity, show it —
        # the reader still sees the potential impact without the count being inflated.
        if pot and pot in _SEV_ORDER and _SEV_ORDER[pot] < _SEV_ORDER.get(cur, 4):
            rows.append(f"| Potential severity (if confirmed) | "
                        f"{_SEV_LABEL.get(pot, 'Informational')} |")
        rows += [
            f"| CVSS Score | {_cvss_score(f)} |",
            f"| CVSS Vector | {_cvss_vector(f)} |",
            f"| {T['status']} | {fx.normalize_status(f.get('status'))} |",
            f"| {T['confidence']} | {fx.confidence_pct(conf, fx.confidence(f))}% |",
            f"| {T['location']} | {f.get('location', '—')} |",
            f"| {T['evidences']} | {refs} |", "",
        ]
        L += rows
        if f.get("description"):
            L += [f"**{T['descr_l']}.** {f['description']}", ""]
        if f.get("impact"):
            L += [f"**{T['impact_l']}.** {f['impact']}", ""]
        if f.get("evidence"):
            L += [f"**{T['evid_act']}.** {f['evidence']}", ""]
        if f.get("recommendation"):
            L += [f"**{T['reco_l']}.** {f['recommendation']}", ""]
    return L


def _conclusions(session: Session, app_name: str) -> List[str]:
    F = session.findings or []
    risk = _overall_risk(F)
    confirmed = [f for f in F if fx.category(f) == "confirmed"]
    presence = "presence" if confirmed else "absence"
    body = [
        f"Given the current state of technology, the risk-exposure profile of **{app_name}** is **{risk}**.", "",
        f"The **{presence}** of criticalities able to facilitate the execution and finalisation of known "
        f"exploits was observed. It is recommended to address the vulnerabilities following the priority "
        f"order in the assessment sheet and to repeat the analysis after the fixes.", "",
    ]
    return [f"## {T['s8']}", ""] + body + ["_______________________  ", f"**{T['validation']}**", ""]


def _appendices(session: Session) -> List[str]:
    none_tool = "No tool calls recorded (offline analysis)."
    none_ev = "No evidence recorded."
    none_warn = "No validation warnings."
    L = [f"## {T['s9']}", "", f"### {T['appA']}", ""]
    rows = _tool_summary(session)
    if rows:
        L += [f"| **{T['tool_h']}** | **{T['calls']}** | **{T['errors']}** |", "| --- | --- | --- |"] + rows
    else:
        L.append(none_tool)
    L += ["", f"### {T['appB']}", ""]
    evs = getattr(session, "evidence", []) or []
    if evs:
        L += [f"| **{T['id']}** | **{T['source']}** | **{T['location']}** | **{T['synth']}** |", "| --- | --- | --- | --- |"]
        for e in evs:
            loc = " ".join(f"{k}={v}" for k, v in (e.get("location") or {}).items() if v) or "—"
            L.append(f"| {e.get('id')} | {e.get('source', '?')} | {loc} | {_clip(e.get('summary') or '', 90)} |")
    else:
        L.append(none_ev)
    L += ["", f"### {T['appC']}", ""]
    warns = fx.validate(session)
    if warns:
        L += [f"- {'⚠️' if w['level'] == 'warn' else 'ℹ️'} {w['msg']}" for w in warns]
    else:
        L.append(none_warn)
    return L + [""]


_ENRICH_EN = """\
You are drafting the report. Given the authoritative structured findings list and the binary's
mitigation profile, write ONLY two Markdown sections, concise and factual, in English, with level
## headings and these exact titles:

## 10. Management summary (AI-assisted)
3-5 sentences: what the target is, the overall risk, the most severe findings (with CWE).

## 11. Prioritized remediation plan (AI-assisted)
Numbered list by priority: what to fix first and why, tying severity to exploitability.

Do not invent evidence or vulnerabilities not present in the findings. Do not repeat the full list.
"""


def _engine_view(session: Session) -> List[Dict[str, Any]]:
    """Gated + risk-scored + deduplicated COPIES of the session findings (single choke point).

    Never mutates the stored findings: the raw status the analyst typed is preserved on disk; the
    delivered report shows the evidence-gated view (prompt §1/§4/§5/§13).
    """
    from .engine import adapter as _ad
    prof = session.target_profile or {}
    sha = prof.get("sha256") or prof.get("sha-256") or ""
    return _ad.normalize(session.findings or [], sha)


def _deterministic(session: Session) -> str:
    """Build the full deterministic report body (no LLM), from the engine-normalized view."""
    original = session.findings
    try:
        session.findings = _engine_view(session)
        app = _app_name(session)
        L: List[str] = []
        L += _cover(session, app)
        L += _toc()
        L += _definitions()
        L += _classification()
        L += _executive_summary(session, app)
        L += _methodology()
        L += _reproducibility_section(session)
        L += _scope(session, app)
        L += _mitigation_profile(session)
        L += _overview(session)
        L += _summary_table(session)
        L += _detailed(session)
        L += _conclusions(session, app)
        L += _appendices(session)
        L.append(f"*{T['end']} — ReTrace · {T['classif']}*")
        return "\n".join(L)
    finally:
        session.findings = original


async def generate(session: Session, lang: str | None = None) -> str:
    """The single, complete report.

    The structure, numbers, tables and CVSS mapping are always deterministic. If an LLM provider
    is configured AND `config.REPORT_USE_LLM_ENRICHMENT` is enabled, an optional AI-assisted
    management summary and remediation plan are appended — purely additive, never altering the
    deterministic content above. Safe to call with no LLM configured: returns the deterministic
    report unchanged.

    `lang` is accepted for call-site compatibility with the UI language setting. This module is
    currently single-language (English, ``T = _STR``); the parameter is reserved for a future
    multi-language table and is otherwise ignored.
    """
    base = _deterministic(session)

    try:
        from . import config
    except Exception:
        return base
    if not getattr(config, "REPORT_USE_LLM_ENRICHMENT", False):
        return base

    from .llm import get_llm
    from .config import system_prompt
    llm = get_llm()
    if not llm.available or not session.findings:
        return base
    try:
        view = _engine_view(session)
        mits = _mitigation_rows(session)
        missing = [str(m.get("name") or "") for m in mits if not m.get("present")]
        payload = ("Findings (JSON):\n" + json.dumps(view, indent=2, default=str)
                   + "\n\nMissing mitigations: " + (", ".join(missing) or "none") + "\n\n" + _ENRICH_EN)
        extra = await llm.complete(system_prompt(), [], payload)
        usage = getattr(llm, "last_usage", None)
        if usage:
            try:
                from . import llm_cost
                session.add_llm_usage(llm_cost.usage_entry(config.LLM_PROVIDER, config.active_model(), usage, None))
                session.persist()
            except Exception:
                pass
        if extra and extra.strip():
            # §15 claim reviewer: strip UNSUPPORTED/overclaim sentences before appending.
            try:
                from .engine import claims as _cl
                known = {r for f in view for r in (f.get("evidence_refs") or [])}
                extra = _cl.review(extra, known)["clean_text"] or extra
            except Exception:
                pass
            marker = f"\n*{T['end']}"
            idx = base.rfind(marker)
            if idx != -1:
                return base[:idx] + "\n" + extra.strip() + "\n" + base[idx:]
            return base + "\n\n" + extra.strip()
    except Exception:
        pass
    return base


def template(lang: str | None = None) -> str:
    """Blank fill-in template (placeholders), same structure, for manual compilation.

    `lang` is accepted for call-site compatibility; the module is single-language (English) today.
    """
    today = "dd/mm/yyyy"
    return "\n".join([
        f"# {T['title']}",
        "## [APPLICATION NAME / DM-VERSION]",
        "",
        f"> **{T['classif']}**",
        f"> **{T['date']}:** {today} · **{T['tool']}:** ReTrace",
        "",
        f"| | **{T['name']}** | **{T['role']}** |",
        "| --- | --- | --- |",
        f"| {T['author']} | [NAME] | Security / Vulnerability Researcher |",
        f"| {T['reviewer']} | [NAME] | Reviewer |",
        "",
        f"## {T['s1']}", "_(standard table)_", "",
        f"## {T['s2']}", "[confidentiality text] · [disclaimer]", "",
        f"## {T['s3']}",
        "In the period [DD/MM/YYYY – DD/MM/YYYY] the analysis of [APPLICATION] was carried out.",
        "The risk-exposure profile is **[LOW / MEDIUM / HIGH]**.", "",
        f"| {T['sev']} | {T['nvuln']} |", "| --- | --- |",
        f"| {T['crit']} | [N] |", f"| {T['high']} | [N] |", f"| {T['med']} | [N] |",
        f"| {T['low']} | [N] |", f"| {T['info']} | [N] |", "",
        f"## {T['s4']}", f"### {T['obj']}", "[methodology and workflow]",
        "### CVSS", "_(standard severity table)_",
        f"### {T['perimeter']}",
        f"| {T['elem']} | {T['value']} |", "| --- | --- |",
        "| Application | [NAME] |", "| Format / Architecture | [PE/ELF · x86/x64] |",
        "| MD5 | [HASH] |", "| SHA-256 | [HASH] |", "",
        f"## {T['s5']}", "[strategic summary + distribution chart]", "",
        f"## {T['s6']}",
        f"| # | {T['vuln']} | {T['sev']} | CWE | {T['reco']} |", "| --- | --- | --- | --- | --- |",
        f"| 1 | [TITLE] | [CRITICAL/HIGH/…] | [CWE-XXX] | [RECOMMENDATION] |", "",
        f"## {T['s7']}", "### 7.1 [VULNERABILITY TITLE]",
        f"| {T['field']} | {T['value']} |", "| --- | --- |",
        "| CWE | [CWE-XXX] |", f"| {T['sev']} | [CRITICAL/HIGH/…] |",
        "| CVSS Score | [0.0-10.0] |", "| CVSS Vector | [CVSS:3.1/...] |",
        f"| {T['location']} | [function @ offset] |", "",
        f"**{T['descr_l']}.** [TEXT]", f"**{T['impact_l']}.** [TEXT]",
        f"**{T['evid_act']}.** [HOW THE VULN WAS REACHED]", f"**{T['reco_l']}.** [HOW TO FIX]", "",
        f"## {T['s8']}", "The risk-exposure profile is **[LOW / MEDIUM / HIGH]**. [TEXT]", "",
        "_______________________  ", f"**{T['validation']}**", "",
        f"## {T['s9']}", f"### {T['appA']}", f"### {T['appB']}", f"### {T['appC']}", "",
        f"*ReTrace template · {T['classif']}*",
    ])
