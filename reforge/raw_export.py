"""Raw export — a complete Markdown dump of everything an investigation has detected, used, and done.

WHY THIS EXISTS
---------------
The operator wants to take an entire ReTrace investigation and drop it, as-is, into *any* LLM (no
API wiring) to have it write a report, or just to archive/inspect it later. This module serializes
the whole session state into one self-contained, human-readable Markdown document:

  * the target profile (format, arch, hashes, mitigations),
  * the static analysis findings,
  * high-signal strings grouped by their EFFECTIVE category (LLM/user reassignments applied),
  * imports and the attack surface (dangerous sinks, untrusted input sources),
  * every uploaded artifact with its offline overview AND offline heuristic findings (CWE-tagged),
  * the Evidence Graph (nodes + relationships),
  * the investigation log (what the agent actually did) and token usage.

It is plain text, deterministic, and offline — no model is called to produce it. The point is the
*raw* material: nothing is summarized away, so a downstream LLM has the full picture.
"""
from __future__ import annotations

from typing import Any, Dict, List

from . import string_signal


def _h(level: int, text: str) -> str:
    return f"{'#' * level} {text}\n"


def _kv(label: str, value: Any) -> str:
    return f"- **{label}:** {value}\n"


def _code(text: str, lang: str = "") -> str:
    return f"```{lang}\n{text}\n```\n"


def _table(headers: List[str], rows: List[List[Any]]) -> str:
    if not rows:
        return "_(no data)_\n"
    out = "| " + " | ".join(headers) + " |\n"
    out += "| " + " | ".join("---" for _ in headers) + " |\n"
    for r in rows:
        cells = [str(c).replace("|", "\\|").replace("\n", " ") for c in r]
        out += "| " + " | ".join(cells) + " |\n"
    return out + "\n"


def _findings_block(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return "_(no detections)_\n\n"
    out = ""
    for f in findings:
        cwe = ", ".join(f.get("cwe", f.get("attck", [])) or []) or "—"
        out += f"#### [{f.get('severity', 'info').upper()}] {f.get('title', '?')}\n"
        out += _kv("Confidence", f.get("confidence", "—"))
        out += _kv("CWE", cwe)
        out += _kv("Occurrences", f.get("count", len(f.get("evidence", []))))
        if f.get("summary"):
            out += f"\n{f['summary']}\n"
        ev = f.get("evidence", [])
        if ev:
            out += "\nEvidence:\n"
            out += _code("\n".join(str(e) for e in ev))
        out += "\n"
    return out


def build_markdown(session) -> str:
    """Serialize the full investigation to a single Markdown string."""
    from datetime import datetime, timezone

    name = getattr(session, "name", None) or getattr(session, "id", "investigation")
    parts: List[str] = []
    parts.append(_h(1, f"ReTrace — Investigation export: {name}"))
    parts.append(_kv("Generated", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")))
    parts.append(_kv("Project ID", getattr(session, "id", "—")))
    parts.append(
        "\n> Raw, complete analysis document (offline). Meant to be pasted into an "
        "LLM to generate a report, or archived. No data has been summarized or omitted.\n\n")

    # ---- Target -----------------------------------------------------------
    parts.append(_h(2, "1. Target"))
    prof = getattr(session, "target_profile", None) or {}
    if getattr(session, "target_path", None):
        parts.append(_kv("Path", session.target_path))
    if prof:
        for k in ("file", "format", "arch", "size", "md5", "sha256", "import_count"):
            if prof.get(k) is not None:
                parts.append(_kv(k, prof[k]))
        if prof.get("mitigations"):
            parts.append(_kv("Mitigations", prof["mitigations"]))
    if not prof and not getattr(session, "target_path", None):
        parts.append("_(no target binary set)_\n")
    parts.append("\n")

    # ---- Static findings --------------------------------------------------
    parts.append(_h(2, "2. Static findings"))
    findings = getattr(session, "findings", []) or []
    if findings:
        for f in findings:
            sev = (f.get("severity") or "info")
            parts.append(f"#### [{str(sev).upper()}] {f.get('title', f.get('name', '?'))}\n")
            for key in ("description", "summary", "detail"):
                if f.get(key):
                    parts.append(f"{f[key]}\n\n")
                    break
            if f.get("evidence"):
                ev = f["evidence"]
                ev = ev if isinstance(ev, list) else [ev]
                parts.append(_code("\n".join(str(e) for e in ev)))
            if f.get("recommendation") or f.get("remediation"):
                parts.append(_kv("Remediation", f.get("recommendation") or f.get("remediation")))
            parts.append("\n")
    else:
        parts.append("_(no static finding recorded)_\n\n")

    # ---- Strings (effective categories) -----------------------------------
    parts.append(_h(2, "3. High-signal strings (effective categories)"))
    overrides = dict(getattr(session, "string_overrides", {}) or {})
    if overrides:
        parts.append(_kv("Reclassifications applied", len(overrides)))
    ov = string_signal.grouped_overview(session)
    groups = ov.get("groups", {})
    if groups:
        for cat, items in groups.items():
            parts.append(f"**{cat}** ({len(items)})\n")
            parts.append(_code("\n".join(items[:200]) + ("" if len(items) <= 200 else f"\n… (+{len(items)-200})")))
    else:
        parts.append("_(no strings)_\n")
    parts.append("\n")

    # ---- Imports ----------------------------------------------------------
    imports = getattr(session, "static_imports", []) or []
    parts.append(_h(2, "4. Imports"))
    if imports:
        parts.append(_code("\n".join(imports)))
    else:
        parts.append("_(no imports)_\n")
    parts.append("\n")

    # ---- Attack surface ---------------------------------------------------
    # Dangerous sinks and untrusted input sources: where to aim the analysis. Presence is not a
    # defect — only a demonstrated source→sink path is.
    surface = getattr(session, "attack_surface", {}) or {}
    sinks_map = surface.get("sinks") or {}
    sources_map = surface.get("sources") or {}
    parts.append(_h(2, "5. Attack surface (sinks and input sources)"))
    if sinks_map:
        parts.append("**Dangerous sinks**\n")
        for klass, apis in sinks_map.items():
            parts.append(f"- `{klass}`: " + ", ".join(f"`{a}`" for a in sorted(apis)) + "\n")
        parts.append("\n")
    if sources_map:
        parts.append("**Untrusted input sources**\n")
        for sym, origin in sorted(sources_map.items()):
            parts.append(f"- `{sym}` — {origin}\n")
        parts.append("\n")
    if not sinks_map and not sources_map:
        parts.append("_(attack surface not mapped — run static analysis on a target)_\n")
    parts.append("\n")

    # ---- Artifacts: overview + heuristics ---------------------------------
    artifacts = getattr(session, "artifacts", []) or []
    parts.append(_h(2, "6. Uploaded artifacts and offline analysis"))
    if not artifacts:
        parts.append("_(no artifact uploaded)_\n\n")
    for a in artifacts:
        parts.append(_h(3, f"{a.get('name', '?')}  ·  {a.get('type', '?')}"))
        parts.append(_kv("ID", a.get("id", "—")))
        parts.append(_kv("Size", a.get("size", "—")))
        if a.get("sha256"):
            parts.append(_kv("SHA-256", a["sha256"]))
        # overview
        aov = a.get("overview") or {}
        if aov.get("headline"):
            parts.append(_kv("Overview", aov["headline"]))
        for key, label in (("top_processes", "Top processes"), ("top_operations", "Top operations"),
                           ("top_talkers", "Top talkers"), ("top_ports", "Top ports"),
                           ("top_network", "Network"), ("sink_classes", "Sink classes"),
                           ("input_sources", "Input sources"),
                           ("notable_findings", "Notable findings")):
            if aov.get(key):
                vals = aov[key]
                rows = [[x[0], x[1]] if isinstance(x, (list, tuple)) else [x, ""] for x in vals[:10]]
                parts.append(f"\n_{label}_\n\n")
                parts.append(_table(["value", "n"], rows))
        # heuristics findings
        he = a.get("heuristics") or {}
        if he.get("headline"):
            parts.append(f"\n**Offline heuristic analysis:** {he['headline']}\n\n")
        if he.get("findings"):
            parts.append(_findings_block(he["findings"]))
        elif he.get("error"):
            parts.append(_kv("Heuristic error", he["error"]))
        parts.append("\n")

    # ---- Graph ------------------------------------------------------------
    parts.append(_h(2, "7. Evidence Graph"))
    try:
        from . import evidence_graph as eg
        g = eg.for_session(session)
        g.sync_from_session(session)
        gj = g.to_json()
        nodes = gj.get("nodes", [])
        edges = gj.get("edges", [])
        parts.append(_kv("Nodes", len(nodes)))
        parts.append(_kv("Relationships", len(edges)))
        if nodes:
            parts.append("\n_Nodes_\n\n")
            rows = [[n.get("id", ""), n.get("type", ""), n.get("label", ""),
                     n.get("severity", "") or ""] for n in nodes[:300]]
            parts.append(_table(["id", "type", "label", "severity"], rows))
        if edges:
            parts.append("\n_Relationships_\n\n")
            rows = [[e.get("source", e.get("src", "")), e.get("type", e.get("edge_type", "")),
                     e.get("target", e.get("dst", ""))] for e in edges[:300]]
            parts.append(_table(["from", "relationship", "to"], rows))
    except Exception as exc:  # noqa: BLE001
        parts.append(f"_(graph unavailable: {exc})_\n")
    parts.append("\n")

    # ---- Investigation log ------------------------------------------------
    log = getattr(session, "investigation_log", []) or []
    parts.append(_h(2, "8. Investigation log (actions performed)"))
    if log:
        rows = []
        for e in log[-200:]:
            rows.append([e.get("ts", e.get("time", "")), e.get("kind", e.get("type", "")),
                         str(e.get("summary", e.get("detail", e.get("text", ""))))[:120]])
        parts.append(_table(["when", "type", "detail"], rows))
    else:
        parts.append("_(empty log)_\n")
    parts.append("\n")

    # ---- Token usage ------------------------------------------------------
    usage = getattr(session, "llm_usage", []) or []
    if usage:
        parts.append(_h(2, "9. LLM usage"))
        parts.append(_kv("Recorded calls", len(usage)))
        tot_in = sum(u.get("input_tokens", 0) or 0 for u in usage)
        tot_out = sum(u.get("output_tokens", 0) or 0 for u in usage)
        parts.append(_kv("Total input tokens", tot_in))
        parts.append(_kv("Total output tokens", tot_out))
        parts.append("\n")

    parts.append("---\n_End of export. Document generated offline by ReTrace._\n")
    return "".join(parts)
