"""Built-in Procmon XML MCP server for ReTrace.

Why this exists: many external Procmon MCP wrappers expect a different XML shape and return
"0 events" for standard Sysinternals exports such as:

  <procmon><processlist>...</processlist><eventlist><event>...</event></eventlist></procmon>

This parser uses streaming ElementTree (`iterparse`) so large UTF-8/UTF-8-BOM XML exports can be
loaded without reading the whole file into memory.
"""
from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from typing import Any, Dict, List, Tuple

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("procmon")

# --- entity-bomb guard ------------------------------------------------------------------------
# A Procmon export is untrusted input. ElementTree does not fetch external entities but it does
# expand internal ones, so a few hundred bytes of declarations become gigabytes in memory.
# A real Sysinternals export has no DTD, so refusing one costs nothing.
#
# Duplicated from reforge/safe_xml.py on purpose: this server is deliberately standalone (see
# servers/_reforge_locator.py on why a missing `reforge` import kills a server before the MCP
# handshake). Six lines of duplication beat a dependency that can take the server down.
_XML_PROLOG_SCAN = 64 * 1024
_XML_DANGEROUS = re.compile(rb"<!\s*(DOCTYPE|ENTITY)\b", re.IGNORECASE)


def _assert_safe_xml(path: str) -> None:
    try:
        with open(path, "rb") as fh:
            head = fh.read(_XML_PROLOG_SCAN)
    except OSError:
        return
    hit = _XML_DANGEROUS.search(head)
    if hit:
        raise ValueError(
            f"XML declares a {hit.group(1).decode('ascii').upper()}; refused before parsing "
            "(entity expansion can exhaust memory). Re-export without a DTD.")

CAP = 12000
_EVENTS: List[Dict[str, str]] = []
_SUMMARY: Dict[str, Any] = {}
_LOADED_PATH = ""

_FIELDS = [
    "Time_of_Day", "Process_Name", "PID", "Operation", "Path", "Result", "Detail",
]

_ALIASES = {
    "Time_of_Day": ("Time_of_Day", "Time of Day", "Time", "Timestamp"),
    "Process_Name": ("Process_Name", "Process Name", "ProcessName", "Image_Name", "Image Name"),
    "PID": ("PID", "Pid", "Process_ID", "Process ID"),
    "Operation": ("Operation", "Event_Class", "Event Class"),
    "Path": ("Path", "Target_Path", "Target Path", "Object"),
    "Result": ("Result", "Status"),
    "Detail": ("Detail", "Details"),
}


def _local(tag: str) -> str:
    return (tag or "").split("}", 1)[-1]


def _norm(tag: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", _local(tag).lower())


def _txt(elem: ET.Element, tag: str) -> str:
    wanted = {_norm(x) for x in _ALIASES.get(tag, (tag,))}
    for child in list(elem):
        if _norm(child.tag) in wanted:
            return (child.text or "").strip()
    v = elem.findtext(tag)
    return (v or "").strip()


def _event_to_dict(elem: ET.Element) -> Dict[str, str]:
    return {k: _txt(elem, k) for k in _FIELDS}


def _cap(s: str) -> str:
    return s[:CAP] + ("\n…(truncated)" if len(s) > CAP else "")


def _match(value: str, wanted: str) -> bool:
    return not wanted or wanted.lower() in (value or "").lower()


def _path_kind(path: str, operation: str = "") -> str:
    p = path or ""
    op = (operation or "").lower()
    if p.startswith(("HKLM", "HKCU", "HKEY_", "HKCR", "HKU")) or op.startswith("reg"):
        return "registry"
    if op.startswith(("tcp", "udp")) or re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b|:[0-9]{1,5}\b", p):
        return "network"
    if re.match(r"^[A-Za-z]:\\|^\\\\", p):
        return "file"
    if "process" in op:
        return "process"
    return "other"


@mcp.tool()
def procmon_load_xml(path: str, process_name: str = "", max_events: int = 60000) -> str:
    """Load a Procmon XML export and build an in-memory searchable event index.

    Args:
      path: Procmon XML export path. Supports standard Sysinternals XML with UTF-8 BOM.
      process_name: optional process-name substring filter while loading, e.g. "BimGrp24.exe".
      max_events: maximum events to keep in memory. Summary counters are computed for kept events.
    """
    global _EVENTS, _SUMMARY, _LOADED_PATH
    if not os.path.isfile(path):
        return f"Procmon XML not found: {path}"
    events: List[Dict[str, str]] = []
    ops: Counter[str] = Counter()
    results: Counter[str] = Counter()
    procs: Counter[str] = Counter()
    files: Counter[str] = Counter()
    regs: Counter[str] = Counter()
    net: Counter[str] = Counter()
    kinds: Counter[str] = Counter()
    total_seen = 0
    matched = 0
    kept = 0
    _assert_safe_xml(path)
    try:
        # noqa justified: _assert_safe_xml(path) above refuses a DTD/ENTITY declaration first.
        for _, elem in ET.iterparse(path, events=("end",)):  # noqa: S314
            # Standard Procmon export uses lowercase <event>.
            if _local(elem.tag).lower() == "event":
                total_seen += 1
                ev = _event_to_dict(elem)
                if _match(ev.get("Process_Name", ""), process_name):
                    matched += 1
                    op = ev.get("Operation", "")
                    p = ev.get("Path", "")
                    kind = _path_kind(p, op)
                    ops[op] += 1
                    results[ev.get("Result", "")] += 1
                    procs[ev.get("Process_Name", "")] += 1
                    kinds[kind] += 1
                    if p:
                        if kind == "registry":
                            regs[p] += 1
                        elif kind == "network":
                            net[p] += 1
                        elif kind == "file":
                            files[p] += 1
                    if kept < max_events:
                        events.append(ev)
                        kept += 1
                elem.clear()
    except ET.ParseError as e:
        return f"Error parsing the Procmon XML: {e}"
    except Exception as e:  # noqa: BLE001
        return f"Error loading the Procmon XML: {e}"

    _EVENTS = events
    _LOADED_PATH = path
    _SUMMARY = {
        "path": path,
        "total_events_seen": total_seen,
        "events_matched": matched,
        "events_loaded": kept,
        "events_truncated": matched > kept,
        "filtered_process_name": process_name,
        "max_events": max_events,
        "top_processes": procs.most_common(10),
        "top_operations": ops.most_common(20),
        "top_results": results.most_common(20),
        "events_by_kind": kinds.most_common(),
        "top_file_paths": files.most_common(20),
        "top_registry_paths": regs.most_common(20),
        "top_network": net.most_common(20),
    }
    if kept == 0:
        return json.dumps(_SUMMARY, indent=2, ensure_ascii=False) + "\nNo events loaded: check the process_name filter or the XML format."
    return json.dumps(_SUMMARY, indent=2, ensure_ascii=False)


@mcp.tool()
def procmon_summary() -> str:
    """Return summary of the currently loaded Procmon XML."""
    if not _EVENTS:
        return "No Procmon XML loaded. Call procmon_load_xml(path=...) first."
    return json.dumps(_SUMMARY, indent=2, ensure_ascii=False)


@mcp.tool()
def procmon_load_artifact(path: str, process_name: str = "", max_events: int = 60000) -> str:
    """Alias for procmon_load_xml used by artifact routers that pass a resolved workspace path."""
    return procmon_load_xml(path=path, process_name=process_name, max_events=max_events)


@mcp.tool()
def procmon_query_events(operation: str = "", path_contains: str = "", result: str = "",
                         detail_contains: str = "", process_name: str = "", limit: int = 80) -> str:
    """Query loaded Procmon events by operation/path/result/detail/process.

    Useful operations: Process Start, Load Image, CreateFile, ReadFile, WriteFile, RegOpenKey,
    RegQueryValue, RegSetValue, TCP Connect, UDP Send, Process Create.
    """
    if not _EVENTS:
        return "No Procmon XML loaded. Call procmon_load_xml(path=...) first."
    limit = max(1, min(int(limit or 80), 500))
    out = []
    for ev in _EVENTS:
        if operation and operation.lower() not in ev.get("Operation", "").lower():
            continue
        if path_contains and path_contains.lower() not in ev.get("Path", "").lower():
            continue
        if result and result.lower() not in ev.get("Result", "").lower():
            continue
        if detail_contains and detail_contains.lower() not in ev.get("Detail", "").lower():
            continue
        if process_name and process_name.lower() not in ev.get("Process_Name", "").lower():
            continue
        out.append(ev)
        if len(out) >= limit:
            break
    if not out:
        return "No events match the filters."
    return _cap(json.dumps({"count": len(out), "events": out}, indent=2, ensure_ascii=False))


@mcp.tool()
def procmon_behavior_summary(process_name: str = "", limit_paths: int = 25) -> str:
    """Summarize behavior from loaded Procmon events: process start, loaded images, files, registry.

    This is intentionally analytical and compact, better for LLM consumption than dumping all events.
    """
    if not _EVENTS:
        return "No Procmon XML loaded. Call procmon_load_xml(path=...) first."
    evs = [e for e in _EVENTS if _match(e.get("Process_Name", ""), process_name)]
    ops = Counter(e.get("Operation", "") for e in evs)
    files = Counter(e.get("Path", "") for e in evs if e.get("Path") and re.match(r"^[A-Za-z]:\\", e.get("Path", "")))
    regs = Counter(e.get("Path", "") for e in evs if e.get("Path", "").startswith(("HKLM", "HKCU", "HKEY_")))
    starts = [e for e in evs if e.get("Operation") in ("Process Start", "Process Create")][:5]
    loads = [e for e in evs if e.get("Operation") == "Load Image"][:20]
    summary = {
        "loaded_path": _LOADED_PATH,
        "events_considered": len(evs),
        "top_operations": ops.most_common(20),
        "process_start_events": starts,
        "loaded_images_sample": loads,
        "top_file_paths": files.most_common(limit_paths),
        "top_registry_paths": regs.most_common(limit_paths),
    }
    return _cap(json.dumps(summary, indent=2, ensure_ascii=False))


# ============================================================================
#  VULNERABILITY-ASSESSMENT VIEWS
#  The tools above answer "what did this process do", which is the malware-analyst question.
#  These answer "what can an attacker abuse", which is the one that produces findings.
# ============================================================================

# Directories a non-administrative user can typically write to.
# NB: single backslashes. In a raw string `r"c:\users\\"` is backslash-backslash and matches
# nothing in a normal Windows path.
_USER_WRITABLE = (
    "c:\\users\\", "c:\\programdata\\", "c:\\windows\\temp", "c:\\temp", "c:\\tmp",
    "\\appdata\\local\\temp", "\\downloads\\", "\\public\\", "\\perflogs\\",
)
_NOT_FOUND = ("name not found", "path not found", "no such file", "name not found")


def _is_user_writable(path: str) -> bool:
    p = (path or "").lower().replace("/", "\\")
    return any(w in p for w in _USER_WRITABLE)


def _win_basename(path: str) -> str:
    """os.path.basename does not split on backslashes when this server runs on Linux,
    which silently breaks DLL-name matching."""
    return (path or "").replace("/", "\\").rsplit("\\", 1)[-1]


@mcp.tool()
def procmon_dll_hijack_candidates(process_name: str = "", limit: int = 60) -> str:
    """Find DLL search-order hijacking candidates from the runtime trace (CWE-427).

    Looks for CreateFile operations on .dll paths that returned NAME NOT FOUND: those are DLLs the
    loader looked for and did not find, meaning it moved on to the next directory in the search
    order. If any directory searched before the successful one is writable by an unprivileged user,
    that is an exploitable hijack.

    This is the runtime counterpart to the static `dll_hijack_candidates` in the winsec server; the
    runtime view is stronger evidence because it shows the search order actually taken."""
    if not _EVENTS:
        return "No Procmon XML loaded. Call procmon_load_xml(path=...) first."
    evs = [e for e in _EVENTS if _match(e.get("Process_Name", ""), process_name)]

    missing: Dict[str, List[str]] = {}
    loaded: Dict[str, str] = {}
    for e in evs:
        path = e.get("Path", "") or ""
        low = path.lower()
        result = (e.get("Result", "") or "").lower()
        if not low.endswith((".dll", ".ocx", ".drv")):
            continue
        name = _win_basename(low)
        if any(nf in result for nf in _NOT_FOUND):
            missing.setdefault(name, [])
            if path not in missing[name]:
                missing[name].append(path)
        elif "success" in result and name not in loaded:
            loaded[name] = path

    if not missing:
        return ("No failed DLL load attempt in the trace.\n"
                "If you expected candidates, make sure the process start was captured: "
                "most DLL resolution happens in the first milliseconds.")

    rows = []
    for name, attempts in missing.items():
        writable = [p for p in attempts if _is_user_writable(p)]
        rows.append({
            "dll": name,
            "attempts": attempts,
            "writable_attempts": writable,
            "resolved_to": loaded.get(name),
            "risk": 3 if writable else (2 if name not in loaded else 1),
        })
    rows.sort(key=lambda r: -r["risk"])

    lines = [f"# DLL hijacking candidates (runtime) — {len(rows)} DLLs not found"]
    high = [r for r in rows if r["risk"] >= 3]
    if high:
        lines.append(f"\n🔴 {len(high)} with attempts in user-writable directories — "
                     "CWE-427")
    for r in rows[:limit]:
        tag = "🔴" if r["risk"] >= 3 else ("🟠" if r["risk"] == 2 else "🟡")
        lines.append(f"\n{tag} **{r['dll']}**")
        for p in r["attempts"][:6]:
            flag = "  ← USER-WRITABLE" if _is_user_writable(p) else ""
            lines.append(f"    cercata in: {p}{flag}")
        if r["resolved_to"]:
            lines.append(f"    later resolved to: {r['resolved_to']}")
        else:
            lines.append("    never resolved (optional import or feature not reached)")
    if len(rows) > limit:
        lines.append(f"\n…{len(rows) - limit} more (raise `limit`)")
    lines.append("\n⚠ Always confirm the directory's real permissions with `acl_audit` on the "
                 "winsec server before reporting: a directory on the search path "
                 "is not automatically writable.")
    return _cap("\n".join(lines))


@mcp.tool()
def procmon_insecure_file_usage(process_name: str = "", limit: int = 50) -> str:
    """Find file operations in user-writable locations (CWE-732, CWE-427, CWE-377).

    Any file that a privileged process READS from a location an unprivileged user can write is an
    input-injection vector: configuration, plugins, scripts, data files. Any file it WRITES there
    with predictable naming is a potential planting or symlink target."""
    if not _EVENTS:
        return "No Procmon XML loaded. Call procmon_load_xml(path=...) first."
    evs = [e for e in _EVENTS if _match(e.get("Process_Name", ""), process_name)]

    reads: Counter[str] = Counter()
    writes: Counter[str] = Counter()
    creates: Counter[str] = Counter()
    for e in evs:
        path = e.get("Path", "") or ""
        if not path or not _is_user_writable(path):
            continue
        op = (e.get("Operation", "") or "").lower()
        result = (e.get("Result", "") or "").lower()
        if "success" not in result:
            continue
        if "readfile" in op or op == "queryinformationfile":
            reads[path] += 1
        elif "writefile" in op or "setrenameinformation" in op:
            writes[path] += 1
        elif "createfile" in op:
            creates[path] += 1

    if not (reads or writes):
        return "No file operations in user-writable directories."

    lines = ["# File use in user-writable paths"]
    if reads:
        lines.append(f"\n## 🔴 Reads ({len(reads)} paths) — untrusted input")
        lines.append("_If the process runs elevated, these files are controllable by an unprivileged "
                     "user: config injection, plugin planting._")
        for p, n in reads.most_common(limit):
            lines.append(f"  - `{p}`  ×{n}")
    if writes:
        lines.append(f"\n## 🟠 Writes ({len(writes)} paths)")
        lines.append("_Check the ACL and how predictable the name is: a predictable name plus a "
                     "shared directory = planting or a symlink attack (CWE-377)._")
        for p, n in writes.most_common(limit):
            lines.append(f"  - `{p}`  ×{n}")
    return _cap("\n".join(lines))


@mcp.tool()
def procmon_toctou_candidates(process_name: str = "", limit: int = 40) -> str:
    """Find time-of-check/time-of-use candidates (CWE-367).

    Reports paths where the process first queries the file (check) and later opens or writes it
    (use). If the path lives in a directory the attacker controls, the file can be swapped between
    the two operations — classically for a symlink or hardlink attack."""
    if not _EVENTS:
        return "No Procmon XML loaded. Call procmon_load_xml(path=...) first."
    evs = [e for e in _EVENTS if _match(e.get("Process_Name", ""), process_name)]

    seq: Dict[str, List[Tuple[int, str]]] = defaultdict(list)
    for idx, e in enumerate(evs):
        path = e.get("Path", "") or ""
        op = (e.get("Operation", "") or "")
        if not path:
            continue
        ol = op.lower()
        if "queryattribute" in ol or "querybasicinformation" in ol or "querydirectory" in ol:
            seq[path].append((idx, "CHECK"))
        elif "createfile" in ol or "writefile" in ol or "readfile" in ol:
            seq[path].append((idx, "USE"))

    candidates = []
    for path, ops in seq.items():
        kinds = [k for _, k in ops]
        if "CHECK" in kinds and "USE" in kinds:
            first_check = next(i for i, k in ops if k == "CHECK")
            later_use = [i for i, k in ops if k == "USE" and i > first_check]
            if later_use:
                candidates.append({
                    "path": path,
                    "gap": later_use[0] - first_check,
                    "writable": _is_user_writable(path),
                    "ops": len(ops),
                })
    if not candidates:
        return ("No check-then-use pattern detected.\n"
                "Note: this is a heuristic on event ordering, not proof. "
                "The absence of candidates does not rule out a TOCTOU.")
    candidates.sort(key=lambda c: (-int(c["writable"]), -c["gap"]))

    lines = [f"# TOCTOU candidates — {len(candidates)} paths (CWE-367)"]
    risky = [c for c in candidates if c["writable"]]
    if risky:
        lines.append(f"\n🔴 {len(risky)} in user-writable directories: "
                     "a genuinely exploitable swap window.")
    for c in candidates[:limit]:
        tag = "🔴" if c["writable"] else "🟡"
        lines.append(f"{tag} `{c['path']}`  (gap {c['gap']} events, {c['ops']} ops)")
    lines.append("\n⚠ Heuristic based on event ordering: many check-then-use sequences are "
                 "harmless. It counts as a finding only if the path is in an attacker-controllable "
                 "directory and the window is exploitable.")
    return _cap("\n".join(lines))


@mcp.tool()
def procmon_va_summary(process_name: str = "") -> str:
    """Run all the vulnerability-assessment views over the loaded trace in one call: DLL hijack
    candidates, insecure file usage, TOCTOU candidates, and registry reads from HKCU. This is the
    right entry point after loading a Procmon capture during a VA."""
    if not _EVENTS:
        return "No Procmon XML loaded. Call procmon_load_xml(path=...) first."
    evs = [e for e in _EVENTS if _match(e.get("Process_Name", ""), process_name)]
    hkcu = Counter(e.get("Path", "") for e in evs
                   if (e.get("Path", "") or "").upper().startswith("HKCU")
                   and "query" in (e.get("Operation", "") or "").lower()
                   and "success" in (e.get("Result", "") or "").lower())

    blocks = [f"# Vulnerability-assessment summary of the trace ({len(evs)} events)\n",
              "## DLL hijacking\n" + procmon_dll_hijack_candidates(process_name, limit=20),
              "\n## Files in writable paths\n" + procmon_insecure_file_usage(process_name, limit=20),
              "\n## TOCTOU\n" + procmon_toctou_candidates(process_name, limit=15)]
    if hkcu:
        blocks.append(f"\n## Configuration from HKCU ({len(hkcu)} keys) — CWE-15\n"
                      "_HKCU is user-writable. If one of these keys influences "
                      "security decisions in an elevated process, that is config injection._")
        for k, n in hkcu.most_common(20):
            blocks.append(f"  - `{k}`  ×{n}")
    return _cap("\n".join(blocks))


@mcp.tool()
def procmon_export_graph_events(artifact_id: str = "", top_ops: int = 12, top_paths: int = 15) -> str:
    """Return a compact graph-ready projection of the loaded Procmon summary.

    This intentionally exports aggregate clusters only. The UI/backend should create nodes for
    the artifact, dominant process, top operation clusters, and top touched objects instead of
    creating one graph node per raw Procmon event.
    """
    if not _SUMMARY:
        return "No Procmon XML loaded. Call procmon_load_xml(path=...) first."
    out = {
        "artifact_id": artifact_id,
        "summary": {
            **_SUMMARY,
            "top_operations": (_SUMMARY.get("top_operations") or [])[:top_ops],
            "top_file_paths": (_SUMMARY.get("top_file_paths") or [])[:top_paths],
            "top_registry_paths": (_SUMMARY.get("top_registry_paths") or [])[:top_paths],
            "top_network": (_SUMMARY.get("top_network") or [])[:top_paths],
        },
        "projection": "aggregate_clusters_only",
    }
    return json.dumps(out, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    mcp.run()
