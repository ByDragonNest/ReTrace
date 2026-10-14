"""Offline heuristic vulnerability-research engine for uploaded trace artifacts.

WHY THIS EXISTS
---------------
ReTrace analyses **benign software to find vulnerabilities** — it is not a malware classifier.
The artifact *overview* (artifact_overview.py) gives counts; this module goes further with real,
deterministic, offline analysis that surfaces **vulnerability-relevant behaviours** observed in a
runtime/network trace of the program under audit, each mapped to a **CWE** with concrete evidence.

The lens is "where could this program be attacked / mishandle untrusted input or sensitive data",
NOT "is this malware". For a Procmon/PCAP trace of a benign target that means, for example:

  * DLL search-order hijack surface — LoadLibrary of an unqualified/relative module name, or a DLL
    probed/loaded from a user-writable directory (CWE-427);
  * insecure file handling — creation of files with predictable names in world-writable shared
    locations (temp/ProgramData), TOCTOU-prone access patterns (CWE-377, CWE-367);
  * sensitive data exposure — credentials/tokens/secrets written to disk or sent in cleartext
    (CWE-312, CWE-319);
  * external input reaching a command/exec or a registry/path used for control flow (CWE-78, CWE-15);
  * weak transport — plaintext protocols carrying app data (CWE-319), missing TLS;
  * world/registry permission weaknesses, untrusted search path (CWE-426).

DESIGN PRINCIPLES
-----------------
* OFFLINE & DETERMINISTIC — pure Python, bounded reads, no network, no subprocess, no LLM, the file
  is never executed. Same trace -> same findings.
* EVIDENCE-BACKED — every finding carries the concrete events/paths/addresses that triggered it.
* TOLERANT — a malformed trace yields whatever is computable plus an `error`, never an exception.
* CWE-RANKED — findings carry a CWE id, a severity, and a confidence so the UI and the report
  pipeline can prioritise. These feed the SAME vulnerability report as the static findings.

A finding:
    {
      "id": "procmon.dll_hijack.unqualified",
      "title": "DLL loaded through an unqualified path (DLL hijacking)",
      "severity": "high", "confidence": 0.8,
      "cwe": ["CWE-427"],
      "summary": "...",
      "evidence": ["app.exe: Load Image config.dll (NAME NOT FOUND in app dir, found in CWD)", ...],
      "count": 3
    }
"""
from __future__ import annotations

import math
import re
import struct
import xml.etree.ElementTree as ET  # noqa: F401  (kept for element APIs)

from . import safe_xml
from collections import Counter
from typing import Any, Dict, List

from . import artifacts as A

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_EVIDENCE_CAP = 12


def _finding(fid, title, severity, confidence, cwe, summary, evidence, count=None) -> Dict[str, Any]:
    ev = list(evidence)[:_EVIDENCE_CAP]
    return {
        "id": fid, "title": title, "severity": severity, "confidence": round(confidence, 2),
        "cwe": cwe, "summary": summary, "evidence": ev,
        "count": count if count is not None else len(evidence),
    }


def _rank(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted(findings, key=lambda f: (-SEVERITY_ORDER.get(f["severity"], 0), -f["confidence"]))


# ============================================================================ PROCMON
_PM = {
    "process": ("Process_Name", "Process Name", "ProcessName", "Image_Name"),
    "operation": ("Operation", "Event_Class"),
    "path": ("Path", "Target_Path", "Object"),
    "result": ("Result", "Status"),
    "detail": ("Detail", "Details"),
}


def _norm_tag(tag: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (tag or "").split("}", 1)[-1].lower())


def _pm_get(elem: ET.Element, keys) -> str:
    wanted = {_norm_tag(k) for k in keys}
    for child in list(elem):
        if _norm_tag(child.tag) in wanted:
            return (child.text or "").strip()
    return ""


_USER_WRITABLE_RX = re.compile(
    r"\\(temp|appdata\\local\\temp|appdata\\roaming|programdata|users\\public|downloads|"
    r"\$recycle\.bin)\\", re.I)
_DLL_RX = re.compile(r"\.(dll|ocx|cpl|drv)$", re.I)
_EXEC_EXT_RX = re.compile(r"\.(exe|dll|scr|com|bat|cmd|ps1|vbs|js|hta|jar|lnk|msi)$", re.I)
_NOTFOUND_RX = re.compile(r"name not found|no such file|path not found", re.I)
_CONFIG_EXT_RX = re.compile(r"\.(ini|cfg|conf|config|json|xml|yaml|yml|properties|bat|cmd|ps1|lua|py)$", re.I)
_SECRET_PATH_RX = re.compile(
    r"(password|passwd|secret|token|apikey|api[_-]?key|credential|\.pem|\.pfx|\.key|id_rsa|"
    r"\.kdbx|wallet|private)", re.I)
_CMD_RX = re.compile(r"\\(cmd|powershell|pwsh|wscript|cscript|bash|sh)\.exe\b|/bin/(sh|bash)\b", re.I)
_RUN_CTRL_RX = re.compile(
    r"\\(currentversion\\run(once)?|winlogon\\(shell|userinit)|services\\[^\\]+\\imagepath|"
    r"image file execution options\\|app paths\\)", re.I)
_NET_RX = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")
_UNQUALIFIED_RX = re.compile(r"^(?![a-zA-Z]:\\|\\\\|\\)[^\\/]+\.(dll|exe)$", re.I)


def analyze_procmon(path: str, max_events: int = 1000000) -> Dict[str, Any]:
    """Heuristic vulnerability analysis of a Procmon trace of the program under audit."""
    dll_notfound: List[str] = []
    dll_from_writable: List[str] = []
    unqualified_load: List[str] = []
    writable_exec_write: List[str] = []
    config_from_writable: List[str] = []
    secret_writes: List[str] = []
    cmd_spawns: List[str] = []
    run_ctrl_writes: List[str] = []
    world_perm: List[str] = []
    net_targets: Counter = Counter()
    total = 0
    procs: Counter = Counter()

    def _ev(pn, op, p, detail=""):
        s = f"{pn or '?'}: {op} {p}".strip()
        return (s + f" [{detail}]") if detail else s

    try:
        # Entity-bomb guard; this parser also runs automatically on upload (T-2).
        for _, elem in safe_xml.iterparse(path, events=("end",)):
            if _norm_tag(elem.tag) != "event":
                continue
            total += 1
            if total > max_events:
                elem.clear()
                continue
            op = _pm_get(elem, _PM["operation"])
            p = _pm_get(elem, _PM["path"])
            pn = _pm_get(elem, _PM["process"])
            res = _pm_get(elem, _PM["result"])
            detail = _pm_get(elem, _PM["detail"])
            opl = op.lower()
            resl = res.lower()
            procs[pn] += 1

            if _DLL_RX.search(p) and ("load image" in opl or "createfile" in opl or "queryopen" in opl):
                if _NOTFOUND_RX.search(resl) or "not found" in resl:
                    dll_notfound.append(_ev(pn, op, p, res))
                elif _USER_WRITABLE_RX.search(p) and ("load image" in opl):
                    dll_from_writable.append(_ev(pn, op, p))
            if _UNQUALIFIED_RX.search(p or "") and "load" in opl:
                unqualified_load.append(_ev(pn, op, p))

            if ("write" in opl or "createfile" in opl) and _USER_WRITABLE_RX.search(p):
                if _EXEC_EXT_RX.search(p):
                    writable_exec_write.append(_ev(pn, op, p))
                if _SECRET_PATH_RX.search(p):
                    secret_writes.append(_ev(pn, op, p))

            if ("read" in opl or "queryopen" in opl or "createfile" in opl) and \
                    _CONFIG_EXT_RX.search(p) and _USER_WRITABLE_RX.search(p):
                config_from_writable.append(_ev(pn, op, p))

            if ("write" in opl) and _SECRET_PATH_RX.search(p) and not _USER_WRITABLE_RX.search(p):
                secret_writes.append(_ev(pn, op, p))

            if "process" in opl and ("start" in opl or "create" in opl) and _CMD_RX.search(p + " " + detail):
                cmd_spawns.append(_ev(pn, op, p, detail))

            if "reg" in opl and ("setvalue" in opl or "createkey" in opl) and _RUN_CTRL_RX.search(p):
                run_ctrl_writes.append(_ev(pn, op, p, detail))

            if re.search(r"everyone|authenticated users.*write|world.*writ|generic_all", detail, re.I):
                world_perm.append(_ev(pn, op, p, detail))

            if opl.startswith(("tcp", "udp")) or "connect" in opl:
                if _NET_RX.search(p):
                    net_targets[p] += 1

            elem.clear()
    except ET.ParseError as exc:
        return {"kind": "procmon", "error": f"invalid XML: {exc}", "findings": [], "stats": {}}
    except Exception as exc:  # noqa: BLE001
        return {"kind": "procmon", "error": str(exc), "findings": [], "stats": {}}

    findings: List[Dict[str, Any]] = []

    if dll_notfound:
        findings.append(_finding(
            "procmon.dll_hijack.search", "DLL hijacking surface (search-order)",
            "high", 0.7, ["CWE-427"],
            "The program looks for DLLs in multiple directories ('NAME NOT FOUND' probes): if one of "
            "these is writable by an unprivileged user, an attacker can plant a malicious DLL that "
            "will get loaded. Check the search order and use absolute paths / "
            "SetDefaultDllDirectories.", dll_notfound))
    if dll_from_writable:
        findings.append(_finding(
            "procmon.dll_hijack.writable", "DLL loaded from a user-writable directory",
            "high", 0.8, ["CWE-427", "CWE-426"],
            "A DLL was loaded from a directory that unprivileged users can modify "
            "(temp/AppData/ProgramData): a local attacker can replace it.", dll_from_writable))
    if unqualified_load:
        findings.append(_finding(
            "procmon.dll_hijack.unqualified", "Module loaded with an unqualified path",
            "medium", 0.6, ["CWE-427"],
            "Module loaded with a relative/unqualified name: resolution depends on the search order "
            "and the CWD, opening the door to planting.", unqualified_load))
    if writable_exec_write:
        findings.append(_finding(
            "procmon.insecure_file.exec_in_writable", "Executable/script written to a shared writable directory",
            "medium", 0.6, ["CWE-377", "CWE-379"],
            "The program creates executables or scripts in a directory writable by other users: "
            "possible tampering with the file before execution (TOCTOU) or planting.",
            writable_exec_write))
    if config_from_writable:
        findings.append(_finding(
            "procmon.untrusted_input.config", "Configuration/script read from a writable location",
            "medium", 0.6, ["CWE-15", "CWE-426"],
            "The program reads configuration files or scripts from a directory that unprivileged "
            "users can modify: the resulting input is untrusted and can alter the "
            "behavior (paths, commands, parameters).", config_from_writable))
    if secret_writes:
        findings.append(_finding(
            "procmon.sensitive.secret_on_disk", "Sensitive data written to disk",
            "high", 0.65, ["CWE-312", "CWE-256"],
            "File with a name suggesting credentials/keys/tokens written to disk: check "
            "encryption at rest and the file ACL.", secret_writes))
    if cmd_spawns:
        findings.append(_finding(
            "procmon.command.spawn", "Command interpreter launched (command-injection sink)",
            "medium", 0.55, ["CWE-78"],
            "The program launches cmd/powershell/shell: if the command line embeds unsanitized "
            "external input, this is a potential command injection. Trace the origin of the "
            "arguments.", cmd_spawns))
    if run_ctrl_writes:
        findings.append(_finding(
            "procmon.control.registry_write", "Write to registry keys that govern execution",
            "medium", 0.5, ["CWE-15"],
            "Write to keys that determine which code is executed (Run, services, IFEO, "
            "App Paths): if the values derive from external input, or if the key is writable by "
            "unprivileged users, this is a controlled-execution risk.", run_ctrl_writes))
    if world_perm:
        findings.append(_finding(
            "procmon.permissions.weak_acl", "Weak permissions (Everyone/world-writable)",
            "high", 0.6, ["CWE-732"],
            "Operations indicating weak ACLs (Everyone/Authenticated Users with write access): a "
            "critical object modifiable by unprivileged users.", world_perm))
    if net_targets:
        ev = [f"{t} x{c}" for t, c in net_targets.most_common(_EVIDENCE_CAP)]
        findings.append(_finding(
            "procmon.network.endpoints", "Network endpoints contacted (network surface)",
            "info", 0.4, ["CWE-319"],
            "Observed connections: check whether application data (especially sensitive data) "
            "travels in cleartext and whether the endpoints are validated (anti-SSRF).", ev, sum(net_targets.values())))

    stats = {
        "events": total, "processes": len([p for p in procs if p]),
        "top_processes": procs.most_common(8), "truncated": total > max_events,
    }
    return {"kind": "procmon", "findings": _rank(findings), "stats": stats}


# ============================================================================ PCAP
_CLEARTEXT_PORTS = {
    21: "FTP", 23: "Telnet", 25: "SMTP", 80: "HTTP", 110: "POP3", 143: "IMAP",
    389: "LDAP", 1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
    11211: "memcached", 27017: "MongoDB", 9200: "Elasticsearch",
}
_HAS_TLS_ALT = {80: "443 (HTTPS)", 21: "FTPS/SFTP", 23: "SSH", 110: "995 (POP3S)",
                143: "993 (IMAPS)", 389: "636 (LDAPS)", 25: "587+STARTTLS"}


def analyze_pcap(path: str, max_packets: int = 500000) -> Dict[str, Any]:
    """Heuristic vulnerability analysis of a network trace: cleartext app data, exposed services,
    missing transport security, sensitive data in plaintext payloads."""
    try:
        with open(path, "rb") as fh:
            magic = fh.read(4)
        if magic == b"\x0a\x0d\x0d\x0a":
            return {"kind": "pcap", "format": "pcapng", "findings": [],
                    "stats": {"note": "PCAPNG: full heuristic analysis via a tshark request in chat."}}
        if magic == b"\xd4\xc3\xb2\xa1":
            endian = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            endian = ">"
        else:
            return {"kind": "pcap", "error": "unrecognized pcap magic", "findings": [], "stats": {}}
    except Exception as exc:  # noqa: BLE001
        return {"kind": "pcap", "error": str(exc), "findings": [], "stats": {}}

    cleartext: Counter = Counter()
    secret_in_payload: List[str] = []
    talkers: Counter = Counter()
    dst_ports: Counter = Counter()
    http_basic: List[str] = []
    total = 0

    try:
        with open(path, "rb") as fh:
            fh.read(24)
            while total < max_packets:
                rec = fh.read(16)
                if len(rec) < 16:
                    break
                _s, _u, caplen, _o = struct.unpack(endian + "IIII", rec)
                if caplen <= 0 or caplen > 0x4000000:
                    break
                data = fh.read(caplen)
                if len(data) < caplen:
                    break
                total += 1
                _decode_packet(data, cleartext, secret_in_payload, talkers, dst_ports, http_basic)
    except Exception as exc:  # noqa: BLE001
        return {"kind": "pcap", "error": str(exc), "findings": [], "stats": {"packets": total}}

    findings: List[Dict[str, Any]] = []

    if cleartext:
        ev = []
        for (dst, port, proto), n in cleartext.most_common(_EVIDENCE_CAP):
            alt = _HAS_TLS_ALT.get(port)
            ev.append(f"{dst}:{port} ({proto}) x{n}" + (f" -- encrypted alternative: {alt}" if alt else ""))
        findings.append(_finding(
            "pcap.cleartext.transport", "Application data transmitted in cleartext",
            "high", 0.7, ["CWE-319"],
            "Traffic over protocols with no transport encryption: application data (potentially "
            "sensitive) is exposed to interception/MITM tampering. Migrate to TLS.",
            ev, sum(cleartext.values())))
    if http_basic:
        findings.append(_finding(
            "pcap.cleartext.http_auth", "Cleartext HTTP authentication (Basic/credentials)",
            "critical", 0.8, ["CWE-319", "CWE-522"],
            "Authentication headers or credentials observed over unencrypted HTTP: the credentials "
            "travel in cleartext.", http_basic))
    if secret_in_payload:
        findings.append(_finding(
            "pcap.cleartext.secret_payload", "Sensitive data in an unencrypted payload",
            "high", 0.6, ["CWE-319", "CWE-312"],
            "Cleartext payload containing apparent tokens/passwords/keys.", secret_in_payload))

    stats = {
        "packets": total, "talkers": len(talkers),
        "top_talkers": talkers.most_common(8), "top_ports": dst_ports.most_common(8),
        "truncated": total >= max_packets,
    }
    return {"kind": "pcap", "findings": _rank(findings), "stats": stats}


_PAYLOAD_SECRET_RX = re.compile(
    rb"(password=|passwd=|pwd=|api[_-]?key|secret=|token=|authorization:\s*bearer|"
    rb"aws_secret|x-api-key)", re.I)
_HTTP_BASIC_RX = re.compile(rb"authorization:\s*basic\s+[A-Za-z0-9+/=]{4,}", re.I)


def _decode_packet(data, cleartext, secret_in_payload, talkers, dst_ports, http_basic):
    """Decode one Ethernet/IPv4 packet; flag cleartext app data and exposed secrets. Silent on odd."""
    try:
        if len(data) < 34 or data[12:14] != b"\x08\x00":
            return
        ihl = (data[14] & 0x0f) * 4
        proto = data[23]
        src = ".".join(str(b) for b in data[26:30])
        dst = ".".join(str(b) for b in data[30:34])
        talkers[src] += 1
        off = 14 + ihl
        if proto == 6 and len(data) >= off + 20:
            dport = struct.unpack(">H", data[off + 2:off + 4])[0]
            dst_ports[dport] += 1
            data_off = off + ((data[off + 12] >> 4) * 4)
            payload = data[data_off:]
            if dport in _CLEARTEXT_PORTS:
                cleartext[(dst, dport, _CLEARTEXT_PORTS[dport])] += 1
            if payload:
                if _HTTP_BASIC_RX.search(payload):
                    http_basic.append(f"{src} -> {dst}:{dport}  (cleartext HTTP Basic auth)")
                elif dport in _CLEARTEXT_PORTS and _PAYLOAD_SECRET_RX.search(payload):
                    m = _PAYLOAD_SECRET_RX.search(payload)
                    secret_in_payload.append(f"{src} -> {dst}:{dport}  token: {m.group(0).decode('latin-1','replace')}")
        elif proto == 17 and len(data) >= off + 8:
            dport = struct.unpack(">H", data[off + 2:off + 4])[0]
            dst_ports[dport] += 1
            if dport in _CLEARTEXT_PORTS:
                cleartext[(dst, dport, _CLEARTEXT_PORTS[dport])] += 1
    except Exception:
        return


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# ============================================================================ BINARY (PE/ELF)
def analyze_binary(path: str) -> Dict[str, Any]:
    """Reuse the static-analysis findings (already vuln-oriented) as heuristic findings."""
    try:
        from . import static_analysis as sa
        res = sa.analyze(path)
    except Exception as exc:  # noqa: BLE001
        return {"kind": "binary", "error": str(exc), "findings": [], "stats": {}}
    if res.get("error"):
        return {"kind": "binary", "error": res["error"], "findings": [], "stats": {}}
    findings = []
    for f in res.get("findings", []):
        sev = (f.get("severity") or "info").lower()
        conf = f.get("confidence")
        try:
            conf = float(conf)
        except (TypeError, ValueError):
            conf = 0.6
        findings.append(_finding(
            "binary." + re.sub(r"[^a-z0-9]+", "_", (f.get("capability") or f.get("title") or "cap").lower()),
            f.get("title") or f.get("capability") or "Indicator",
            sev if sev in SEVERITY_ORDER else "info", conf,
            f.get("cwe") or [], f.get("description") or "",
            f.get("evidence") or [f.get("title", "")]))
    target = res.get("target", {})
    return {"kind": "binary", "findings": _rank(findings),
            "stats": {"format": target.get("format"), "arch": target.get("arch"),
                      "imports": target.get("import_count")}}


# ============================================================================ dispatcher
def analyze(rec: Dict[str, Any]) -> Dict[str, Any]:
    """Run the offline vulnerability heuristic engine for the artifact type. Never raises.

    Returns {kind, findings:[...], stats:{...}, error?} plus a `severity` rollup and `headline`.
    Findings are vulnerability-relevant (CWE-tagged) and feed the same report as the static ones.
    """
    import os
    path = rec.get("path", "")
    atype = rec.get("type", "")
    if not path or not os.path.isfile(path):
        return {"kind": atype or "unknown", "error": "file not found", "findings": [], "stats": {}}
    try:
        if atype == A.TYPE_PROCMON_XML:
            res = analyze_procmon(path)
        elif atype == A.TYPE_PCAP:
            res = analyze_pcap(path)
        elif atype in (A.TYPE_PE, A.TYPE_ELF):
            res = analyze_binary(path)
        else:
            return {"kind": atype or "unknown", "findings": [], "stats": {},
                    "note": "No heuristic engine for this type; use the overview or ask for analysis in chat."}
    except Exception as exc:  # noqa: BLE001
        return {"kind": atype or "unknown", "error": str(exc), "findings": [], "stats": {}}

    findings = res.get("findings", [])
    top = findings[0]["severity"] if findings else "info"
    res["severity"] = top
    sev_counts = Counter(f["severity"] for f in findings)
    res["severity_counts"] = dict(sev_counts)
    res["headline"] = (f"{len(findings)} potential weaknesses - "
                       + ", ".join(f"{n} {s}" for s, n in
                                   sorted(sev_counts.items(), key=lambda x: -SEVERITY_ORDER.get(x[0], 0)))
                       if findings else "No relevant weakness detected offline in the trace.")
    return res
