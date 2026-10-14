"""Offline static overview for uploaded artifacts (no LLM, no live MCP server).

WHY THIS EXISTS
---------------
Until now an uploaded artifact carried only type + size + sha256. The user wants a *static,
offline* overview as soon as a file lands — a Procmon XML should already show event/process/object
counts, a PCAP its packet/protocol shape, a PE its arch/sections/attack surface — visible in the
Artifacts panel without running the agent or an external tool.

This module is the per-type dispatcher. Every analyzer is:
  * OFFLINE  — pure Python, bounded reads, no network, no subprocess, never executes the file;
  * BOUNDED  — large files are sampled (head read / streamed counters) so a 500MB Procmon XML or
               PCAP never blows up memory or time;
  * TOLERANT — any parser error is captured into the overview as `error`, never raised, so a
               malformed upload still registers.

The result is a small JSON dict stored on the artifact record under `overview` and rendered by the
Artifacts UI. It is a *summary*, not the full parse — the MCP tools (procmon, tshark) remain the
path for deep, queryable analysis.
"""
from __future__ import annotations

import os
import re
import struct
import xml.etree.ElementTree as ET  # noqa: F401  (kept for element APIs)

from . import safe_xml
from collections import Counter
from typing import Any, Dict

from . import artifacts as A

# Files larger than this are sampled rather than fully analysed during auto-overview.
DEFAULT_AUTO_LIMIT = 20 * 1024 * 1024          # 20 MB: auto-run threshold (server decides)
_HEAD_BYTES = 256 * 1024                         # generic head sample for text/json/binary


def _norm(tag: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (tag or "").split("}", 1)[-1].lower())


# --------------------------------------------------------------------------- Procmon XML
_PM_FIELDS = {
    "processname": ("Process_Name", "Process Name", "ProcessName", "Image_Name"),
    "operation": ("Operation", "Event_Class"),
    "path": ("Path", "Target_Path", "Object"),
    "result": ("Result", "Status"),
}


def _pm_field(elem: ET.Element, keys) -> str:
    wanted = {_norm(k) for k in keys}
    for child in list(elem):
        if _norm(child.tag) in wanted:
            return (child.text or "").strip()
    return ""


def _kind_of(path: str, op: str) -> str:
    p, o = path or "", (op or "").lower()
    if p.startswith(("HKLM", "HKCU", "HKEY_", "HKCR", "HKU")) or o.startswith("reg"):
        return "registry"
    if o.startswith(("tcp", "udp")) or re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b|:[0-9]{1,5}\b", p):
        return "network"
    if re.match(r"^[A-Za-z]:\\|^\\\\", p):
        return "file"
    if "process" in o:
        return "process"
    return "other"


def overview_procmon_xml(path: str, max_events: int = 500000) -> Dict[str, Any]:
    """Streaming Procmon XML overview: counts by op / process / result / object kind + top objects."""
    ops: Counter[str] = Counter()
    procs: Counter[str] = Counter()
    results: Counter[str] = Counter()
    kinds: Counter[str] = Counter()
    files: Counter[str] = Counter()
    regs: Counter[str] = Counter()
    net: Counter[str] = Counter()
    total = 0
    try:
        # safe_xml refuses a DTD/ENTITY declaration before parsing: this runs automatically
        # on upload, so an entity bomb would otherwise exhaust memory unattended (T-2).
        for _, elem in safe_xml.iterparse(path, events=("end",)):
            if (elem.tag or "").split("}", 1)[-1].lower() != "event":
                continue
            total += 1
            if total > max_events:
                elem.clear()
                continue
            op = _pm_field(elem, _PM_FIELDS["operation"])
            p = _pm_field(elem, _PM_FIELDS["path"])
            pn = _pm_field(elem, _PM_FIELDS["processname"])
            res = _pm_field(elem, _PM_FIELDS["result"])
            kind = _kind_of(p, op)
            ops[op] += 1; procs[pn] += 1; results[res] += 1; kinds[kind] += 1
            if p:
                if kind == "registry":
                    regs[p] += 1
                elif kind == "network":
                    net[p] += 1
                elif kind == "file":
                    files[p] += 1
            elem.clear()
    except ET.ParseError as exc:
        return {"kind": "procmon", "error": f"invalid XML: {exc}", "events": total}
    except Exception as exc:  # noqa: BLE001
        return {"kind": "procmon", "error": str(exc), "events": total}
    headline = (f"{total} events · {len([p for p in procs if p])} processes · "
                f"{kinds.get('file',0)} file, {kinds.get('registry',0)} registry, "
                f"{kinds.get('network',0)} network")
    return {
        "kind": "procmon",
        "headline": headline,
        "events": total,
        "events_by_kind": kinds.most_common(),
        "top_processes": procs.most_common(8),
        "top_operations": ops.most_common(12),
        "top_results": results.most_common(8),
        "top_file_paths": files.most_common(10),
        "top_registry_paths": regs.most_common(10),
        "top_network": net.most_common(10),
        "truncated": total > max_events,
    }


# --------------------------------------------------------------------------- PCAP / PCAPNG
_LINKTYPES = {0: "NULL", 1: "ETHERNET", 101: "RAW", 105: "IEEE802_11", 113: "LINUX_SLL", 127: "IEEE802_11_RADIO"}


def overview_pcap(path: str, max_packets: int = 200000) -> Dict[str, Any]:
    """Dependency-free PCAP/PCAPNG overview: packet count, link type, rough talkers + L4 ports.

    Parses the classic libpcap global+record headers (and detects pcapng) without scapy/dpkt. For
    ETHERNET/IPv4 frames it extracts src/dst IP and TCP/UDP ports to surface top talkers; anything
    exotic is counted but not decoded. Deep analysis stays the job of the tshark MCP server.
    """
    try:
        with open(path, "rb") as fh:
            magic = fh.read(4)
            if magic == b"\x0a\x0d\x0d\x0a":
                return _overview_pcapng(path)
            if magic == b"\xd4\xc3\xb2\xa1":
                endian = "<"
            elif magic == b"\xa1\xb2\xc3\xd4":
                endian = ">"
            elif magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
                endian = "<" if magic == b"\x4d\x3c\xb2\xa1" else ">"
            else:
                return {"kind": "pcap", "error": "unrecognized pcap magic", "packets": 0}
            ghdr = fh.read(20)
            if len(ghdr) < 20:
                return {"kind": "pcap", "error": "truncated global header", "packets": 0}
            # version_major, version_minor, thiszone, sigfigs, snaplen, network(linktype)
            _vmaj, _vmin, _tz, _sig, _snap, linktype = struct.unpack(endian + "HHiIII", ghdr)
            packets = 0
            total_len = 0
            talkers: Counter[str] = Counter()
            ports: Counter[int] = Counter()
            l3: Counter[str] = Counter()
            while packets < max_packets:
                rec = fh.read(16)
                if len(rec) < 16:
                    break
                _, _, caplen, origlen = struct.unpack(endian + "IIII", rec)
                if caplen <= 0 or caplen > 0x4000000:   # guard against corrupt length
                    break
                data = fh.read(caplen)
                if len(data) < caplen:
                    break
                packets += 1
                total_len += origlen
                _decode_eth_ipv4(data, linktype, talkers, ports, l3) if linktype == 1 else None
            return {
                "kind": "pcap",
                "headline": (f"{packets} packets · link={_LINKTYPES.get(linktype, linktype)} · "
                             f"{len(talkers)} IPs observed"),
                "packets": packets,
                "link_type": _LINKTYPES.get(linktype, str(linktype)),
                "avg_packet_bytes": round(total_len / packets, 1) if packets else 0,
                "top_talkers": talkers.most_common(10),
                "top_ports": ports.most_common(10),
                "l3_protocols": l3.most_common(),
                "truncated": packets >= max_packets,
                "note": "Offline overview without full decoding. For deep analysis use the tshark MCP server.",
            }
    except Exception as exc:  # noqa: BLE001
        return {"kind": "pcap", "error": str(exc)}


def _decode_eth_ipv4(data: bytes, linktype: int, talkers: Counter, ports: Counter, l3: Counter) -> None:
    """Best-effort Ethernet+IPv4 decode to pull src/dst IP and TCP/UDP ports. Silent on anything odd."""
    try:
        if len(data) < 34 or data[12:14] != b"\x08\x00":   # not IPv4 ethertype
            l3["non-ipv4"] += 1
            return
        ihl = (data[14] & 0x0f) * 4
        proto = data[23]
        src = ".".join(str(b) for b in data[26:30])
        talkers[src] += 1
        l3[{6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"ip-proto-{proto}")] += 1
        off = 14 + ihl
        if proto in (6, 17) and len(data) >= off + 4:
            sport, dport = struct.unpack(">HH", data[off:off + 4])
            ports[dport] += 1
            _ = sport
    except Exception:
        return


def _overview_pcapng(path: str) -> Dict[str, Any]:
    """Minimal PCAPNG overview: count Enhanced/Simple Packet Blocks. No per-packet decode."""
    try:
        pkts = 0
        with open(path, "rb") as fh:
            data = fh.read()
        i = 0
        n = len(data)
        endian = "<"
        while i + 8 <= n:
            block_type = struct.unpack(endian + "I", data[i:i + 4])[0]
            if block_type == 0x0A0D0D0A and i + 12 <= n:    # Section Header: read byte-order magic
                bom = struct.unpack("<I", data[i + 8:i + 12])[0]
                endian = ">" if bom == 0x4D3C2B1A else "<"
            blen = struct.unpack(endian + "I", data[i + 4:i + 8])[0]
            if blen < 12 or i + blen > n:
                break
            if block_type in (0x00000006, 0x00000003):       # Enhanced / Simple Packet Block
                pkts += 1
            i += blen
        return {"kind": "pcap", "format": "pcapng", "packets": pkts,
                "headline": f"{pkts} packets (pcapng) · full decode via the tshark MCP server",
                "note": "Minimal pcapng overview. Use the tshark MCP server for flow analysis."}
    except Exception as exc:  # noqa: BLE001
        return {"kind": "pcap", "format": "pcapng", "error": str(exc)}


# --------------------------------------------------------------------------- PE / ELF binary
def overview_binary(path: str) -> Dict[str, Any]:
    """Reuse the offline static triage for a PE/ELF target and compress it to an overview."""
    try:
        from . import static_analysis as sa
        res = sa.analyze(path)
    except Exception as exc:  # noqa: BLE001
        return {"kind": "binary", "error": str(exc)}
    if res.get("error"):
        return {"kind": "binary", "error": res["error"]}
    target = res.get("target", {})
    findings = res.get("findings", [])
    notable = sorted({f.get("title") for f in findings
                      if f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM")})
    surface = res.get("attack_surface") or {}
    sink_classes = sorted((surface.get("sinks") or {}).keys())
    return {
        "kind": "binary",
        "headline": (f"{target.get('format','?')} {target.get('arch','')} · "
                     f"{target.get('import_count', 0)} imports · {len(findings)} findings · "
                     f"{len(sink_classes)} sink classes"),
        "format": target.get("format"),
        "arch": target.get("arch"),
        "import_count": target.get("import_count"),
        "sections": target.get("sections"),
        "notable_findings": [c for c in notable if c][:12],
        "sink_classes": sink_classes,
        "input_sources": sorted((surface.get("sources") or {}).keys())[:12],
    }


# --------------------------------------------------------------------------- JSON / CSV / text
def overview_text_like(path: str, atype: str) -> Dict[str, Any]:
    """Structural summary for json/csv/log/text: size shape, columns/keys, line count, sample."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            head = fh.read(_HEAD_BYTES)
        text = head.decode("utf-8", "replace")
        # bounded line count over the head (exact only when not truncated)
        full = size <= _HEAD_BYTES
        lines = text.count("\n") + (1 if text and not text.endswith("\n") else 0)
        ov: Dict[str, Any] = {"kind": atype, "size": size, "line_count": lines,
                              "line_count_exact": full}
        if atype == A.TYPE_JSON:
            import json as _json
            try:
                obj = _json.loads(text) if full else _json.loads(text[:text.rfind("}") + 1] or "{}")
                if isinstance(obj, dict):
                    ov["json_keys"] = list(obj.keys())[:30]
                    ov["headline"] = f"JSON object · {len(obj)} top-level keys"
                elif isinstance(obj, list):
                    ov["json_array_len"] = len(obj)
                    ov["headline"] = f"JSON array · {len(obj)} items (sample)"
            except Exception:
                ov["headline"] = "JSON (sample parsed partially)"
        elif atype == A.TYPE_TEXT and ("," in text.split("\n", 1)[0]):
            first = text.split("\n", 1)[0]
            cols = [c.strip() for c in first.split(",")]
            if 1 < len(cols) <= 200:
                ov["csv_columns"] = cols[:40]
                ov["headline"] = f"CSV-like · {len(cols)} columns · ~{lines} lines"
        ov.setdefault("headline", f"{atype} · {size} bytes · ~{lines} lines")
        ov["sample"] = text[:1200]
        return ov
    except Exception as exc:  # noqa: BLE001
        return {"kind": atype, "error": str(exc)}


# --------------------------------------------------------------------------- dispatcher
def build_overview(rec: Dict[str, Any]) -> Dict[str, Any]:
    """Compute the offline overview for an artifact record, dispatching on its detected type.

    Returns a dict always carrying at least {kind, headline|error}. Never raises.
    """
    path = rec.get("path", "")
    atype = rec.get("type", "")
    if not path or not os.path.isfile(path):
        return {"kind": atype or "unknown", "error": "file not found"}
    try:
        if atype == A.TYPE_PROCMON_XML:
            return overview_procmon_xml(path)
        if atype == A.TYPE_PCAP:
            return overview_pcap(path)
        if atype in (A.TYPE_PE, A.TYPE_ELF):
            return overview_binary(path)
        if atype in (A.TYPE_JSON, A.TYPE_TEXT, A.TYPE_XML):
            return overview_text_like(path, atype)
        return {"kind": atype or "binary",
                "headline": f"{atype or 'binary'} · {rec.get('size', 0)} byte",
                "note": "No dedicated offline analyzer for this type."}
    except Exception as exc:  # noqa: BLE001
        return {"kind": atype or "unknown", "error": str(exc)}


def should_auto_run(rec: Dict[str, Any], limit: int = DEFAULT_AUTO_LIMIT) -> bool:
    """Auto-run the overview on upload only for files under the size limit (CPU/time guard)."""
    try:
        return int(rec.get("size", 0)) <= int(limit)
    except Exception:
        return False
