"""MCP server: attack-surface analysis of Windows kernel drivers.

When the target installs a .sys file, the driver usually becomes the highest-severity finding in
the whole assessment. A driver runs in ring 0, and if it exposes a device object that an
unprivileged user can open, every IOCTL it handles is reachable across the user/kernel privilege
boundary. A single missing bounds check there is a full local privilege escalation, not an
application bug.

The two questions that matter, in order:
  1. Can a non-administrator open a handle to the device? If not, the surface is not reachable
     and most findings collapse to informational.
  2. Which IOCTLs does it expose, and how do they transfer buffers? METHOD_NEITHER combined with
     FILE_ANY_ACCESS is the classic arbitrary read/write primitive.

This server answers both. It enumerates and assesses; the actual bug still has to be found by
reading the dispatch routine in the decompiler.
"""
from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
import sys
from collections import Counter, defaultdict
from typing import Any, Dict, List, Tuple

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("driver")
CAP = 14000
IS_WIN = sys.platform.startswith("win")

METHODS = {
    0: ("METHOD_BUFFERED", "info",
        "the kernel copies the buffers into system memory: the safest of the four"),
    1: ("METHOD_IN_DIRECT", "low",
        "input buffer mapped through an MDL: the kernel validates the address, but the size "
        "still has to be checked"),
    2: ("METHOD_OUT_DIRECT", "low",
        "output buffer mapped through an MDL: as above"),
    3: ("METHOD_NEITHER", "high",
        "the driver receives the RAW USER-MODE POINTERS. It must call ProbeForRead/ProbeForWrite "
        "inside a __try/__except and validate everything by hand. The most common source of "
        "arbitrary read/write in ring 0"),
}

ACCESS = {
    0: ("FILE_ANY_ACCESS", "high",
        "no access requirement: anyone who can open a handle to the device can "
        "invoke this IOCTL"),
    1: ("FILE_READ_ACCESS", "medium", "requires read access on the handle"),
    2: ("FILE_WRITE_ACCESS", "medium", "requires write access on the handle"),
    3: ("FILE_READ_ACCESS|FILE_WRITE_ACCESS", "low", "requires read and write access"),
}

# Kernel APIs whose presence in a driver signals a specific risk.
KERNEL_RISK = {
    "MmMapIoSpace": ("critical", "maps arbitrary physical memory in ring 0. If the address "
                                 "comes from user mode it is an immediate privilege escalation"),
    "MmMapIoSpaceEx": ("critical", "like MmMapIoSpace"),
    "ZwMapViewOfSection": ("critical", "section mapping: with \\Device\\PhysicalMemory it is "
                                       "equivalent to physical RAM access"),
    "MmGetPhysicalAddress": ("high", "physical address translation: often next to "
                                     "a mapping primitive"),
    "MmCopyMemory": ("critical", "copies from arbitrary physical or virtual memory"),
    "MmMapLockedPagesSpecifyCache": ("high", "MDL mapping: check AccessMode"),
    "ZwOpenProcess": ("high", "opens arbitrary processes from ring 0, bypassing process "
                              "protection"),
    "ZwTerminateProcess": ("high", "arbitrary process termination, including an AV/EDR"),
    "PsLookupProcessByProcessId": ("medium", "process lookup by PID"),
    "KeStackAttachProcess": ("high", "attaches to another process's context: read/write "
                                     "of its memory"),
    "ZwWriteFile": ("high", "file writes from ring 0, bypassing filesystem ACLs"),
    "ZwCreateFile": ("medium", "file access from ring 0"),
    "ZwOpenKey": ("medium", "registry access from ring 0"),
    "ZwSetValueKey": ("high", "registry writes from ring 0, bypassing ACLs"),
    "IoCreateDevice": ("info", "creates the device object: check whether it uses IoCreateDeviceSecure"),
    "IoCreateDeviceSecure": ("info", "creates the device with an explicit SDDL: good practice"),
    "IoCreateSymbolicLink": ("medium", "exposes the device in the \\??\\ namespace, "
                                       "reachable from user mode via CreateFile"),
    "ObRegisterCallbacks": ("info", "handle callbacks: typical of security products"),
    "MmGetSystemRoutineAddress": ("medium", "dynamic resolution of kernel symbols"),
    "RtlCopyMemory": ("medium", "memcpy in ring 0: always check the length"),
    "memcpy": ("medium", "unbounded copy in ring 0"),
    "ProbeForRead": ("info", "user-mode pointer validation: its PRESENCE is a good "
                             "sign, its ABSENCE with METHOD_NEITHER is a red flag"),
    "ProbeForWrite": ("info", "like ProbeForRead"),
    "ExAllocatePoolWithTag": ("info", "pool allocation: check for integer overflow in the size "
                                      "computation"),
    "ExAllocatePool2": ("info", "pool allocation (modern API)"),
}


def _cap(s: str) -> str:
    return s[:CAP] + "\n…(truncated)" if len(s) > CAP else s


def _run(cmd: List[str], timeout: int = 60) -> Dict[str, Any]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        return {"ok": True, "out": p.stdout or "", "err": p.stderr or "", "rc": p.returncode}
    except FileNotFoundError:
        return {"ok": False, "err": f"not found: {cmd[0]}"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "err": f"timeout after {timeout}s"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "err": str(e)}


def _powershell(script: str, timeout: int = 90) -> Dict[str, Any]:
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if not exe:
        return {"ok": False, "err": "PowerShell not found"}
    return _run([exe, "-NoProfile", "-NonInteractive", "-Command", script], timeout)


# ---------------------------------------------------------------------------
# IOCTL decoding
# ---------------------------------------------------------------------------
def decode_ioctl(code: int) -> Dict[str, Any]:
    """CTL_CODE(DeviceType, Function, Method, Access)
         = (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
    """
    device_type = (code >> 16) & 0xFFFF
    access = (code >> 14) & 0x3
    function = (code >> 2) & 0xFFF
    method = code & 0x3
    return {
        "code": code,
        "hex": f"0x{code:08X}",
        "device_type": device_type,
        "device_type_hex": f"0x{device_type:04X}",
        "custom_device_type": device_type >= 0x8000,
        "function": function,
        "custom_function": function >= 0x800,
        "method": method,
        "method_name": METHODS[method][0],
        "access": access,
        "access_name": ACCESS[access][0],
    }


def _plausible(code: int) -> bool:
    """A CTL_CODE has structural constraints. Filter on them before doing anything else."""
    if code <= 0 or code > 0xFFFFFFFF:
        return False
    device_type = (code >> 16) & 0xFFFF
    function = (code >> 2) & 0xFFF
    if device_type == 0:
        return False
    # Microsoft reserves DeviceType < 0x8000; third-party drivers are supposed to use >= 0x8000.
    # Values above 0xFFFF cannot occur by construction.
    if device_type > 0xFFFF:
        return False
    # Function 0 with a custom device type is legal but very rare as the only code.
    if function == 0 and device_type >= 0x8000:
        return False
    return True


def _pe_text_sections(path: str) -> List[Tuple[str, bytes, int]]:
    try:
        import pefile
    except ImportError:
        return []
    try:
        pe = pefile.PE(path, fast_load=True)
    except Exception:  # noqa: BLE001
        return []
    out = []
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("utf-8", "ignore")
        if s.Characteristics & 0x20000000 or name in (".text", "PAGE", "INIT", ".textbss"):
            out.append((name, s.get_data(), s.VirtualAddress))
    return out


# x86/x64 compare-with-immediate opcodes, which is how an IOCTL dispatch switch is compiled.
_CMP_PREFIXES = (
    b"\x3d",              # cmp eax, imm32
    b"\x81\xf8", b"\x81\xf9", b"\x81\xfa", b"\x81\xfb",
    b"\x81\xfd", b"\x81\xfe", b"\x81\xff",   # cmp r32, imm32
    b"\x81\x7d", b"\x81\x7c",                # cmp [ebp+x], imm32
    b"\x2d",                                 # sub eax, imm32 (jump-table lowering)
)

# A dispatch comparison is always followed by a branch. Requiring this kills most of the
# noise that a stray 0x3D byte in dense x86 would otherwise produce.
_JMP_OPCODES = {0x74, 0x75, 0x72, 0x73, 0x76, 0x77, 0x7C, 0x7D, 0x7E, 0x7F, 0xEB, 0xE9}


def _followed_by_branch(data: bytes, after: int) -> bool:
    if after >= len(data):
        return False
    if data[after] in _JMP_OPCODES:
        return True
    # Near conditional jump: 0F 8x
    if data[after] == 0x0F and after + 1 < len(data) and 0x80 <= data[after + 1] <= 0x8F:
        return True
    return False


def extract_ioctls(path: str, strict: bool = True) -> Dict[str, Any]:
    """Recover candidate IOCTL codes from a driver's executable sections.

    Two signals are combined, because raw dword scanning alone is far too noisy:
      * the dword is preceded by a compare-with-immediate opcode (how a dispatch switch compiles);
      * several codes share the same DeviceType (real drivers group their IOCTLs under one type).
    """
    sections = _pe_text_sections(path)
    if not sections:
        return {"error": "no readable executable section (is pefile installed? is this a PE?)"}

    cmp_hits: Dict[int, int] = Counter()
    branch_hits: Dict[int, int] = Counter()
    raw_hits: Dict[int, int] = Counter()
    for _name, data, _va in sections:
        for i in range(len(data) - 4):
            code = struct.unpack_from("<I", data, i)[0]
            if not _plausible(code):
                continue
            raw_hits[code] += 1
            for pref in _CMP_PREFIXES:
                start = i - len(pref)
                if start >= 0 and data[start:i] == pref:
                    cmp_hits[code] += 1
                    if _followed_by_branch(data, i + 4):
                        branch_hits[code] += 1
                    break

    # Cluster by DeviceType: a group of codes sharing a type is strong evidence they are real.
    type_counts: Counter[int] = Counter()
    for code in set(list(cmp_hits) + list(raw_hits)):
        type_counts[(code >> 16) & 0xFFFF] += 1

    results = []
    for code in sorted(set(list(cmp_hits) + list(raw_hits))):
        dt = (code >> 16) & 0xFFFF
        cluster = type_counts[dt]
        has_cmp = bool(cmp_hits.get(code))
        has_branch = bool(branch_hits.get(code))
        recurs = raw_hits.get(code, 0)

        confidence = 0
        reasons = []
        if has_cmp:
            confidence += 3
            reasons.append("preceded by a compare-immediate")
        if has_branch:
            confidence += 3
            reasons.append("followed by a conditional jump (dispatch pattern)")
        if cluster >= 2:
            # Real drivers group their IOCTLs under one DeviceType. Scale with the group size:
            # this is the single strongest signal and it separates dispatch tables from noise.
            confidence += min(cluster, 4)
            reasons.append(f"DeviceType 0x{dt:04X} shared with {cluster - 1} other codes")
        if dt >= 0x8000:
            confidence += 1
            reasons.append("DeviceType custom (>=0x8000)")
        if recurs > 1:
            confidence += 1
            reasons.append(f"ricorre {recurs} volte")

        if strict:
            # A stray 0x3D byte in front of a plausible dword happens constantly in dense x86.
            # Require the compare AND independent corroboration before reporting anything.
            if not has_cmp:
                continue
            if not has_branch and cluster < 3:
                continue
            if cluster < 2 and recurs < 2 and not has_branch:
                continue
            if confidence < 7:
                continue
        d = decode_ioctl(code)
        d["confidence"] = confidence
        d["reasons"] = reasons
        results.append(d)

    results.sort(key=lambda d: (-d["confidence"], d["code"]))
    return {"ioctls": results, "device_types": type_counts.most_common(10)}


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
@mcp.tool()
def list_ioctls(path: str, strict: bool = True, limit: int = 60) -> str:
    """Recover the IOCTL codes a driver handles and decode each one into DeviceType, Function,
    transfer Method and required Access, with the security implication of each.

    Sort order is by risk: METHOD_NEITHER plus FILE_ANY_ACCESS first, because that combination
    means an unprivileged caller hands raw user-mode pointers to ring 0.

    strict=false widens the search when a driver hides its codes behind a jump table, at the cost
    of many more false positives."""
    if not os.path.isfile(path):
        return f"file not found: {path}"
    res = extract_ioctls(path, strict=strict)
    if "error" in res:
        return res["error"]
    ioctls = res["ioctls"]
    if not ioctls:
        return ("No plausible IOCTL identified.\n"
                "Try strict=false. If still nothing, the dispatch may use a jump table "
                "or computed codes: locate IRP_MJ_DEVICE_CONTROL in DriverEntry with "
                "Ghidra e leggi la routine di dispatch a mano.")

    def risk(d):
        r = 0
        if d["method"] == 3:
            r += 3
        if d["access"] == 0:
            r += 2
        if d["custom_device_type"]:
            r += 1
        return r

    ioctls.sort(key=lambda d: (-risk(d), -d["confidence"]))
    high = [d for d in ioctls if d["method"] == 3 and d["access"] == 0]

    lines = [f"# IOCTL in {os.path.basename(path)} — {len(ioctls)} candidates",
             f"Recurring DeviceTypes: "
             + ", ".join(f"0x{t:04X}(×{n})" for t, n in res["device_types"][:5])]
    if high:
        lines.append(f"\n🔴 **{len(high)} with METHOD_NEITHER + FILE_ANY_ACCESS** — the highest-risk "
                     "combination: raw user-mode pointers accepted from a caller "
                     "with no access requirement.")

    for d in ioctls[:limit]:
        m_name, m_sev, m_desc = METHODS[d["method"]]
        a_name, a_sev, a_desc = ACCESS[d["access"]]
        tag = "🔴" if (d["method"] == 3 and d["access"] == 0) else (
            "🟠" if d["method"] == 3 or d["access"] == 0 else "🟡")
        lines.append(f"\n{tag} **{d['hex']}**  (confidence {d['confidence']})")
        lines.append(f"   DeviceType {d['device_type_hex']}"
                     f"{' [custom]' if d['custom_device_type'] else ' [reserved by Microsoft]'}"
                     f"  Function 0x{d['function']:03X}")
        lines.append(f"   {m_name} — {m_desc}")
        lines.append(f"   {a_name} — {a_desc}")
        if d["reasons"]:
            lines.append(f"   _evidence: {'; '.join(d['reasons'])}_")
    if len(ioctls) > limit:
        lines.append(f"\n…{len(ioctls) - limit} more (raise `limit`)")

    lines.append("\n---\n⚠ Heuristic extraction: confirm the codes by reading the dispatch "
                 "routine. A high-confidence candidate says where to look, it is not a "
                 "finding already demonstrated.")
    return _cap("\n".join(lines))


@mcp.tool()
def decode_ioctl_code(code: str) -> str:
    """Decode a single IOCTL code into its four fields and explain what each implies.
    Accepts hex ('0x222000') or decimal. Use it when the decompiler shows a constant you want
    to understand."""
    try:
        val = int(code, 16) if code.lower().startswith("0x") else int(code, 0)
    except ValueError:
        return f"invalid code: {code}"
    d = decode_ioctl(val)
    m_name, _m_sev, m_desc = METHODS[d["method"]]
    a_name, _a_sev, a_desc = ACCESS[d["access"]]
    lines = [f"# {d['hex']}",
             f"- **DeviceType**: {d['device_type_hex']} "
             f"({'custom, third party' if d['custom_device_type'] else 'reserved by Microsoft'})",
             f"- **Function**: 0x{d['function']:03X} "
             f"({'custom' if d['custom_function'] else 'reserved by Microsoft'})",
             f"- **Method**: {m_name}\n    {m_desc}",
             f"- **Access**: {a_name}\n    {a_desc}"]
    if d["method"] == 3 and d["access"] == 0:
        lines.append("\n🔴 METHOD_NEITHER + FILE_ANY_ACCESS: the worst combination. "
                     "Check that the dispatch has ProbeForRead/ProbeForWrite inside "
                     "a __try/__except, and that the lengths are validated.")
    return "\n".join(lines)


@mcp.tool()
def driver_imports_audit(path: str) -> str:
    """Audit the kernel APIs a driver imports, ranked by the risk each one carries in ring 0.

    Also checks for the ProbeForRead/ProbeForWrite pair: their absence in a driver that exposes
    METHOD_NEITHER IOCTLs is a strong indicator of unvalidated user-mode pointers."""
    if not os.path.isfile(path):
        return f"file not found: {path}"
    try:
        import pefile
    except ImportError:
        return "pefile is not installed. Install it with: pip install pefile"
    try:
        pe = pefile.PE(path, fast_load=False)
    except Exception as e:  # noqa: BLE001
        return f"PE parsing error: {e}"

    subsystem = pe.OPTIONAL_HEADER.Subsystem
    if subsystem != 1:
        note = (f"\n⚠ Subsystem = {subsystem}, not IMAGE_SUBSYSTEM_NATIVE (1). "
                "This file may not be a kernel driver.")
    else:
        note = ""

    imports: List[str] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        for imp in entry.imports or []:
            if imp.name:
                imports.append(imp.name.decode("utf-8", "ignore"))

    by_sev: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
    for api in sorted(set(imports)):
        if api in KERNEL_RISK:
            sev, desc = KERNEL_RISK[api]
            by_sev[sev].append((api, desc))

    lines = [f"# Kernel imports: {os.path.basename(path)}",
             f"{len(imports)} imports in total{note}"]
    for sev in ("critical", "high", "medium", "info"):
        if sev in by_sev:
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "info": "⚪"}[sev]
            lines.append(f"\n## {icon} {sev.upper()}")
            for api, desc in by_sev[sev]:
                lines.append(f"- **{api}** — {desc}")

    has_probe = any(a in imports for a in ("ProbeForRead", "ProbeForWrite"))
    if not has_probe:
        lines.append("\n🔴 **ProbeForRead/ProbeForWrite missing from the imports.**\n"
                     "If the driver exposes METHOD_NEITHER IOCTLs, user-mode pointers "
                     "are not validated: that is the pattern that leads to arbitrary read/write "
                     "in ring 0. Check with `list_ioctls`.")
    else:
        lines.append("\n✅ ProbeForRead/ProbeForWrite present. Still check that they are "
                     "called on EVERY METHOD_NEITHER path, not just some.")

    if not by_sev:
        lines.append("\nNo import in a known category. Either a very simple driver, or imports "
                     "resolved dynamically with MmGetSystemRoutineAddress.")
    return _cap("\n".join(lines))


@mcp.tool()
def find_device_names(path: str, limit: int = 40) -> str:
    """Extract the device and symbolic-link names a driver creates (\\Device\\X, \\DosDevices\\X,
    \\??\\X). These are what a user-mode process opens with CreateFile, so they are the entry point
    to the whole IOCTL surface. Feed the result to device_access_check."""
    if not os.path.isfile(path):
        return f"file not found: {path}"
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as e:
        return f"read error: {e}"

    names: Counter[str] = Counter()
    # Driver name strings are UNICODE_STRING, so UTF-16LE.
    for pattern in (rb"(?:[\x20-\x7e]\x00){4,}",):
        for m in re.finditer(pattern, data):
            s = m.group(0).decode("utf-16le", "ignore")
            if re.match(r"^\\(Device|DosDevices|\?\?)\\", s, re.I):
                names[s] += 1
    for m in re.finditer(rb"\\(?:Device|DosDevices|\?\?)\\[\x20-\x7e]{2,60}", data):
        names[m.group(0).decode("ascii", "ignore")] += 1

    if not names:
        return ("No device name found.\n"
                "The name may be built at runtime. Look for IoCreateDevice / "
                "IoCreateSymbolicLink in DriverEntry with Ghidra.")
    lines = [f"# Nomi device in {os.path.basename(path)}"]
    for name, n in names.most_common(limit):
        user_path = None
        m = re.match(r"^\\(?:DosDevices|\?\?)\\(.+)$", name, re.I)
        if m:
            user_path = f"\\\\.\\{m.group(1)}"
        lines.append(f"- `{name}`" + (f"  → openable from user mode as `{user_path}`"
                                      if user_path else ""))
    lines.append("\nCheck with `device_access_check` whether an unprivileged user can "
                 "open a handle: without a handle, the whole IOCTL surface is unreachable.")
    return _cap("\n".join(lines))


@mcp.tool()
def device_access_check(device_path: str) -> str:
    """Test empirically whether the CURRENT user can open a handle to a device object.

    This is the single most important check on a driver. Every IOCTL finding is gated behind it:
    if only SYSTEM can open the device, a METHOD_NEITHER bug is an informational note; if any
    authenticated user can, the same bug is a local privilege escalation.

    Run this as an UNPRIVILEGED user — running it as administrator answers the wrong question.
    device_path example: '\\\\.\\MyDriver'."""
    if not IS_WIN:
        return (f"device_access_check requires Windows (current platform: {sys.platform}). "
                "Run it on the test machine, as an UNPRIVILEGED user.")

    ps = f"""
    $ErrorActionPreference = 'Stop'
    $sig = @'
    using System;
    using System.Runtime.InteropServices;
    public class Dev {{
      [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
      public static extern IntPtr CreateFile(string n, uint a, uint s, IntPtr sec,
                                             uint c, uint f, IntPtr t);
      [DllImport("kernel32.dll", SetLastError=true)]
      public static extern bool CloseHandle(IntPtr h);
    }}
'@
    Add-Type -TypeDefinition $sig
    $h = [Dev]::CreateFile('{device_path}', 0xC0000000, 0, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
    $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    if ($h -eq -1 -or $h -eq [IntPtr]::Zero) {{
        "FAIL|$err"
    }} else {{
        [Dev]::CloseHandle($h) | Out-Null
        "OK|0"
    }}
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    "USER|$($id.Name)|$($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))"
    """
    r = _powershell(ps)
    if not r.get("ok"):
        return f"PowerShell error: {r.get('err')}"
    out = r["out"].strip().splitlines()
    status, err_code, user, is_admin = "?", "?", "?", "?"
    for line in out:
        if line.startswith(("OK|", "FAIL|")):
            status, err_code = line.split("|", 1)
        elif line.startswith("USER|"):
            parts = line.split("|")
            user = parts[1] if len(parts) > 1 else "?"
            is_admin = parts[2] if len(parts) > 2 else "?"

    lines = [f"# Accesso a `{device_path}`",
             f"user: {user}  |  administrator: {is_admin}"]
    if is_admin.lower() == "true":
        lines.append("\n⚠ **You are running as administrator.** The result says nothing "
                     "about the real reachability of the surface. Re-run as an "
                     "standard.")
    if status == "OK":
        lines.append("\n🔴 **Handle obtained.** The device can be opened from this context: "
                     "the whole IOCTL surface is reachable.")
        if is_admin.lower() == "false":
            lines.append("For an unprivileged user this means every bug in the "
                         "dispatch is a local privilege escalation (CWE-782 / CWE-269).")
    else:
        code_map = {"5": "ACCESS_DENIED — the device's DACL blocks this user",
                    "2": "FILE_NOT_FOUND — the device does not exist or the driver is not loaded",
                    "32": "SHARING_VIOLATION — device already open exclusively"}
        lines.append(f"\n✅ Handle NOT obtained (error {err_code}: "
                     f"{code_map.get(err_code, 'see the Win32 error code')}).")
        if err_code == "5":
            lines.append("The IOCTL surface is not reachable by this user. "
                         "Bugs in the dispatch stay informational unless there is "
                         "another way to obtain the handle.")
    return "\n".join(lines)


@mcp.tool()
def find_installed_drivers(name_filter: str = "") -> str:
    """Enumerate the kernel drivers registered on the system, with their image path, start type and
    state. Use name_filter to narrow to the vendor or product under assessment.

    Third-party drivers that start automatically and are loaded are the ones worth analysing."""
    if not IS_WIN:
        return (f"find_installed_drivers requires Windows (current platform: {sys.platform}).\n"
                "On the test machine you can also look for the .sys files by hand in the product's "
                "installation directory.")
    ps = (r"Get-CimInstance Win32_SystemDriver | ForEach-Object { "
          r'"$($_.Name)|$($_.PathName)|$($_.StartMode)|$($_.State)|$($_.ServiceType)" }')
    r = _powershell(ps)
    if not r.get("ok"):
        return f"PowerShell error: {r.get('err')}"
    rows = []
    winroot = (os.environ.get("SystemRoot", r"C:\Windows")).lower()
    for line in r["out"].splitlines():
        parts = line.strip().split("|")
        if len(parts) < 4 or not parts[0]:
            continue
        name, path, start, state = parts[0], parts[1], parts[2], parts[3]
        if name_filter and name_filter.lower() not in (name + path).lower():
            continue
        third_party = bool(path) and not path.lower().startswith(winroot)
        rows.append({"name": name, "path": path, "start": start, "state": state,
                     "third_party": third_party})
    if not rows:
        return f"No driver matches '{name_filter}'." if name_filter else "No drivers."

    third = [x for x in rows if x["third_party"]]
    lines = [f"# Kernel drivers — {len(rows)} in total, {len(third)} outside System32"]
    if third:
        lines.append("\n## 🔴 Third-party drivers — analyse these first")
        for x in third:
            flag = " **[running]**" if x["state"].lower() == "running" else ""
            lines.append(f"- **{x['name']}**{flag} — `{x['path']}`  ({x['start']}, {x['state']})")
    others = [x for x in rows if not x["third_party"]]
    if others and name_filter:
        lines.append(f"\n## Matching system drivers ({len(others)})")
        for x in others[:30]:
            lines.append(f"- {x['name']} — `{x['path']}` ({x['state']})")
    lines.append("\nFor each relevant driver: `driver_attack_surface` on the .sys path.")
    return _cap("\n".join(lines))


@mcp.tool()
def driver_attack_surface(path: str, strict: bool = True) -> str:
    """Full driver assessment in one call: kernel imports by risk, IOCTL codes decoded and ranked,
    device names, and the reachability question spelled out.

    This is the right entry point when the target installs a .sys file."""
    if not os.path.isfile(path):
        return f"file not found: {path}"
    blocks = [f"# Driver attack surface: {os.path.basename(path)}\n",
              "## 1. Kernel imports\n" + driver_imports_audit(path),
              "\n## 2. Exposed IOCTLs\n" + list_ioctls(path, strict=strict, limit=30),
              "\n## 3. Device names\n" + find_device_names(path, limit=15),
              "\n## 4. Mandatory next step\n"
              "Run `device_access_check` on the device name, **as an unprivileged user**. "
              "Everything else depends on that answer: without an obtainable handle, bugs in the "
              "dispatch stay informational; with an obtainable handle they become local privilege "
              "escalation.\n\n"
              "Then open the IRP_MJ_DEVICE_CONTROL routine in Ghidra and, for every high-risk "
              "IOCTL, check: ProbeForRead/Write inside __try/__except, checks on "
              "InputBufferLength and OutputBufferLength, and no integer overflow in the size "
              "computation."]
    return _cap("\n".join(blocks))


if __name__ == "__main__":
    mcp.run()
