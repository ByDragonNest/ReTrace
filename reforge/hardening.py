"""Binary hardening / exploit-mitigation audit (checksec for PE and ELF).

Deterministic, offline. For a benign-binary vuln audit this frames the exploitability
of any memory-corruption finding: a stack overflow is far more dangerous with no /GS
cookie and no DEP/ASLR. Produces a mitigations table + CWE findings for the gaps.
"""
import struct
from typing import Any, Dict

# PE DllCharacteristics bits
_DYNAMICBASE = 0x0040      # ASLR
_FORCE_INTEGRITY = 0x0080
_NX_COMPAT = 0x0100        # DEP
_NO_ISOLATION = 0x0200
_NO_SEH = 0x0400
_HIGH_ENTROPY_VA = 0x0020  # 64-bit ASLR
_GUARD_CF = 0x4000         # Control Flow Guard
_RELOCS_STRIPPED = 0x0001  # FILE_HEADER.Characteristics
_FILE_DLL = 0x2000


def _f(name, sev, status, cwe, desc, reco=None):
    return {"title": name, "severity": sev, "status": status, "vuln_type": "hardening",
            "cwe": cwe, "evidence_source": "binary headers", "evidence_type": "mitigation flags",
            "location": "PE/ELF headers (DllCharacteristics / LoadConfig)",
            "evidence": "Security flag absent from the binary's headers (checksec).",
            "description": f"{name}: the mitigation does not appear to be active in the analyzed binary.",
            "plain": ("This is a standard security protection that this program has not enabled. By "
                      "itself it is not a hole, but it is like leaving a door without a deadbolt: if "
                      "another defect exists, it becomes much easier for an attacker to exploit it."),
            "impact": desc,
            "recommendation": reco or ("Enable the mitigation in the toolchain (for MSVC: /GS, /DYNAMICBASE, "
                "/NXCOMPAT, /guard:cf, /SAFESEH) and re-verify with checksec. By itself it does not "
                "introduce a vulnerability, but it amplifies the exploitability of any memory corruption.")}


# --------------------------------------------------------------------------
def _audit_pe(data: bytes) -> Dict[str, Any]:
    import pefile
    pe = pefile.PE(data=data, fast_load=True)
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"],
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]])

    machine = pe.FILE_HEADER.Machine
    is64 = machine == 0x8664 or machine == 0xaa64
    dc = pe.OPTIONAL_HEADER.DllCharacteristics
    file_chars = pe.FILE_HEADER.Characteristics
    relocs_stripped = bool(file_chars & _RELOCS_STRIPPED)
    is_dll = bool(file_chars & _FILE_DLL)

    lc = getattr(pe, "DIRECTORY_ENTRY_LOAD_CONFIG", None)
    lcs = lc.struct if lc else None
    security_cookie = getattr(lcs, "SecurityCookie", 0) if lcs else 0
    seh_count = getattr(lcs, "SEHandlerCount", 0) if lcs else 0
    seh_table = getattr(lcs, "SEHandlerTable", 0) if lcs else 0
    guard_flags = getattr(lcs, "GuardFlags", 0) if lcs else 0

    try:
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        signed = sec_dir.Size > 0
    except Exception:
        signed = False

    aslr = bool(dc & _DYNAMICBASE)
    aslr_effective = aslr and not relocs_stripped
    dep = bool(dc & _NX_COMPAT)
    gs = bool(security_cookie)
    cfg = bool(dc & _GUARD_CF) or bool(guard_flags & 0x100)
    high_entropy = bool(dc & _HIGH_ENTROPY_VA)
    safeseh = (not is64) and (seh_count > 0 and seh_table != 0) and not (dc & _NO_SEH)
    no_seh = bool(dc & _NO_SEH)

    mit = []
    findings = []

    def add(present, label, detail_on, detail_off, sev, cwe):
        mit.append({"name": label, "present": present,
                    "detail": detail_on if present else detail_off})
        if not present:
            findings.append(_f(f"Missing mitigation: {label}", sev, "CONFIRMED", cwe,
                               detail_off))

    add(dep, "DEP / NX", "Stack/heap are non-executable.",
        "DEP/NX absent: executable shellcode in stack/heap; increases the exploitability of overflows.",
        "MEDIUM", "CWE-119")
    add(aslr_effective, "ASLR (DYNAMICBASE)", "Randomized loading.",
        ("ASLR absent: predictable addresses, ROP/ret2libc made easier."
         + (" (DYNAMICBASE is set but relocations are stripped → ASLR ineffective.)" if aslr and relocs_stripped else "")),
        "MEDIUM", "CWE-693")
    add(gs, "Stack canary (/GS)", "Stack cookie present.",
        "No /GS: stack buffer overflows (CWE-121) are not detected at runtime — high exploitability.",
        "MEDIUM", "CWE-693")
    add(cfg, "Control Flow Guard", "CFG active.",
        "CFG absent: no protection on control-flow integrity (indirect calls).",
        "LOW", "CWE-693")
    if not is64:
        add(safeseh, "SafeSEH", "SEH handlers validated.",
            ("SafeSEH absent"
             + (" (module declares NO_SEH: no SEH handler)." if no_seh else ": SEH overwrite possible on handled crashes.")),
            "MEDIUM" if not no_seh else "LOW", "CWE-693")
    if is64:
        add(high_entropy, "High-Entropy ASLR (64-bit)", "High-entropy ASLR.",
            "High-Entropy VA absent: reduced randomization space on 64-bit.", "LOW", "CWE-693")
    add(signed, "Authenticode signature", "A signature is present (validity not verified).",
        "Unsigned binary: no guarantee of integrity/origin.", "LOW", "CWE-347")

    profile = {"format": "PE", "arch": "x86_64" if is64 else "x86",
               "kind": "DLL" if is_dll else "EXE", "relocs_stripped": relocs_stripped}
    return {"profile": profile, "mitigations": mit, "findings": findings}


# --------------------------------------------------------------------------
_PT_GNU_STACK = 0x6474E551
_PT_GNU_RELRO = 0x6474E552


def _audit_elf(data: bytes) -> Dict[str, Any]:
    ei_class = data[4]                      # 1=32, 2=64
    ei_data = data[5]                       # 1=LE, 2=BE
    en = "<" if ei_data == 1 else ">"
    is64 = ei_class == 2
    e_type = struct.unpack_from(en + "H", data, 16)[0]   # 2=EXEC, 3=DYN
    if is64:
        e_phoff = struct.unpack_from(en + "Q", data, 32)[0]
        e_phentsize, e_phnum = struct.unpack_from(en + "HH", data, 54)
    else:
        e_phoff = struct.unpack_from(en + "I", data, 28)[0]
        e_phentsize, e_phnum = struct.unpack_from(en + "HH", data, 42)

    gnu_stack_x = None      # None = header absent
    relro = False
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from(en + "I", data, off)[0]
        if is64:
            p_flags = struct.unpack_from(en + "I", data, off + 4)[0]
        else:
            p_flags = struct.unpack_from(en + "I", data, off + 24)[0]
        if p_type == _PT_GNU_STACK:
            gnu_stack_x = bool(p_flags & 0x1)        # X bit
        elif p_type == _PT_GNU_RELRO:
            relro = True

    nx = gnu_stack_x is False                         # NX on only if GNU_STACK exists and not X
    pie = e_type == 3
    blob = data.lower()
    canary = b"__stack_chk_fail" in blob
    fortify = b"_chk" in blob and (b"__memcpy_chk" in blob or b"__printf_chk" in blob
                                   or b"__sprintf_chk" in blob or b"__strcpy_chk" in blob)

    mit, findings = [], []

    def add(present, label, detail_on, detail_off, sev, cwe):
        mit.append({"name": label, "present": present,
                    "detail": detail_on if present else detail_off})
        if not present:
            findings.append(_f(f"Missing mitigation: {label}", sev, "CONFIRMED", cwe, detail_off))

    add(nx, "NX (GNU_STACK)", "Stack is non-executable.",
        "Executable stack or GNU_STACK absent: shellcode in stack is possible.", "MEDIUM", "CWE-119")
    add(pie, "PIE", "Position-independent executable (full ASLR).",
        "No-PIE: code base at a fixed address, ROP made easier.", "MEDIUM", "CWE-693")
    add(relro, "RELRO", "GNU_RELRO segment present (at least partial).",
        "No RELRO: writable GOT, GOT overwrite possible.", "MEDIUM", "CWE-693")
    add(canary, "Stack canary", "__stack_chk_fail detected.",
        "No canary detected: stack overflows are not detected at runtime (CWE-121).", "MEDIUM", "CWE-693")
    add(fortify, "FORTIFY_SOURCE", "*_chk functions detected.",
        "FORTIFY_SOURCE not detected: no bounds checks on libc str/mem functions.", "LOW", "CWE-693")

    profile = {"format": "ELF", "arch": "x86_64" if is64 else "x86", "kind": "PIE" if pie else "EXEC",
               "note": "canary/FORTIFY detected heuristically from symbols"}
    return {"profile": profile, "mitigations": mit, "findings": findings}


# --------------------------------------------------------------------------
def audit(path: str) -> Dict[str, Any]:
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as e:
        return {"error": f"cannot read file: {e}"}
    try:
        if data[:2] == b"MZ":
            res = _audit_pe(data)
        elif data[:4] == b"\x7fELF":
            res = _audit_elf(data)
        else:
            return {"error": "unsupported format (expected PE 'MZ' or ELF)"}
    except Exception as e:  # noqa: BLE001
        return {"error": f"audit failed: {e}"}
    res["text"] = render(res)
    return res


def render(res: Dict[str, Any]) -> str:
    if "error" in res:
        return f"Hardening audit: {res['error']}"
    p = res["profile"]
    L = [f"## Mitigations ({p['format']} {p['arch']} {p['kind']})", "",
         "| Mitigation | Status | Notes |", "|---|---|---|"]
    for m in res["mitigations"]:
        L.append(f"| {m['name']} | {'✅' if m['present'] else '❌'} | {m['detail']} |")
    missing = [f for f in res["findings"]]
    L.append("")
    if missing:
        L.append(f"**{len(missing)} missing mitigations** (see findings).")
    else:
        L.append("All main mitigations are active.")
    return "\n".join(L)
