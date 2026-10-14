"""MCP server for attack-surface enumeration of a PE/ELF binary.

Answers the question that must come BEFORE any bug hunting: where does untrusted input enter,
and who can reach it. Without this you find bugs without knowing whether anyone can trigger them.

Pure-Python (pefile for PE, minimal ELF parser). No external CLI needed.
"""
from __future__ import annotations

import os
import re
import struct
from collections import defaultdict
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("attack-surface")
CAP = 12000

# ---------------------------------------------------------------------------
# Imports grouped by the vulnerability class they enable. The point is not
# "this API is bad" but "if untrusted data reaches this, here is the CWE".
# ---------------------------------------------------------------------------
SINKS: Dict[str, Dict[str, Any]] = {
    "memory_copy": {
        "cwe": "CWE-120/121/122 (buffer overflow)",
        "why": "unbounded or length-controlled copy into a fixed buffer",
        "apis": {"strcpy", "strcat", "wcscpy", "wcscat", "sprintf", "swprintf", "vsprintf",
                 "gets", "memcpy", "memmove", "CopyMemory", "RtlCopyMemory", "lstrcpyA",
                 "lstrcpyW", "lstrcatA", "lstrcatW", "StrCpyA", "StrCpyW", "bcopy",
                 "strncpy", "strncat", "wcsncpy", "_mbscpy", "alloca", "_alloca"},
    },
    "format_string": {
        "cwe": "CWE-134 (format string)",
        "why": "attacker-controlled format specifier",
        "apis": {"printf", "fprintf", "vprintf", "vfprintf", "syslog", "wprintf",
                 "FormatMessageA", "FormatMessageW", "_snprintf", "_vsnprintf"},
    },
    "command_exec": {
        "cwe": "CWE-78 (OS command injection)",
        "why": "spawns a process, often with a concatenated command line",
        "apis": {"system", "popen", "_popen", "execl", "execlp", "execv", "execve", "_wsystem",
                 "CreateProcessA", "CreateProcessW", "CreateProcessAsUserA", "CreateProcessAsUserW",
                 "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
                 "WinExec", "_spawnl", "_spawnv"},
    },
    "library_load": {
        "cwe": "CWE-427 (uncontrolled search path) / DLL hijacking",
        "why": "loads code by name; resolution order may reach a writable directory",
        "apis": {"LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
                 "GetProcAddress", "dlopen", "dlsym", "LoadPackagedLibrary", "LoadModule"},
    },
    "deserialization": {
        "cwe": "CWE-502 (unsafe deserialization)",
        "why": "reconstructs objects from a byte stream",
        "apis": {"OleLoadFromStream", "CoGetInstanceFromFile", "IPersistStreamInit",
                 "BinaryFormatter", "ReadObject"},
    },
    "file_ops": {
        "cwe": "CWE-22/CWE-367 (path traversal, TOCTOU)",
        "why": "filesystem access on an attacker-influenced path",
        "apis": {"CreateFileA", "CreateFileW", "fopen", "_wfopen", "open", "DeleteFileA",
                 "DeleteFileW", "MoveFileA", "MoveFileW", "CopyFileA", "CopyFileW",
                 "GetTempFileNameA", "GetTempFileNameW", "GetTempPathA", "GetTempPathW",
                 "tmpnam", "mktemp", "SetCurrentDirectoryA", "SetCurrentDirectoryW"},
    },
    "privilege": {
        "cwe": "CWE-269 (improper privilege management)",
        "why": "token/impersonation handling; a bug here is a direct privesc",
        "apis": {"ImpersonateLoggedOnUser", "SetThreadToken", "AdjustTokenPrivileges",
                 "CreateProcessWithLogonW", "LogonUserA", "LogonUserW", "OpenProcessToken",
                 "setuid", "seteuid", "setgid", "RevertToSelf", "DuplicateTokenEx"},
    },
    "crypto": {
        "cwe": "CWE-327/CWE-338 (weak crypto, weak PRNG)",
        "why": "cryptographic primitive selection and RNG quality",
        "apis": {"CryptGenRandom", "rand", "srand", "CryptCreateHash", "CryptDeriveKey",
                 "MD5Init", "MD5_Init", "SHA1_Init", "RC4", "DES_set_key", "EVP_des_cbc"},
    },
    "network": {
        "cwe": "attack surface (remote input)",
        "why": "remote input reaches the process",
        "apis": {"socket", "bind", "listen", "accept", "recv", "recvfrom", "WSAStartup",
                 "WSASocketA", "WSASocketW", "connect", "InternetOpenA", "InternetOpenW",
                 "InternetOpenUrlA", "InternetOpenUrlW", "HttpSendRequestA", "HttpSendRequestW",
                 "WinHttpOpen", "WinHttpSendRequest", "URLDownloadToFileA", "URLDownloadToFileW",
                 "curl_easy_perform"},
    },
    "ipc": {
        "cwe": "attack surface (local cross-privilege input)",
        "why": "another local process, possibly less privileged, can talk to this one",
        "apis": {"CreateNamedPipeA", "CreateNamedPipeW", "ConnectNamedPipe", "CreateMailslotA",
                 "CreateFileMappingA", "CreateFileMappingW", "MapViewOfFile", "RpcServerListen",
                 "RpcServerUseProtseq", "RpcServerRegisterIf", "CoRegisterClassObject",
                 "DdeInitializeA", "SetWindowsHookExA", "SetWindowsHookExW"},
    },
    "registry": {
        "cwe": "CWE-15 (external control of system setting)",
        "why": "reads config from the registry; HKCU is user-writable",
        "apis": {"RegOpenKeyExA", "RegOpenKeyExW", "RegQueryValueExA", "RegQueryValueExW",
                 "RegGetValueA", "RegGetValueW", "RegCreateKeyExA", "RegCreateKeyExW",
                 "RegSetValueExA", "RegSetValueExW"},
    },
    "memory_protection": {
        "cwe": "CWE-119 (mitigation weakening)",
        "why": "makes memory writable+executable, defeating DEP",
        "apis": {"VirtualProtect", "VirtualProtectEx", "VirtualAlloc", "VirtualAllocEx",
                 "WriteProcessMemory", "mprotect", "CreateRemoteThread", "NtProtectVirtualMemory"},
    },
}

_API_INDEX: Dict[str, List[str]] = defaultdict(list)
for _cat, _meta in SINKS.items():
    for _api in _meta["apis"]:
        _API_INDEX[_api.lower()].append(_cat)


def _cap(s: str) -> str:
    return s[:CAP] + "\n…(truncated)" if len(s) > CAP else s


def _fmt(path: str) -> str:
    try:
        with open(path, "rb") as fh:
            magic = fh.read(4)
    except OSError:
        return "unreadable"
    if magic[:2] == b"MZ":
        return "pe"
    if magic == b"\x7fELF":
        return "elf"
    if magic[:4] in (b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        return "macho"
    return "unknown"


# ---------------------------------------------------------------------------
# PE helpers
# ---------------------------------------------------------------------------
def _load_pe(path: str):
    import pefile
    return pefile.PE(path, fast_load=False)


def _pe_imports(pe) -> List[Dict[str, str]]:
    out = []
    for attr, kind in (("DIRECTORY_ENTRY_IMPORT", "import"),
                       ("DIRECTORY_ENTRY_DELAY_IMPORT", "delay-import")):
        for entry in getattr(pe, attr, []) or []:
            dll = (entry.dll or b"").decode("utf-8", "ignore")
            for imp in entry.imports or []:
                name = (imp.name or b"").decode("utf-8", "ignore")
                if name:
                    out.append({"dll": dll, "api": name, "kind": kind})
    return out


def _pe_exports(pe) -> List[Dict[str, Any]]:
    out = []
    d = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if not d:
        return out
    for exp in d.symbols or []:
        out.append({
            "name": (exp.name or b"").decode("utf-8", "ignore") or f"#{exp.ordinal}",
            "ordinal": exp.ordinal,
            "rva": hex(exp.address or 0),
        })
    return out


def _pe_manifest(pe) -> Optional[str]:
    import pefile
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return None
    for rt in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if getattr(rt, "id", None) != pefile.RESOURCE_TYPE["RT_MANIFEST"]:
            continue
        for rid in getattr(rt.directory, "entries", []):
            for lang in getattr(rid.directory, "entries", []):
                data = pe.get_data(lang.data.struct.OffsetToData, lang.data.struct.Size)
                return data.decode("utf-8", "ignore")
    return None


def _pe_tls_callbacks(pe) -> List[str]:
    tls = getattr(pe, "DIRECTORY_ENTRY_TLS", None)
    if not tls or not tls.struct.AddressOfCallBacks:
        return []
    out = []
    try:
        base = pe.OPTIONAL_HEADER.ImageBase
        ptr_size = 8 if pe.OPTIONAL_HEADER.Magic == 0x20B else 4
        rva = tls.struct.AddressOfCallBacks - base
        for i in range(16):
            raw = pe.get_data(rva + i * ptr_size, ptr_size)
            val = int.from_bytes(raw, "little")
            if not val:
                break
            out.append(hex(val))
    except Exception:  # noqa: BLE001
        pass
    return out


# ---------------------------------------------------------------------------
# Minimal ELF symbol reader (avoids a hard dependency on pyelftools)
# ---------------------------------------------------------------------------
def _elf_symbols(path: str) -> Dict[str, List[str]]:
    imported: List[str] = []
    exported: List[str] = []
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        is64 = data[4] == 2
        little = data[5] == 1
        end = "<" if little else ">"
        if is64:
            e_shoff, e_shentsize, e_shnum, e_shstrndx = (
                struct.unpack_from(end + "Q", data, 0x28)[0],
                struct.unpack_from(end + "H", data, 0x3A)[0],
                struct.unpack_from(end + "H", data, 0x3C)[0],
                struct.unpack_from(end + "H", data, 0x3E)[0])
            sh_fmt, sym_fmt, sym_sz = end + "IIQQQQIIQQ", end + "IBBHQQ", 24
        else:
            e_shoff, e_shentsize, e_shnum, e_shstrndx = (
                struct.unpack_from(end + "I", data, 0x20)[0],
                struct.unpack_from(end + "H", data, 0x2E)[0],
                struct.unpack_from(end + "H", data, 0x30)[0],
                struct.unpack_from(end + "H", data, 0x32)[0])
            sh_fmt, sym_fmt, sym_sz = end + "IIIIIIIIII", end + "IIIBBH", 16

        sections = []
        for i in range(e_shnum):
            sections.append(struct.unpack_from(sh_fmt, data, e_shoff + i * e_shentsize))
        shstr_off = sections[e_shstrndx][4]

        def sname(idx):
            off = shstr_off + sections[idx][0]
            return data[off:data.index(b"\x00", off)].decode("utf-8", "ignore")

        for i, sec in enumerate(sections):
            nm = sname(i)
            if nm not in (".dynsym", ".symtab"):
                continue
            strtab = sections[sec[6]][4]
            count = sec[5] // sym_sz
            for j in range(count):
                off = sec[4] + j * sym_sz
                if is64:
                    st_name, st_info, _o, st_shndx, _v, _s = struct.unpack_from(sym_fmt, data, off)
                else:
                    st_name, _v, _s, st_info, _o, st_shndx = struct.unpack_from(sym_fmt, data, off)
                if not st_name:
                    continue
                s = strtab + st_name
                try:
                    name = data[s:data.index(b"\x00", s)].decode("utf-8", "ignore")
                except ValueError:
                    continue
                if not name:
                    continue
                if st_shndx == 0:
                    imported.append(name)
                elif (st_info & 0xF) in (1, 2):  # OBJECT / FUNC
                    exported.append(name)
    except Exception:  # noqa: BLE001
        pass
    return {"imported": sorted(set(imported)), "exported": sorted(set(exported))}


def _classify(names: List[str]) -> Dict[str, List[str]]:
    found: Dict[str, List[str]] = defaultdict(list)
    for n in names:
        base = n.lstrip("_").split("@")[0]
        for cand in (n, base, base.rstrip("AW")):
            cats = _API_INDEX.get(cand.lower())
            if cats:
                for c in cats:
                    if n not in found[c]:
                        found[c].append(n)
                break
    return dict(found)


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
@mcp.tool()
def attack_surface_summary(path: str) -> str:
    """START HERE for any binary. One-shot triage of the attack surface: format, architecture,
    required privilege level (UAC manifest), entry points, and which vulnerability-relevant API
    categories the binary imports. Tells you WHO can reach this code and WHAT classes of bug to
    look for, before you open a decompiler."""
    if not os.path.isfile(path):
        return f"file not found: {path}"
    kind = _fmt(path)
    lines = [f"# Attack surface: {os.path.basename(path)}",
             f"format: {kind}  |  size: {os.path.getsize(path) / 1024:.1f} KB"]

    if kind == "pe":
        try:
            pe = _load_pe(path)
        except Exception as e:  # noqa: BLE001
            return f"PE parsing error: {e}"
        is64 = pe.OPTIONAL_HEADER.Magic == 0x20B
        subsystem = pe.OPTIONAL_HEADER.Subsystem
        is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
        lines.append(f"arch: {'x64' if is64 else 'x86'}  |  "
                     f"type: {'DLL' if is_dll else 'EXE'}  |  "
                     f"subsystem: {'GUI' if subsystem == 2 else 'CONSOLE' if subsystem == 3 else subsystem}")

        manifest = _pe_manifest(pe)
        if manifest:
            m = re.search(r'level\s*=\s*"([^"]+)"', manifest)
            ui = re.search(r'uiAccess\s*=\s*"([^"]+)"', manifest)
            level = m.group(1) if m else "asInvoker (implicit)"
            lines.append(f"\n## Required privilege\nrequestedExecutionLevel = **{level}**")
            if m and "requireAdministrator" in m.group(1):
                lines.append("  ⚠ runs elevated: every piece of untrusted input that reaches this process "
                             "is a potential privilege escalation, not just an application bug.")
            if ui and ui.group(1).lower() == "true":
                lines.append("  ⚠ uiAccess=true: bypasses UIPI isolation.")
        else:
            lines.append("\n## Required privilege\nno embedded RT_MANIFEST "
                         "(default asInvoker; check for an external .manifest)")

        exports = _pe_exports(pe)
        tls = _pe_tls_callbacks(pe)
        lines.append(f"\n## Entry point\n- OEP: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)} (RVA)")
        if tls:
            lines.append(f"- TLS callbacks: {', '.join(tls)}  ← run BEFORE main")
        if exports:
            lines.append(f"- exports: {len(exports)} functions "
                         f"({', '.join(e['name'] for e in exports[:12])}"
                         f"{'…' if len(exports) > 12 else ''})")
            if is_dll:
                lines.append("  → every export is a surface reachable by whoever loads the DLL")

        imports = _pe_imports(pe)
        names = [i["api"] for i in imports]
        delay = [i["api"] for i in imports if i["kind"] == "delay-import"]
        cats = _classify(names)
        lines.append(f"\n## Relevant imports ({len(imports)} in total from "
                     f"{len({i['dll'] for i in imports})} DLL)")
        if not cats:
            lines.append("no API in a known category. Statically linked or packed? "
                         "Check the import count: below 10 it is probably packed.")
        for cat, apis in sorted(cats.items(), key=lambda kv: -len(kv[1])):
            meta = SINKS[cat]
            lines.append(f"\n### {cat} — {meta['cwe']}")
            lines.append(f"_{meta['why']}_")
            lines.append("  " + ", ".join(sorted(set(apis))[:20]))
        if delay:
            lines.append(f"\n### delay-import ({len(delay)})")
            lines.append("  resolved at runtime → prime candidates for DLL hijacking: "
                         + ", ".join(sorted(set(delay))[:15]))

    elif kind == "elf":
        syms = _elf_symbols(path)
        cats = _classify(syms["imported"])
        lines.append(f"\n## Symbols\n- imported: {len(syms['imported'])}  |  "
                     f"exported: {len(syms['exported'])}")
        for cat, apis in sorted(cats.items(), key=lambda kv: -len(kv[1])):
            meta = SINKS[cat]
            lines.append(f"\n### {cat} — {meta['cwe']}\n_{meta['why']}_\n  "
                         + ", ".join(sorted(set(apis))[:20]))
    else:
        return f"format not supported for static analysis: {kind}"

    lines.append("\n---\nNext steps: `input_vectors` to see where input enters, "
                 "then the xrefs to these sinks in the decompiler.")
    return _cap("\n".join(lines))


@mcp.tool()
def input_vectors(path: str) -> str:
    """Enumerate how untrusted data can reach the binary: network sockets, named pipes, RPC/COM,
    shared memory, registry, files, command line, environment. Each vector is reported with the
    evidence (which imported API implies it) and the privilege boundary it crosses."""
    if not os.path.isfile(path):
        return f"file not found: {path}"
    kind = _fmt(path)
    if kind == "pe":
        try:
            pe = _load_pe(path)
        except Exception as e:  # noqa: BLE001
            return f"PE parsing error: {e}"
        names = [i["api"] for i in _pe_imports(pe)]
    elif kind == "elf":
        names = _elf_symbols(path)["imported"]
    else:
        return f"unsupported format: {kind}"

    # Exact-name matching. Substring matching produces nonsense such as `bindtextdomain`
    # being reported as a listening socket.
    def has(*apis):
        wanted = {a.lower() for a in apis}
        hits = set()
        for n in names:
            base = n.lstrip("_").split("@")[0]
            for cand in (n, base, base.rstrip("AW")):
                if cand.lower() in wanted:
                    hits.add(n)
                    break
        return sorted(hits)

    vectors = [
        ("Network (remote)",
         has("socket", "bind", "listen", "accept", "accept4", "recv", "recvfrom", "recvmsg",
             "WSAStartup", "WSASocket", "WSARecv", "WSAAccept", "socketpair"),
         "unauthenticated remote input: top priority"),
        ("HTTP client (remote, semi-trusted)",
         has("InternetOpen", "InternetOpenUrl", "InternetReadFile", "WinHttpOpen",
             "WinHttpSendRequest", "WinHttpReceiveResponse", "HttpSendRequest",
             "URLDownloadToFile", "curl_easy_perform", "curl_easy_setopt"),
         "server responses are untrusted input; check the TLS validation"),
        ("Named pipe / mailslot (local, cross-privilege)",
         has("CreateNamedPipe", "ConnectNamedPipe", "CreateMailslot", "CallNamedPipe",
             "TransactNamedPipe", "mkfifo"),
         "if the process is elevated, an unprivileged user can talk to it: privilege escalation"),
        ("Shared memory (local)",
         has("CreateFileMapping", "OpenFileMapping", "MapViewOfFile", "shmget", "shmat",
             "shm_open", "mmap"),
         "check the section's DACL: world-writable means an attack channel"),
        ("RPC / COM (local or remote)",
         has("RpcServerListen", "RpcServerUseProtseq", "RpcServerUseProtseqEp",
             "RpcServerRegisterIf", "CoRegisterClassObject", "CoCreateInstance",
             "CoInitializeSecurity"),
         "the classic Windows privesc surface"),
        ("Window messages (local)",
         has("SetWindowsHookEx", "SendMessage", "PostMessage", "RegisterWindowMessage",
             "DdeInitialize"),
         "shatter attack if the elevated process has windows on a shared desktop"),
        ("File / parsing",
         has("CreateFile", "fopen", "_wfopen", "open", "open64", "ReadFile", "fread",
             "MapViewOfFile", "_open", "freopen"),
         "the most natural fuzzing target if the binary parses a format"),
        ("Registro",
         has("RegOpenKeyEx", "RegQueryValueEx", "RegGetValue", "RegEnumKeyEx", "RegEnumValue",
             "SHGetValue", "RegOpenKey", "RegQueryValue"),
         "HKCU is user-writable: config injection if read by an elevated process"),
        ("Environment variables",
         has("getenv", "secure_getenv", "GetEnvironmentVariable", "ExpandEnvironmentStrings",
             "GetEnvironmentStrings", "_wgetenv"),
         "user-controlled; dangerous when used to build paths"),
        ("Command line",
         has("GetCommandLine", "CommandLineToArgv", "__getmainargs", "__wgetmainargs",
             "getopt", "getopt_long"),
         "controlled by whoever launches the process"),
    ]

    lines = [f"# Input vectors: {os.path.basename(path)}"]
    active = [(n, ev, note) for n, ev, note in vectors if ev]
    if not active:
        lines.append("\nNo vector detected from the imports. If the binary is packed or static, "
                     "this analysis is blind: check the import count with `attack_surface_summary` "
                     "of imports, and fall back to dynamic analysis.")
        return "\n".join(lines)
    for name, ev, note in active:
        lines.append(f"\n## {name}\n_{note}_\n  evidence: {', '.join(ev[:12])}")
    lines.append("\n---\nFor each active vector, trace in the decompiler the path "
                 "from the entry function to the sinks listed by `attack_surface_summary`.")
    return _cap("\n".join(lines))


@mcp.tool()
def list_exports(path: str, limit: int = 300) -> str:
    """List the exported functions of a DLL/shared object with their RVA. On a DLL every export is
    directly reachable attack surface. Use the names to drive decompilation."""
    if not os.path.isfile(path):
        return f"file not found: {path}"
    kind = _fmt(path)
    if kind == "pe":
        try:
            pe = _load_pe(path)
        except Exception as e:  # noqa: BLE001
            return f"PE parsing error: {e}"
        exports = _pe_exports(pe)
        if not exports:
            return "No exports (not a DLL, or it exports by ordinal only, without names)."
        lines = [f"{len(exports)} export in {os.path.basename(path)}:"]
        lines += [f"  {e['rva']:>12}  #{e['ordinal']:<5} {e['name']}" for e in exports[:limit]]
        if len(exports) > limit:
            lines.append(f"  …{len(exports) - limit} more (raise `limit`)")
        return _cap("\n".join(lines))
    if kind == "elf":
        syms = _elf_symbols(path)["exported"]
        if not syms:
            return "No exported symbols."
        return _cap(f"{len(syms)} exported symbols:\n  " + "\n  ".join(syms[:limit]))
    return f"unsupported format: {kind}"


@mcp.tool()
def find_sink_imports(path: str, category: str = "") -> str:
    """List the imported APIs that map to a specific vulnerability class, with the associated CWE.
    Categories: memory_copy, format_string, command_exec, library_load, deserialization, file_ops,
    privilege, crypto, network, ipc, registry, memory_protection. Empty = all.

    Feed the resulting API names to the Ghidra MCP to get the cross-references to each call site."""
    if not os.path.isfile(path):
        return f"file not found: {path}"
    kind = _fmt(path)
    if kind == "pe":
        try:
            names = [i["api"] for i in _pe_imports(_load_pe(path))]
        except Exception as e:  # noqa: BLE001
            return f"PE parsing error: {e}"
    elif kind == "elf":
        names = _elf_symbols(path)["imported"]
    else:
        return f"unsupported format: {kind}"

    cats = _classify(names)
    if category:
        if category not in SINKS:
            return f"unknown category: {category}. Valid: {', '.join(sorted(SINKS))}"
        cats = {category: cats.get(category, [])}
    lines = []
    for cat, apis in sorted(cats.items()):
        meta = SINKS[cat]
        lines.append(f"## {cat} — {meta['cwe']}\n_{meta['why']}_")
        lines.append("  " + (", ".join(sorted(set(apis))) if apis else "(none)"))
    return _cap("\n".join(lines) or "No sink found.")


if __name__ == "__main__":
    mcp.run()
