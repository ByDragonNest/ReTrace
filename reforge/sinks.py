"""Dangerous-sink and input-source inventory for binary vulnerability auditing.

Given a list of imported/known symbols, classify them into vulnerability-relevant
SINK classes (each CWE-tagged) and INPUT SOURCES (taint origins). This maps the
attack surface: where untrusted data can enter, and the risky operations it might
reach. Reachability (source -> sink) is then confirmed with Ghidra xrefs by the agent.

Presence of a sink is NOT a vulnerability by itself, so findings are HYPOTHESIS:
they tell the analyst where to look.
"""
from typing import Any, Dict, List

# --- sink classes: klass -> (cwe, severity-if-reachable, note) ----------------
_PLAIN = {
    "mem_copy":  "The program copies data into a memory area without checking that it fits: "
                 "if the incoming data is larger than expected it can 'overflow' and make "
                 "the program behave unexpectedly, up to running commands chosen by an attacker.",
    "format":    "The program uses externally supplied text as a printing 'template': an attacker "
                 "can exploit it to read or write the program's memory.",
    "unbounded": "The program reads data from the outside with no length limit: input that is "
                 "too long can crash it or hijack its control flow.",
    "exec":      "The program launches other programs or commands: if an attacker controls what "
                 "gets launched (or replaces the launched file), they can make the computer run "
                 "whatever they want.",
    "load":      "The program loads additional components (DLLs) without specifying a safe path: "
                 "an attacker can plant a fake one and have it loaded instead of the real one.",
    "alloc_int": "The program computes how much memory to reserve: a wrong calculation can reserve "
                 "a space that is too small and lead to exploitable memory errors.",
    "file":      "The program opens files using a path that can come from the outside: without "
                 "checks, an attacker can read or write files it shouldn't.",
}

_CLASS = {
    "mem_copy":   ("CWE-120", "HIGH",   "Copy into a buffer with no size check → overflow (CWE-121/787).",
                   "Stack/heap overwrite: crash (DoS) and, absent /GS+DEP+ASLR, arbitrary code execution."),
    "format":     ("CWE-134", "HIGH",   "Non-literal format string → arbitrary memory read/write.",
                   "Information disclosure (%x/%s) and arbitrary write (%n) → memory corruption and potential RCE."),
    "unbounded":  ("CWE-120", "HIGH",   "Input read with no length limit → overflow.",
                   "Destination buffer overflow: DoS and possible code execution."),
    "exec":       ("CWE-78",  "CRITICAL","Command/process execution → command injection if the argument is controllable; untrusted search path if the path is relative (CWE-426/427).",
                   "Arbitrary code execution in the process context (RCE) or hijacking of the launched binary/DLL."),
    "load":       ("CWE-427", "HIGH",   "Library loading → DLL side-loading if the path is not absolute/validated.",
                   "Loading of a malicious DLL planted in the search order → arbitrary code execution."),
    "alloc_int":  ("CWE-190", "MEDIUM", "Allocation with a computed size → integer overflow/underflow in the size (CWE-190/680).",
                   "Undersized buffer followed by an out-of-bounds write → heap corruption."),
    "file":       ("CWE-22",  "MEDIUM", "File opened with a controllable path → path traversal/arbitrary write.",
                   "Reading/writing files outside the intended directory → disclosure or tampering."),
}

# --- sinks: canonical lowercased base name -> klass ---------------------------
# Windows A/W suffixes are stripped before lookup, so store the base (e.g. createprocess).
_SINKS = {
    # memory copy / concat
    "strcpy": "mem_copy", "strcpyn": "mem_copy", "strcat": "mem_copy", "strncat": "mem_copy",
    "lstrcpy": "mem_copy", "lstrcat": "mem_copy", "lstrcpyn": "mem_copy",
    "wcscpy": "mem_copy", "wcscat": "mem_copy", "stpcpy": "mem_copy", "strlcat": "mem_copy",
    "memcpy": "mem_copy", "memmove": "mem_copy", "copymemory": "mem_copy", "rtlcopymemory": "mem_copy",
    "sprintf": "mem_copy", "vsprintf": "mem_copy", "swprintf": "mem_copy", "wsprintf": "mem_copy",
    "strncpy": "mem_copy",
    # format string
    "printf": "format", "fprintf": "format", "vprintf": "format", "vfprintf": "format",
    "snprintf": "format", "vsnprintf": "format", "syslog": "format", "wprintf": "format",
    # unbounded input
    "gets": "unbounded", "scanf": "unbounded", "sscanf": "unbounded", "fscanf": "unbounded",
    # command / process execution
    "system": "exec", "popen": "exec", "wsystem": "exec", "spawnv": "exec", "spawnve": "exec",
    "spawnl": "exec", "execl": "exec", "execv": "exec", "execve": "exec", "execvp": "exec",
    "winexec": "exec", "createprocess": "exec", "createprocessasuser": "exec",
    "shellexecute": "exec", "shellexecuteex": "exec",
    # library loading
    "loadlibrary": "load", "loadlibraryex": "load", "loadmodule": "load", "dlopen": "load",
    # allocation with computed size
    "malloc": "alloc_int", "calloc": "alloc_int", "realloc": "alloc_int", "alloca": "alloc_int",
    "heapalloc": "alloc_int", "localalloc": "alloc_int", "globalalloc": "alloc_int",
    "virtualalloc": "alloc_int",
    # file open
    "fopen": "file", "wfopen": "file", "open": "file", "openfile": "file", "createfile": "file",
    "_open": "file",
}

# --- input sources (taint origins) -------------------------------------------
_SOURCES = {
    "getcommandline": "command-line arguments", "__getmainargs": "argv",
    "getenvironmentvariable": "environment variables", "getenv": "environment variables",
    "recv": "network (socket)", "recvfrom": "network (socket)", "wsarecv": "network (socket)",
    "wsarecvfrom": "network (socket)", "internetreadfile": "network (WinINet)", "accept": "network (socket)",
    "readfile": "file", "fread": "file", "read": "file", "fgets": "file", "readconsole": "console/stdin",
    "regqueryvalueex": "system registry", "reggetvalue": "system registry",
    "deviceiocontrol": "IOCTL (driver/device)", "getwindowtext": "GUI input",
}


def _candidates(sym: str) -> List[str]:
    s = sym.strip().lower()
    s = s.lstrip("_")
    if s.startswith("imp_"):
        s = s[4:]
    out = {s}
    if s and s[-1] in ("a", "w"):     # Win32 ANSI/Wide variants
        out.add(s[:-1])
    return list(out)


def _match(sym: str, table: Dict[str, Any]):
    for c in _candidates(sym):
        if c in table:
            return table[c]
    return None


def inventory(symbols: List[str]) -> Dict[str, Any]:
    """Classify symbols into CWE-tagged sink classes and input sources."""
    sink_hits: Dict[str, set] = {}
    source_hits: Dict[str, str] = {}
    for sym in symbols or []:
        if not isinstance(sym, str):
            continue
        klass = _match(sym, _SINKS)
        if klass:
            sink_hits.setdefault(klass, set()).add(sym)
        src = _match(sym, _SOURCES)
        if src:
            source_hits[sym] = src

    findings = []
    src_ctx = ""
    if source_hits:
        src_ctx = (" Untrusted input sources present in the binary: "
                   + ", ".join(f"{s} ({d})" for s, d in sorted(source_hits.items())) + ".")
    have_source = bool(source_hits)
    for klass, apis in sink_hits.items():
        cwe, potential_sev, note, impact = _CLASS[klass]
        api_list = ", ".join(sorted(apis))
        # Presence in the import table is *attack surface*, not a vulnerability. The severity that
        # matters — the one in `_CLASS` — is the worst case IF the sink is reachable from untrusted
        # input with the control absent. Until a source→sink path is demonstrated (by the agent via
        # xrefs, or dynamically), the finding ships at a low *presence* severity so it cannot inflate
        # the report's CRITICAL/HIGH counts on every ordinary binary. The worst case is preserved in
        # `potential_severity`, and the evidence_bundle tells the engine what is (and isn't) known so
        # the status is capped at INDICATOR (sink only) / HYPOTHESIS (sink + a plausible source).
        presence_sev = "LOW" if have_source else "INFO"
        bundle = {"sink": True}
        if have_source:
            bundle["source"] = True          # a plausible taint origin co-occurs → worth checking
        else:
            bundle["isolated_only"] = True    # sink symbol alone, no source in view
        findings.append({
            "title": f"{klass} sink present ({api_list})",
            "severity": presence_sev, "potential_severity": potential_sev,
            "status": "HYPOTHESIS", "vuln_type": klass, "cwe": cwe,
            "location": "import table / symbols",
            "evidence_source": "import table", "evidence_type": "symbol inventory",
            "evidence_bundle": bundle,
            "evidence": f"Imported APIs in the \u00ab{klass}\u00bb class: {api_list}." + src_ctx,
            "plain": _PLAIN.get(klass, ""),
            "description": note + f" Presence alone is not a vulnerability (attack surface only; "
                                  f"worst case if reachable: {potential_sev}): the call sites must be "
                                  "checked, and whether the arguments derive from an untrusted source.",
            "impact": impact,
            "recommendation": "1) Locate every call site with xrefs; 2) decompile and trace each "
                              "sink argument back to its source; 3) verify reachability from "
                              "external input and the absence of validation/limits; 4) mark CONFIRMED "
                              "only with a demonstrated (static) or observed (dynamic) source→sink path.",
        })
    return {"sinks": {k: sorted(v) for k, v in sink_hits.items()},
            "sources": source_hits, "findings": findings, "text": render(sink_hits, source_hits)}


def render(sink_hits: Dict[str, set], source_hits: Dict[str, str]) -> str:
    L = ["## Attack surface — sinks & sources", ""]
    if sink_hits:
        L += ["**Dangerous sinks** (presence != vulnerability: reachability must be verified):", "",
              "| Class | CWE | Severity | APIs found |", "|---|---|---|---|"]
        for klass, apis in sorted(sink_hits.items()):
            cwe, sev, _, _ = _CLASS[klass]
            L.append(f"| {klass} | {cwe} | {sev} | {', '.join(sorted(apis))} |")
        L.append("")
    else:
        L += ["No known dangerous sinks among the provided symbols.", ""]
    if source_hits:
        srcs = sorted({f"{s} ({why})" for s, why in source_hits.items()})
        L += ["**Input sources** (taint origins): " + ", ".join(srcs), ""]
    else:
        L += ["No known input sources among the provided symbols.", ""]
    if sink_hits and source_hits:
        L += ["→ For each sink, use xrefs to trace whether an argument traces back to one of these "
              "sources: that is the source→sink path to confirm.", ""]
    return "\n".join(L)
