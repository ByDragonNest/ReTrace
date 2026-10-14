# Binary vulnerability-research methodology (ReTrace built-in)

Original, concise reference for auditing **benign** binaries for vulnerabilities and
misconfigurations. Drop your own reference books (PDF/TXT/MD) in this folder to extend it.

## Overall workflow
1. Recon: format/arch, imports/exports, strings, sections, entropy.
2. Hardening audit (DEP/NX, ASLR/PIE, stack canary/GS, CFG, SafeSEH, RELRO). Missing mitigations
   raise the exploitability of every memory bug found later.
3. Attack surface: enumerate dangerous sinks (exec, memory copy, format, alloc, file, library load)
   and input sources (argv, env, files, sockets, registry, IOCTL).
4. Reachability: for each sink, find call sites (xrefs), decompile the caller, and trace whether the
   sink arguments derive from an untrusted source. A source->sink path is a candidate vulnerability.
5. Confirmation: dynamically confirm with the debugger (breakpoint on the sink, inspect arguments).
6. Severity: combine the bug class with the mitigation profile and the reachability.
7. Report: per finding — class, CWE, location, root cause, reachability, mitigations, PoC, fix.

## Source -> sink reasoning
A vulnerability needs untrusted data to reach a dangerous operation. Sources: command line,
environment, files, network, registry, IPC/IOCTL, GUI fields. Sinks: see classes below. Trace the
data flow: rename variables semantically, follow each argument backward to its origin, note any
validation/sanitization on the path. No reachable source = lower priority.

## Command / process execution — CWE-78 (and CWE-426/427)
Look for: system, popen, exec*, WinExec, CreateProcess*, ShellExecute*. Risk when the command line
or program path is built from untrusted input (injection), or when the program/library path is
relative or unqualified (untrusted search path -> CWE-426; DLL side-loading -> CWE-427).
Trace: decompile the caller; is lpApplicationName/lpCommandLine attacker-influenced or a relative
path? Confirm dynamically: break on the API, read the path/command argument actually passed.

## Memory copy / overflow — CWE-120 / CWE-121 / CWE-787
Look for: strcpy, strcat, sprintf, gets, scanf("%s"), memcpy with a non-constant length, fixed stack
buffers filled in a loop without bounds. Trace: where does the size/source come from? Is the
destination a fixed-size stack/global buffer? Severity is much higher with no stack canary (/GS) and
no DEP/ASLR. Confirm: break before the copy, inspect source length vs destination size.

## Format string — CWE-134
Look for: printf/fprintf/syslog/sprintf where the format argument is a variable, not a literal.
A user-controlled format enables memory read (%x/%s) and write (%n). Trace the format argument to
its origin.

## Integer overflow/underflow — CWE-190 / CWE-680
Look for: allocation sizes computed by multiplication/addition (malloc(n*size), HeapAlloc with a
computed length), length subtractions on unsigned values. An overflow yields an undersized buffer
followed by an out-of-bounds write. Trace the arithmetic feeding the allocation/copy length.

## Path traversal / arbitrary file — CWE-22
Look for: fopen/CreateFile/open with a path built from untrusted input without canonicalization or
"../" filtering. Trace the filename argument; check for sanitization.

## Untrusted search path / DLL side-loading — CWE-426 / CWE-427
Look for: LoadLibrary with a non-absolute name, CreateProcess with a relative application name,
SetDllDirectory/AddDllDirectory misuse, missing SafeDllSearchMode. The attacker plants a malicious
DLL/EXE earlier in the search order. Confirm with the debugger which path is actually resolved.

## Weak cryptography — CWE-327 / CWE-328 / CWE-326
Look for: MD5/SHA1 for security, DES/3DES/RC4/RC2/Blowfish, ECB mode, small keys, insecure RNG
(rand/srand for keys/nonces -> CWE-338). Confirm the algorithm is used for a security purpose, not a
mere checksum.

## Hardcoded secrets — CWE-798 / CWE-321
Look for: embedded private keys, API/cloud tokens, passwords, connection strings, hardcoded crypto
keys/IVs. Presence is itself the issue; never expose the full secret in a report (redact).

## Mitigation-aware severity
- No DEP/NX: shellcode in stack/heap becomes viable.
- No ASLR/PIE: fixed addresses simplify ROP/ret2libc.
- No stack canary/GS: classic stack overflows are not detected at runtime.
- No CFG/SafeSEH: indirect-call / SEH-overwrite control-flow hijacks are easier.
A memory-corruption bug in a binary with none of these is typically high/critical; the same bug with
all of them enabled may be only a denial-of-service.

## Recommended external references (user-provided, not bundled)
The Art of Software Security Assessment; Practical Binary Analysis; A Bug Hunter's Diary;
Hacking: The Art of Exploitation; The Shellcoder's Handbook; Windows internals references; and
fuzzing literature. Place them as PDFs in this folder to enrich the methodology search.
