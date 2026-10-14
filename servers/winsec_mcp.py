"""MCP server for Windows deployment-misconfiguration auditing around an executable.

This is the highest-yield category on a VA of a Windows application, and it is invisible to
static binary analysis: the bug is not in the code, it is in how the code is installed. Writable
install directory, unquoted service path, weak service DACL, missing signature, DLL search-order
hijacking. All deterministic, all fast, all trivially understood by the client reading the report.

Requires Windows for the ACL/service checks (icacls, sc, PowerShell). The static DLL-hijack and
signature checks work anywhere.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from typing import Any, Dict, List

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("winsec")
CAP = 12000
IS_WIN = sys.platform.startswith("win")

# Principals that should never hold write access to a privileged binary or its directory.
UNTRUSTED = [
    "Everyone", "BUILTIN\\Users", "Users", "NT AUTHORITY\\Authenticated Users",
    "Authenticated Users", "BUILTIN\\Guests", "Guests", "NT AUTHORITY\\INTERACTIVE",
    "INTERACTIVE", "Authenticated users",
    # Localised names of Everyone and Users as icacls prints them on an Italian Windows install.
    # Input the tool must recognise, not text it emits.
    "Tutti", "Utenti",
]
# icacls permission tokens that grant write or control.
DANGEROUS_RIGHTS = ["(F)", "(M)", "(W)", "(WD)", "(AD)", "(WDAC)", "(WO)", "(DC)", "(DE)"]

# DLLs resolved from KnownDLLs: never hijackable via search order.
KNOWN_DLLS = {
    "ntdll.dll", "kernel32.dll", "kernelbase.dll", "advapi32.dll", "user32.dll", "gdi32.dll",
    "ole32.dll", "oleaut32.dll", "rpcrt4.dll", "shell32.dll", "shlwapi.dll", "msvcrt.dll",
    "combase.dll", "sechost.dll", "ws2_32.dll", "imm32.dll", "setupapi.dll", "difxapi.dll",
    "clbcatq.dll", "comdlg32.dll", "coml2.dll", "gdiplus.dll", "imagehlp.dll",
    "normaliz.dll", "nsi.dll", "psapi.dll", "wldap32.dll", "wintrust.dll", "crypt32.dll",
    "msasn1.dll", "bcrypt.dll", "ncrypt.dll", "profapi.dll", "powrprof.dll", "cfgmgr32.dll",
}


def _cap(s: str) -> str:
    return s[:CAP] + "\n…(truncated)" if len(s) > CAP else s


def _need_windows(what: str) -> str:
    return (f"{what} requires Windows (current platform: {sys.platform}). "
            "Run this MCP server on the test machine.")


def _run(cmd: List[str], timeout: int = 60) -> Dict[str, Any]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           errors="replace")
        return {"ok": True, "out": p.stdout or "", "err": p.stderr or "", "rc": p.returncode}
    except FileNotFoundError:
        return {"ok": False, "err": f"executable not found: {cmd[0]}"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "err": f"timeout after {timeout}s"}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "err": str(e)}


def _powershell(script: str, timeout: int = 90) -> Dict[str, Any]:
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if not exe:
        return {"ok": False, "err": "PowerShell not found"}
    return _run([exe, "-NoProfile", "-NonInteractive", "-Command", script], timeout)


def _parse_icacls(output: str, target: str = "") -> List[Dict[str, str]]:
    """icacls prints `PATH PRINCIPAL:(FLAGS)(RIGHTS)` on the first line, then indented
    continuation lines holding only `PRINCIPAL:(RIGHTS)`.

    The path is stripped by matching the known target rather than by regex: both Windows paths
    and principals may contain spaces and backslashes (`C:\\Program Files\\x.exe`,
    `NT AUTHORITY\\SYSTEM`), so no positional heuristic is reliable.
    """
    entries = []
    # `[^:]+` would stop at the drive-letter colon, so normalise the path away first.
    prefixes = []
    if target:
        t = target.rstrip("\\/")
        prefixes = [t, t + "\\", os.path.abspath(t)]
    for line in output.splitlines():
        raw = line.strip()
        if not raw or raw.lower().startswith("successfully") or "processed file" in raw.lower():
            continue
        for p in prefixes:
            if p and raw.startswith(p):
                raw = raw[len(p):].strip()
                break
        m = re.search(r"(.+?):(\([^)]*\)(?:\([^)]*\))*)\s*$", raw)
        if not m:
            continue
        principal = m.group(1).strip()
        # Residual drive-letter path (target not matched, e.g. icacls echoed a different case).
        principal = re.sub(r'^[A-Za-z]:[\\/].*?\s+(?=\S+\\|\S+$)', "", principal).strip()
        if not principal:
            continue
        entries.append({"principal": principal, "rights": m.group(2)})
    return entries


def _is_untrusted(principal: str) -> bool:
    p = principal.strip().upper()
    return any(p == u.upper() or p.endswith("\\" + u.upper().split("\\")[-1])
               for u in UNTRUSTED)


def _has_write(rights: str) -> List[str]:
    return [r for r in DANGEROUS_RIGHTS if r in rights.upper()]


def _audit_acl(target: str) -> Dict[str, Any]:
    r = _run(["icacls", target])
    if not r.get("ok"):
        return {"error": r.get("err")}
    findings = []
    for e in _parse_icacls(r["out"], target):
        if _is_untrusted(e["principal"]):
            bad = _has_write(e["rights"])
            if bad:
                findings.append({"principal": e["principal"], "rights": e["rights"],
                                 "granted": bad})
    return {"path": target, "raw": r["out"].strip(), "weak_aces": findings}


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
@mcp.tool()
def acl_audit(path: str) -> str:
    """Check the DACL of a file or directory for write access granted to untrusted principals
    (Users, Everyone, Authenticated Users). If a low-privileged user can overwrite a binary that
    runs elevated — or any file in its directory — that is a direct privilege escalation,
    typically CWE-732."""
    if not IS_WIN:
        return _need_windows("acl_audit")
    if not os.path.exists(path):
        return f"path not found: {path}"
    res = _audit_acl(path)
    if "error" in res:
        return f"icacls error: {res['error']}"
    lines = [f"# ACL: {path}"]
    if res["weak_aces"]:
        lines.append("\n🔴 **WEAK PERMISSIONS** — CWE-732 (Incorrect Permission Assignment)")
        for f in res["weak_aces"]:
            lines.append(f"  - `{f['principal']}` has {', '.join(f['granted'])} → {f['rights']}")
        lines.append("\nImpact: if the target runs with higher privileges than whoever holds "
                     "these permissions, it is a direct privilege escalation.")
    else:
        lines.append("\n✅ No untrusted principal has write permission.")
    lines.append(f"\n<details>Full ACL\n{res['raw']}\n</details>")
    return _cap("\n".join(lines))


@mcp.tool()
def install_dir_audit(directory: str, max_items: int = 400) -> str:
    """Walk an installation directory and report every file and subdirectory whose ACL grants write
    access to untrusted principals. This is the check that finds 'any user can replace the EXE that
    the service runs as SYSTEM'. Run it against the whole install root, not just the main binary."""
    if not IS_WIN:
        return _need_windows("install_dir_audit")
    if not os.path.isdir(directory):
        return f"directory not found: {directory}"

    weak: List[Dict[str, Any]] = []
    checked = 0
    for root, dirs, files in os.walk(directory):
        for name in list(dirs) + files:
            if checked >= max_items:
                break
            target = os.path.join(root, name)
            checked += 1
            res = _audit_acl(target)
            if res.get("weak_aces"):
                weak.append({"path": target, "aces": res["weak_aces"],
                             "executable": name.lower().endswith((".exe", ".dll", ".sys",
                                                                  ".ocx", ".cpl", ".scr"))})
        if checked >= max_items:
            break

    lines = [f"# Install directory audit: {directory}",
             f"objects analysed: {checked}"]
    if not weak:
        lines.append("\n✅ No object is writable by untrusted principals.")
        return "\n".join(lines)

    execs = [w for w in weak if w["executable"]]
    others = [w for w in weak if not w["executable"]]
    lines.append(f"\n🔴 {len(weak)} objects with weak permissions "
                 f"({len(execs)} executables/libraries)")
    if execs:
        lines.append("\n## Overwritable executables and libraries — top priority")
        lines.append("_Replaceable by an unprivileged user: if the binary runs "
                     "with higher privileges, that is an immediate privilege escalation (CWE-732)._")
        for w in execs[:60]:
            who = ", ".join(f"{a['principal']}{''.join(a['granted'])}" for a in w["aces"])
            lines.append(f"  - `{w['path']}`  ←  {who}")
    if others:
        lines.append(f"\n## Other writable objects ({len(others)})")
        for w in others[:60]:
            who = ", ".join(a["principal"] for a in w["aces"])
            lines.append(f"  - `{w['path']}`  ←  {who}")
        lines.append("\nNon-executable files count too: config, .ini, .json read by an "
                     "elevated process are untrusted input.")
    return _cap("\n".join(lines))


@mcp.tool()
def service_audit(service_name: str = "") -> str:
    """Audit Windows services for the classic privesc primitives: unquoted service path with spaces
    (CWE-428), binary or binary directory writable by untrusted users, and a service DACL that lets
    non-admins reconfigure the service. Empty service_name audits every service, which is slower
    but is how you find the ones belonging to your target."""
    if not IS_WIN:
        return _need_windows("service_audit")

    ps = r"""
    $svcs = Get-CimInstance Win32_Service | Select-Object Name,DisplayName,PathName,StartMode,StartName,State
    $svcs | ForEach-Object {
        "{0}|{1}|{2}|{3}|{4}" -f $_.Name,$_.PathName,$_.StartMode,$_.StartName,$_.State
    }
    """
    r = _powershell(ps)
    if not r.get("ok"):
        return f"PowerShell error: {r.get('err')}"

    rows = []
    for line in r["out"].splitlines():
        parts = line.strip().split("|")
        if len(parts) >= 5 and parts[0]:
            rows.append({"name": parts[0], "path": parts[1], "start": parts[2],
                         "account": parts[3], "state": parts[4]})
    if service_name:
        rows = [x for x in rows if service_name.lower() in x["name"].lower()
                or service_name.lower() in (x["path"] or "").lower()]
        if not rows:
            return f"no service matches '{service_name}'"

    findings = []
    for svc in rows:
        path = (svc["path"] or "").strip()
        if not path:
            continue
        privileged = (svc["account"] or "").lower() in (
            "localsystem", "nt authority\\system", "nt authority\\localservice",
            "nt authority\\networkservice", ".\\localsystem")

        # Unquoted path containing spaces, only if it is not already quoted.
        exe = path
        if not path.startswith('"'):
            m = re.match(r"^(.*?\.exe)(\s|$)", path, re.I)
            if m:
                exe = m.group(1)
                if " " in exe:
                    findings.append({
                        "service": svc["name"], "type": "unquoted_path",
                        "cwe": "CWE-428 (Unquoted Search Path)",
                        "detail": path, "privileged": privileged,
                    })
        else:
            m = re.match(r'^"([^"]+)"', path)
            exe = m.group(1) if m else path

        exe = os.path.expandvars(exe.strip().strip('"'))
        if os.path.isfile(exe):
            acl = _audit_acl(exe)
            if acl.get("weak_aces"):
                findings.append({"service": svc["name"], "type": "writable_binary",
                                 "cwe": "CWE-732", "detail": exe,
                                 "aces": acl["weak_aces"], "privileged": privileged})
            d = os.path.dirname(exe)
            dacl = _audit_acl(d)
            if dacl.get("weak_aces"):
                findings.append({"service": svc["name"], "type": "writable_dir",
                                 "cwe": "CWE-732", "detail": d,
                                 "aces": dacl["weak_aces"], "privileged": privileged})

        sd = _run(["sc", "sdshow", svc["name"]], timeout=20)
        if sd.get("ok") and sd["out"]:
            sddl = sd["out"].strip()
            # WD = Everyone, BU = Users, AU = Authenticated Users with write/control rights.
            for sid, label in (("WD", "Everyone"), ("BU", "Users"), ("AU", "Authenticated Users")):
                for ace in re.findall(r"\(A;[^)]*;([^;]*);[^;]*;[^;]*;" + sid + r"\)", sddl):
                    if any(r in ace for r in ("WP", "DT", "WD", "WO", "SD", "CC", "GA", "GW")):
                        findings.append({"service": svc["name"], "type": "weak_service_dacl",
                                         "cwe": "CWE-732", "detail": f"{label}: {ace}",
                                         "sddl": sddl, "privileged": privileged})

    lines = [f"# Service audit ({len(rows)} analysed)"]
    if not findings:
        lines.append("\n✅ No misconfiguration detected.")
        return "\n".join(lines)

    crit = [f for f in findings if f.get("privileged")]
    lines.append(f"\n🔴 {len(findings)} problems ({len(crit)} on privileged services)")
    for f in findings:
        flag = " **[SYSTEM/privilegiato]**" if f.get("privileged") else ""
        lines.append(f"\n## {f['service']} — {f['type']}{flag}\n{f['cwe']}\n  `{f['detail']}`")
        if f["type"] == "unquoted_path":
            lines.append("  If there is a writable directory along the path, Windows tries to "
                         "run `C:\\Program.exe` before the real binary.")
        for a in f.get("aces", []):
            lines.append(f"  - {a['principal']} → {', '.join(a['granted'])}")
    return _cap("\n".join(lines))


@mcp.tool()
def dll_hijack_candidates(path: str) -> str:
    """Static DLL search-order hijacking analysis of a PE. Lists imported and delay-loaded DLLs that
    are NOT in KnownDLLs and NOT present in System32, meaning the loader will search the application
    directory first — where an attacker may be able to plant a DLL (CWE-427).

    Cross-check the result with Procmon (`procmon_dll_hijack_candidates`) for the runtime view,
    and with `acl_audit` on the application directory to confirm exploitability."""
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

    imports: List[Dict[str, str]] = []
    for attr, kind in (("DIRECTORY_ENTRY_IMPORT", "import"),
                       ("DIRECTORY_ENTRY_DELAY_IMPORT", "delay-import")):
        for entry in getattr(pe, attr, []) or []:
            dll = (entry.dll or b"").decode("utf-8", "ignore")
            if dll:
                imports.append({"dll": dll, "kind": kind})

    app_dir = os.path.dirname(os.path.abspath(path))
    sys32 = os.environ.get("SystemRoot", r"C:\Windows") + r"\System32"

    rows = []
    for imp in imports:
        low = imp["dll"].lower()
        in_known = low in KNOWN_DLLS
        in_sys32 = os.path.isfile(os.path.join(sys32, imp["dll"])) if IS_WIN else None
        in_appdir = os.path.isfile(os.path.join(app_dir, imp["dll"]))
        if in_known:
            verdict, risk = "protected by KnownDLLs", 0
        elif in_appdir:
            verdict, risk = "present in the app dir (check the dir's ACL!)", 2
        elif in_sys32 is True:
            verdict, risk = "resolved from System32", 1
        elif in_sys32 is False:
            verdict, risk = "NOT in System32 → searched in the app dir", 3
        else:
            verdict, risk = "unknown (not on Windows)", 1
        if imp["kind"] == "delay-import" and risk >= 1:
            risk += 1
            verdict += " + delay-load"
        rows.append({"dll": imp["dll"], "kind": imp["kind"], "verdict": verdict, "risk": risk})

    rows.sort(key=lambda r: -r["risk"])
    high = [r for r in rows if r["risk"] >= 2]

    lines = [f"# DLL hijacking candidates: {os.path.basename(path)}",
             f"app dir: `{app_dir}`", f"{len(rows)} imported DLLs"]
    if not IS_WIN:
        lines.append("\n⚠ Not on Windows: presence in System32 cannot be checked, "
                     "so the verdict is partial.")
    if high:
        lines.append(f"\n🔴 {len(high)} candidates (CWE-427 Uncontrolled Search Path)")
        for r in high:
            lines.append(f"  - **{r['dll']}** [{r['kind']}] — {r['verdict']}")
        lines.append("\n⚠ A candidate is exploitable ONLY if the search directory is writable. "
                     f"Confirm with: `acl_audit('{app_dir}')`. Without that confirmation it is a "
                     "false positive and must not be reported.")
    else:
        lines.append("\n✅ No obvious candidate: every DLL is a KnownDLL or lives in System32.")

    low_rows = [r for r in rows if r["risk"] < 2]
    if low_rows:
        lines.append(f"\n<details>DLL a basso rischio ({len(low_rows)})\n"
                     + "\n".join(f"  {r['dll']} — {r['verdict']}" for r in low_rows)
                     + "\n</details>")
    return _cap("\n".join(lines))


@mcp.tool()
def signature_check(path: str) -> str:
    """Verify the Authenticode signature of a binary: present, valid, trusted chain, timestamped,
    and which certificate signed it. An unsigned or invalidly signed binary means tampering cannot
    be detected, and it weakens every 'replace the binary' finding into a trivially exploitable one."""
    if not os.path.isfile(path):
        return f"file not found: {path}"
    with open(path, "rb") as fh:
        if fh.read(2) != b"MZ":
            return ("Authenticode applies to PE files only (this is not a PE). "
                    "For an ELF check the distribution package signature instead "
                    "(rpm --checksig / dpkg-sig) o eventuali firme detached.")
    if not IS_WIN:
        try:
            import pefile
            pe = pefile.PE(path, fast_load=True)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]])
            sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            if sec.VirtualAddress == 0 or sec.Size == 0:
                return ("🔴 **No embedded Authenticode signature** (CWE-347).\n"
                        "The binary is unsigned: tampering cannot be detected.")
            return (f"Embedded signature present ({sec.Size} bytes).\n"
                    "⚠ Not on Windows: the VALIDITY of the chain cannot be checked here. "
                    "Re-run on Windows for the full verdict.")
        except ImportError:
            return "pefile is not installed and this is not Windows: cannot verify."
        except Exception as e:  # noqa: BLE001
            return f"error: {e}"

    ps = (f"$s = Get-AuthenticodeSignature -LiteralPath '{path}'; "
          "\"$($s.Status)|$($s.StatusMessage)|$($s.SignerCertificate.Subject)|"
          "$($s.SignerCertificate.NotAfter)|$($s.TimeStamperCertificate.Subject)\"")
    r = _powershell(ps)
    if not r.get("ok"):
        return f"PowerShell error: {r.get('err')}"
    parts = (r["out"].strip().splitlines() or [""])[0].split("|")
    status = parts[0] if parts else "Unknown"
    lines = [f"# Signature: {os.path.basename(path)}", f"status: **{status}**"]
    if status == "Valid":
        lines.append("✅ Valid signature and trusted chain.")
    elif status == "NotSigned":
        lines.append("🔴 **Unsigned** — CWE-347 (Improper Verification of Cryptographic "
                     "Signature). No integrity guarantee.")
    else:
        lines.append(f"🔴 Signature problem: {parts[1] if len(parts) > 1 else ''}")
    if len(parts) > 2 and parts[2]:
        lines.append(f"\nsigner: {parts[2]}")
    if len(parts) > 3 and parts[3]:
        lines.append(f"certificate expiry: {parts[3]}")
    if len(parts) > 4:
        lines.append(f"timestamp: {parts[4] or '⚠ missing — the signature expires with the certificate'}")
    return _cap("\n".join(lines))


@mcp.tool()
def full_deployment_audit(exe_path: str, install_dir: str = "", service_name: str = "") -> str:
    """Run the whole deployment-side checklist in one call: signature, ACL of the binary, ACL of the
    install directory, DLL hijack candidates and (if given) the service configuration. This is the
    fastest way to get the local-privesc findings for a report. install_dir defaults to the
    directory containing exe_path."""
    if not os.path.isfile(exe_path):
        return f"file not found: {exe_path}"
    install_dir = install_dir or os.path.dirname(os.path.abspath(exe_path))
    blocks = [f"# Deployment audit: {os.path.basename(exe_path)}\n",
              "## 1. Signature\n" + signature_check(exe_path),
              "\n## 2. DLL hijacking (static)\n" + dll_hijack_candidates(exe_path)]
    if IS_WIN:
        blocks.append("\n## 3. ACL of the binary\n" + acl_audit(exe_path))
        blocks.append("\n## 4. ACL of the install directory\n"
                      + install_dir_audit(install_dir, max_items=250))
        if service_name:
            blocks.append("\n## 5. Service\n" + service_audit(service_name))
    else:
        blocks.append("\n⚠ ACL/service checks skipped: not on Windows.")
    return _cap("\n".join(blocks))


if __name__ == "__main__":
    mcp.run()
