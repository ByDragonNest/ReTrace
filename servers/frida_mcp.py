"""MCP server: Frida-based API tracing.

Complements x64dbg rather than replacing it. x64dbg is for stopping and looking closely at one
call; Frida is for watching hundreds of calls go by with their arguments while the program runs
normally. That is what you need to map "which input reaches which sink" instead of guessing.

Requires frida + frida-tools (`pip install frida frida-tools`).
"""
from __future__ import annotations

import json
import os
import threading
from typing import Any, Dict, List

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("frida")
CAP = 14000

# Preset sink groups. Keyed by the vulnerability class each one evidences.
SINK_PRESETS: Dict[str, List[str]] = {
    "command_exec": ["CreateProcessA", "CreateProcessW", "WinExec", "ShellExecuteA",
                     "ShellExecuteW", "ShellExecuteExW", "system", "_wsystem"],
    "library_load": ["LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW"],
    "file_ops": ["CreateFileA", "CreateFileW", "DeleteFileW", "MoveFileExW", "CopyFileW",
                 "GetTempFileNameW"],
    "registry": ["RegOpenKeyExA", "RegOpenKeyExW", "RegQueryValueExA", "RegQueryValueExW",
                 "RegSetValueExW"],
    "memory_copy": ["strcpy", "strcat", "sprintf", "memcpy", "wcscpy", "lstrcpyW", "lstrcatW"],
    "network": ["connect", "send", "recv", "WSAConnect", "InternetOpenUrlW",
                "WinHttpSendRequest", "HttpSendRequestW"],
    "crypto": ["CryptGenRandom", "BCryptGenRandom", "CryptCreateHash", "CryptEncrypt"],
    "privilege": ["AdjustTokenPrivileges", "ImpersonateLoggedOnUser", "CreateProcessWithLogonW",
                  "SetThreadToken"],
}

# String-typed argument indices per API, so the agent knows what to dereference.
STR_ARGS: Dict[str, Dict[int, str]] = {
    "CreateProcessA": {0: "ansi", 1: "ansi"}, "CreateProcessW": {0: "utf16", 1: "utf16"},
    "WinExec": {0: "ansi"}, "system": {0: "ansi"}, "_wsystem": {0: "utf16"},
    "ShellExecuteA": {2: "ansi", 3: "ansi"}, "ShellExecuteW": {2: "utf16", 3: "utf16"},
    "LoadLibraryA": {0: "ansi"}, "LoadLibraryW": {0: "utf16"},
    "LoadLibraryExA": {0: "ansi"}, "LoadLibraryExW": {0: "utf16"},
    "CreateFileA": {0: "ansi"}, "CreateFileW": {0: "utf16"},
    "DeleteFileW": {0: "utf16"}, "MoveFileExW": {0: "utf16", 1: "utf16"},
    "CopyFileW": {0: "utf16", 1: "utf16"},
    "RegOpenKeyExA": {1: "ansi"}, "RegOpenKeyExW": {1: "utf16"},
    "RegQueryValueExA": {1: "ansi"}, "RegQueryValueExW": {1: "utf16"},
    "RegSetValueExW": {1: "utf16"},
    "strcpy": {0: "ptr", 1: "ansi"}, "strcat": {0: "ptr", 1: "ansi"},
    "sprintf": {0: "ptr", 1: "ansi"}, "wcscpy": {0: "ptr", 1: "utf16"},
    "lstrcpyW": {0: "ptr", 1: "utf16"}, "lstrcatW": {0: "ptr", 1: "utf16"},
    "InternetOpenUrlW": {1: "utf16"}, "HttpSendRequestW": {1: "utf16"},
}

AGENT_JS = r"""
'use strict';
var CFG = %CONFIG%;
var count = 0;

function readArg(ptrVal, kind) {
    if (ptrVal === null || ptrVal.isNull()) return null;
    try {
        if (kind === 'ansi')  return Memory.readCString(ptrVal, 512);
        if (kind === 'utf16') return Memory.readUtf16String(ptrVal, 512);
        return ptrVal.toString();
    } catch (e) { return '<unreadable:' + ptrVal + '>'; }
}

CFG.hooks.forEach(function (h) {
    var addr = null;
    try {
        addr = h.module ? Module.getExportByName(h.module, h.name)
                        : Module.findExportByName(null, h.name);
    } catch (e) { addr = null; }
    if (addr === null) { return; }

    try {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                if (count >= CFG.max_events) return;
                count++;
                var rec = { api: h.name, module: h.module || '?', args: [], tid: this.threadId };
                for (var i = 0; i < CFG.arg_count; i++) {
                    var kind = (h.strargs && h.strargs[String(i)]) || 'ptr';
                    rec.args.push({ i: i, kind: kind, value: readArg(args[i], kind) });
                }
                if (CFG.backtrace) {
                    rec.stack = Thread.backtrace(this.context, Backtracer.FUZZY)
                                      .slice(0, 6)
                                      .map(DebugSymbol.fromAddress)
                                      .map(function (s) { return s.toString(); });
                }
                send(rec);
            }
        });
        send({ _meta: 'hooked', api: h.name });
    } catch (e) {
        send({ _meta: 'hook_failed', api: h.name, error: e.message });
    }
});
send({ _meta: 'ready' });
"""


def _cap(s: str) -> str:
    return s[:CAP] + "\n…(truncated)" if len(s) > CAP else s


def _frida():
    try:
        import frida
        return frida, None
    except ImportError:
        return None, ("frida is not installed. Install it with: pip install frida frida-tools\n"
                      "On Windows you may need to run as administrator to attach to "
                      "elevated processes.")


def _build_hooks(apis: List[str]) -> List[Dict[str, Any]]:
    hooks = []
    for api in apis:
        module = None
        if api in ("system", "_wsystem", "strcpy", "strcat", "sprintf", "memcpy", "wcscpy"):
            module = None  # CRT: let Frida search all modules
        hooks.append({"name": api, "module": module,
                      "strargs": {str(k): v for k, v in STR_ARGS.get(api, {}).items()}})
    return hooks


def _collect(session, script_src: str, duration: int, resume_fn=None) -> Dict[str, Any]:
    events: List[Dict[str, Any]] = []
    meta: List[Dict[str, Any]] = []
    done = threading.Event()

    def on_message(message, data):
        if message.get("type") == "send":
            p = message.get("payload", {})
            if isinstance(p, dict) and "_meta" in p:
                meta.append(p)
                if p["_meta"] == "ready" and resume_fn:
                    try:
                        resume_fn()
                    except Exception:  # noqa: BLE001
                        pass
            else:
                events.append(p)
        elif message.get("type") == "error":
            meta.append({"_meta": "script_error",
                         "error": message.get("description", "?")})

    script = session.create_script(script_src)
    script.on("message", on_message)
    script.load()
    done.wait(timeout=duration)
    try:
        script.unload()
    except Exception:  # noqa: BLE001
        pass
    return {"events": events, "meta": meta}


def _format(result: Dict[str, Any], title: str) -> str:
    events = result["events"]
    meta = result["meta"]
    hooked = [m["api"] for m in meta if m.get("_meta") == "hooked"]
    failed = [m for m in meta if m.get("_meta") == "hook_failed"]
    errors = [m for m in meta if m.get("_meta") == "script_error"]

    lines = [f"# {title}",
             f"hooks installed: {len(hooked)}  |  events captured: {len(events)}"]
    if errors:
        lines.append(f"\n⚠ script errors: {errors[0].get('error', '')[:300]}")
    if not events:
        lines.append("\nNo call intercepted. Possible causes: the APIs were not "
                     "invoked during the observation window, the binary resolves them "
                     "dynamically through GetProcAddress, or it has anti-hooking protection.")
        if failed:
            lines.append(f"failed hooks: {', '.join(m['api'] for m in failed[:15])}")
        return "\n".join(lines)

    by_api: Dict[str, List[dict]] = {}
    for e in events:
        by_api.setdefault(e.get("api", "?"), []).append(e)

    lines.append("")
    for api, evs in sorted(by_api.items(), key=lambda kv: -len(kv[1])):
        lines.append(f"\n## {api} — {len(evs)} chiamate")
        seen = set()
        shown = 0
        for e in evs:
            strs = [a["value"] for a in e.get("args", [])
                    if a.get("kind") in ("ansi", "utf16") and a.get("value")]
            key = "|".join(strs)
            if key in seen:
                continue
            seen.add(key)
            shown += 1
            if shown > 12:
                break
            if strs:
                lines.append(f"  - {'  ||  '.join(str(s)[:160] for s in strs)}")
            else:
                ptrs = ", ".join(str(a.get("value")) for a in e.get("args", [])[:4])
                lines.append(f"  - (no string) args: {ptrs}")
            if e.get("stack"):
                lines.append(f"      called from: {e['stack'][0]}")
        dupes = len(evs) - len(seen)
        if dupes > 0:
            lines.append(f"  _({dupes} calls with identical arguments omitted)_")
    if failed:
        lines.append(f"\n<details>hooks not installed ({len(failed)}): "
                     + ", ".join(m["api"] for m in failed[:20]) + "</details>")
    return _cap("\n".join(lines))


@mcp.tool()
def frida_list_processes(filter_name: str = "") -> str:
    """List running processes visible to Frida, to find the PID to attach to."""
    frida, err = _frida()
    if err:
        return err
    try:
        procs = frida.enumerate_processes()
    except Exception as e:  # noqa: BLE001
        return f"frida: {e}"
    if filter_name:
        procs = [p for p in procs if filter_name.lower() in p.name.lower()]
    if not procs:
        return "No matching process."
    return _cap("\n".join(f"{p.pid:>8}  {p.name}" for p in sorted(procs, key=lambda x: x.name)))


@mcp.tool()
def trace_sinks(target: str, categories: str = "command_exec,library_load,file_ops",
                duration: int = 20, spawn: bool = True, args: str = "",
                backtrace: bool = False, max_events: int = 3000) -> str:
    """Trace the security-relevant APIs a program calls, with their actual string arguments.

    This is the fastest way to see the real command lines, file paths, DLL names and registry keys
    the target uses at runtime — the evidence that turns a suspected sink into a confirmed finding.

    target: an executable path (spawn=true) or a process name/PID (spawn=false).
    categories: comma-separated from command_exec, library_load, file_ops, registry, memory_copy,
                network, crypto, privilege.
    duration: seconds to observe. backtrace: also record the calling stack (slower)."""
    frida, err = _frida()
    if err:
        return err

    cats = [c.strip() for c in categories.split(",") if c.strip()]
    unknown = [c for c in cats if c not in SINK_PRESETS]
    if unknown:
        return (f"unknown categories: {', '.join(unknown)}. "
                f"Valid: {', '.join(sorted(SINK_PRESETS))}")
    apis: List[str] = []
    for c in cats:
        apis.extend(SINK_PRESETS[c])
    apis = sorted(set(apis))

    cfg = {"hooks": _build_hooks(apis), "arg_count": 4,
           "backtrace": bool(backtrace), "max_events": int(max_events)}
    script_src = AGENT_JS.replace("%CONFIG%", json.dumps(cfg))

    try:
        if spawn:
            argv = [target] + ([a for a in args.split() if a] if args else [])
            pid = frida.spawn(argv)
            session = frida.attach(pid)
            result = _collect(session, script_src, duration, resume_fn=lambda: frida.resume(pid))
            try:
                frida.kill(pid)
            except Exception:  # noqa: BLE001
                pass
        else:
            handle = int(target) if target.isdigit() else target
            session = frida.attach(handle)
            result = _collect(session, script_src, duration)
        try:
            session.detach()
        except Exception:  # noqa: BLE001
            pass
    except Exception as e:  # noqa: BLE001
        return (f"frida: {e}\n"
                "If the target is elevated, run this server as administrator. "
                "If the process exits immediately, try spawn=false and attach to a running process.")

    return _format(result, f"Trace sink: {os.path.basename(target)} ({', '.join(cats)})")


@mcp.tool()
def trace_custom_apis(target: str, apis: str, duration: int = 20, spawn: bool = True,
                      args: str = "", arg_count: int = 4, backtrace: bool = True) -> str:
    """Trace an arbitrary comma-separated list of exported functions. Use this after the decompiler
    has pointed you at a specific API, or to hook a function exported by the target itself.

    Arguments are dumped as pointers unless the API is in the known string-argument table; enable
    backtrace to see which of the target's own functions performed the call."""
    frida, err = _frida()
    if err:
        return err
    api_list = [a.strip() for a in apis.split(",") if a.strip()]
    if not api_list:
        return "No API specified."
    cfg = {"hooks": _build_hooks(api_list), "arg_count": max(1, min(int(arg_count), 8)),
           "backtrace": bool(backtrace), "max_events": 3000}
    script_src = AGENT_JS.replace("%CONFIG%", json.dumps(cfg))
    try:
        if spawn:
            argv = [target] + ([a for a in args.split() if a] if args else [])
            pid = frida.spawn(argv)
            session = frida.attach(pid)
            result = _collect(session, script_src, duration, resume_fn=lambda: frida.resume(pid))
            try:
                frida.kill(pid)
            except Exception:  # noqa: BLE001
                pass
        else:
            handle = int(target) if target.isdigit() else target
            session = frida.attach(handle)
            result = _collect(session, script_src, duration)
        try:
            session.detach()
        except Exception:  # noqa: BLE001
            pass
    except Exception as e:  # noqa: BLE001
        return f"frida: {e}"
    return _format(result, f"Trace custom: {', '.join(api_list[:8])}")


@mcp.tool()
def list_sink_presets() -> str:
    """Show the available sink categories and which APIs each one hooks."""
    lines = ["Categories available for trace_sinks:\n"]
    for cat, apis in sorted(SINK_PRESETS.items()):
        lines.append(f"## {cat}\n  {', '.join(apis)}")
    return "\n".join(lines)


if __name__ == "__main__":
    mcp.run()
