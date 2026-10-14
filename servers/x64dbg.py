import sys
import os
import inspect
import json
import time
from typing import Any, Callable, Dict, List, Optional
import requests

from mcp.server.fastmcp import FastMCP

DEFAULT_X64DBG_SERVER = "http://127.0.0.1:8888/"

def _resolve_server_url_from_args_env() -> str:
    env_url = os.getenv("X64DBG_URL")
    if env_url and env_url.startswith("http"):
        return env_url
    if len(sys.argv) > 1 and isinstance(sys.argv[1], str) and sys.argv[1].startswith("http"):
        return sys.argv[1]
    return DEFAULT_X64DBG_SERVER

x64dbg_server_url = _resolve_server_url_from_args_env()
_X64DBG_LAST_STATE: Dict[str, Any] = {}

def set_x64dbg_server_url(url: str) -> None:
    global x64dbg_server_url
    if url and url.startswith("http"):
        x64dbg_server_url = url

mcp = FastMCP("x64dbg-mcp")

# ============================================================================
#  MCP SURFACE NOTE
#  The functions below are intentionally NOT decorated with @mcp.tool(). Past roughly 40 tool
#  definitions an LLM's tool selection degrades noticeably, and this module had 70 — including
#  five that answered the same "is the process alive" question.
#
#  Removing the decorator does NOT remove the function. `_get_mcp_tools_registry()` enumerates
#  globals() by name, so every one of these stays callable from the CLI and from reforge via
#  `_invoke_tool_by_name`. Only the MCP tool list shrinks.
#
#  Unregistered: AssemblerAssemble, AssemblerAssembleMem, CommentGet, CommentSet, FlagGet, FlagSet, GetPatchAt, GetPatchList, GetTebAddress, IsDebugActive, IsDebugging, LabelGet, LabelList, LabelSet, MemoryIsValidPtr, MemoryRemoteAlloc, MemoryRemoteFree, SetPageRights, StackPeek, StackPop, StackPush, StepInWithDisasm, XrefCount, x64dbg_check_consistent_state, x64dbg_current_location, x64dbg_get_debug_status, x64dbg_get_process_info, x64dbg_is_debuggee_alive, x64dbg_last_event, x64dbg_list_threads, x64dbg_process_state
# ============================================================================


def safe_get(endpoint: str, params: dict = None):
    """
    Perform a GET request with optional query parameters.
    Returns parsed JSON if possible, otherwise text content
    """
    if params is None:
        params = {}

    url = f"{x64dbg_server_url}{endpoint}"

    try:
        response = requests.get(url, params=params, timeout=15)
        response.encoding = 'utf-8'
        if response.ok:
            # Try to parse as JSON first
            try:
                return response.json()
            except ValueError:
                return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"

def safe_post(endpoint: str, data: dict | str):
    """
    Perform a POST request with data.
    Returns parsed JSON if possible, otherwise text content
    """
    try:
        url = f"{x64dbg_server_url}{endpoint}"
        if isinstance(data, dict):
            response = requests.post(url, data=data, timeout=5)
        else:
            response = requests.post(url, data=data.encode("utf-8"), timeout=5)
        
        response.encoding = 'utf-8'
        
        if response.ok:
            # Try to parse as JSON first
            try:
                return response.json()
            except ValueError:
                return response.text.strip()
        else:
            return f"Error {response.status_code}: {response.text.strip()}"
    except Exception as e:
        return f"Request failed: {str(e)}"


def _jsonish(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return value
    return value


def _probe_bool(value: Any, *keys: str) -> Optional[bool]:
    """Return True/False only from explicit booleans; timeout/errors/empty output stay None."""
    value = _jsonish(value)
    if isinstance(value, dict):
        raw = " ".join(str(value.get(k, "")) for k in ("error", "text", "raw", "detail")).lower()
        if value.get("timeout") or value.get("is_error") or "timeout" in raw or "request failed" in raw:
            return None
        for key in keys + ("isDebugging", "isdebugging", "isRunning", "isDebugActive", "result", "value"):
            if key in value and isinstance(value[key], bool):
                return value[key]
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if not text or text == "(no output)" or "timeout" in text or "request failed" in text:
            return None
        if text in ("true", "1", "yes"):
            return True
        if text in ("false", "0", "no"):
            return False
        if "true" in text and "false" not in text:
            return True
        if "false" in text and "true" not in text:
            return False
    return None


def _compact_error(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("error") or value.get("detail") or value.get("raw") or value)[:500]
    return str(value)[:500]


def _register_dump_safe() -> Dict[str, Any]:
    result = safe_get("RegisterDump")
    if isinstance(result, dict):
        return result
    parsed = _jsonish(result)
    return parsed if isinstance(parsed, dict) else {"error": _compact_error(result)}


def _thread_list_safe() -> Dict[str, Any]:
    result = safe_get("GetThreadList")
    if isinstance(result, dict):
        return result
    parsed = _jsonish(result)
    return parsed if isinstance(parsed, dict) else {"error": _compact_error(result)}


def _debug_status_raw() -> Dict[str, Any]:
    return {
        "is_debugging_raw": safe_get("Is_Debugging"),
        "is_debug_active_raw": safe_get("IsDebugActive"),
    }


def _classify_process_state(confirm_exit: bool = True) -> Dict[str, Any]:
    """Deterministic process-state classifier.

    Never maps timeout/no-event/empty output to termination. Termination is confirmed only when
    two explicit debugger probes agree that no debuggee is present, or when a future bridge exposes
    a structured exit event.
    """
    evidence: List[str] = []
    raw1 = _debug_status_raw()
    dbg1 = _probe_bool(raw1["is_debugging_raw"], "isDebugging")
    active1 = _probe_bool(raw1["is_debug_active_raw"], "isRunning", "isDebugActive")
    evidence.append(f"is_debugging={dbg1}")
    evidence.append(f"is_debug_active={active1}")

    regs = _register_dump_safe()
    threads = _thread_list_safe()
    pid = None
    if isinstance(threads, dict):
        pid = threads.get("pid") or threads.get("processId") or threads.get("process_id")

    if dbg1 is True:
        state = "running" if active1 is True else "paused"
        verdict = {
            "state": state,
            "is_alive": True,
            "pid": pid,
            "last_event": "debuggee_present",
            "last_event_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "evidence": evidence,
            "confidence": 0.90 if active1 is None else 0.95,
            "raw": {"debug_status": raw1, "registers": regs, "threads": threads},
        }
    elif dbg1 is False and confirm_exit:
        time.sleep(0.15)
        raw2 = _debug_status_raw()
        dbg2 = _probe_bool(raw2["is_debugging_raw"], "isDebugging")
        active2 = _probe_bool(raw2["is_debug_active_raw"], "isRunning", "isDebugActive")
        evidence.extend([f"second_is_debugging={dbg2}", f"second_is_debug_active={active2}"])
        if dbg2 is False and active2 in (False, None):
            verdict = {
                "state": "terminated_confirmed",
                "is_alive": False,
                "pid": pid,
                "last_event": "debugger_reports_no_debuggee",
                "last_event_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "evidence": evidence,
                "confidence": 0.95,
                "raw": {"first": raw1, "second": raw2, "threads": threads},
            }
        else:
            verdict = {
                "state": "unknown",
                "is_alive": None,
                "pid": pid,
                "last_event": "inconsistent_debugger_state",
                "last_event_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "evidence": evidence,
                "confidence": 0.30,
                "raw": {"first": raw1, "second": raw2, "threads": threads},
            }
    elif dbg1 is False:
        verdict = {
            "state": "unknown",
            "is_alive": None,
            "pid": pid,
            "last_event": "single_negative_probe",
            "last_event_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "evidence": evidence,
            "confidence": 0.45,
            "raw": {"debug_status": raw1, "threads": threads},
        }
    else:
        verdict = {
            "state": "unknown",
            "is_alive": None,
            "pid": pid,
            "last_event": "no_conclusive_debugger_event",
            "last_event_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "evidence": evidence + ["timeout/no_event/empty_output_is_not_termination"],
            "confidence": 0.20,
            "raw": {"debug_status": raw1, "registers": regs, "threads": threads},
        }

    global _X64DBG_LAST_STATE
    _X64DBG_LAST_STATE = verdict
    return verdict


def _get_mcp_tools_registry() -> Dict[str, Callable[..., Any]]:
    """
    Build a registry of available MCP-exposed tool callables in this module.
    Heuristic: exported callables starting with an uppercase letter.
    """
    registry: Dict[str, Callable[..., Any]] = {}
    for name, obj in globals().items():
        if not name or not name[0].isupper():
            continue
        if callable(obj):
            try:
                # Validate signature to ensure it's a plain function
                inspect.signature(obj)
                registry[name] = obj
            except (TypeError, ValueError):
                pass
    return registry

def _describe_tool(name: str, func: Callable[..., Any]) -> Dict[str, Any]:
    sig = inspect.signature(func)
    params = []
    for p in sig.parameters.values():
        if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
            # Skip non-JSON friendly params in schema
            continue
        params.append({
            "name": p.name,
            "required": p.default is inspect._empty,
            "type": "string" if p.annotation in (str, inspect._empty) else ("boolean" if p.annotation is bool else ("integer" if p.annotation is int else "string"))
        })
    return {
        "name": name,
        "description": (func.__doc__ or "").strip(),
        "params": params
    }

def _list_tools_description() -> List[Dict[str, Any]]:
    reg = _get_mcp_tools_registry()
    return [_describe_tool(n, f) for n, f in sorted(reg.items(), key=lambda x: x[0].lower())]

def _invoke_tool_by_name(name: str, args: Dict[str, Any]) -> Any:
    reg = _get_mcp_tools_registry()
    if name not in reg:
        return {"error": f"Unknown tool: {name}"}
    func = reg[name]
    try:
        # Prefer keyword invocation; convert all values to strings unless bool/int expected
        sig = inspect.signature(func)
        bound_kwargs: Dict[str, Any] = {}
        for p in sig.parameters.values():
            if p.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD, inspect.Parameter.POSITIONAL_ONLY):
                continue
            if p.name in args:
                value = args[p.name]
                # Simple coercions for common types
                if p.annotation is bool and isinstance(value, str):
                    value = value.lower() in ("1", "true", "yes", "on")
                elif p.annotation is int and isinstance(value, str):
                    try:
                        value = int(value, 0)
                    except Exception:
                        try:
                            value = int(value)
                        except Exception:
                            pass
                bound_kwargs[p.name] = value
        return func(**bound_kwargs)
    except Exception as e:
        return {"error": str(e)}


def _block_to_dict(block: Any) -> Dict[str, Any]:
    try:
        # Newer anthropic SDK objects are Pydantic models
        if hasattr(block, "model_dump") and callable(getattr(block, "model_dump")):
            return block.model_dump()
    except Exception:
        pass
    if isinstance(block, dict):
        return block
    btype = getattr(block, "type", None)
    if btype == "text":
        return {"type": "text", "text": getattr(block, "text", "")}
    if btype == "tool_use":
        return {
            "type": "tool_use",
            "id": getattr(block, "id", None),
            "name": getattr(block, "name", None),
            "input": getattr(block, "input", {}) or {},
        }
    # Fallback generic representation
    return {"type": str(btype or "unknown"), "raw": str(block)}


@mcp.tool()
def ExecCommand(cmd: str, offset: int = 0, limit: int = 100) -> dict:
    """
    Execute a command in x64dbg and return its output

    Ensure that if if the command has arguments, you comma separate the values, but not the command itself I.E. findallmem findallmem 0x140001000,CC,20480 
    
    Parameters for commands that use the Reference View:
        cmd: Command to execute
        offset: Pagination offset for reference view results (default: 0)
        limit: Maximum number of reference view rows to return (default: 100, max: 5000)
    
    Returns:
        Dictionary with:
        - success: Whether the command executed successfully
        - refView: References tab data populated by the command (if any), with:
          - rowCount: Total number of rows in the references view
          - rows: List of rows (paginated), where each row is a list of cell strings
                  (typically [address, disassembly] or [address, disassembly, string_address, string])
    """
    return safe_get("ExecCommand", {"cmd": cmd, "offset": offset, "limit": limit})


def IsDebugActive() -> bool:
    """
    Check if debugger is active (running)

    Returns:
        True if running, False otherwise
    """
    result = safe_get("IsDebugActive")
    if isinstance(result, dict) and "isRunning" in result:
        return result["isRunning"] is True
    if isinstance(result, str):
        try:
            import json
            parsed = json.loads(result)
            return parsed.get("isRunning", False) is True
        except Exception:
            return False
    return False

def IsDebugging() -> bool:
    """
    Check if x64dbg is debugging a process

    Returns:
        True if debugging, False otherwise
    """
    result = safe_get("Is_Debugging")
    if isinstance(result, dict) and "isDebugging" in result:
        return result["isDebugging"] is True
    if isinstance(result, str):
        try:
            import json
            parsed = json.loads(result)
            return parsed.get("isDebugging", False) is True
        except Exception:
            return False
    return False


def x64dbg_process_state(confirm_exit: bool = True) -> dict:
    """
    Return structured debuggee state. This is the authoritative tool to call before saying a
    process terminated. timeout/no_event/empty output returns state=unknown, never terminated.

    Returns:
      {
        state: running|paused|unknown|terminated_confirmed,
        is_alive: true|false|null,
        pid: optional pid,
        last_event, last_event_time, evidence[], confidence, raw
      }
    """
    return _classify_process_state(confirm_exit=confirm_exit)


def x64dbg_is_debuggee_alive() -> dict:
    """Boolean-oriented liveness check backed by x64dbg_process_state."""
    state = _classify_process_state(confirm_exit=True)
    return {
        "is_alive": state.get("is_alive"),
        "state": state.get("state"),
        "confidence": state.get("confidence"),
        "evidence": state.get("evidence", []),
        "note": "unknown means ambiguous; do not report the process as terminated.",
    }


def x64dbg_get_debug_status() -> dict:
    """Raw but structured debugger status probes."""
    raw = _debug_status_raw()
    return {
        "is_debugging": _probe_bool(raw["is_debugging_raw"], "isDebugging"),
        "is_debug_active": _probe_bool(raw["is_debug_active_raw"], "isRunning", "isDebugActive"),
        "raw": raw,
    }


def x64dbg_get_process_info() -> dict:
    """Best-effort process/module/thread info without inferring termination from failures."""
    modules = GetModuleList()
    threads = _thread_list_safe()
    state = _classify_process_state(confirm_exit=False)
    return {"state": state, "modules": modules, "threads": threads}


def x64dbg_last_event() -> dict:
    """Return the last structured state/event observed by x64dbg_process_state."""
    if not _X64DBG_LAST_STATE:
        return {"state": "unknown", "last_event": "no_state_probe_yet",
                "note": "Call x64dbg_process_state first."}
    return _X64DBG_LAST_STATE


def x64dbg_list_threads() -> dict:
    """Return thread list plus current process-state verdict."""
    return {"state": _classify_process_state(confirm_exit=False), "threads": _thread_list_safe()}


def x64dbg_current_location() -> dict:
    """Return current instruction pointer and nearby disassembly when the debuggee is paused."""
    state = _classify_process_state(confirm_exit=False)
    regs = _register_dump_safe()
    cip = regs.get("cip") or regs.get("rip") or regs.get("eip")
    out = {"state": state, "cip": cip, "registers": regs}
    if cip:
        try:
            out["instruction"] = DisasmGetInstructionRange(str(cip), 6)
        except Exception as exc:
            out["instruction_error"] = str(exc)
    return out


def x64dbg_check_consistent_state() -> dict:
    """Run two state probes and report whether they agree."""
    first = _classify_process_state(confirm_exit=False)
    time.sleep(0.15)
    second = _classify_process_state(confirm_exit=False)
    consistent = first.get("state") == second.get("state") and first.get("is_alive") == second.get("is_alive")
    return {"consistent": consistent, "first": first, "second": second,
            "safe_to_claim_terminated": consistent and second.get("state") == "terminated_confirmed"}


@mcp.tool()
def x64dbg_wait_for_exit(timeout_seconds: int = 10, poll_interval_ms: int = 500) -> dict:
    """Poll for confirmed process exit. Timeout returns state=timeout, not terminated."""
    deadline = time.time() + max(1, min(int(timeout_seconds or 10), 300))
    interval = max(100, min(int(poll_interval_ms or 500), 5000)) / 1000.0
    last = {}
    while time.time() < deadline:
        last = _classify_process_state(confirm_exit=True)
        if last.get("state") == "terminated_confirmed":
            return last
        time.sleep(interval)
    return {"state": "timeout", "is_alive": last.get("is_alive", None),
            "last_event": "wait_for_exit_timeout",
            "last_event_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "evidence": ["timeout while waiting; timeout is not termination", *(last.get("evidence") or [])],
            "confidence": 0.10, "last_state": last}

@mcp.tool()
def x64dbg_state(include_threads: bool = True, include_modules: bool = False) -> dict:
    """THE single tool for "what is the debuggee doing right now": alive or not, running or paused,
    where it stopped, registers, threads and optionally loaded modules.

    Replaces the ten separate status probes this module used to expose (IsDebugActive, IsDebugging,
    x64dbg_process_state, x64dbg_get_debug_status, x64dbg_is_debuggee_alive, ...), which all
    answered variations of the same question and made tool selection unreliable. Those functions
    still exist and are callable from the CLI; they are just no longer separate MCP tools.

    Timeouts and empty output are never reported as termination: `state` is only
    'terminated_confirmed' when two independent probes agree."""
    verdict = _classify_process_state(confirm_exit=True)
    out: Dict[str, Any] = {
        "state": verdict.get("state"),
        "is_alive": verdict.get("is_alive"),
        "pid": verdict.get("pid"),
        "confidence": verdict.get("confidence"),
        "evidence": verdict.get("evidence"),
    }
    if verdict.get("state") == "paused":
        regs = _register_dump_safe()
        out["cip"] = regs.get("cip") or regs.get("rip") or regs.get("eip")
        out["registers"] = regs
        try:
            out["disassembly"] = DisasmGetInstructionRange(str(out["cip"]), 5)
        except Exception:  # noqa: BLE001
            pass
        try:
            out["call_stack"] = GetCallStack()
        except Exception:  # noqa: BLE001
            pass
    elif verdict.get("state") == "running":
        out["note"] = ("the process is running: registers and memory cannot be read "
                       "consistently. Use DebugPause() or WaitForBreak() after a breakpoint.")
    if include_threads:
        out["threads"] = _thread_list_safe()
    if include_modules:
        try:
            out["modules"] = GetModuleList()
        except Exception:  # noqa: BLE001
            pass
    return out


@mcp.tool()
def RegisterGet(register: str) -> str:
    """
    Get register value using Script API
    
    Parameters:
        register: Register name (e.g. "eax", "rax", "rip")
    
    Returns:
        Register value in hex format
    """
    return safe_get("Register/Get", {"register": register})

@mcp.tool()
def RegisterSet(register: str, value: str) -> str:
    """
    Set register value using Script API
    
    Parameters:
        register: Register name (e.g. "eax", "rax", "rip")
        value: Value to set (in hex format, e.g. "0x1000")
    
    Returns:
        Status message
    """
    return safe_get("Register/Set", {"register": register, "value": value})


@mcp.tool()
def MemoryRead(addr: str, size: str) -> str:
    """
    Read memory using enhanced Script API
    
    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
        size: Number of bytes to read
    
    Returns:
        Hexadecimal string representing the memory contents
    """
    return safe_get("Memory/Read", {"addr": addr, "size": size})

@mcp.tool()
def MemoryWrite(addr: str, data: str) -> str:
    """
    Write memory using enhanced Script API
    
    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
        data: Hexadecimal string representing the data to write
    
    Returns:
        Status message
    """
    # POST: writes longer than a few hundred bytes exceed the practical URL length limit.
    result = safe_post("Memory/Write", {"addr": addr, "data": data})
    if isinstance(result, str) and result.startswith(("Error 40", "Error 50")):
        # Bridges that only implement the GET route.
        return safe_get("Memory/Write", {"addr": addr, "data": data})
    return result

def MemoryIsValidPtr(addr: str) -> bool:
    """
    Check if memory address is valid
    
    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
    
    Returns:
        True if valid, False otherwise
    """
    result = safe_get("Memory/IsValidPtr", {"addr": addr})
    if isinstance(result, str):
        return result.lower() == "true"
    return False

@mcp.tool()
def MemoryGetProtect(addr: str) -> str:
    """
    Get memory protection flags
    
    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
    
    Returns:
        Protection flags in hex format
    """
    return safe_get("Memory/GetProtect", {"addr": addr})


@mcp.tool()
def DebugRun() -> str:
    """
    Resume execution of the debugged process using Script API
    
    Returns:
        Status message
    """
    return safe_get("Debug/Run")

@mcp.tool()
def DebugPause() -> str:
    """
    Pause execution of the debugged process using Script API
    
    Returns:
        Status message
    """
    return safe_get("Debug/Pause")

@mcp.tool()
def DebugStop() -> str:
    """
    Stop debugging using Script API
    
    Returns:
        Status message
    """
    return safe_get("Debug/Stop")

@mcp.tool()
def DebugStepIn() -> str:
    """
    Step into the next instruction using Script API
    
    Returns:
        Status message
    """
    return safe_get("Debug/StepIn")

@mcp.tool()
def DebugStepOver() -> str:
    """
    Step over the next instruction using Script API
    
    Returns:
        Status message
    """
    return safe_get("Debug/StepOver")

@mcp.tool()
def DebugStepOut() -> str:
    """
    Step out of the current function using Script API
    
    Returns:
        Status message
    """
    return safe_get("Debug/StepOut")

@mcp.tool()
def DebugSetBreakpoint(addr: str) -> str:
    """
    Set breakpoint at address using Script API
    
    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
    
    Returns:
        Status message
    """
    return safe_get("Debug/SetBreakpoint", {"addr": addr})

@mcp.tool()
def DebugDeleteBreakpoint(addr: str) -> str:
    """
    Delete breakpoint at address using Script API
    
    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
    
    Returns:
        Status message
    """
    return safe_get("Debug/DeleteBreakpoint", {"addr": addr})


def AssemblerAssemble(addr: str, instruction: str) -> dict:
    """
    Assemble instruction at address using Script API
    
    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
        instruction: Assembly instruction (e.g. "mov eax, 1")
    
    Returns:
        Dictionary with assembly result
    """
    result = safe_get("Assembler/Assemble", {"addr": addr, "instruction": instruction})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse assembly result", "raw": result}
    return {"error": "Unexpected response format"}

def AssemblerAssembleMem(addr: str, instruction: str) -> str:
    """
    Assemble instruction directly into memory using Script API
    
    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
        instruction: Assembly instruction (e.g. "mov eax, 1")
    
    Returns:
        Status message
    """
    return safe_get("Assembler/AssembleMem", {"addr": addr, "instruction": instruction})


def StackPop() -> str:
    """
    Pop value from stack using Script API
    
    Returns:
        Popped value in hex format
    """
    return safe_get("Stack/Pop")

def StackPush(value: str) -> str:
    """
    Push value to stack using Script API
    
    Parameters:
        value: Value to push (in hex format, e.g. "0x1000")
    
    Returns:
        Previous top value in hex format
    """
    return safe_get("Stack/Push", {"value": value})

def StackPeek(offset: str = "0") -> str:
    """
    Peek at stack value using Script API
    
    Parameters:
        offset: Stack offset (default: "0")
    
    Returns:
        Stack value in hex format
    """
    return safe_get("Stack/Peek", {"offset": offset})


def FlagGet(flag: str) -> bool:
    """
    Get CPU flag value using TitanEngine
    
    Parameters:
        flag: Flag name (ZF, OF, CF, PF, SF, TF, AF, DF, IF)
    
    Returns:
        Flag value (True/False)
    """
    result = safe_get("Flag/Get", {"flag": flag})
    if isinstance(result, bool):
        return result
    if isinstance(result, str):
        return result.lower() == "true"
    return False

def FlagSet(flag: str, value: bool) -> str:
    """
    Set CPU flag value using Script API
    
    Parameters:
        flag: Flag name (ZF, OF, CF, PF, SF, TF, AF, DF, IF)
        value: Flag value (True/False)
    
    Returns:
        Status message
    """
    return safe_get("Flag/Set", {"flag": flag, "value": "true" if value else "false"})


@mcp.tool()
def PatternFindMem(start: str, size: str, pattern: str) -> str:
    """
    Find pattern in memory using Script API
    
    Parameters:
        start: Start address (in hex format, e.g. "0x1000")
        size: Size to search IN DECIMAL
        pattern: Pattern to find (e.g. "48 8B 05 ?? ?? ?? ??")
    
    Returns:
        Found address in hex format or error message
    """
    return safe_get("Pattern/FindMem", {"start": start, "size": size, "pattern": pattern})


@mcp.tool()
def MiscParseExpression(expression: str) -> str:
    """
    Parse expression using Script API (numeric / duint result only NO STRINGS).

    Parameters:
        expression: Expression to parse (e.g. "[rsp+8]" or "cip")

    Returns:
        Parsed value in hex format
    """
    return safe_get("Misc/ParseExpression", {"expression": expression})


@mcp.tool()
def MiscRemoteGetProcAddress(module: str, api: str) -> str:
    """
    Get remote procedure address using Script API
    
    Parameters:
        module: Module name (e.g. "kernel32.dll")
        api: API name (e.g. "GetProcAddress")
    
    Returns:
        Function address in hex format
    """
    return safe_get("Misc/RemoteGetProcAddress", {"module": module, "api": api})


@mcp.tool()
def DisasmGetInstructionRange(addr: str, count: int = 1) -> list:
    """
    Get disassembly of multiple instructions starting at the specified address
    
    Parameters:
        addr: Memory address (in hex format, e.g. "0x1000")
        count: Number of instructions to disassemble (default: 1, max: 100)
    
    Returns:
        List of dictionaries containing instruction details
    """
    result = safe_get("Disasm/GetInstructionRange", {"addr": addr, "count": str(count)})
    if isinstance(result, list):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return [{"error": "Failed to parse disassembly result", "raw": result}]
    return [{"error": "Unexpected response format"}]


def StepInWithDisasm() -> dict:
    """
    Step into the next instruction and return both step result and current instruction disassembly
    
    Returns:
        Dictionary containing step result and current instruction info
    """
    result = safe_get("Disasm/StepInWithDisasm")
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse step result", "raw": result}
    return {"error": "Unexpected response format"}


def _parse_module_list_payload(result: Any) -> Optional[List[Dict[str, Any]]]:
    """Normalize HTTP/MCP payloads into a list of module dicts."""
    if isinstance(result, list):
        return [m for m in result if isinstance(m, dict)]
    if isinstance(result, str):
        try:
            data = json.loads(result)
            return [m for m in data if isinstance(m, dict)] if isinstance(data, list) else None
        except json.JSONDecodeError:
            return None
    if isinstance(result, dict):
        if "raw" in result and isinstance(result["raw"], str):
            try:
                data = json.loads(result["raw"])
                if isinstance(data, list):
                    return [m for m in data if isinstance(m, dict)]
            except json.JSONDecodeError:
                pass
        if "modules" in result and isinstance(result["modules"], list):
            return [m for m in result["modules"] if isinstance(m, dict)]
    return None


@mcp.tool()
def GetModuleList() -> dict:
    """
    Get list of loaded modules.

    Returns:
        Dictionary with count, modules (list of objects), and summary (human-readable lines).
    """
    result = safe_get("GetModuleList")
    modules = _parse_module_list_payload(result)
    if not modules:
        return {
            "error": "Failed to get or parse module list",
            "detail": str(result)[:2000] if result is not None else None,
        }

    lines: List[str] = []
    for m in modules:
        name = m.get("name", "?")
        base = m.get("base", "")
        size = m.get("size", "")
        entry = m.get("entry", "")
        path = m.get("path", "")
        lines.append(f"{name:<40} base={base:<14} size={size:<14} entry={entry}")
        if path:
            lines.append(f"  path: {path}")

    return {
        "count": len(modules),
        "modules": modules,
        "summary": "\n".join(lines),
    }

@mcp.tool()
def QuerySymbols(module: str, offset: int = 0, limit: int = 5000) -> dict:
    """
    Enumerate symbols for a specific module. Use GetModuleList first to discover module names.
    Returns imports, exports, and user-defined function symbols for the given module.
    
    Args:
        module: Module name to query symbols for (e.g. "kernel32.dll", "ntdll.dll"). Required.
        offset: Pagination offset - number of symbols to skip (default: 0)
        limit: Maximum number of symbols to return per page (default: 5000, max: 50000)
    
    Returns:
        Dictionary with:
        - total: Total number of symbols in the module
        - module: The module name queried
        - offset: Current offset
        - limit: Current limit
        - symbols: List of symbol objects with rva, name, manual, type fields
    """
    params = {
        "module": module,
        "offset": str(offset),
        "limit": str(limit),
    }
    
    result = safe_get("SymbolEnum", params)
    
    # Parse JSON response if it's a string
    if isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    
    return result

@mcp.tool()
def GetThreadList() -> dict:
    """
    Get list of all threads in the debugged process with detailed information.
    
    Returns:
        Dictionary with:
        - count: Number of threads
        - currentThread: Index of the currently focused thread
        - threads: List of thread objects with threadNumber, threadId, threadName,
          startAddress, localBase, cip, suspendCount, priority, waitReason,
          lastError, cycles
    """
    result = safe_get("GetThreadList")
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse thread list", "raw": result}
    return {"error": "Unexpected response format"}

def GetTebAddress(tid: str) -> dict:
    """
    Get the Thread Environment Block (TEB) address for a specific thread.
    Use GetThreadList first to discover thread IDs.
    
    Args:
        tid: Thread ID (decimal integer string, e.g. "1234")
    
    Returns:
        Dictionary with tid and tebAddress fields
    """
    result = safe_get("GetTebAddress", {"tid": tid})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse TEB response", "raw": result}
    return {"error": "Unexpected response format"}

@mcp.tool()
def MemoryBase(addr: str) -> dict:
    """
    Find the base address and size of a module containing the given address
    
    Parameters:
        addr: Memory address (in hex format, e.g. "0x7FF12345")
    
    Returns:
        Dictionary containing base_address and size of the module
    """
    try:
        # Make the request to the endpoint
        result = safe_get("MemoryBase", {"addr": addr})
        
        # Handle different response types
        if isinstance(result, dict):
            return result
        elif isinstance(result, str):
            try:
                # Try to parse the string as JSON
                return json.loads(result)
            except:
                # Fall back to string parsing if needed
                if "," in result:
                    parts = result.split(",")
                    return {
                        "base_address": parts[0],
                        "size": parts[1]
                    }
                return {"raw_response": result}
        
        return {"error": "Unexpected response format"}
            
    except Exception as e:
        return {"error": str(e)}
        
def SetPageRights(addr: str, rights: str) -> bool:
    """
    Set memory page protection rights at a given address

    Args:
        addr: Virtual address (hex string, e.g. "0x401000")
        rights: Rights string (e.g. "rwx", "rx", "rw")

    Returns:
        True if successful, False otherwise
    """
    params = {
        "addr": addr,
        "rights": rights
    }

    result = safe_post("Memory/SetPageRights", params)

    if isinstance(result, dict):
        return result.get("success", False) is True

    if isinstance(result, str):
        try:
            import json
            parsed = json.loads(result)
            return parsed.get("success", False) is True
        except Exception:
            return result.strip().lower() in ("ok", "true", "success")

    return False


@mcp.tool()
def StringGetAt(addr: str) -> dict:
    """
    Retrieve the string at a given address in the debugged process.
    Uses x64dbg's internal string detection (same as the disassembly view).
    
    Parameters:
        addr: Memory address (in hex format, e.g. "0x1400010a0")
    
    Returns:
        Dictionary with:
        - address: The queried address
        - found: Whether a string was detected at that address
        - string: The string content (empty if not found)
    """
    result = safe_get("String/GetAt", {"addr": addr})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def XrefGet(addr: str) -> dict:
    """
    Get all cross-references (xrefs) TO the specified address.
    Returns the list of addresses that reference the target address,
    along with the type of each reference (data, jmp, call).
    
    Note: Results depend on x64dbg's analysis database. Run analysis
    first for comprehensive results.
    
    Parameters:
        addr: Target address to find references to (hex format, e.g. "0x1400010a0")
    
    Returns:
        Dictionary with:
        - address: The queried target address
        - refcount: Number of cross-references found
        - references: List of reference objects, each with:
          - addr: Address of the referrer (the instruction that references the target)
          - type: Reference type ("data", "jmp", "call", or "none")
          - string: Optional string context at the referrer address
    """
    result = safe_get("Xref/Get", {"addr": addr})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}

def XrefCount(addr: str) -> dict:
    """
    Get the count of cross-references to the specified address.
    This is a lightweight check that doesn't fetch the full reference list.
    
    Parameters:
        addr: Target address to count references for (hex format, e.g. "0x1400010a0")
    
    Returns:
        Dictionary with:
        - address: The queried address
        - count: Number of cross-references
    """
    result = safe_get("Xref/Count", {"addr": addr})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def GetMemoryMap() -> dict:
    """
    Get the full virtual memory map of the debugged process.
    Returns all memory pages with their base address, size, protection, type, and info.
    
    Returns:
        Dictionary with:
        - count: Number of memory pages
        - pages: List of page objects with base, size, protect (ERW/ER-/-RW/-R-/E--/---),
          type (IMG/MAP/PRV), and info (module name or description)
    """
    result = safe_get("MemoryMap")
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


def MemoryRemoteAlloc(size: str, addr: str = "0") -> dict:
    """
    Allocate memory in the debuggee's address space.
    Useful for code injection, shellcode testing, or creating data buffers.
    
    Parameters:
        size: Size in bytes to allocate (hex format, e.g. "0x1000")
        addr: Preferred base address (hex format, default "0" for any address)
    
    Returns:
        Dictionary with:
        - address: The allocated memory address
        - size: The requested size
    """
    result = safe_get("Memory/RemoteAlloc", {"addr": addr, "size": size})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}

def MemoryRemoteFree(addr: str) -> dict:
    """
    Free memory previously allocated in the debuggee's address space via MemoryRemoteAlloc.
    
    Parameters:
        addr: Address of the memory to free (hex format, e.g. "0x1000")
    
    Returns:
        Dictionary with success status
    """
    result = safe_get("Memory/RemoteFree", {"addr": addr})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def GetBranchDestination(addr: str) -> dict:
    """
    Get the destination address of a branch instruction (jmp, call, jcc, etc.).
    Resolves where the branch at the given address would jump/call to.
    
    Parameters:
        addr: Address of the branch instruction (hex format, e.g. "0x1400010a0")
    
    Returns:
        Dictionary with:
        - address: The queried instruction address
        - destination: The resolved target address
        - resolved: Whether the destination was successfully resolved
    """
    result = safe_get("GetBranchDestination", {"addr": addr})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def GetCallStack() -> dict:
    """
    Get the current call stack of the debugged thread.
    Returns the full stack trace with addresses, return addresses, and comments.
    
    Returns:
        Dictionary with:
        - total: Number of stack frames
        - entries: List of call stack entries, each with:
          - addr: Current address in the frame
          - from: Return address (caller)
          - to: Called address (callee)
          - comment: Auto-generated comment (function name, etc.)
    """
    result = safe_get("GetCallStack")
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def GetBreakpointList(type: str = "all") -> dict:
    """
    Get list of all breakpoints currently set in the debugger.
    
    Parameters:
        type: Breakpoint type filter - "all" (default), "normal", "hardware", "memory", "dll", "exception"
    
    Returns:
        Dictionary with:
        - count: Number of breakpoints
        - breakpoints: List of breakpoint objects with type, addr, enabled, singleshoot,
          active, name, module, hitCount, fastResume, silent, breakCondition, logText, commandText
    """
    result = safe_get("Breakpoint/List", {"type": type})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


def LabelSet(addr: str, text: str) -> dict:
    """
    Set a label at the specified address in x64dbg.
    Labels appear in the disassembly view and are useful for marking important addresses.
    
    Parameters:
        addr: Address to set the label at (hex format, e.g. "0x1400010a0")
        text: Label text (e.g. "main_decrypt_loop")
    
    Returns:
        Dictionary with success status, address, and label text
    """
    result = safe_get("Label/Set", {"addr": addr, "text": text})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}

def LabelGet(addr: str) -> dict:
    """
    Get the label at the specified address.
    
    Parameters:
        addr: Address to query (hex format, e.g. "0x1400010a0")
    
    Returns:
        Dictionary with:
        - address: The queried address
        - found: Whether a label exists at that address
        - label: The label text (empty if not found)
    """
    result = safe_get("Label/Get", {"addr": addr})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}

def LabelList() -> dict:
    """
    Get all labels defined in the current debugging session.
    
    Returns:
        Dictionary with:
        - count: Number of labels
        - labels: List of label objects with module, rva, text, and manual fields
    """
    result = safe_get("Label/List")
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


def CommentSet(addr: str, text: str) -> dict:
    """
    Set a comment at the specified address in x64dbg.
    Comments appear in the disassembly view next to the instruction.
    
    Parameters:
        addr: Address to set the comment at (hex format, e.g. "0x1400010a0")
        text: Comment text
    
    Returns:
        Dictionary with success status and address
    """
    result = safe_get("Comment/Set", {"addr": addr, "text": text})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}

def CommentGet(addr: str) -> dict:
    """
    Get the comment at the specified address.
    
    Parameters:
        addr: Address to query (hex format, e.g. "0x1400010a0")
    
    Returns:
        Dictionary with:
        - address: The queried address
        - found: Whether a comment exists
        - comment: The comment text
    """
    result = safe_get("Comment/Get", {"addr": addr})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def GetRegisterDump() -> dict:
    """
    Get a complete dump of all CPU registers in one call.
    Returns general purpose registers, segment registers, debug registers,
    flags, and last error/status information.
    
    Much more efficient than reading registers individually.
    
    Returns:
        Dictionary with all register values (cax/ccx/cdx/cbx/csp/cbp/csi/cdi,
        r8-r15 on x64, cip, eflags, segment regs, debug regs, flags object,
        lastError, lastStatus)
    """
    result = safe_get("RegisterDump")
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def SetHardwareBreakpoint(addr: str, type: str = "execute") -> dict:
    """
    Set a hardware breakpoint at the specified address.
    Hardware breakpoints use CPU debug registers (limited to 4 simultaneous).
    
    Parameters:
        addr: Address to set the breakpoint at (hex format, e.g. "0x1400010a0")
        type: Breakpoint type - "execute" (default), "access" (read/write), or "write" (write only)
    
    Returns:
        Dictionary with success status and address
    """
    result = safe_get("Debug/SetHardwareBreakpoint", {"addr": addr, "type": type})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}

@mcp.tool()
def DeleteHardwareBreakpoint(addr: str) -> dict:
    """
    Delete a hardware breakpoint at the specified address.
    
    Parameters:
        addr: Address of the hardware breakpoint to delete (hex format)
    
    Returns:
        Dictionary with success status and address
    """
    result = safe_get("Debug/DeleteHardwareBreakpoint", {"addr": addr})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def EnumTcpConnections() -> dict:
    """
    Enumerate all TCP connections of the debugged process.
    Useful for analyzing network activity and identifying which remote endpoints feed
    untrusted input into the process.
    
    Returns:
        Dictionary with:
        - count: Number of connections
        - connections: List of connection objects with remoteAddress, remotePort,
          localAddress, localPort, and state
    """
    result = safe_get("EnumTcpConnections")
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


def GetPatchList() -> dict:
    """
    Enumerate all memory patches applied in the current debugging session.
    Shows original and patched byte values for each patched address.
    
    Returns:
        Dictionary with:
        - count: Number of patches
        - patches: List of patch objects with module, address, oldByte, newByte
    """
    result = safe_get("Patch/List")
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}

def GetPatchAt(addr: str) -> dict:
    """
    Check if a specific address has been patched and get patch details.
    
    Parameters:
        addr: Address to check (hex format, e.g. "0x1400010a0")
    
    Returns:
        Dictionary with:
        - address: The queried address
        - patched: Whether the address is patched
        - module: Module name (if patched)
        - oldByte: Original byte value (if patched)
        - newByte: Patched byte value (if patched)
    """
    result = safe_get("Patch/Get", {"addr": addr})
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}


@mcp.tool()
def EnumHandles() -> dict:
    """
    Enumerate all open handles in the debugged process.
    Returns handle values, types, access rights, names, and type names.
    Useful for analyzing file handles, registry keys, mutexes, events, etc.
    
    Returns:
        Dictionary with:
        - count: Number of handles
        - handles: List of handle objects with handle (hex), typeNumber,
          grantedAccess (hex), name, and typeName
    """
    result = safe_get("EnumHandles")
    if isinstance(result, dict):
        return result
    elif isinstance(result, str):
        try:
            return json.loads(result)
        except:
            return {"error": "Failed to parse response", "raw": result}
    return {"error": "Unexpected response format"}

import argparse

def main_cli():
    parser = argparse.ArgumentParser(description="x64dbg MCP CLI wrapper")

    parser.add_argument("tool", help="Tool/function name (e.g. ExecCommand, RegisterGet, MemoryRead)")
    parser.add_argument("args", nargs="*", help="Arguments for the tool")
    parser.add_argument("--x64dbg-url", dest="x64dbg_url", default=os.getenv("X64DBG_URL"), help="x64dbg HTTP server URL")

    opts = parser.parse_args()

    if opts.x64dbg_url:
        set_x64dbg_server_url(opts.x64dbg_url)

    # Map CLI call → actual MCP tool function
    if opts.tool in globals():
        func = globals()[opts.tool]
        if callable(func):
            try:
                # Try to unpack args dynamically
                result = func(*opts.args)
                print(json.dumps(result, indent=2))
            except TypeError as e:
                print(f"Error calling {opts.tool}: {e}")
        else:
            print(f"{opts.tool} is not callable")
    else:
        print(f"Unknown tool: {opts.tool}")


def claude_cli():
    parser = argparse.ArgumentParser(description="Chat with Claude using x64dbg MCP tools")
    parser.add_argument("prompt", nargs=argparse.REMAINDER, help="Initial user prompt. If empty, read from stdin")
    # NB: verify the current model IDs at https://docs.claude.com/en/docs/about-claude/models
    parser.add_argument("--model", dest="model", default=os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5"), help="Claude model")
    parser.add_argument("--api-key", dest="api_key", default=os.getenv("ANTHROPIC_API_KEY"), help="Anthropic API key")
    parser.add_argument("--system", dest="system", default="You can control x64dbg via MCP tools.", help="System prompt")
    parser.add_argument("--max-steps", dest="max_steps", type=int, default=100, help="Max tool-use iterations")
    parser.add_argument("--x64dbg-url", dest="x64dbg_url", default=os.getenv("X64DBG_URL"), help="x64dbg HTTP server URL")
    parser.add_argument("--no-tools", dest="no_tools", action="store_true", help="Disable tool-use (text-only)")

    opts = parser.parse_args()

    if opts.x64dbg_url:
        set_x64dbg_server_url(opts.x64dbg_url)

    # Resolve prompt
    user_prompt = " ".join(opts.prompt).strip()
    if not user_prompt:
        user_prompt = sys.stdin.read().strip()
    if not user_prompt:
        print("No prompt provided.")
        return

    try:
        import anthropic
    except Exception as e:
        print("Anthropic SDK not installed. Run: pip install anthropic")
        print(str(e))
        return

    if not opts.api_key:
        print("Missing Anthropic API key. Set ANTHROPIC_API_KEY or pass --api-key.")
        return

    client = anthropic.Anthropic(api_key=opts.api_key)

    tools_spec: List[Dict[str, Any]] = []
    if not opts.no_tools:
        tools_spec = [
            {
                "name": "mcp_list_tools",
                "description": "List available MCP tool functions and their parameters.",
                "input_schema": {"type": "object", "properties": {}},
            },
            {
                "name": "mcp_call_tool",
                "description": "Invoke an MCP tool by name with arguments.",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "tool": {"type": "string"},
                        "args": {"type": "object"}
                    },
                    "required": ["tool"],
                },
            },
        ]

    messages: List[Dict[str, Any]] = [
        {"role": "user", "content": user_prompt}
    ]

    step = 0
    while True:
        step += 1
        response = client.messages.create(
            model=opts.model,
            system=opts.system,
            messages=messages,
            tools=tools_spec if not opts.no_tools else None,
            max_tokens=1024,
        )

        # Print any assistant text
        assistant_text_chunks: List[str] = []
        tool_uses: List[Dict[str, Any]] = []
        for block in response.content:
            b = _block_to_dict(block)
            if b.get("type") == "text":
                assistant_text_chunks.append(b.get("text", ""))
            elif b.get("type") == "tool_use":
                tool_uses.append(b)

        if assistant_text_chunks:
            print("\n".join(assistant_text_chunks))

        if not tool_uses or opts.no_tools:
            break

        # Prepare tool results as a new user message
        tool_result_blocks: List[Dict[str, Any]] = []
        for tu in tool_uses:
            name = tu.get("name")
            tu_id = tu.get("id")
            input_obj = tu.get("input", {}) or {}
            result: Any
            if name == "mcp_list_tools":
                result = {"tools": _list_tools_description()}
            elif name == "mcp_call_tool":
                tool_name = input_obj.get("tool")
                args = input_obj.get("args", {}) or {}
                result = _invoke_tool_by_name(tool_name, args)
            else:
                result = {"error": f"Unknown tool: {name}"}

            # Ensure serializable content (string)
            try:
                result_text = json.dumps(result)
            except Exception:
                result_text = str(result)

            tool_result_blocks.append({
                "type": "tool_result",
                "tool_use_id": tu_id,
                "content": result_text,
            })

        # Normalize assistant content to plain dicts
        assistant_blocks = [_block_to_dict(b) for b in response.content]
        messages.append({"role": "assistant", "content": assistant_blocks})
        messages.append({"role": "user", "content": tool_result_blocks})

        if step >= opts.max_steps:
            break


# ============================================================================
#  VULN-RESEARCH HELPERS (added) — encapsulate the painful x64dbg patterns:
#  software breakpoint + run (HW breakpoints can suspend at CRT init),
#  arch-aware argument reading, smart string deref. No StepInWithDisasm.
#  All built on the existing primitives above.
# ============================================================================
def _vr_hexint(v):
    try:
        if isinstance(v, int):
            return v
        s = str(v).strip().strip('"').strip()
        return int(s, 16)
    except Exception:
        try:
            return int(str(v))
        except Exception:
            return None


def _vr_is_x64(dump: dict) -> bool:
    return isinstance(dump, dict) and ("r8" in dump or "r15" in dump)


def _vr_read_bytes(addr: int, size: int) -> Optional[bytes]:
    raw = MemoryRead(hex(addr), str(size))
    if not isinstance(raw, str):
        return None
    h = raw.strip().replace(" ", "").replace("\n", "")
    if h.lower().startswith("0x"):
        h = h[2:]
    if len(h) % 2:
        h = h[:-1]
    try:
        return bytes.fromhex(h)
    except Exception:
        return None


def _vr_read_ptr(addr: int, size: int):
    data = _vr_read_bytes(addr, size)
    if not data or len(data) < size:
        return None
    return int.from_bytes(data[:size], "little")


def _vr_reg(dump: dict, *names):
    """x64dbg bridges expose either arch-neutral names (ccx/cdx/csp) or native ones (rcx/ecx).
    Try every spelling instead of silently returning None."""
    for n in names:
        if n in dump and dump[n] not in (None, ""):
            return dump[n]
    lowered = {str(k).lower(): v for k, v in dump.items()}
    for n in names:
        v = lowered.get(n.lower())
        if v not in (None, ""):
            return v
    return None


_VR_TEXTY = set(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def _vr_printable(s: str, min_len: int = 2) -> bool:
    if not s or len(s) < min_len:
        return False
    return all(ord(c) in _VR_TEXTY for c in s)


def _vr_decode_utf16(data: bytes) -> str:
    out = []
    for i in range(0, len(data) - 1, 2):
        if data[i] == 0 and data[i + 1] == 0:
            break
        try:
            ch = data[i:i + 2].decode("utf-16le")
        except Exception:
            break
        out.append(ch)
    return "".join(out)


def _vr_looks_utf16(data: bytes) -> bool:
    """Wide strings alternate ASCII byte / null byte. Check the first few pairs."""
    pairs = min(6, len(data) // 2)
    if pairs < 2:
        return False
    hits = sum(1 for i in range(pairs) if data[2 * i] != 0 and data[2 * i + 1] == 0)
    return hits >= max(2, pairs - 1)


@mcp.tool()
def ReadStringSmart(addr: str, max_len: int = 256) -> dict:
    """Read a string at an address: try x64dbg's own detection first, then decode raw memory as
    UTF-16LE or ASCII. Handy to read the path/command pointed to by a call argument. addr in hex.

    UTF-16 is attempted BEFORE ASCII when the bytes alternate char/null, because most Windows APIs
    are W variants and a naive ASCII read truncates a wide string to its first character."""
    s = StringGetAt(addr)
    if isinstance(s, dict) and s.get("found") and s.get("string"):
        return {"address": addr, "string": s.get("string", ""), "method": "x64dbg"}

    start = _vr_hexint(addr)
    if start is None:
        return {"address": addr, "string": "", "method": "none", "error": "invalid address"}
    data = _vr_read_bytes(start, max_len)
    if not data:
        return {"address": addr, "string": "", "method": "none"}

    if _vr_looks_utf16(data):
        wide = _vr_decode_utf16(data)
        if _vr_printable(wide):
            return {"address": addr, "string": wide, "method": "utf16",
                    "truncated": len(wide) * 2 >= max_len - 2}

    narrow = data.split(b"\x00")[0].decode("latin-1", "ignore")
    if _vr_printable(narrow):
        return {"address": addr, "string": narrow, "method": "ascii",
                "truncated": len(narrow) >= max_len - 1}

    wide = _vr_decode_utf16(data)
    if _vr_printable(wide):
        return {"address": addr, "string": wide, "method": "utf16"}
    return {"address": addr, "string": "", "method": "none"}


@mcp.tool()
def WaitForBreak(timeout_seconds: int = 30, poll_interval_ms: int = 200) -> dict:
    """Block until the debuggee is actually PAUSED (breakpoint hit), or the timeout expires.

    This is the missing synchronization primitive: Debug/Run returns as soon as the bridge accepts
    the command, so reading registers straight afterwards samples a still-running process and yields
    plausible-looking garbage. Always call this between DebugRun() and any register/memory read."""
    deadline = time.time() + max(1, int(timeout_seconds))
    interval = max(0.05, poll_interval_ms / 1000.0)
    last = {}
    while time.time() < deadline:
        last = _classify_process_state(confirm_exit=False)
        state = last.get("state")
        if state == "paused":
            return {"paused": True, "state": state, "cip": RegisterGet("cip"),
                    "waited_seconds": round(timeout_seconds - (deadline - time.time()), 2)}
        if state == "terminated_confirmed" or last.get("is_alive") is False:
            return {"paused": False, "state": "terminated",
                    "note": "the debuggee exited before the breakpoint was hit"}
        time.sleep(interval)
    return {"paused": False, "state": last.get("state", "unknown"), "timeout": True,
            "note": f"still not paused after {timeout_seconds}s: the breakpoint was probably never "
                    "reached, or the process is waiting on input"}


@mcp.tool()
def ReadCallArguments(count: int = 4, as_strings: bool = True) -> dict:
    """At the CURRENT break (e.g. right after entering a function), read the first `count` call
    arguments per the platform calling convention, optionally dereferencing each as a string.
    x64: rcx, rdx, r8, r9 then stack ([rsp+0x28]+); x86: [esp+4], [esp+8], ...  No stepping needed."""
    dump = GetRegisterDump()
    if not isinstance(dump, dict):
        return {"error": "cannot read registers (process running, or not debugging?)", "raw": dump}
    x64 = _vr_is_x64(dump)
    sp = _vr_hexint(_vr_reg(dump, "csp", "rsp", "esp"))
    if sp is None:
        return {"error": "cannot read stack pointer (is the process paused?)", "raw": dump}
    args = []
    if x64:
        regs = [_vr_reg(dump, "ccx", "rcx"), _vr_reg(dump, "cdx", "rdx"),
                _vr_reg(dump, "r8"), _vr_reg(dump, "r9")]
        for i in range(count):
            args.append(_vr_hexint(regs[i]) if i < 4 else _vr_read_ptr(sp + 0x28 + (i - 4) * 8, 8))
    else:
        for i in range(count):
            args.append(_vr_read_ptr(sp + 4 + i * 4, 4))
    out = []
    for i, v in enumerate(args):
        entry = {"index": i + 1, "value": hex(v) if isinstance(v, int) else None}
        if as_strings and isinstance(v, int) and v:
            st = ReadStringSmart(hex(v))
            if st.get("string"):
                entry["as_string"] = st["string"]
        out.append(entry)
    return {"arch": "x64" if x64 else "x86", "csp": hex(sp), "arguments": out}


@mcp.tool()
def BreakAndInspect(addr: str, arg_count: int = 4, as_strings: bool = True,
                    timeout_seconds: int = 30, keep_breakpoint: bool = False) -> dict:
    """Set a SOFTWARE breakpoint at `addr` (a sink or call site), run until it is ACTUALLY hit, then
    dump the call arguments (see ReadCallArguments). Software BP + run avoids the hardware-breakpoint
    stalls at CRT init. The breakpoint is removed automatically unless keep_breakpoint=true.

    Arguments are only read once the debuggee is confirmed paused, and only if it stopped at `addr`:
    a timeout or a stop somewhere else returns an error instead of garbage register values."""
    target = _vr_hexint(addr)
    if target is None:
        return {"error": f"invalid address: {addr}"}

    set_res = DebugSetBreakpoint(addr)
    try:
        DebugRun()
        wait = WaitForBreak(timeout_seconds=timeout_seconds)
        if not wait.get("paused"):
            return {"breakpoint": addr, "hit": False, "set_result": set_res, **wait}

        cip_raw = RegisterGet("cip")
        cip = _vr_hexint(cip_raw)
        if cip is not None and cip != target:
            return {"breakpoint": addr, "hit": False, "stopped_at": cip_raw,
                    "error": "the debuggee paused somewhere other than the breakpoint "
                             "(another breakpoint, or an exception). Arguments not read.",
                    "hint": "inspect with x64dbg_last_event() / GetCallStack()"}

        res = ReadCallArguments(arg_count, as_strings)
        return {"breakpoint": addr, "hit": True, "stopped_at": cip_raw, **res}
    finally:
        if not keep_breakpoint:
            try:
                DebugDeleteBreakpoint(addr)
            except Exception:  # noqa: BLE001
                pass


@mcp.tool()
def BreakAtApiAndInspect(module: str, api: str, arg_count: int = 4, as_strings: bool = True,
                         timeout_seconds: int = 30, keep_breakpoint: bool = False) -> dict:
    """Resolve an imported API (e.g. module="kernel32.dll", api="CreateProcessA"), set a SOFTWARE
    breakpoint on it, run until it is called, and dump the arguments — e.g. to see the actual
    command line / path passed to CreateProcess / WinExec / ShellExecute. The reliable way to
    confirm a command-injection or untrusted-search-path sink at runtime."""
    addr = MiscRemoteGetProcAddress(module, api)
    a = addr.strip() if isinstance(addr, str) else str(addr)
    if not a or "rror" in a.lower() or "fail" in a.lower():
        return {"error": f"cannot resolve {module}!{api}", "raw": addr}
    res = BreakAndInspect(a, arg_count, as_strings,
                          timeout_seconds=timeout_seconds, keep_breakpoint=keep_breakpoint)
    res["api"] = f"{module}!{api}"
    res["api_address"] = a
    return res



if __name__ == "__main__":
    # Support multiple modes:
    #  - "serve" or "--serve": run MCP server
    #  - "claude" subcommand: run Claude Messages chat loop
    #  - default: tool invocation CLI
    if len(sys.argv) > 1:
        if sys.argv[1] in ("--serve", "serve"):
            mcp.run()
        elif sys.argv[1] == "claude":
            # Shift off the subcommand and re-dispatch
            sys.argv.pop(1)
            claude_cli()
        else:
            main_cli()
    else:
        mcp.run()
