"""MCP host: one dedicated task per server owns its client session for the whole
app lifetime (open + serve + close all in the SAME task, so anyio cancel scopes
are never torn down across tasks). Connections are isolated: a server that is
offline or misbehaving records an error and never blocks startup or the others.

Tools are namespaced "<server>__<tool>".
"""
import asyncio
import sys
import shutil
import os
import logging
import time
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional, Tuple

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from . import config

logger = logging.getLogger("reforge.mcp_host")

NS_SEP = "__"
CONNECT_TIMEOUT = 8  # seconds to wait for a server before marking it offline


_PYTHON_NAMES = {"python", "python3", "py"}


class ServerSpecError(RuntimeError):
    """The catalogue entry cannot be spawned, and the reason is one the operator can act on."""


def resolve_stdio_command(spec: Dict[str, Any]) -> Tuple[str, List[str]]:
    """Turn a catalogue entry's `command`/`args` into something that will actually spawn.

    The catalogue says `"command": "python"` for every bundled server, which is what a Windows
    install has and what a macOS or Linux box usually does not (`python3` only). The child then
    failed with a bare `FileNotFoundError: [Errno 2]` that named neither the command nor the
    fix, and every server showed as unavailable at once.

    * A bare interpreter name that is not on the PATH resolves to **the interpreter running
      ReTrace**. That is the right default anyway: the bundled servers need the same `mcp`
      package ReTrace imports, and `sys.executable` is the one place it is certain to be.
    * Any other bare command that is not on the PATH is refused with its name in the message.
    * A first argument that looks like a script path and does not exist is refused the same
      way - the placeholder `PATH/TO/GhidraMCP/...` in a fresh catalogue reads as itself
      instead of as a crash inside the child.
    """
    command = str(spec.get("command") or "").strip()
    args = [str(a) for a in (spec.get("args") or [])]
    if not command:
        raise ServerSpecError("no `command` in the catalogue entry")
    bare = os.path.basename(command) == command
    if bare and shutil.which(command) is None:
        if command.lower() in _PYTHON_NAMES:
            logger.info("command %r is not on the PATH; using the interpreter running ReTrace (%s)",
                        command, sys.executable)
            command = sys.executable
        else:
            raise ServerSpecError(
                f"command {command!r} is not on the PATH. Give its absolute path in mcp.servers.json.")
    if args and args[0].lower().endswith(".py") and not os.path.isfile(args[0]):
        raise ServerSpecError(
            f"script not found: {args[0]}. Edit the path in mcp.servers.json"
            + (" (it is still the placeholder)." if "PATH/TO" in args[0] else "."))
    return command, args


class ToolInfo:
    def __init__(self, server: str, name: str, description: str, schema: Dict[str, Any],
                 server_meta: Optional[Dict[str, Any]] = None):
        self.server = server
        self.name = name
        self.qualified = f"{server}{NS_SEP}{name}"
        self.description = description or ""
        self.schema = schema or {"type": "object", "properties": {}}
        m = server_meta or {}
        self.tags: List[str] = m.get("tags") or []           # topic tags from mcp.servers.json
        self.risk_class: str = m.get("risk_class") or "safe_read"
        self.cost: str = m.get("cost") or "medium"           # fast | medium | high | slow


class _Connection:
    """A single MCP server connection driven by its own long-lived task."""

    def __init__(self, name: str, spec: Dict[str, Any]):
        self.name = name
        self.spec = spec
        self.tools: Dict[str, ToolInfo] = {}
        self.error: Optional[str] = None
        self._requests: asyncio.Queue = asyncio.Queue()
        self._ready = asyncio.Event()
        self._task: Optional[asyncio.Task] = None

    @asynccontextmanager
    async def _open(self):
        transport = self.spec.get("transport", "stdio")
        if transport == "stdio":
            command, args = resolve_stdio_command(self.spec)
            params = StdioServerParameters(
                command=command, args=args,
                env=self.spec.get("env"), cwd=self.spec.get("cwd"))
            async with stdio_client(params) as (read, write):
                yield read, write
        elif transport in ("streamable-http", "http"):
            from mcp.client.streamable_http import streamablehttp_client
            async with streamablehttp_client(self.spec["url"]) as streams:
                yield streams[0], streams[1]
        elif transport == "sse":
            from mcp.client.sse import sse_client
            async with sse_client(self.spec["url"]) as (read, write):
                yield read, write
        else:
            raise ValueError(f"Unknown transport: {transport}")

    async def _run(self) -> None:
        try:
            async with self._open() as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    listed = await session.list_tools()
                    for t in listed.tools:
                        schema = getattr(t, "inputSchema", None) or {"type": "object", "properties": {}}
                        info = ToolInfo(self.name, t.name, t.description or "", schema,
                                       server_meta=self.spec)
                        self.tools[info.qualified] = info
                    self._ready.set()
                    logger.info("Connected MCP server '%s' (%d tools)", self.name, len(self.tools))
                    while True:
                        req = await self._requests.get()
                        if req is None:                       # shutdown sentinel
                            break
                        fut, tool_name, args = req
                        try:
                            res = await session.call_tool(tool_name, args or {})
                            if not fut.done():
                                fut.set_result(res)
                        except Exception as exc:              # one bad call mustn't kill the session
                            if not fut.done():
                                fut.set_exception(exc)
        except BaseException as exc:  # noqa: BLE001 - includes Cancelled during failed connect
            self.error = "cancelled" if isinstance(exc, asyncio.CancelledError) else f"{type(exc).__name__}: {exc}"
            logger.warning("MCP server '%s' unavailable: %s", self.name, self.error)
        finally:
            self._ready.set()  # always unblock start()

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run())
        try:
            await asyncio.wait_for(self._ready.wait(), CONNECT_TIMEOUT)
        except asyncio.TimeoutError:
            self.error = self.error or f"connect timeout after {CONNECT_TIMEOUT}s"
            self._task.cancel()

    @property
    def connected(self) -> bool:
        return bool(self.tools) and self.error is None

    async def call(self, tool_name: str, args: Dict[str, Any]):
        if not self.connected:
            raise RuntimeError(f"server '{self.name}' not connected")
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        await self._requests.put((fut, tool_name, args))
        return await fut

    async def stop(self) -> None:
        if not self._task:
            return
        await self._requests.put(None)
        try:
            await asyncio.wait_for(asyncio.shield(self._task), timeout=5)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            self._task.cancel()


class MCPHost:
    def __init__(self, servers: Dict[str, Dict[str, Any]]):
        self._servers = servers
        self._conns: Dict[str, _Connection] = {}
        self.tools: Dict[str, ToolInfo] = {}
        self.errors: Dict[str, str] = {}
        self._fail: Dict[str, int] = {}          # consecutive failures per server
        self._open_until: Dict[str, float] = {}  # circuit-breaker: server disabled until ts

    def _record_fail(self, server: str) -> None:
        n = self._fail.get(server, 0) + 1
        self._fail[server] = n
        if n >= getattr(config, "TOOL_BREAKER_THRESHOLD", 4):
            self._open_until[server] = time.monotonic() + getattr(config, "TOOL_BREAKER_COOLDOWN", 60)
            logger.warning("circuit breaker OPEN for server '%s' after %d failures", server, n)

    def health(self) -> Dict[str, Dict[str, Any]]:
        """Per-server reliability view for the status endpoint."""
        now = time.monotonic()
        return {name: {"consecutive_failures": self._fail.get(name, 0),
                       "breaker_open": self._open_until.get(name, 0) > now}
                for name in self._servers}

    async def connect_all(self, enabled: Optional[set] = None) -> None:
        names = [n for n in self._servers if (enabled is None or n in enabled)]
        self._conns = {name: _Connection(name, self._servers[name]) for name in names}
        await asyncio.gather(*(c.start() for c in self._conns.values()), return_exceptions=True)
        for name, conn in self._conns.items():
            self.tools.update(conn.tools)
            if conn.error:
                self.errors[name] = conn.error

    async def connect_one(self, name: str) -> bool:
        """Start a single server at runtime. Returns True if it connected."""
        if name not in self._servers:
            return False
        old = self._conns.get(name)
        if old:
            await old.stop()
            for q in list(self.tools):
                if self.tools[q].server == name:
                    del self.tools[q]
        conn = _Connection(name, self._servers[name])
        self._conns[name] = conn
        self.errors.pop(name, None)
        await conn.start()
        self.tools.update(conn.tools)
        if conn.error:
            self.errors[name] = conn.error
        return conn.connected

    async def disconnect_one(self, name: str) -> None:
        """Stop a single server and drop its tools."""
        conn = self._conns.pop(name, None)
        for q in list(self.tools):
            if self.tools[q].server == name:
                del self.tools[q]
        self.errors.pop(name, None)
        if conn:
            await conn.stop()

    def server_status(self, configured: Dict[str, Dict[str, Any]], enabled: set) -> List[Dict[str, Any]]:
        """Per-server status for the UI: enabled/connected/error + its tools (name+description)."""
        out = []
        for name, spec in configured.items():
            conn = self._conns.get(name)
            tools = [{"name": t.name, "description": (t.description or "").strip().split("\n")[0][:160]}
                     for t in self.tools.values() if t.server == name]
            out.append({"name": name, "enabled": name in enabled,
                        "connected": bool(conn and conn.connected),
                        "error": self.errors.get(name), "transport": spec.get("transport", "stdio"),
                        "comment": spec.get("comment", ""), "tool_count": len(tools), "tools": tools})
        return out

    def catalog(self) -> List[ToolInfo]:
        return list(self.tools.values())

    async def call(self, qualified: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        info = self.tools.get(qualified)
        if not info:
            return {"is_error": True, "text": f"Unknown tool: {qualified}"}
        conn = self._conns.get(info.server)
        if not conn:
            return {"is_error": True, "text": f"Server '{info.server}' not connected"}
        # Circuit breaker: a repeatedly-failing server is short-circuited for a cooldown window.
        if self._open_until.get(info.server, 0) > time.monotonic():
            return {"is_error": True, "breaker": True, "code": "server_breaker_open",
                    "server": info.server,
                    "text": (f"Server '{info.server}' is temporarily disabled after repeated "
                             "failures. It will be retried automatically, or re-enable it from "
                             "the Servers panel.")}
        # Gateway: a manifested server's manifest is an allow-list for its own tools. A server
        # that grows a capability after review does not get to use it silently (ADR 0003, T-4).
        from . import policy as _policy

        allowed, why = _policy.is_allowed(qualified, getattr(info, "risk_class", "") or "")
        if not allowed:
            logger.warning("tool %s refused by the MCP gateway: %s", qualified, why)
            return {"is_error": True, "gateway_refused": True,
                    "text": f"Refused by the MCP gateway: {why}"}

        # Validate the arguments against the tool's declared schema before they reach the server.
        # The server validates too, but to protect itself; this protects the host, and catches a
        # model that invented an argument before that argument reaches a live debugger.
        from . import mcp_manifest as _manifest

        try:
            _manifest.validate_against(getattr(info, "schema", None), arguments or {},
                                       direction="arguments", tool=qualified)
        except _manifest.SchemaViolation as exc:
            logger.warning("tool %s refused: %s", qualified, exc)
            return {"is_error": True, "schema_violation": True, "text": str(exc)}

        spec = self._servers.get(info.server, {})
        timeout = spec.get("timeout") or getattr(config, "TOOL_CALL_TIMEOUT", 120)
        t0 = time.monotonic()
        try:
            result = await asyncio.wait_for(conn.call(info.name, arguments or {}), timeout=timeout)
        except asyncio.TimeoutError:
            self._record_fail(info.server)
            logger.warning("tool %s TIMEOUT after %ss (server=%s)", qualified, timeout, info.server)
            return {"is_error": True, "timeout": True, "code": "tool_timeout",
                    "tool": qualified, "timeout_seconds": timeout,
                    "text": f"Tool '{qualified}' did not respond within {timeout}s."}
        except Exception as exc:  # noqa: BLE001
            self._record_fail(info.server)
            return {"is_error": True, "text": f"Tool call failed: {exc}"}
        self._fail[info.server] = 0               # success resets the breaker
        text = self._flatten(result)

        # Validate the REPLY, not only the call. The arguments came from us; the reply came from
        # the server, and it is the reply that flows on into evidence, into the model's context
        # and into a report. A server that is wrong - or hostile - is wrong here (ADR 0003, T-4).
        _decision = _policy.resolve_risk(qualified, getattr(info, "risk_class", "") or "")
        _out_schema = _decision.get("output_schema")
        if _out_schema:
            import json as _json

            try:
                parsed = _json.loads(text) if text.strip().startswith(("{", "[")) else text
                _manifest.validate_against(_out_schema, parsed,
                                           direction="result", tool=qualified)
            except _manifest.SchemaViolation as exc:
                self._record_fail(info.server)
                logger.warning("tool %s returned a non-conforming result: %s", qualified, exc)
                return {"is_error": True, "schema_violation": True, "code": "bad_tool_result",
                        "text": str(exc)}
            except ValueError:
                pass                          # not JSON; the schema only constrains structured replies

        truncated = False
        # A per-tool ceiling, when the manifest sets one, below the global cap. A tool that should
        # return a verdict has no business returning a megabyte, and the global cap is too loose
        # to notice.
        per_tool = _decision.get("max_output_chars")
        if per_tool and len(text) > int(per_tool):
            text = text[:int(per_tool)] + (
                f"\n…(truncated at this tool's declared {per_tool}-character ceiling; "
                f"{len(text)} total)")
            truncated = True
        cap = getattr(config, "TOOL_OUTPUT_MAX_CHARS", 0)
        if cap and len(text) > cap:
            text = text[:cap] + f"\n…(output truncated to {cap} characters; {len(text)} total)"
            truncated = True
        is_error = bool(getattr(result, "isError", False))
        dur = time.monotonic() - t0
        # The correlation id goes on the tool-call line too: without it, the one log entry that
        # says what a request actually DID cannot be tied back to the request that caused it.
        # This is not distributed tracing - the id does not cross into the server's own logs -
        # but it closes the gap on our side of the boundary.
        _ctx = __import__("reforge.observability", fromlist=["context"]).context()
        logger.info("tool %s server=%s dur=%.2fs status=%s len=%d trunc=%s cid=%s",
                    qualified, info.server, dur, "ERR" if is_error else "ok", len(text),
                    truncated, _ctx.get("correlation_id") or "-")
        # Carry the provenance back with the result so evidence can record WHICH build of which
        # tool produced it. Without this a finding cites a tool name and nothing else, and a
        # customer disputing it cannot be answered (threat T-11).
        decision = _decision
        from . import observability as _obs

        _obs.METRICS.increment(
            "retrace_tool_calls_total", help="MCP tool calls by server and outcome.",
            server=info.server, outcome="error" if is_error else "ok")
        _obs.METRICS.observe("retrace_tool_call_seconds", dur,
                             help="MCP tool call duration in seconds.", server=info.server)
        return {"is_error": is_error, "text": text, "truncated": truncated, "duration": dur,
                "tool": qualified, "server": info.server,
                "server_version": decision.get("server_version", ""),
                "risk_class": decision.get("risk_class", ""),
                "risk_source": decision.get("source", "")}

    @staticmethod
    def _flatten(result: Any) -> str:
        parts: List[str] = []
        for block in getattr(result, "content", []) or []:
            if getattr(block, "type", None) == "text":
                parts.append(block.text)
            else:
                parts.append(str(getattr(block, "text", block)))
        return "\n".join(parts) if parts else "(no output)"

    async def aclose(self) -> None:
        await asyncio.gather(*(c.stop() for c in self._conns.values()), return_exceptions=True)
