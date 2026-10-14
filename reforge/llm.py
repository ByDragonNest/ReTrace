"""Provider-agnostic LLM layer.

The agent keeps a NEUTRAL message history and never touches a vendor SDK directly.
Two backends implement the same interface:
  - AnthropicLLM: cloud Messages API, token-streamed.
  - LocalLLM:     any OpenAI-compatible endpoint (Ollama / LM Studio / llama.cpp).

Neutral history items:
  {"role": "user", "content": str}
  {"role": "assistant", "text": str, "tool_calls": [{"id","name","input"}]}
  {"role": "tool", "results": [{"id","content","is_error"}]}
"""
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from . import config

OnDelta = Callable[[str], Awaitable[None]]

_FENCE = re.compile(r"```[A-Za-z0-9_+-]*\s*(.*?)```", re.S)
_TOOLCALL_TAG = re.compile(r"<tool_call>\s*(.*?)\s*</tool_call>", re.S)


def _iter_json_objects(text: str):
    """Yield top-level {...} substrings that parse as JSON (brace-matched)."""
    depth = start = 0
    in_str = esc = False
    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                chunk = text[start:i + 1]
                try:
                    yield json.loads(chunk)
                except json.JSONDecodeError:
                    pass


def _first_json_object(text: str) -> Dict[str, Any]:
    """Best-effort: return the first top-level JSON object found in `text` (dict), else {}.

    Tolerant to models that wrap JSON in ```json fences or surround it with prose. Tries the whole
    text first, then fenced blocks, then any brace-matched object.
    """
    text = (text or "").strip()
    if not text:
        return {}
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass
    for block in _FENCE.findall(text) + [text]:
        for obj in _iter_json_objects(block):
            if isinstance(obj, dict):
                return obj
    return {}


def _json_calls(text: str) -> List[Dict[str, Any]]:
    candidates = _TOOLCALL_TAG.findall(text) + _FENCE.findall(text)
    if not candidates:
        candidates = [text]
    out = []
    for c in candidates:
        for obj in _iter_json_objects(c):
            fn = obj.get("function") if isinstance(obj.get("function"), dict) else {}
            name = obj.get("name") or obj.get("tool") or fn.get("name")
            if not name or not isinstance(name, str):
                continue
            args = obj.get("arguments", obj.get("parameters", obj.get("input", fn.get("arguments", {}))))
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except json.JSONDecodeError:
                    args = {}
            out.append({"name": name, "args": args if isinstance(args, dict) else {}})
    return out


_NAME = re.compile(r"\b([A-Za-z0-9_]+__[A-Za-z0-9_]+|search_tools|consult_methodology|add_finding)\b")
_FLAG = re.compile(r"--([A-Za-z0-9_]+)(?:[=\s]+(\"[^\"]*\"|'[^']*'|[^\s]+))?")


def _parse_flags(s: str):
    args, n = {}, 0
    for fm in _FLAG.finditer(s):
        n += 1
        v = fm.group(2)
        args[fm.group(1)] = True if v is None else v.strip("\"'")
    return args, n


def _cli_calls(text: str, valid: Optional[set]) -> List[Dict[str, Any]]:
    """Recover pseudo-CLI invocations like `server__tool ghidra__x --name main`.
    Only names in `valid` are accepted; outside code fences a flag is required."""
    found: Dict[tuple, Dict[str, Any]] = {}

    def add(name, args):
        if valid is not None and name not in valid:
            return
        found.setdefault((name, tuple(sorted(args.items()))), {"name": name, "args": args})

    for block in _FENCE.findall(text):                 # inside fences: bare names ok
        for line in block.splitlines():
            for m in _NAME.finditer(line):
                name = m.group(1)
                if valid is not None and name not in valid:
                    continue
                args, _ = _parse_flags(line[m.end():])
                add(name, args)
    for m in _NAME.finditer(text):                     # elsewhere: require >=1 flag
        line = text[m.end():].split("\n", 1)[0]
        args, n = _parse_flags(line)
        if n >= 1:
            add(m.group(1), args)
    return list(found.values())


# Tools a SALVAGED call may never invoke, whatever the text looked like.
#
# Salvage guesses intent from prose. That is acceptable for a read: a misread `list_imports` costs
# one wasted call and corrects itself. It is not acceptable for anything that changes state, and
# least of all for `add_finding` - a finding scraped out of a sentence the model was only
# *discussing* is a fabricated claim with a real title attached to it, which is the one thing this
# product exists not to do (ADR 0002: best-effort parsing "may never produce a finding").
#
# A model that genuinely wants one of these has to emit a real tool call. If it cannot, that is a
# model that should not be recording findings unattended.
_NEVER_SALVAGED = {
    "add_finding", "approve", "deny", "set_workflow", "delete_project",
    "export_query_results", "parse_artifact",
}


def salvageable(name: str) -> bool:
    """Whether a tool may be invoked from a call recovered out of free text."""
    base = (name or "").split("__", 1)[-1].lower()
    if base in _NEVER_SALVAGED or name in _NEVER_SALVAGED:
        return False
    from . import policy
    return policy.risk_class(name) == "safe_read"


def salvage_tool_calls(text: str, valid: Optional[set] = None,
                       *, allow_state_changing: bool = False) -> List[Dict[str, Any]]:
    """Recover tool calls a weak model emitted as TEXT (JSON, <tool_call>, or pseudo-CLI).

    A COMPATIBILITY FALLBACK, not a parsing strategy. It exists because small local models often
    describe a call instead of emitting one, and losing the whole turn over that is worse than
    guessing. It is restricted to read-only tools: see `_NEVER_SALVAGED`.
    """
    out = _json_calls(text)
    if not out:
        out = _cli_calls(text, valid)
    if valid is not None:
        out = [r for r in out if r["name"] in valid]
    if not allow_state_changing:
        dropped = [r["name"] for r in out if not salvageable(r["name"])]
        if dropped:
            logging.getLogger("reforge.llm").info(
                "ignored salvaged call(s) to %s: a state-changing tool must be a real tool call, "
                "not text recovered from the reply", ", ".join(sorted(set(dropped))))
        out = [r for r in out if salvageable(r["name"])]
    return out


@dataclass
class ToolCall:
    id: str
    name: str
    input: Dict[str, Any]


@dataclass
class TurnResult:
    text: str = ""
    tool_calls: List[ToolCall] = field(default_factory=list)
    stop_reason: str = "end"
    usage: Dict[str, Any] = field(default_factory=dict)


class BaseLLM:
    available = True
    #: Whether calling this provider sends data off the host. The egress gate keys on it, so a new
    #: remote provider that forgets to set it would bypass the gate - which is why
    #: `test_every_remote_provider_declares_itself` exists.
    is_remote = False
    provider_name = "none"
    async def run(self, system: str, history: List[Dict], tools: List[Dict],
                  on_delta: OnDelta) -> TurnResult:
        raise NotImplementedError
    async def complete(self, system: str, history: List[Dict], extra_user: str) -> str:
        raise NotImplementedError

    async def complete_json(self, system: str, extra_user: str) -> Dict[str, Any]:
        """Return a parsed JSON object from the model (tolerant; `{}` when nothing parses).

        This is the TRANSPORT. It is tolerant on purpose - it strips fences and surrounding prose -
        and that tolerance is why it must not be called directly for anything that matters: `{}`
        is indistinguishable from "the model answered with an empty object".

        Use `reforge.llm_schema.structured()` instead. It layers schema validation, a bounded
        corrective retry and a hard failure on top of this, so an unusable reply becomes an error
        rather than an empty result that flows on as data.
        """
        text = await self.complete(system, [], extra_user)
        return _first_json_object(text)


# --------------------------------------------------------------------------

def _model_obj_to_dict(obj: Any) -> Dict[str, Any]:
    """Convert SDK usage objects into plain JSON-serializable dicts."""
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return obj
    for meth in ("model_dump", "dict"):
        fn = getattr(obj, meth, None)
        if callable(fn):
            try:
                return dict(fn())
            except Exception:
                pass
    out: Dict[str, Any] = {}
    for key in ("input_tokens", "output_tokens", "cache_creation_input_tokens",
                "cache_read_input_tokens", "server_tool_use"):
        if hasattr(obj, key):
            out[key] = getattr(obj, key)
    return out


def _payload_text(system: str, messages: List[Dict]) -> str:
    """Everything that would be sent, as one string, for classification.

    A request is only as safe as its most sensitive part, so the whole payload is classified
    together rather than per message.
    """
    parts = [str(system or "")]
    for message in messages or []:
        content = message.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    parts.append(str(block.get("text") or block.get("content") or ""))
                else:
                    parts.append(str(block))
    return "\n".join(parts)


def _apply_redaction(system: str, messages: List[Dict]):
    """Redact each part, so what is sent matches what the gate approved."""
    from . import redact as _redact

    out_messages = []
    for message in messages or []:
        content = message.get("content")
        if isinstance(content, str):
            out_messages.append({**message, "content": _redact.redact(content)})
        elif isinstance(content, list):
            blocks = []
            for block in content:
                if isinstance(block, dict) and isinstance(block.get("text"), str):
                    blocks.append({**block, "text": _redact.redact(block["text"])})
                else:
                    blocks.append(block)
            out_messages.append({**message, "content": blocks})
        else:
            out_messages.append(message)
    return _redact.redact(str(system or "")), out_messages


class AnthropicLLM(BaseLLM):
    is_remote = True
    provider_name = "anthropic"

    def __init__(self):
        from anthropic import AsyncAnthropic
        self._c = AsyncAnthropic(api_key=config.ANTHROPIC_API_KEY or None,
                                 timeout=float(getattr(config, 'LLM_TIMEOUT_S', 120)),
                                 max_retries=int(getattr(config, 'LLM_MAX_RETRIES', 2)))
        self._model = config.DEFAULT_MODEL

    def _guard(self, payload: str, purpose: str) -> str:
        """Classify, redact and record before anything leaves the host.

        Here rather than at the call sites: a check at the caller is a check the next caller
        forgets. Everything this provider sends passes through this method or does not go.
        Raises model_gateway.EgressDenied, which the caller surfaces rather than swallows.
        """
        from . import model_gateway

        outbound, _decision = model_gateway.guard(
            payload, provider=self.provider_name, model=self._model,
            purpose=purpose, cfg=config)
        return outbound

    @staticmethod
    def _to_messages(history: List[Dict]) -> List[Dict]:
        out: List[Dict[str, Any]] = []
        for m in history:
            if m["role"] == "user":
                c = m["content"]
                # The API rejects empty text blocks ("text content blocks must be non-empty").
                # A user turn is either a plain string or a list of blocks (tool_result). Only guard
                # the plain-string case; never send an empty/whitespace-only string.
                if isinstance(c, str):
                    if not c.strip():
                        continue
                    out.append({"role": "user", "content": c})
                elif c:
                    out.append({"role": "user", "content": c})
            elif m["role"] == "assistant":
                content = []
                text = (m.get("text") or "").strip()
                if text:
                    content.append({"type": "text", "text": text})
                for tc in m.get("tool_calls", []):
                    content.append({"type": "tool_use", "id": tc["id"],
                                    "name": tc["name"], "input": tc["input"]})
                # An assistant turn with neither text nor tool calls carries no information and would
                # otherwise be sent as an empty text block → drop it entirely.
                if content:
                    out.append({"role": "assistant", "content": content})
            elif m["role"] == "tool":
                out.append({"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": r["id"],
                     "content": r["content"] or "(no output)", "is_error": r["is_error"]}
                    for r in m["results"]]})
        return out

    async def run(self, system, history, tools, on_delta):
        messages = self._to_messages(history)
        # The whole conversation is classified as one payload: a request is only as safe as its
        # most sensitive part, and classifying message-by-message would let a decompilation ride
        # along beside a benign question.
        guarded = self._guard(_payload_text(system, messages), purpose="agent_turn")
        if guarded != _payload_text(system, messages):
            system, messages = _apply_redaction(system, messages)
        async with self._c.messages.stream(
                model=self._model, max_tokens=config.MAX_TOKENS, system=system,
                messages=messages, tools=tools) as stream:
            async for delta in stream.text_stream:
                await on_delta(delta)
            final = await stream.get_final_message()
        text = "".join(b.text for b in final.content if b.type == "text")
        calls = [ToolCall(b.id, b.name, b.input or {}) for b in final.content if b.type == "tool_use"]
        return TurnResult(text, calls, final.stop_reason, _model_obj_to_dict(getattr(final, "usage", None)))

    async def complete(self, system, history, extra_user):
        msgs = self._to_messages(history) + [{"role": "user", "content": (extra_user or "").strip() or "(continue)"}]
        self._guard(_payload_text(system, msgs), purpose="completion")
        system, msgs = _apply_redaction(system, msgs)
        resp = await self._c.messages.create(
            model=self._model, max_tokens=config.MAX_TOKENS, system=system, messages=msgs)
        self.last_usage = _model_obj_to_dict(getattr(resp, "usage", None))
        return "".join(b.text for b in resp.content if b.type == "text")


# --------------------------------------------------------------------------
class LocalLLM(BaseLLM):
    is_remote = False
    provider_name = "local"

    """OpenAI-compatible. Non-streamed (emits the full reply once) for simplicity."""
    def __init__(self):
        from openai import AsyncOpenAI
        self._c = AsyncOpenAI(base_url=config.LOCAL_BASE_URL, api_key=config.LOCAL_API_KEY,
                              timeout=float(getattr(config, 'LOCAL_TIMEOUT_S', 600)),
                              max_retries=int(getattr(config, 'LLM_MAX_RETRIES', 2)))
        self._model = config.LOCAL_MODEL

    def _opts(self) -> Dict[str, Any]:
        kw: Dict[str, Any] = {}
        t = getattr(config, "LOCAL_TEMPERATURE", None)
        if t is not None:
            kw["temperature"] = t
        eb: Dict[str, Any] = {}
        ctx = getattr(config, "LOCAL_NUM_CTX", 0)
        if ctx:
            eb["options"] = {"num_ctx": ctx}
        ka = getattr(config, "LOCAL_KEEP_ALIVE", None)
        if ka:
            eb["keep_alive"] = ka
        if eb:
            kw["extra_body"] = eb
        return kw

    @staticmethod
    def _to_messages(system: str, history: List[Dict]) -> List[Dict]:
        out = [{"role": "system", "content": system}]
        for m in history:
            if m["role"] == "user":
                out.append({"role": "user", "content": m["content"]})
            elif m["role"] == "assistant":
                msg = {"role": "assistant", "content": m.get("text") or ""}
                if m.get("tool_calls"):
                    msg["tool_calls"] = [
                        {"id": tc["id"], "type": "function",
                         "function": {"name": tc["name"], "arguments": json.dumps(tc["input"])}}
                        for tc in m["tool_calls"]]
                out.append(msg)
            elif m["role"] == "tool":
                for r in m["results"]:
                    out.append({"role": "tool", "tool_call_id": r["id"],
                                "content": r["content"] or "(no output)"})
        return out

    @staticmethod
    def _to_tools(tools: List[Dict]) -> List[Dict]:
        return [{"type": "function",
                 "function": {"name": t["name"], "description": t["description"],
                              "parameters": t["input_schema"]}} for t in tools]

    async def run(self, system, history, tools, on_delta):
        # Ollama + small models: streaming with tools is unreliable (tool_calls may arrive only
        # on the final chunk, or not at all when the model writes the call as text). We use
        # stream=False by default for local models so we get the complete message at once and can
        # reliably detect both native tool_calls and text-embedded calls.
        use_stream = getattr(config, "LOCAL_STREAM", False)
        kw = self._opts()
        msgs = self._to_messages(system, history)
        local_tools = self._to_tools(tools) if tools else []

        if not use_stream:
            resp = await self._c.chat.completions.create(
                model=self._model, messages=msgs,
                tools=local_tools or None,
                tool_choice="auto" if local_tools else None,
                **kw)
            choice = resp.choices[0]
            msg = choice.message
            text = msg.content or ""
            # Emit the text as a single delta so the UI still streams it visually.
            if text:
                await on_delta(text)

            calls = []
            # Native tool_calls channel (works on capable models).
            for tc in (msg.tool_calls or []):
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}
                calls.append(ToolCall(tc.id or ("call_" + uuid.uuid4().hex[:8]),
                                      tc.function.name, args))

            # Fallback: model wrote the call as text (common with qwen / smaller models).
            if not calls and text:
                valid = {t["name"] for t in tools}
                for s in salvage_tool_calls(text, valid):
                    calls.append(ToolCall("call_" + uuid.uuid4().hex[:8], s["name"], s["args"]))

            stop = "tool_use" if calls else "end"
            return TurnResult(text, calls, stop, _model_obj_to_dict(getattr(resp, "usage", None)))

        # Streaming path (opt-in via LOCAL_STREAM=True).
        stream = await self._c.chat.completions.create(
            model=self._model, messages=msgs,
            tools=local_tools or None,
            tool_choice="auto" if local_tools else None,
            stream=True, **kw)
        parts: List[str] = []
        acc: Dict[int, Dict[str, str]] = {}
        async for chunk in stream:
            if not chunk.choices:
                continue
            delta = chunk.choices[0].delta
            if getattr(delta, "content", None):
                parts.append(delta.content)
                await on_delta(delta.content)
            for tc in (getattr(delta, "tool_calls", None) or []):
                slot = acc.setdefault(tc.index, {"id": "", "name": "", "args": ""})
                if tc.id:
                    slot["id"] = tc.id
                if tc.function:
                    if tc.function.name:
                        slot["name"] += tc.function.name
                    if tc.function.arguments:
                        slot["args"] += tc.function.arguments
        text = "".join(parts)
        calls = []
        for idx in sorted(acc):
            s = acc[idx]
            try:
                args = json.loads(s["args"] or "{}")
            except json.JSONDecodeError:
                args = {}
            calls.append(ToolCall(s["id"] or ("call_" + uuid.uuid4().hex[:8]), s["name"], args))
        if not calls and text:
            valid = {t["name"] for t in tools}
            for s in salvage_tool_calls(text, valid):
                calls.append(ToolCall("call_" + uuid.uuid4().hex[:8], s["name"], s["args"]))
        stop = "tool_use" if calls else "end"
        return TurnResult(text, calls, stop)

    async def complete(self, system, history, extra_user):
        msgs = self._to_messages(system, history) + [{"role": "user", "content": extra_user}]
        resp = await self._c.chat.completions.create(model=self._model, messages=msgs, **self._opts())
        self.last_usage = _model_obj_to_dict(getattr(resp, "usage", None))
        return resp.choices[0].message.content or ""

    async def complete_json(self, system, extra_user):
        """Force JSON output via response_format when the endpoint supports it; else fall back.

        Ollama and LM Studio honour {"type":"json_object"}; some llama.cpp servers reject it, so on
        any error we retry without it and brace-extract the JSON from the reply.
        """
        msgs = [{"role": "system", "content": system}, {"role": "user", "content": extra_user}]
        opts = self._opts()
        try:
            resp = await self._c.chat.completions.create(
                model=self._model, messages=msgs,
                response_format={"type": "json_object"}, **opts)
            self.last_usage = _model_obj_to_dict(getattr(resp, "usage", None))
            return _first_json_object(resp.choices[0].message.content or "")
        except Exception:
            try:
                resp = await self._c.chat.completions.create(model=self._model, messages=msgs, **opts)
                self.last_usage = _model_obj_to_dict(getattr(resp, "usage", None))
                return _first_json_object(resp.choices[0].message.content or "")
            except Exception:
                return {}


class NoLLM(BaseLLM):
    """What stands in for a provider that is not configured or could not be built.

    `reason` is the construction failure when there was one ("No module named 'openai'"), so the
    status endpoint, the CLI and a failed turn can say what is actually wrong instead of
    "No LLM configured" - which was shown for a fully configured local provider whose SDK was
    simply not installed in the interpreter running ReTrace.
    """
    is_remote = False
    provider_name = "none"
    available = False

    def __init__(self, reason: str = "", provider: str = ""):
        self.reason = reason
        self.failed_provider = provider

    def problem(self) -> str:
        if not self.reason:
            return "No LLM configured. Set llm_provider to anthropic or local (Settings, or `retrace config set`)."
        return provider_install_hint(self.failed_provider, self.reason)

    async def run(self, *a, **k):
        raise RuntimeError(self.problem())

    async def complete(self, *a, **k):
        raise RuntimeError(self.problem())


_SDK_EXTRA = {"openai": "local", "anthropic": "cloud"}


def provider_install_hint(provider: str, reason: str) -> str:
    """Turn an import failure into the install line that fixes it."""
    m = re.search(r"No module named '([^']+)'", reason or "")
    if m:
        extra = _SDK_EXTRA.get(m.group(1).split(".")[0])
        if extra:
            return (f"The {provider} provider needs the '{m.group(1)}' package, which is not installed in "
                    f"the interpreter running ReTrace: pip install \"retrace[{extra}]\" (or pip install "
                    f"{m.group(1)}), then restart.")
    return f"The {provider} provider could not be initialised: {reason}"


def provider_problem() -> str:
    """"" when the configured provider is usable; otherwise why it is not (SDK missing, etc.)."""
    if config.LLM_PROVIDER == "none":
        return ""
    inst = get_llm()
    return inst.problem() if isinstance(inst, NoLLM) else ""


_INSTANCE: Optional[BaseLLM] = None            # the configured provider, built on first use
_ROUTE_INSTANCES: Dict[str, BaseLLM] = {}      # per explicit route (anthropic / local)


def _safe_construct(factory, provider: str) -> BaseLLM:
    """Build an LLM backend, degrading to NoLLM if its SDK/deps are missing (never raises here)."""
    try:
        return factory()
    except Exception as exc:  # noqa: BLE001 - e.g. missing 'openai'/'anthropic' package
        import logging
        logging.getLogger("reforge.llm").warning("LLM provider '%s' unavailable: %s", provider, exc)
        return NoLLM(reason=str(exc), provider=provider)


# --------------------------------------------------------------------------- reachability
# `llm_available` used to mean "a provider is configured". With a local model that is the wrong
# question: Ollama installed and not running looks identical to Ollama running, so the UI showed
# no banner and the first turn died with the SDK's "Connection error". The status endpoint now
# asks the local server whether it is there. Cached, because the SPA polls status.
_PROBE_CACHE: Dict[str, Any] = {"at": 0.0, "url": "", "ok": None, "error": ""}
_PROBE_TTL_S = 10.0


def model_missing_message(model: str, listing: Any) -> str:
    """"" when `model` is in an OpenAI-style `{"data":[{"id":...}]}` listing, else what to do.

    Ollama running with nothing pulled is the step after "Ollama not running": the server answers,
    the first turn fails with `NotFoundError`. Exact id match, or the untagged name when the
    configured one carries no tag (`qwen3` matches `qwen3:30b`).
    """
    if not isinstance(listing, dict):
        return ""
    # Ollama answers `"data": null` when nothing is pulled - the case this exists for.
    try:
        ids = [str(m.get("id") or m.get("name") or "") for m in (listing.get("data") or [])]
    except (AttributeError, TypeError):
        return ""
    if model in ids or (":" not in model and any(i.split(":")[0] == model for i in ids)):
        return ""
    shown = ", ".join(ids[:6]) if ids else "none"
    return (f"model '{model}' is not on the server (available: {shown}). "
            f"Pull it with `ollama pull {model}` or set `local_model` to one of the available ones.")


def _probe_url(base_url: str, timeout: float) -> Tuple[bool, str]:
    """GET <base_url>/models (OpenAI-compatible; Ollama answers it). Blocking; run in a thread.

    Returns (reachable, error). `error` is set while reachable when the configured model is not
    on the server, so the status endpoint can say so before the first turn fails.
    """
    import json as _json
    import urllib.error
    import urllib.request
    url = base_url.rstrip("/") + "/models"
    try:
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {config.LOCAL_API_KEY or 'x'}"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - operator-configured loopback URL
            body = resp.read(1 << 20)
        try:
            return True, model_missing_message(config.LOCAL_MODEL, _json.loads(body.decode("utf-8", "replace")))
        except ValueError:
            return True, ""            # reachable, listing not JSON: nothing more to say
    except urllib.error.HTTPError as exc:
        # The server is there; an auth or routing error still means "reachable".
        return True, f"HTTP {exc.code}"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"


async def local_reachable(timeout: float = 2.0) -> Tuple[Optional[bool], str]:
    """(reachable, error) for the configured provider.

    None when the question does not apply: no provider, or a cloud provider that is not probed
    from the status endpoint (that would be egress on every poll).
    """
    import asyncio as _asyncio
    import time as _time
    if config.LLM_PROVIDER != "local" or not config.LOCAL_BASE_URL:
        return None, ""
    now = _time.monotonic()
    if (_PROBE_CACHE["url"] == config.LOCAL_BASE_URL and _PROBE_CACHE["ok"] is not None
            and now - float(_PROBE_CACHE["at"]) < _PROBE_TTL_S):
        return _PROBE_CACHE["ok"], _PROBE_CACHE["error"]
    ok, err = await _asyncio.to_thread(_probe_url, config.LOCAL_BASE_URL, timeout)
    _PROBE_CACHE.update(at=now, url=config.LOCAL_BASE_URL, ok=ok, error=err)
    return ok, err


def explain_error(exc: BaseException, provider_name: str) -> str:
    """The sentence a failed turn shows for a transport failure, naming what to do.

    `APIConnectionError: Connection error.` is what the SDK says when nothing listens on the
    local port. The analyst needs the URL and the likely cause, not the exception class.
    """
    name = type(exc).__name__
    text = str(exc)
    if name in ("APIConnectionError", "ConnectError", "ConnectionError", "ConnectionRefusedError") \
            or "Connection error" in text or "connection refused" in text.lower():
        if provider_name == "local":
            return (f"The local LLM server at {config.LOCAL_BASE_URL} is not reachable. Start it "
                    f"(for Ollama: open the Ollama app or run `ollama serve`), check that the model "
                    f"'{config.LOCAL_MODEL}' is pulled (`ollama list`), then send the message again.")
        return f"The {provider_name} API could not be reached ({text}). Check the network and the proxy settings."
    if name in ("APITimeoutError", "ReadTimeout", "TimeoutError"):
        ceiling = config.LOCAL_TIMEOUT_S if provider_name == "local" else config.LLM_TIMEOUT_S
        return (f"The {provider_name} provider did not answer within {ceiling} s. "
                + ("A local model may still be loading its weights: wait and retry, or raise "
                   "`local_timeout_s`." if provider_name == "local" else "Retry, or raise `llm_timeout_s`."))
    if name == "NotFoundError" and provider_name == "local":
        return (f"The local server does not know the model '{config.LOCAL_MODEL}' ({text}). "
                f"Pull it (`ollama pull {config.LOCAL_MODEL}`) or set `local_model` to one that `ollama list` shows.")
    return f"{name}: {text}"


def get_llm(provider: Optional[str] = None) -> BaseLLM:
    global _INSTANCE
    if provider:
        if provider not in _ROUTE_INSTANCES:
            if provider == "anthropic":
                _ROUTE_INSTANCES[provider] = _safe_construct(AnthropicLLM, "anthropic") if config.ANTHROPIC_API_KEY else NoLLM()
            elif provider == "local":
                _ROUTE_INSTANCES[provider] = _safe_construct(LocalLLM, "local") if config.LOCAL_BASE_URL else NoLLM()
            else:
                _ROUTE_INSTANCES[provider] = NoLLM()
        return _ROUTE_INSTANCES[provider]
    if _INSTANCE is None:
        if config.LLM_PROVIDER == "anthropic":
            _INSTANCE = _safe_construct(AnthropicLLM, "anthropic")
        elif config.LLM_PROVIDER == "local":
            _INSTANCE = _safe_construct(LocalLLM, "local")
        else:
            _INSTANCE = NoLLM()
    return _INSTANCE


def reset() -> None:
    """Drop the cached client so the next get_llm() rebuilds from current config."""
    global _INSTANCE
    _INSTANCE = None
    _ROUTE_INSTANCES.clear()
