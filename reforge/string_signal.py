"""High-signal strings: server-side categories, classifier, and reassignment application.

WHY THIS EXISTS
---------------
The Strings tab groups extracted strings by *signal* (network, secret, registry, …). The local
LLM can be asked to fix mis-categorised strings; previously it only emitted `REASSIGN:` lines that
the browser applied to an in-memory map, lost on reload and invisible to every other consumer
(graph, report, exports). The user's requirement is explicit: the reassignment must *actually*
move the string, durably.

This module is the single source of truth, shared by the backend:

  * CATEGORIES        — the allowed groups (must match reforge/web/app.js STR_KIND_ORDER).
  * classify()        — deterministic category for a string (mirror of the JS strKindStatic).
  * effective_kind()  — classify() unless a persisted override moves it elsewhere.
  * parse_reassignments() — turn raw LLM text (`REASSIGN: <str> => <cat>`) into validated moves.
  * apply_reassignments() — persist validated moves onto a session, returning what changed.

Everything here treats LLM output as UNTRUSTED: a reassignment is accepted only if the target
category is allowed AND the quoted string actually exists in the session's extracted strings
(matched exactly, else by unique substring). A move back to the string's natural static category
clears the override rather than storing a redundant one.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field

from . import config, llm_schema, prompts

# Allowed categories — keep in lockstep with STR_KIND_ORDER in reforge/web/app.js. Ordered by signal
# priority for vulnerability research: likely-findings first, sinks/surfaces next, noise last.
CATEGORIES: List[str] = [
    "secret", "crypto", "url", "network", "command", "registry", "dll", "ipc",
    "path", "format", "identity", "diagnostic", "config", "api", "generic",
]
_CATSET = set(CATEGORIES)

# Aliases the LLM might emit -> canonical category (mirror of STR_KIND_ALIASES, flattened).
_ALIASES: Dict[str, str] = {
    "endpoints": "url", "endpoint": "url", "urls": "url", "urlendpoint": "url",
    "host": "network", "hosts": "network", "ip": "network", "hostip": "network",
    "reg": "registry", "registrykey": "registry", "registrykeys": "registry",
    "autorun": "registry", "startup": "path", "runkey": "registry",
    "cmd": "command", "shell": "command", "commands": "command",
    "token": "secret", "secrets": "secret", "credential": "secret", "credentials": "secret",
    "secretstokens": "secret", "tokens": "secret",
    "module": "dll", "modules": "dll", "library": "dll", "libraries": "dll", "dllmodule": "dll",
    "pipe": "ipc", "mutex": "ipc", "service": "ipc", "ipcservices": "ipc",
    "user": "identity", "email": "identity", "emails": "identity", "identityaccount": "identity",
    "cert": "crypto", "encoding": "crypto", "cryptoencoding": "crypto",
    "parser": "format", "protocol": "format", "formatprotocol": "format",
    "symbol": "api", "apisymbols": "api",
    "log": "diagnostic", "logs": "diagnostic", "error": "diagnostic", "diagnostics": "diagnostic",
    "setting": "config", "settings": "config", "option": "config", "options": "config",
    "configoptions": "config",
    "file": "path", "filepath": "path", "pathfile": "path", "files": "path",
    "other": "generic", "misc": "generic", "unknown": "generic",
}


def normalize_category(raw: str) -> str:
    """Map an LLM-supplied category name to a canonical category, or '' if not allowed."""
    t = re.sub(r"[^a-z0-9_ -]", "", (raw or "").strip().lower())
    t = re.sub(r"\s+", "_", t)
    flat = t.replace("_", "").replace("-", "")
    val = _ALIASES.get(t) or _ALIASES.get(flat) or t
    return val if val in _CATSET else ""


# --- deterministic classifier (server mirror of JS strKindStatic) -----------------------------
# ORDER MATTERS: most-specific / highest-signal first; first match wins. This list is the single
# source of truth and MUST stay byte-for-byte equivalent to strKindStatic() in reforge/web/app.js so the
# UI, the report and the graph never disagree about where a string belongs.
_RX = [
    # -- secrets & crypto: the strings most likely to BE (or lead to) a finding ----------------
    ("secret", re.compile(r"-----BEGIN [A-Z0-9 ]+PRIVATE KEY-----")),
    ("secret", re.compile(
        r"\b(api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|access[_-]?key|"
        r"refresh[_-]?token|auth[_-]?token|bearer|password|passwd|\bpwd\b|passphrase|"
        r"credentials?|session[_-]?id)\b", re.I)),
    ("secret", re.compile(r"\b(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_\-]{20,}|xox[baprs]-[0-9A-Za-z-]{6,}|"
                          r"ghp_[0-9A-Za-z]{10,}|eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.)")),
    ("crypto", re.compile(
        r"\b(md5|md4|sha-?1|sha-?256|sha-?512|aes(?:-\d{3})?|3des|\bdes\b|rc4|rc2|blowfish|"
        r"chacha20|rsa|ecdsa|ed25519|hmac|pbkdf2|bcrypt|scrypt|argon2|x509|ecb\b|cbc\b|gcm\b)\b",
        re.I)),
    # -- remote surface: endpoints & network literals ------------------------------------------
    ("url", re.compile(r"(?:https?|ftp|wss?)://", re.I)),
    ("network", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b|\[[a-f0-9:]{6,}\]", re.I)),
    # -- execution / filesystem / module: the classic sink surfaces ----------------------------
    ("command", re.compile(
        r"\bcmd\.exe\b|\bpowershell(?:\.exe)?\b|\bpwsh\b|\bwscript\b|\bcscript\b|"
        r"/bin/(?:sh|bash|zsh)\b|\bsystem\(|\bpopen\b|\bexec[lv]p?\(|"
        r"\bShellExecute\w*|\bCreateProcess\w*|\bWinExec\b", re.I)),
    ("registry", re.compile(
        r"\bhkey_[a-z_]+|\bhk(?:lm|cu|cr|u)\\|\\registry\\|\\software\\|"
        r"\\system\\currentcontrolset\\", re.I)),
    ("dll", re.compile(r"\.(?:dll|sys|ocx|drv|cpl)\b", re.I)),
    ("ipc", re.compile(r"\\\\\.\\pipe\\|\\BaseNamedObjects\\|(?:^|[^\\A-Za-z0-9])(?:Global|Local|Session)\\[A-Za-z0-9_.{}-]{2,}|"
                       r"\bnamed pipe\b|\bmutex\b|\bsemaphore\b", re.I)),
    ("path", re.compile(
        r"[a-z]:\\|%(?:appdata|temp|programdata|userprofile|systemroot|windir)%|"
        r"\\\\[^\\/:*?\"<>|\r\n]+\\|/(?:usr|etc|var|tmp|home|opt|bin|sbin|lib|proc)/|"
        r"\.(?:exe|dat|cfg|conf|ini|log|tmp|pdb|bak|db|sqlite)\b", re.I)),
    # -- input surfaces: parseable formats/protocols the program consumes ----------------------
    ("format", re.compile(
        r"\b(json|xml|yaml|ini|csv|zip|rar|7z|gzip|tar|content-type|user-agent|multipart|"
        r"application/[a-z0-9.+-]+|sqlite|protobuf|msgpack|asn\.?1|base64)\b", re.I)),
    # -- accounts / identity (tight: email, SID, DOMAIN\user only) ------------------------------
    ("identity", re.compile(
        r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b|\bS-\d-\d+(?:-\d+){2,}\b|"
        r"\b[A-Z][A-Z0-9-]{1,14}\\[A-Za-z][A-Za-z0-9._$-]{1,30}\b", re.I)),
    # -- diagnostics: error/log text that maps out code branches -------------------------------
    ("diagnostic", re.compile(
        r"\b(error|failed|failure|exception|denied|invalid|warning|fatal|assert(?:ion)?|"
        r"cannot|unable|unexpected|not found|overflow|out of (?:range|bounds|memory))\b", re.I)),
    # -- config: ONLY flag-like tokens or a short whitelist of config words (tight) -------------
    ("config", re.compile(r"^[-/]{1,2}[a-z][a-z0-9_-]{1,32}$", re.I)),
    ("config", re.compile(
        r"^.{0,48}\b(enable|disable|timeout|retry|verbose|maxsize|threshold|loglevel|"
        r"configuration)\b.{0,16}$", re.I)),
]
# Domain-like (no scheme) -> url, but not module/object files.
_RX_DOMAIN = re.compile(
    r"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?){1,}\b"
    r"(?::\d{2,5})?(?:/[^\s]*)?", re.I)
_RX_NOT_DOMAIN = re.compile(r"\.(dll|exe|pdb|obj|lib|sys|dat|cfg|ini|log)$", re.I)


def classify(s: str) -> str:
    """Deterministic static category for a string (mirror of the UI's strKindStatic)."""
    x = (s or "")
    for kind, rx in _RX:
        if rx.search(x):
            return kind
    if _RX_DOMAIN.search(x) and not _RX_NOT_DOMAIN.search(x):
        return "url"
    return "generic"


def effective_kind(s: str, overrides: Optional[Dict[str, str]] = None) -> str:
    """Category after applying a persisted override, else the static classification."""
    if overrides and s in overrides:
        return overrides[s]
    return classify(s)


# --- reassignment parsing / application -------------------------------------------------------
_REASSIGN_RX = re.compile(
    r"""(?:REASSIGN\s*:)?\s*["'`]?(?P<str>.+?)["'`]?\s*(?:=>|->|:)\s*["'`]?(?P<cat>[a-zA-Z_ -]{3,24})["'`]?\s*$""")


def _clean_ref(ref: str) -> str:
    return (ref or "").strip().strip("`'\"").strip()


def parse_reassignments(text: str) -> List[Tuple[str, str]]:
    """Extract (string_ref, category) pairs from raw LLM text. No validation against a corpus yet.

    Only lines that look like reassignments are considered (contain REASSIGN, '=>' or '->').
    """
    out: List[Tuple[str, str]] = []
    for line in (text or "").splitlines():
        if not re.search(r"REASSIGN|=>|->", line, re.I):
            continue
        m = _REASSIGN_RX.match(line.strip())
        if not m:
            continue
        ref = _clean_ref(m.group("str"))
        cat = normalize_category(m.group("cat"))
        if ref and cat:
            out.append((ref, cat))
    return out


def _coerce_pairs(data: Any) -> List[Tuple[str, str]]:
    """Normalize any accepted reassignment shape into [(string_ref, category), ...].

    Accepts: a JSON dict with a "reassignments" list of {string/value/s, category/group/kind/to},
    a list of pairs/dicts, or raw text with REASSIGN lines.
    """
    if data is None:
        return []
    # dict with a reassignments list (the structured-JSON path)
    if isinstance(data, dict):
        items = data.get("reassignments") or data.get("moves") or data.get("changes") or []
        out: List[Tuple[str, str]] = []
        for it in items if isinstance(items, list) else []:
            if isinstance(it, dict):
                ref = it.get("string") or it.get("value") or it.get("s") or it.get("text") or ""
                cat = it.get("category") or it.get("group") or it.get("kind") or it.get("to") or ""
            elif isinstance(it, (list, tuple)) and len(it) >= 2:
                ref, cat = it[0], it[1]
            else:
                continue
            ref = _clean_ref(str(ref))
            cat = normalize_category(str(cat))
            if ref and cat:
                out.append((ref, cat))
        return out
    # list of pairs/dicts
    if isinstance(data, list):
        out2: List[Tuple[str, str]] = []
        for it in data:
            if isinstance(it, (list, tuple)) and len(it) >= 2:
                ref, cat = _clean_ref(str(it[0])), normalize_category(str(it[1]))
                if ref and cat:
                    out2.append((ref, cat))
            elif isinstance(it, dict):
                out2.extend(_coerce_pairs({"reassignments": [it]}))
        return out2
    # raw text: try to extract a JSON object first (model may wrap JSON in prose), else REASSIGN lines
    text = str(data)
    obj = _extract_json_object(text)
    if obj:
        return _coerce_pairs(obj)
    return parse_reassignments(text)


def _extract_json_object(text: str) -> Optional[Dict[str, Any]]:
    """Find the first brace-matched JSON object in text that looks like a reassignment payload."""
    import json as _json
    depth = start = 0
    in_str = esc = False
    for i, ch in enumerate(text or ""):
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
                try:
                    obj = _json.loads(text[start:i + 1])
                    if isinstance(obj, dict) and ("reassignments" in obj or "moves" in obj or "changes" in obj):
                        return obj
                except Exception:
                    pass
    return None


def match_string(ref: str, corpus: List[str]) -> Optional[str]:
    """Resolve an LLM string reference to an exact corpus string.

    Exact match wins; otherwise a *unique* substring match is accepted (the LLM often quotes a
    fragment). Ambiguous or absent references return None and are skipped — we never guess.
    """
    if not ref:
        return None
    if ref in corpus:
        return ref
    low = ref.lower()
    hits = [s for s in corpus if low in s.lower()]
    if len(hits) == 1:
        return hits[0]
    # Prefer an exact case-insensitive match if present among multiple substring hits.
    ci = [s for s in corpus if s.lower() == low]
    return ci[0] if len(ci) == 1 else None


def apply_reassignments(session, text_or_pairs: Any) -> Dict[str, Any]:
    """Validate and PERSIST reassignments onto a session. Returns {applied, skipped, cleared}.

    Accepts any of:
      * a JSON dict {"reassignments":[{"string": "...", "category": "..."}], ...}
      * a list of (string, category) pairs
      * raw LLM text containing `REASSIGN: <string> => <category>` lines

    A move is applied only when the string exists in session.static_strings and the target category
    differs from the string's current effective category. Moving a string back to its natural
    static category clears any override instead of storing a no-op. Persists once at the end.
    """
    corpus = list(getattr(session, "static_strings", []) or [])
    overrides: Dict[str, str] = dict(getattr(session, "string_overrides", {}) or {})
    pairs = _coerce_pairs(text_or_pairs)

    applied: List[Dict[str, str]] = []
    cleared: List[str] = []
    skipped: List[str] = []

    for ref, cat in pairs:
        full = match_string(ref, corpus)
        if not full or not cat:
            skipped.append(ref)
            continue
        static_kind = classify(full)
        current = overrides.get(full, static_kind)
        if cat == current:
            skipped.append(ref)
            continue
        if cat == static_kind:
            # Back to natural category -> drop the override.
            overrides.pop(full, None)
            cleared.append(full)
            applied.append({"value": full, "from": current, "to": cat})
        else:
            overrides[full] = cat
            applied.append({"value": full, "from": current, "to": cat})

    if applied:
        session.string_overrides = overrides
        if hasattr(session, "persist"):
            session.persist()
    return {"applied": applied, "cleared": cleared, "skipped": skipped,
            "override_count": len(overrides)}


def grouped_overview(session, limit_per_group: int = 0) -> Dict[str, Any]:
    """Return high-signal strings grouped by effective category (overrides honoured).

    Useful for backend consumers (report/graph) that need the *moved* categorisation, not the raw
    static one. `limit_per_group=0` means no per-group cap.
    """
    corpus = list(getattr(session, "static_strings", []) or [])
    overrides = dict(getattr(session, "string_overrides", {}) or {})
    groups: Dict[str, List[str]] = {}
    for s in corpus:
        groups.setdefault(effective_kind(s, overrides), []).append(s)
    ordered = {k: (groups[k][:limit_per_group] if limit_per_group else groups[k])
               for k in CATEGORIES if k in groups}
    return {"groups": ordered,
            "counts": {k: len(groups[k]) for k in CATEGORIES if k in groups},
            "override_count": len(overrides)}


# --------------------------------------------------------------------------- LLM-driven reclassify
class Reassignment(BaseModel):
    """One proposed move. The category is constrained by the schema, not checked afterwards."""
    model_config = ConfigDict(extra="forbid")
    string: str = Field(min_length=1, description="exact string, copied from the context")
    category: str = Field(min_length=1, description="one of the allowed categories")


class ReclassifyResponse(BaseModel):
    """The contract for `llm_reclassify`.

    Declared as a schema rather than described in the prompt and hoped for: the same object is sent
    to the model as its instruction and used to validate the reply, so the two cannot drift. A
    reply that does not fit is an error, not an empty result silently treated as "no changes".
    """
    model_config = ConfigDict(extra="forbid")
    reassignments: List[Reassignment] = Field(default_factory=list)
    notes: str = ""


_RECLASSIFY_PROMPT = prompts.inline("string_reclassify", (
    "You are a classifier for strings extracted from binaries for defensive reverse engineering. "
    "Your ONLY task is to fix the category of strings that are clearly misclassified. "
    "Answer EXCLUSIVELY with a valid JSON object, no text before or after, no markdown. "
    "Schema: {\"reassignments\": [{\"string\": \"<exact string from the context>\", "
    "\"category\": \"<one allowed category>\"}], \"notes\": \"<optional short note>\"}. "
    "Strict rules: (1) use ONLY the strings present in the context, copied EXACTLY; "
    "(2) use ONLY the allowed categories; (3) include a string ONLY if its current category "
    "is WRONG and needs changing — do not repeat ones that are already correct; (4) if no string "
    "needs correction, answer {\"reassignments\": []}. Do NOT explain, do NOT add any other text."
))
#: Back-compat alias; the versioned Prompt stringifies to its text.
_RECLASSIFY_SYSTEM = _RECLASSIFY_PROMPT.text


def _build_reclassify_user(items: List[Dict[str, Any]]) -> str:
    """Build the user message: the allowed categories + the strings with their current category."""
    lines = ["Allowed categories: " + ", ".join(CATEGORIES) + ".",
             "Strings (current category → string):"]
    for it in items:
        lines.append(f"- [{it['current']}] {it['string']}")
    lines.append("Return only the JSON with the necessary reassignments.")
    return "\n".join(lines)


def candidate_items(session, query: str = "", limit: int = 160) -> List[Dict[str, Any]]:
    """Pick strings to submit for reclassification: their current effective category + the string.

    Prioritises 'generic' (most likely mis-binned) and shorter strings, optionally filtered by a
    free-text query. Bounded so the prompt stays small.
    """
    corpus = list(getattr(session, "static_strings", []) or [])
    overrides = dict(getattr(session, "string_overrides", {}) or {})
    q = (query or "").lower().strip()
    items = []
    for s in corpus:
        if q and q not in s.lower():
            continue
        items.append({"string": s, "current": effective_kind(s, overrides)})
    items.sort(key=lambda it: (it["current"] != "generic", len(it["string"])))
    return items[:max(1, limit)]


async def llm_reclassify(session, llm, query: str = "", limit: int = 160) -> Dict[str, Any]:
    """Authoritative LLM reclassification: force structured JSON, then APPLY + PERSIST the moves.

    The response is validated against `ReclassifyResponse` before anything is applied. A model
    that cannot produce that shape - after a bounded corrective retry - raises
    `llm_schema.StructuredOutputError` instead of returning `{}`, which used to be indistinguishable
    from "the model found nothing to change". Each accepted move is then still checked against the
    actual corpus and the allowed categories: the schema proves the shape, not the content.
    """
    items = candidate_items(session, query=query, limit=limit)
    if not items:
        return {"applied": [], "skipped": [], "cleared": [], "override_count": 0,
                "note": "No strings to analyze."}
    user = _build_reclassify_user(items)
    try:
        parsed = await llm_schema.structured(
            llm, ReclassifyResponse,
            system=_RECLASSIFY_PROMPT.text, user=user,
            prompt_version=_RECLASSIFY_PROMPT.version,
            provider=getattr(config, "LLM_PROVIDER", ""),
            model_name=config.active_model() if hasattr(config, "active_model") else "")
    except llm_schema.StructuredOutputError as exc:
        # Reported, not swallowed: the operator is told the model failed rather than being shown
        # an empty result that looks like a clean bill of health.
        return {"applied": [], "skipped": [], "cleared": [], "override_count": 0,
                "error": str(exc), "submitted": len(items),
                "note": "The model did not return a valid reclassification; nothing was changed."}
    data = parsed.model_dump(mode="json")
    res = apply_reassignments(session, data)
    res["model_json"] = data
    res["submitted"] = len(items)
    res["prompt_version"] = _RECLASSIFY_PROMPT.version
    return res
