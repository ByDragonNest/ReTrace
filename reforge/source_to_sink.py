"""Source→sink reasoning over deterministic facts (slice P1-S5).

Not a decompiler: a structured model of the claim "an untrusted source reaches a dangerous sink".
Truth does not come from the LLM - chains are built from facts (sinks from the import inventory,
known sources, call sites observed via xrefs); the model may comment on them but is never the only
source.

WHAT CHANGED AND WHY
--------------------
`build_candidate_chains()` used to emit the full cartesian product of sources x sinks, each at
confidence 0.40-0.55. On an ordinary, well-written Windows program - `recv`, `getenv`,
`GetCommandLineW`, `memcpy`, `CreateProcessW`, `LoadLibraryW`, ... - that produced **32 "chains"
with no evidence of any connection whatsoever**, including `recv -> LoadLibraryW` at 0.55. Both
endpoints existing in an import table is attack surface. It is not a chain, and presenting it as
one at a confidence that reads like a lead is exactly the noise this product category dies of
(prompt §7.2: distinguish a capability that is present from a path that is actually reachable).

Three deterministic controls now apply, in order:

1. **Plausibility.** Pairings whose source data cannot reach the sink are dropped; ones that are
   possible but need a parsing or reinterpretation step are kept and *labelled* `conversion`,
   which costs them confidence. Stated honestly: at symbol granularity this drops very little -
   network bytes really can become a DLL path - so the label and the confidence penalty, not the
   dropping, are what this control actually buys. It is not a reachability analysis and does not
   claim to be.
2. **Tiering.** A chain states what is actually known about it - `capability`, `path`, `dataflow`
   or `confirmed` - as a field the evidence gate reads, instead of the gate inferring it from
   prose. A `capability` chain is hard-capped below the confidence band that reads as a lead.
3. **Mitigation.** A bounded counterpart of the operation in the same binary (`strcpy_s` beside
   `strcpy`) is recorded against the chain and lowers its confidence. It does not eliminate it -
   the unsafe symbol is still imported - but an analyst should see it.
"""
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

# Argomento "pericoloso" tipico per sink noti (per suggerire `argument`).
_SINK_ARG = {
    "createprocess": "lpCommandLine",
    "winexec": "lpCmdLine",
    "system": "command",
    "shellexecute": "lpFile",
    "loadlibrary": "lpLibFileName",
    "strcpy": "dest",
    "strcat": "dest",
    "sprintf": "buffer",
    "memcpy": "count",
    "gets": "buffer",
}

# What a chain is actually known to be. Ordered: each tier requires the evidence of the one below.
TIER_CAPABILITY = "capability"   # both endpoints exist in the binary. No path evidence. NOT a lead.
TIER_PATH = "path"               # a call site is known
TIER_DATAFLOW = "dataflow"       # the sink argument is traced back to the source
TIER_CONFIRMED = "confirmed"     # observed at runtime
TIER_ORDER = [TIER_CAPABILITY, TIER_PATH, TIER_DATAFLOW, TIER_CONFIRMED]

#: Hard ceiling per tier. A capability-tier chain must never reach a confidence that reads like a
#: lead, however many weak signals accumulate underneath it.
_TIER_CEILING = {
    TIER_CAPABILITY: 0.20,
    TIER_PATH: 0.55,
    TIER_DATAFLOW: 0.80,
    TIER_CONFIRMED: 0.97,
}

# --- what kind of data a source yields -------------------------------------------------------
_SOURCE_KIND = {
    "argv": "string", "getcommandline": "string", "commandline": "string",
    "getenv": "string", "environ": "string",
    "recv": "bytes", "recvfrom": "bytes", "wsarecv": "bytes", "internetreadfile": "bytes",
    "read": "bytes", "fread": "bytes", "readfile": "bytes", "mmap": "bytes",
    "scanf": "string", "fgets": "string", "gets": "string", "getline": "string",
    "regqueryvalue": "string", "getprivateprofilestring": "string",
}

# --- which source kinds can plausibly reach which sink class ---------------------------------
# "direct": the data can be used as-is. "conversion": physically possible, but something has to
# parse or reinterpret it first - which is a real step an analyst must find, not an assumption we
# make for them. Absent: implausible; no chain is emitted.
_PLAUSIBLE: Dict[str, Dict[str, str]] = {
    "string": {"exec": "direct", "load": "direct", "file": "direct", "format": "direct",
               "mem_copy": "direct", "unbounded": "direct", "alloc_int": "conversion"},
    "bytes":  {"mem_copy": "direct", "unbounded": "direct", "alloc_int": "direct",
               "format": "conversion", "exec": "conversion", "load": "conversion",
               "file": "conversion"},
}

#: Bounded counterparts. Importing one of these alongside the unsafe symbol is evidence the author
#: knew about the hazard - worth showing, not worth concluding from.
_MITIGATING = {
    "mem_copy": {"strcpy_s", "strncpy_s", "strcat_s", "strncat_s", "memcpy_s", "memmove_s",
                 "strlcpy", "strlcat", "stringcchcopy", "stringcchcat", "stringcbcopy",
                 "sprintf_s", "snprintf", "vsnprintf", "_snprintf_s"},
    "unbounded": {"fgets", "getline", "strnlen", "readfile"},
    "format":    {"__printf_chk", "__sprintf_chk", "__fprintf_chk"},
    "exec":      {"createprocessw"},          # the W form at least avoids the ANSI path pitfalls
    "file":      {"pathcchcanonicalize", "getfullpathname", "realpath", "canonicalize_file_name"},
}

# Confidenza di base per origine della sorgente (più "esterna" = più rilevante).
_SOURCE_WEIGHT = {
    "argv": 0.35, "getenv": 0.30, "recv": 0.40, "read": 0.30,
    "fread": 0.28, "scanf": 0.32, "getcommandline": 0.35,
}


@dataclass
class Chain:
    source: str
    sink: str
    function: str = ""
    callsite: str = ""
    argument: str = ""
    validation_seen: bool = False
    confidence: float = 0.0
    notes: str = ""
    confirmed_dynamic: bool = False
    evidence_refs: List[str] = field(default_factory=list)
    # --- P1-S5: what is actually known, as data rather than as prose ---
    tier: str = TIER_CAPABILITY
    sink_class: str = ""
    source_kind: str = ""
    linkage: str = ""                 # "direct" | "conversion"
    dataflow_traced: bool = False
    mitigating_symbols: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _sink_arg(sink: str) -> str:
    base = sink.lower().rstrip("aw")
    for key, arg in _SINK_ARG.items():
        if base.startswith(key):
            return arg
    return ""


def _source_weight(source: str) -> float:
    s = source.lower()
    for key, w in _SOURCE_WEIGHT.items():
        if key in s:
            return w
    return 0.20


def source_kind(source: str) -> str:
    """The kind of data a source yields: 'string', 'bytes', or '' when unknown."""
    s = source.lower()
    for key, kind in _SOURCE_KIND.items():
        if key in s:
            return kind
    return ""


def sink_class(sink: str) -> str:
    from . import sinks as _sinks

    return _sinks._match(sink, _sinks._SINKS) or ""


def linkage(source: str, sink: str) -> str:
    """'direct', 'conversion', or '' when this source cannot plausibly reach this sink."""
    kind = source_kind(source)
    klass = sink_class(sink)
    if not kind or not klass:
        # Unknown on either side: keep it, at capability tier, rather than assert impossibility
        # from ignorance. Dropping what we failed to classify would hide gaps in the tables.
        return "unknown"
    return _PLAUSIBLE.get(kind, {}).get(klass, "")


def mitigating_symbols(klass: str, symbols: List[str]) -> List[str]:
    """Bounded counterparts of `klass` present in the same binary."""
    wanted = _MITIGATING.get(klass, set())
    if not wanted:
        return []
    present = {str(s).lower().lstrip("_") for s in (symbols or [])}
    return sorted(w for w in wanted if w.lower().lstrip("_") in present)


def infer_tier(chain: Chain) -> str:
    """The highest tier the chain's own evidence supports. Never what was claimed for it."""
    if chain.confirmed_dynamic:
        return TIER_CONFIRMED
    if chain.dataflow_traced and chain.callsite:
        return TIER_DATAFLOW
    if chain.callsite:
        return TIER_PATH
    return TIER_CAPABILITY


def compute_confidence(chain: Chain) -> float:
    """Deterministic confidence in [0,1], hard-capped by the chain's evidence tier.

    The cap is the point. Before it, a capability-tier chain could accumulate 0.55 from source
    weight plus "no validation seen" - where "not seen" meant nobody had looked, and absence of
    evidence was being scored as evidence of absence.
    """
    tier = infer_tier(chain)
    c = _source_weight(chain.source)
    if chain.callsite:
        c += 0.15
    if chain.function:
        c += 0.07
    if chain.argument:
        c += 0.05
    # "No validation seen" only counts once somebody has actually looked at the call site.
    if not chain.validation_seen and chain.callsite:
        c += 0.10
    if chain.dataflow_traced:
        c += 0.10
    if chain.confirmed_dynamic:
        c += 0.25
    if chain.linkage == "conversion":
        c -= 0.10          # something must parse the data first; that step is not established
    if chain.mitigating_symbols:
        c -= 0.08          # the author shipped the bounded counterpart too
    return round(max(0.0, min(_TIER_CEILING.get(tier, 0.97), c)), 2)


def build_candidate_chains(sources: List[str], sinks: List[str],
                           max_chains: int = 200,
                           all_symbols: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Plausible source→sink candidates. Implausible pairings are not emitted at all.

    `all_symbols` is the full import list, used to spot bounded counterparts of each sink class.
    Returns chains sorted by confidence. When more than `max_chains` are plausible the weakest are
    dropped and a `_truncated` marker chain records how many - silent truncation would make the
    count meaningless.
    """
    # Capability-tier candidates are AGGREGATED by (source kind, sink class) rather than emitted
    # per symbol pair.
    #
    # At this tier the symbol-level identity carries no information: nothing distinguishes
    # `recv -> memcpy` from `recv -> sprintf` when neither has a call site. What the analyst needs
    # is "untrusted bytes enter here, and these memory-copy sinks exist" - one row, with the
    # contributing symbols on it - not one row per pairing. On an ordinary Windows program that is
    # the difference between 32 rows and a handful, with nothing lost: every symbol is still named.
    #
    # Symbol-level identity returns as soon as there is a call site, because from then on the rows
    # are about distinct code locations and the distinction is real.
    groups: Dict[tuple, Dict[str, Any]] = {}
    dropped_implausible = 0
    for snk in sinks or []:
        klass = sink_class(snk)
        mitigations = mitigating_symbols(klass, all_symbols or [])
        for src in sources or []:
            link = linkage(src, snk)
            if not link:
                dropped_implausible += 1
                continue
            key = (source_kind(src) or "unknown", klass or "unknown", link)
            slot = groups.setdefault(key, {"sources": set(), "sinks": set(),
                                           "mitigations": set(), "link": link})
            slot["sources"].add(src)
            slot["sinks"].add(snk)
            slot["mitigations"].update(mitigations)

    out: List[Chain] = []
    for (kind, klass, link), slot in groups.items():
        srcs = sorted(slot["sources"])
        snks = sorted(slot["sinks"])
        ch = Chain(source=", ".join(srcs), sink=", ".join(snks),
                   argument=_sink_arg(snks[0]) if len(snks) == 1 else "",
                   sink_class=klass, source_kind=kind, linkage=link,
                   mitigating_symbols=sorted(slot["mitigations"]))
        ch.tier = infer_tier(ch)
        ch.confidence = compute_confidence(ch)
        ch.notes = _candidate_note(ch)
        out.append(ch)

    out.sort(key=lambda c: (TIER_ORDER.index(c.tier), c.confidence), reverse=True)
    truncated = max(0, len(out) - max_chains)
    out = out[:max_chains]
    result = [c.to_dict() for c in out]
    result.append({
        "_meta": True,
        "emitted": len(out),
        "implausible_dropped": dropped_implausible,
        "truncated": truncated,
        "pairings_considered": len(sources or []) * len(sinks or []),
        "note": ("Capability-tier candidates are grouped by source kind and sink class: at this "
                 "tier no call site is known, so a row per symbol pairing would be N x M rows of "
                 "the same single fact. Both endpoints existing in an import table is attack "
                 "surface, not a chain."),
    })
    return result


def _candidate_note(ch: Chain) -> str:
    if ch.tier == TIER_CAPABILITY:
        base = ("Capability only: source and sink both present, no call site and no dataflow "
                "established. Resolve the call site (Ghidra xrefs) before treating this as a lead.")
    else:
        base = "Call site known; trace the sink argument back to the source to establish dataflow."
    if ch.linkage == "conversion":
        base += (f" The {ch.source_kind} from this source must be parsed or reinterpreted before it "
                 f"can reach a {ch.sink_class} sink; find that step.")
    if ch.mitigating_symbols:
        base += (" The binary also imports " + ", ".join(ch.mitigating_symbols)
                 + ", so a bounded form of this operation is in use somewhere.")
    return base


_CHAIN_FIELDS = ("source", "sink", "function", "callsite", "argument", "validation_seen",
                 "confidence", "notes", "confirmed_dynamic", "evidence_refs", "tier",
                 "sink_class", "source_kind", "linkage", "dataflow_traced", "mitigating_symbols")


def _rehydrate(chain: Dict[str, Any]) -> Chain:
    """Rebuild a Chain from a dict, tolerating one stored before the P1-S5 fields existed."""
    kwargs: Dict[str, Any] = {k: chain.get(k) for k in _CHAIN_FIELDS if chain.get(k) is not None}
    obj = Chain(**kwargs)
    if not obj.sink_class:
        obj.sink_class = sink_class(obj.sink)
    if not obj.source_kind:
        obj.source_kind = source_kind(obj.source)
    if not obj.linkage:
        obj.linkage = linkage(obj.source, obj.sink) or "unknown"
    return obj


def refine_chain(chain: Dict[str, Any], *, function: str = "", callsite: str = "",
                 argument: str = "", validation_seen: Optional[bool] = None,
                 dataflow_traced: Optional[bool] = None) -> Dict[str, Any]:
    """Enrich a chain with the observed call site / function / argument (static)."""
    ch = _rehydrate(chain)
    if function:
        ch.function = function
    if callsite:
        ch.callsite = callsite
    if argument:
        ch.argument = argument
    if validation_seen is not None:
        ch.validation_seen = validation_seen
    if dataflow_traced is not None:
        ch.dataflow_traced = dataflow_traced
    ch.tier = infer_tier(ch)
    ch.confidence = compute_confidence(ch)
    ch.notes = _candidate_note(ch)
    return ch.to_dict()


def confirm_chain(chain: Dict[str, Any], evidence_ref: str = "") -> Dict[str, Any]:
    """Mark a chain as dynamically confirmed (raises its confidence)."""
    ch = chain.copy()
    ch["confirmed_dynamic"] = True
    if evidence_ref:
        ch.setdefault("evidence_refs", []).append(evidence_ref)
    obj = _rehydrate(ch)
    ch["tier"] = infer_tier(obj)
    ch["confidence"] = compute_confidence(obj)
    return ch


def from_session(session) -> List[Dict[str, Any]]:
    """Build candidate chains from the sinks and sources derived from the session's imports."""
    try:
        from . import sinks as _sinks
        imps = [i if isinstance(i, str) else (i.get("name") if isinstance(i, dict) else str(i))
                for i in (getattr(session, "static_imports", []) or [])]
        inv = _sinks.inventory([i for i in imps if i])
        sink_names = [api for apis in (inv.get("sinks") or {}).values() for api in apis]
        source_names = list((inv.get("sources") or {}).keys()) or ["argv[1]", "getenv", "recv"]
        # The full symbol list goes in so bounded counterparts of each sink class are spotted.
        return build_candidate_chains(source_names, sink_names, all_symbols=[i for i in imps if i])
    except Exception:
        return []
