"""MCP server: static reachability and symbolic reasoning with angr.

Closes the loop between the attack-surface server ("here is where input enters") and the
decompiler ("here is a dangerous call"): this one answers whether the two are actually connected.

A sink that no input can reach is not a vulnerability, it is noise in the report. Call-graph
reachability is cheap and reliable and rules out most of that noise automatically.

Symbolic execution is offered too, but with honest expectations: on a real-world Windows binary
it frequently fails to converge. Reachability first, symbolic only on a narrow, already-identified
target.

Requires angr (`pip install angr`). It is a heavy dependency — a venv is strongly recommended.
"""
from __future__ import annotations

import os
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Set, Tuple

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("reach")
CAP = 14000

# Cache CFGs: building one on a mid-sized binary takes minutes, and every tool here needs it.
_CACHE: Dict[str, Any] = {}

DANGEROUS = {
    "strcpy": "CWE-120", "strcat": "CWE-120", "sprintf": "CWE-120", "vsprintf": "CWE-120",
    "gets": "CWE-242", "memcpy": "CWE-120", "memmove": "CWE-120", "alloca": "CWE-770",
    "wcscpy": "CWE-120", "wcscat": "CWE-120", "lstrcpyA": "CWE-120", "lstrcpyW": "CWE-120",
    "lstrcatA": "CWE-120", "lstrcatW": "CWE-120", "swprintf": "CWE-120",
    "system": "CWE-78", "popen": "CWE-78", "_popen": "CWE-78", "execve": "CWE-78",
    "WinExec": "CWE-78", "CreateProcessA": "CWE-78", "CreateProcessW": "CWE-78",
    "ShellExecuteA": "CWE-78", "ShellExecuteW": "CWE-78", "_wsystem": "CWE-78",
    "LoadLibraryA": "CWE-427", "LoadLibraryW": "CWE-427", "LoadLibraryExA": "CWE-427",
    "LoadLibraryExW": "CWE-427", "dlopen": "CWE-427",
    "printf": "CWE-134", "fprintf": "CWE-134", "syslog": "CWE-134",
    "malloc": "CWE-190", "calloc": "CWE-190", "realloc": "CWE-190", "HeapAlloc": "CWE-190",
    "free": "CWE-415", "HeapFree": "CWE-415",
}


def _cap(s: str) -> str:
    return s[:CAP] + "\n…(truncated)" if len(s) > CAP else s


def _angr():
    try:
        import angr
        import logging
        # angr is extremely chatty; without this the MCP transport drowns in log lines.
        for noisy in ("angr", "cle", "pyvex", "claripy", "archinfo"):
            logging.getLogger(noisy).setLevel(logging.ERROR)
        return angr, None
    except ImportError:
        return None, ("angr is not installed. Install it with: pip install angr\n"
                      "It is a heavy dependency (~1 GB): use a dedicated virtualenv.\n"
                      "On Windows it may need the Visual C++ Build Tools.")


def _load(path: str, force: bool = False) -> Tuple[Any, Optional[str]]:
    """Build (and cache) the project and a fast CFG."""
    angr, err = _angr()
    if err:
        return None, err
    if not os.path.isfile(path):
        return None, f"file not found: {path}"
    key = os.path.abspath(path)
    if not force and key in _CACHE:
        return _CACHE[key], None
    try:
        proj = angr.Project(path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast(normalize=True, show_progressbar=False)
    except Exception as e:  # noqa: BLE001
        return None, (f"angr: could not build the CFG: {e}\n"
                      "Typical causes: packed binary, unsupported format, or an exotic "
                      "architecture. If the binary is packed, unpack it first.")
    entry = {"proj": proj, "cfg": cfg, "path": key}
    _CACHE[key] = entry
    return entry, None


def _func_name(proj, addr) -> str:
    try:
        f = proj.kb.functions.get(addr)
        return f.name if f else hex(addr)
    except Exception:  # noqa: BLE001
        return hex(addr)


def _build_callgraph(ctx) -> Tuple[Dict[int, Set[int]], Dict[int, Set[int]]]:
    """Forward and reverse call graphs keyed by function address."""
    cfg = ctx["cfg"]
    fwd: Dict[int, Set[int]] = defaultdict(set)
    rev: Dict[int, Set[int]] = defaultdict(set)
    try:
        cg = cfg.functions.callgraph
        for caller, callee in cg.edges():
            fwd[caller].add(callee)
            rev[callee].add(caller)
    except Exception:  # noqa: BLE001
        pass
    return fwd, rev


def _is_synthetic(proj, addr: int) -> bool:
    """angr places SimProcedure hooks in a synthetic `extern_object`. Those addresses are not real
    code in the target and appear as phantom duplicates of every hooked import."""
    for attr in ("extern_object", "kernel_object"):
        try:
            obj = getattr(proj.loader, attr, None)
            if obj is not None and obj.min_addr <= addr <= obj.max_addr:
                return True
        except Exception:  # noqa: BLE001
            continue
    return False


def _resolve_targets(ctx, name: str) -> List[int]:
    """Find every function address matching a name (imports, PLT stubs, local functions),
    excluding angr's synthetic hook addresses."""
    proj, cfg = ctx["proj"], ctx["cfg"]
    hits = []
    low = name.lower()
    for addr, func in cfg.functions.items():
        if _is_synthetic(proj, addr):
            continue
        fn = (func.name or "")
        base = fn.lstrip("_").split("@")[0]
        if fn.lower() == low or base.lower() == low or base.rstrip("AW").lower() == low.rstrip("aw"):
            hits.append(addr)
    return hits


def _paths_to(rev: Dict[int, Set[int]], target: int, roots: Set[int],
              max_depth: int = 12, max_paths: int = 6) -> List[List[int]]:
    """BFS backwards from a sink to any entry root, returning shortest call chains."""
    paths: List[List[int]] = []
    queue = deque([[target]])
    seen: Set[int] = set()
    while queue and len(paths) < max_paths:
        path = queue.popleft()
        head = path[-1]
        if len(path) > max_depth:
            continue
        if head in roots and len(path) > 1:
            paths.append(list(reversed(path)))
            continue
        for caller in rev.get(head, ()):
            if caller in path:          # cycle
                continue
            key = (caller, len(path))
            if key in seen:
                continue
            seen.add(key)
            queue.append(path + [caller])
    return paths


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
@mcp.tool()
def build_cfg(path: str, force_rebuild: bool = False) -> str:
    """Build and cache the control-flow graph of a binary. Every other tool in this server needs it,
    and on a mid-sized binary it takes minutes, so do it once explicitly rather than paying the cost
    inside another call. Reports function count and how much of the binary was recovered."""
    ctx, err = _load(path, force=force_rebuild)
    if err:
        return err
    proj, cfg = ctx["proj"], ctx["cfg"]
    funcs = list(cfg.functions.values())
    named = [f for f in funcs if f.name and not f.name.startswith("sub_")]
    try:
        # networkx returns a view in some versions and a generator in others.
        nodes = cfg.graph.number_of_nodes()
    except Exception:  # noqa: BLE001
        nodes = sum(1 for _ in cfg.graph.nodes())
    lines = [f"# CFG: {os.path.basename(path)}",
             f"arch: {proj.arch.name}  |  entry point: {hex(proj.entry)}",
             f"functions recovered: {len(funcs)} ({len(named)} of them named)",
             f"CFG nodes: {nodes}"]
    if len(funcs) < 20:
        lines.append("\n⚠ Very few functions recovered: the binary is probably packed "
                     "or obfuscated. Static analysis will be blind until you unpack it.")
    lines.append("\nCFG cached. Now `reachable_sinks` to see which sinks are "
                 "actually reachable.")
    return _cap("\n".join(lines))


@mcp.tool()
def reachable_sinks(path: str, from_entry: bool = True, max_depth: int = 12) -> str:
    """List which dangerous functions are actually REACHABLE in the call graph, and which are not.

    This is the triage step that removes most false positives: an import table entry for strcpy
    proves nothing, because the call may sit in dead code or in a library path the program never
    takes. Only reachable sinks are worth spending decompiler time on.

    from_entry=true starts from the entry point; false also treats every exported function as a
    root, which is what you want for a DLL."""
    ctx, err = _load(path)
    if err:
        return err
    proj = ctx["proj"]
    fwd, rev = _build_callgraph(ctx)

    roots: Set[int] = {proj.entry}
    if not from_entry:
        try:
            for exp in (proj.loader.main_object.exports or []):
                a = getattr(exp, "rebased_addr", None)
                if a:
                    roots.add(a)
        except Exception:  # noqa: BLE001
            pass

    # Forward-reachable set from the roots, bounded by `max_depth` as the signature promises.
    # The argument used to be accepted and ignored, so "reachable within 12 calls" silently
    # meant "reachable at any depth".
    reachable: Set[int] = set()
    queue = deque((r, 0) for r in roots)
    while queue:
        cur, depth = queue.popleft()
        if cur in reachable:
            continue
        reachable.add(cur)
        if depth < max_depth:
            queue.extend((n, depth + 1) for n in fwd.get(cur, ()))

    found, unreachable = [], []
    for name, cwe in DANGEROUS.items():
        for addr in _resolve_targets(ctx, name):
            callers = rev.get(addr, set())
            entry = {"name": name, "cwe": cwe, "addr": addr,
                     "callers": len(callers),
                     "caller_names": sorted({_func_name(proj, c) for c in callers})[:8]}
            (found if addr in reachable else unreachable).append(entry)

    if not found and not unreachable:
        return ("No known sink found in the CFG.\n"
                "If the binary is statically linked the names may be missing: try "
                "`find_sink_imports` on the attack-surface server first, then look the addresses up "
                "in Ghidra and use `paths_to_address`.")

    lines = [f"# Reachable sinks: {os.path.basename(path)}",
             f"root: {'entry point' if from_entry else 'entry point + export'}"]
    if found:
        by_cwe: Dict[str, List[dict]] = defaultdict(list)
        for f in found:
            by_cwe[f["cwe"]].append(f)
        lines.append(f"\n## 🔴 Reachable ({len(found)}) — analyse these")
        for cwe, items in sorted(by_cwe.items()):
            lines.append(f"\n### {cwe}")
            for f in sorted(items, key=lambda x: -x["callers"]):
                lines.append(f"  - **{f['name']}** @ {hex(f['addr'])} — {f['callers']} callers")
                if f["caller_names"]:
                    lines.append(f"      from: {', '.join(f['caller_names'])}")
    if unreachable:
        lines.append(f"\n## ⚪ Not reachable ({len(unreachable)}) — probably dead code")
        lines.append("  " + ", ".join(sorted({u['name'] for u in unreachable})))
        lines.append("  _Present in the binary but not reachable from the chosen roots. "
                     "Do not report them without proof that they can be invoked: they may be, "
                     "through indirect calls the static CFG does not resolve._")
    lines.append("\n⚠ The static CFG does not resolve indirect calls (function pointers, "
                 "vtables, GetProcAddress). 'Not reachable' means 'not reachable by a "
                 "direct route', not 'dead for certain'.")
    return _cap("\n".join(lines))


@mcp.tool()
def paths_to_sink(path: str, sink_name: str, max_paths: int = 6, max_depth: int = 12) -> str:
    """Show the call chains that lead from an entry point to a specific dangerous function.

    This is the answer to 'can untrusted input actually get here', expressed as a concrete list of
    functions to read in the decompiler. Follow each chain forward looking for where the data comes
    from and whether a length check exists."""
    ctx, err = _load(path)
    if err:
        return err
    proj = ctx["proj"]
    _fwd, rev = _build_callgraph(ctx)

    targets = _resolve_targets(ctx, sink_name)
    if not targets:
        return (f"'{sink_name}' not found in the CFG.\n"
                "Check the exact name with `reachable_sinks`, or use `paths_to_address` "
                "if you already have the address from Ghidra.")

    roots: Set[int] = {proj.entry}
    try:
        for exp in (proj.loader.main_object.exports or []):
            a = getattr(exp, "rebased_addr", None)
            if a:
                roots.add(a)
    except Exception:  # noqa: BLE001
        pass

    lines = [f"# Paths to {sink_name}"]
    total = 0
    for t in targets:
        paths = _paths_to(rev, t, roots, max_depth, max_paths)
        if not paths:
            lines.append(f"\n## {hex(t)} — no path from an entry point or export")
            callers = rev.get(t, set())
            if callers:
                lines.append(f"  called from {len(callers)} functions, but none of them is "
                             "connected to the roots: probably an unresolved indirect call.")
            continue
        total += len(paths)
        lines.append(f"\n## {hex(t)} — {len(paths)} paths")
        for i, p in enumerate(paths, 1):
            chain = " → ".join(f"{_func_name(proj, a)}" for a in p)
            lines.append(f"  {i}. {chain}")
            lines.append(f"     ({' → '.join(hex(a) for a in p)})")
    if total:
        lines.append("\nOpen the intermediate functions of each chain in Ghidra and look for: where "
                     "the buffer comes from, which length is used, whether there is a check.")
    return _cap("\n".join(lines))


@mcp.tool()
def paths_to_address(path: str, target_address: str, max_paths: int = 6,
                     max_depth: int = 12) -> str:
    """Same as paths_to_sink but for an arbitrary address — use it when Ghidra has pointed you at
    an interesting function that has no recognisable import name (an inlined copy loop, a custom
    parser). target_address in hex, e.g. '0x401a20'."""
    ctx, err = _load(path)
    if err:
        return err
    proj = ctx["proj"]
    try:
        target = int(target_address, 16) if isinstance(target_address, str) else int(target_address)
    except ValueError:
        return f"invalid address: {target_address}"
    _fwd, rev = _build_callgraph(ctx)

    if target not in rev and target not in {a for a in ctx["cfg"].functions}:
        # Maybe it is inside a function rather than at its head.
        try:
            fn = ctx["cfg"].functions.floor_func(target)
            if fn:
                return (f"{target_address} is not the start of a function. "
                        f"Appartiene a `{fn.name}` @ {hex(fn.addr)}. "
                        f"Re-run with target_address={hex(fn.addr)}.")
        except Exception:  # noqa: BLE001
            pass
        return f"{target_address} is not in the CFG."

    roots: Set[int] = {proj.entry}
    try:
        for exp in (proj.loader.main_object.exports or []):
            a = getattr(exp, "rebased_addr", None)
            if a:
                roots.add(a)
    except Exception:  # noqa: BLE001
        pass

    paths = _paths_to(rev, target, roots, max_depth, max_paths)
    if not paths:
        return (f"No path from an entry point/export to {target_address}.\n"
                "It may be dead code, or reached only through an indirect call.")
    lines = [f"# Paths to {target_address} ({_func_name(proj, target)}) — {len(paths)}"]
    for i, p in enumerate(paths, 1):
        lines.append(f"  {i}. " + " → ".join(_func_name(proj, a) for a in p))
    return _cap("\n".join(lines))


@mcp.tool()
def function_callers(path: str, function_name: str) -> str:
    """List the direct callers of a function, with their addresses. The quick lookup for
    'who calls this' without computing full paths."""
    ctx, err = _load(path)
    if err:
        return err
    proj = ctx["proj"]
    _fwd, rev = _build_callgraph(ctx)
    targets = _resolve_targets(ctx, function_name)
    if not targets:
        return f"'{function_name}' not found in the CFG."
    lines = []
    for t in targets:
        callers = rev.get(t, set())
        lines.append(f"## {_func_name(proj, t)} @ {hex(t)} — {len(callers)} direct callers")
        for c in sorted(callers):
            lines.append(f"  - {_func_name(proj, c)} @ {hex(c)}")
    return _cap("\n".join(lines))


@mcp.tool()
def find_input_to_sink_flow(path: str, source_name: str, sink_name: str,
                            max_depth: int = 15) -> str:
    """Check whether a data-flow path plausibly exists between an input source (recv, ReadFile,
    fgets, GetCommandLineW, ...) and a dangerous sink, by looking for functions that call both, or
    call chains that pass through both.

    This is a call-graph heuristic, NOT a real taint analysis: it tells you where to look, and a
    hit still has to be confirmed by reading the decompiled code. It is deliberately conservative
    about saying anything is confirmed."""
    ctx, err = _load(path)
    if err:
        return err
    proj = ctx["proj"]
    fwd, rev = _build_callgraph(ctx)

    sources = _resolve_targets(ctx, source_name)
    sinks = _resolve_targets(ctx, sink_name)
    if not sources:
        return f"source '{source_name}' not found in the CFG."
    if not sinks:
        return f"sink '{sink_name}' not found in the CFG."

    src_callers = {c for s in sources for c in rev.get(s, set())}
    sink_callers = {c for s in sinks for c in rev.get(s, set())}
    direct = src_callers & sink_callers

    lines = [f"# Flow {source_name} → {sink_name}"]
    if direct:
        lines.append(f"\n## 🔴 {len(direct)} functions call BOTH")
        lines.append("_Top priority: the same function reads input and passes it to a sink. "
                     "The classic pattern. Decompile these first._")
        for f in sorted(direct):
            lines.append(f"  - **{_func_name(proj, f)}** @ {hex(f)}")
    else:
        lines.append("\nNo function calls both the source and the sink directly.")

    # Indirect: a source caller that transitively reaches a sink caller.
    indirect = []
    for sc in src_callers:
        seen: Set[int] = set()
        queue = deque([(sc, 0)])
        while queue:
            cur, d = queue.popleft()
            if cur in seen or d > max_depth:
                continue
            seen.add(cur)
            if cur in sink_callers and cur != sc:
                indirect.append((sc, cur, d))
                break
            queue.extend((n, d + 1) for n in fwd.get(cur, ()))
    if indirect:
        lines.append(f"\n## 🟠 {len(indirect)} indirect paths")
        for sc, tc, d in indirect[:15]:
            lines.append(f"  - {_func_name(proj, sc)} → …({d} hop)… → {_func_name(proj, tc)}")
        lines.append("_The data may travel along these chains. Check that it is the same "
                     "buffer and not two unrelated values._")

    if not direct and not indirect:
        lines.append("\n⚪ No connection found in the call graph. Not proof of "
                     "absence: indirect calls, globals and shared buffers "
                     "escape this analysis.")
    else:
        lines.append("\n⚠ Call-graph heuristic, not taint analysis. A result says "
                     "where to look, it is not a finding: confirm it by reading the "
                     "decompiled code before reporting it.")
    return _cap("\n".join(lines))


@mcp.tool()
def clear_cache() -> str:
    """Drop the cached CFGs. Use after recompiling or patching the target, otherwise the analysis
    keeps using the stale graph."""
    n = len(_CACHE)
    _CACHE.clear()
    return f"Cache cleared ({n} CFGs removed)."


if __name__ == "__main__":
    mcp.run()
