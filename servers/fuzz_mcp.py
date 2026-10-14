"""MCP server: fuzzing campaign management and crash triage.

Fuzzers are good at producing crashes and terrible at telling you which ones matter. A campaign
routinely yields thousands of crash files that collapse into three or four actual bugs. This server
handles the unglamorous part: corpus hygiene, crash deduplication, and severity classification, so
the time goes into analysing distinct bugs instead of re-reading the same one.

Classification is deliberately triage-level (what kind of memory error, how likely it is to be
exploitable) — the goal is prioritising the report, not weaponising anything.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional

# Resolve external tools without depending on the PATH the MCP client happened to inherit.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _toolpath import resolve as _tool

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("fuzz")
CAP = 14000
IS_WIN = sys.platform.startswith("win")


def _cap(s: str) -> str:
    return s[:CAP] + "\n…(truncated)" if len(s) > CAP else s


def _run(cmd: List[str], timeout: int = 120, stdin_data: Optional[bytes] = None) -> Dict[str, Any]:
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, input=stdin_data)
        return {"ok": True, "out": (p.stdout or b"").decode("utf-8", "replace"),
                "err": (p.stderr or b"").decode("utf-8", "replace"), "rc": p.returncode}
    except FileNotFoundError:
        return {"ok": False, "err": f"not found: {cmd[0]}"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "err": "timeout", "timeout": True}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "err": str(e)}


def _sha(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Crash classification
# ---------------------------------------------------------------------------
# Heuristics adapted from the classic !exploitable / CERT triage rules.
SIGNALS = {
    "SIGSEGV": "invalid memory access",
    "SIGBUS": "misaligned access or invalid mapping",
    "SIGFPE": "arithmetic error",
    "SIGABRT": "abort (often an assert or internal corruption detection)",
    "SIGILL": "illegal instruction (often corrupted control flow)",
}

ASAN_CLASSES = {
    "heap-buffer-overflow": ("high", "CWE-122", "heap overflow: a write or read beyond "
                                                "the bounds of an allocation"),
    "stack-buffer-overflow": ("critical", "CWE-121", "stack overflow: potential control "
                                                     "of the execution flow"),
    "global-buffer-overflow": ("high", "CWE-120", "overflow on a global buffer"),
    "heap-use-after-free": ("critical", "CWE-416", "use-after-free: a powerful primitive, often "
                                                   "exploitable"),
    "double-free": ("high", "CWE-415", "double free: corruption of the allocator's metadata"),
    "stack-overflow": ("low", "CWE-674", "stack exhaustion through recursion: typically "
                                         "DoS only"),
    "attempting-free-on-address": ("high", "CWE-590", "free on an address that was not allocated"),
    "SEGV on unknown address": ("medium", "CWE-476", "invalid pointer dereference"),
    "use-after-poison": ("high", "CWE-416", "access to poisoned memory"),
    "alloc-dealloc-mismatch": ("medium", "CWE-762", "allocator/deallocator mismatch"),
    "memory leaks": ("info", "CWE-401", "memory leak: availability impact"),
    "int-divide-by-zero": ("low", "CWE-369", "division by zero"),
    "negative-size-param": ("high", "CWE-190", "negative size: probable integer overflow "
                                               "upstream"),
}


def _classify_output(text: str) -> Dict[str, Any]:
    """Classify a crash from sanitizer / debugger output."""
    low = text.lower()
    for marker, (sev, cwe, desc) in ASAN_CLASSES.items():
        if marker.lower() in low:
            res = {"class": marker, "severity": sev, "cwe": cwe, "description": desc}
            # A write is materially worse than a read.
            if re.search(r"\bWRITE of size\b", text):
                res["access"] = "WRITE"
                if sev in ("medium", "high"):
                    res["severity"] = "critical" if sev == "high" else "high"
                res["note"] = "WRITE access: makes exploitability considerably worse"
            elif re.search(r"\bREAD of size\b", text):
                res["access"] = "READ"
                res["note"] = "READ access: more often an info leak or DoS than RCE"
            return res

    m = re.search(r"SIGSEGV|SIGBUS|SIGFPE|SIGABRT|SIGILL", text)
    if m:
        return {"class": m.group(0), "severity": "medium", "cwe": "CWE-119",
                "description": SIGNALS.get(m.group(0), "crash")}
    if re.search(r"0xc0000005|ACCESS_VIOLATION|Access violation", text, re.I):
        near_null = re.search(r"0x0{4,8}(?:\b|[^0-9a-f])", text)
        return {"class": "access_violation",
                "severity": "low" if near_null else "high",
                "cwe": "CWE-476" if near_null else "CWE-119",
                "description": ("null pointer dereference: typically DoS only"
                                if near_null else
                                "access violation at a non-null address: possible corruption")}
    if re.search(r"0xc0000409|STACK_BUFFER_OVERRUN|stack smashing", text, re.I):
        return {"class": "stack_cookie", "severity": "high", "cwe": "CWE-121",
                "description": "stack canary tripped: stack overflow confirmed"}
    if re.search(r"0xc0000374|heap corruption|HEAP_CORRUPTION", text, re.I):
        return {"class": "heap_corruption", "severity": "high", "cwe": "CWE-122",
                "description": "heap corruption detected by the allocator"}
    return {"class": "unknown", "severity": "info", "cwe": "",
            "description": "no recognised crash pattern in the output"}


def _stack_hash(text: str, frames: int = 5) -> str:
    """Dedup key from the top N stack frames, normalised to drop addresses and offsets.
    Two crashes with the same top frames are almost always the same bug."""
    found: List[str] = []
    for line in text.splitlines():
        m = re.search(r"#\d+\s+0x[0-9a-f]+\s+in\s+([^\s(]+)", line)          # ASAN / gdb
        if not m:
            m = re.search(r"^\s*[0-9a-f`]+\s+[0-9a-f`]+\s+(\S+!\S+)", line)  # cdb / windbg
        if m:
            fn = re.sub(r"\+0x[0-9a-f]+$", "", m.group(1))
            found.append(fn)
        if len(found) >= frames:
            break
    if not found:
        return ""
    return hashlib.sha256("|".join(found).encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
@mcp.tool()
def corpus_stats(corpus_dir: str) -> str:
    """Summarise a fuzzing corpus: file count, size distribution, exact duplicates, and the mix of
    file magics. A corpus full of duplicates or of a single size wastes fuzzing cycles."""
    if not os.path.isdir(corpus_dir):
        return f"directory not found: {corpus_dir}"
    files = [os.path.join(corpus_dir, f) for f in os.listdir(corpus_dir)
             if os.path.isfile(os.path.join(corpus_dir, f))]
    if not files:
        return "Empty corpus."
    sizes = []
    hashes: Dict[str, List[str]] = defaultdict(list)
    magics: Counter[str] = Counter()
    for f in files:
        try:
            sizes.append(os.path.getsize(f))
            hashes[_sha(f)].append(f)
            with open(f, "rb") as fh:
                magics[fh.read(4).hex()] += 1
        except OSError:
            continue
    dupes = {h: v for h, v in hashes.items() if len(v) > 1}
    wasted = sum(len(v) - 1 for v in dupes.values())
    sizes.sort()
    lines = [f"# Corpus: {corpus_dir}",
             f"files: {len(files)}  |  unique: {len(hashes)}  |  exact duplicates: {wasted}",
             f"sizes: min={sizes[0]}  median={sizes[len(sizes) // 2]}  "
             f"max={sizes[-1]}  total={sum(sizes) / 1024:.1f} KB"]
    if wasted:
        lines.append(f"\n⚠ {wasted} duplicate files ({100 * wasted / len(files):.0f}%): "
                     "use `corpus_minimize` to remove them.")
    if sizes[-1] > 1024 * 1024:
        lines.append(f"\n⚠ largest file {sizes[-1] / 1024 / 1024:.1f} MB: large inputs "
                     "slow fuzzing down a lot. Consider trimming them.")
    lines.append("\n## Most common magic bytes")
    for magic, n in magics.most_common(8):
        lines.append(f"  {magic}  ×{n}")
    if len(magics) == 1:
        lines.append("\n⚠ a single magic: the corpus covers one input type only. "
                     "More variety = more coverage.")
    return _cap("\n".join(lines))


@mcp.tool()
def corpus_minimize(corpus_dir: str, output_dir: str = "", max_size_kb: int = 0,
                    dry_run: bool = True) -> str:
    """Remove exact duplicates from a corpus, and optionally drop files above a size threshold.
    Keeps the smallest file of each duplicate set, because smaller inputs run faster.

    dry_run=true (default) only reports what would change. Set output_dir to copy the minimized
    corpus elsewhere instead of deleting in place."""
    if not os.path.isdir(corpus_dir):
        return f"directory not found: {corpus_dir}"
    files = [os.path.join(corpus_dir, f) for f in os.listdir(corpus_dir)
             if os.path.isfile(os.path.join(corpus_dir, f))]
    groups: Dict[str, List[str]] = defaultdict(list)
    oversized = []
    for f in files:
        try:
            if max_size_kb and os.path.getsize(f) > max_size_kb * 1024:
                oversized.append(f)
                continue
            groups[_sha(f)].append(f)
        except OSError:
            continue
    keep = [min(v, key=lambda p: os.path.getsize(p)) for v in groups.values()]
    drop = [f for v in groups.values() for f in v if f not in keep] + oversized

    lines = [f"# Corpus minimisation: {corpus_dir}",
             f"original: {len(files)}  |  to keep: {len(keep)}  |  to discard: {len(drop)}"]
    if oversized:
        lines.append(f"  di cui {len(oversized)} oltre {max_size_kb} KB")
    if dry_run:
        lines.append("\n**dry_run=true**: nothing was changed. "
                     "Re-run with dry_run=false to apply.")
        return _cap("\n".join(lines))

    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        for f in keep:
            shutil.copy2(f, os.path.join(output_dir, os.path.basename(f)))
        lines.append(f"\n✅ {len(keep)} files copied to {output_dir} (originals untouched).")
    else:
        removed = 0
        for f in drop:
            try:
                os.remove(f)
                removed += 1
            except OSError:
                pass
        lines.append(f"\n✅ {removed} file(s) removed from {corpus_dir}.")
    return _cap("\n".join(lines))


@mcp.tool()
def triage_crash(binary: str, crash_file: str, args_template: str = "@@",
                 timeout: int = 30) -> str:
    """Run one crash input against the target under a debugger and classify the resulting fault:
    what kind of memory error, which CWE, and how severe it is for reporting purposes.

    args_template uses @@ as the placeholder for the crash file path (AFL convention); use '-' to
    feed the input on stdin instead. Uses gdb on Linux and cdb on Windows when available, and falls
    back to sanitizer output on stderr."""
    if not os.path.isfile(binary):
        return f"binary not found: {binary}"
    if not os.path.isfile(crash_file):
        return f"crash file not found: {crash_file}"

    stdin_data = None
    if args_template.strip() == "-":
        argv = [binary]
        with open(crash_file, "rb") as fh:
            stdin_data = fh.read()
    else:
        argv = [binary] + [crash_file if a == "@@" else a for a in args_template.split()]

    debugger_out = ""
    if IS_WIN and _tool("cdb"):
        cmd = [_tool("cdb"), "-g", "-G", "-c", "g;.echo ---CRASH---;!analyze -v;q"] + argv
        r = _run(cmd, timeout)
        debugger_out = (r.get("out", "") + r.get("err", ""))
    elif not IS_WIN and _tool("gdb"):
        script = "run\necho ---CRASH---\\n\nbt 15\ninfo registers rip rsp\nquit\n"
        cmd = [_tool("gdb"), "-batch", "-nx", "-ex", "set confirm off"]
        for line in script.strip().split("\n"):
            cmd += ["-ex", line]
        cmd += ["--args"] + argv
        r = _run(cmd, timeout, stdin_data)
        debugger_out = (r.get("out", "") + r.get("err", ""))
    else:
        r = _run(argv, timeout, stdin_data)
        debugger_out = (r.get("out", "") + r.get("err", ""))

    if r.get("timeout"):
        return (f"# Triage: {os.path.basename(crash_file)}\n\n"
                f"⏱ **Hang**, not a crash: no termination within {timeout}s.\n"
                "A hang is still an availability finding (CWE-834 Excessive Iteration "
                "or CWE-835 Infinite Loop), but it is classified separately from crashes.")

    cls = _classify_output(debugger_out)
    shash = _stack_hash(debugger_out)
    rc = r.get("rc")

    lines = [f"# Triage: {os.path.basename(crash_file)}",
             f"target: `{binary}`",
             f"exit code: {rc}"]
    if cls["class"] == "unknown" and rc == 0:
        lines.append("\n✅ No crash: the target exited normally. "
                     "The input may no longer reproduce (state dependence, "
                     "ASLR, or a different build from the one fuzzed).")
        return "\n".join(lines)

    lines.append(f"\n## Classification\n"
                 f"- type: **{cls['class']}**\n"
                 f"- estimated severity: **{cls['severity']}**\n"
                 f"- CWE: {cls['cwe'] or 'n/d'}\n"
                 f"- {cls['description']}")
    if cls.get("access"):
        lines.append(f"- {cls.get('note', '')}")
    if shash:
        lines.append(f"\n**stack hash: `{shash}`** — use it to deduplicate: crashes with the same "
                     "hash are almost always the same bug.")
    else:
        lines.append("\n⚠ No extractable stack trace: without symbols deduplication is "
                     "unreliable. Build with symbols or use an ASAN build.")
    lines.append(f"\n<details>Output debugger\n{debugger_out[-3000:]}\n</details>")
    lines.append("\nIf you confirm the finding, record it with `finding_add` on the findings server.")
    return _cap("\n".join(lines))


@mcp.tool()
def dedup_crashes(binary: str, crashes_dir: str, args_template: str = "@@",
                  timeout: int = 20, max_files: int = 200) -> str:
    """Group a directory of crash files into distinct bugs by stack hash, and report one
    representative per group with its classification.

    This is the step that turns '3000 crashes' into 'four bugs, here they are, ranked'. Run it
    before doing any manual analysis."""
    if not os.path.isdir(crashes_dir):
        return f"directory not found: {crashes_dir}"
    files = sorted(os.path.join(crashes_dir, f) for f in os.listdir(crashes_dir)
                   if os.path.isfile(os.path.join(crashes_dir, f))
                   and not f.startswith(("README", ".")))
    if not files:
        return "No crash files found."
    truncated = len(files) > max_files
    files = files[:max_files]

    groups: Dict[str, Dict[str, Any]] = {}
    unclassified = 0
    for f in files:
        stdin_data = None
        if args_template.strip() == "-":
            argv = [binary]
            with open(f, "rb") as fh:
                stdin_data = fh.read()
        else:
            argv = [binary] + [f if a == "@@" else a for a in args_template.split()]
        if not IS_WIN and _tool("gdb"):
            cmd = [_tool("gdb"), "-batch", "-nx", "-ex", "set confirm off", "-ex", "run",
                   "-ex", "bt 15", "-ex", "quit", "--args"] + argv
            r = _run(cmd, timeout, stdin_data)
        else:
            r = _run(argv, timeout, stdin_data)
        out = r.get("out", "") + r.get("err", "")
        cls = _classify_output(out)
        h = _stack_hash(out) or f"nostack:{cls['class']}"
        if h not in groups:
            groups[h] = {"representative": f, "count": 0, "class": cls, "size": os.path.getsize(f)}
        groups[h]["count"] += 1
        # Keep the smallest reproducer: easier to analyse and to hand to the developer.
        if os.path.getsize(f) < groups[h]["size"]:
            groups[h]["representative"] = f
            groups[h]["size"] = os.path.getsize(f)
        if cls["class"] == "unknown":
            unclassified += 1

    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    ranked = sorted(groups.items(), key=lambda kv: -order.get(kv[1]["class"]["severity"], 0))

    lines = [f"# Crash deduplication: {crashes_dir}",
             f"{len(files)} files → **{len(groups)} distinct bugs**"]
    if truncated:
        lines.append(f"⚠ only the first {max_files} files were analysed (raise max_files)")
    if unclassified:
        lines.append(f"⚠ {unclassified} files with no recognisable crash pattern "
                     "(not reproducible?)")
    for h, g in ranked:
        cls = g["class"]
        lines.append(f"\n## [{cls['severity'].upper()}] {cls['class']}  ×{g['count']}")
        lines.append(f"- CWE: {cls['cwe'] or 'n/d'}")
        lines.append(f"- {cls['description']}")
        lines.append(f"- minimal reproducer: `{g['representative']}` ({g['size']} bytes)")
        lines.append(f"- stack hash: `{h}`")
    lines.append("\nDig into each group with `triage_crash` on the reproducer, "
                 "then record the confirmed ones with `finding_add`.")
    return _cap("\n".join(lines))


@mcp.tool()
def check_fuzzing_setup(binary: str = "") -> str:
    """Check which fuzzing and triage tooling is available, and suggest the right fuzzer for the
    situation. Run this before starting a campaign to avoid discovering a missing dependency
    three hours in."""
    tools = {
        "afl-fuzz": "AFL++ — sources available, compile-time instrumentation",
        "afl-clang-fast": "AFL++ compiler wrapper",
        "honggfuzz": "honggfuzz — a good alternative, also supports persistent mode",
        "radamsa": "radamsa — dumb mutator, useful for a quick first pass",
        "gdb": "gdb — crash triage on Linux",
        "cdb": "cdb — crash triage on Windows (Debugging Tools for Windows)",
        "valgrind": "valgrind — detects memory errors without recompiling (slow)",
        "syft": "syft — SBOM",
    }
    lines = ["# Available fuzzing tooling\n"]
    available = []
    for t, desc in tools.items():
        p = _tool(t)
        mark = "✅" if p else "—"
        lines.append(f"{mark} `{t}` — {desc}")
        if p:
            available.append(t)

    lines.append("\n## Choosing the fuzzer")
    lines.append("- **You have the sources**: AFL++ with `afl-clang-fast` and ASAN enabled. "
                 "Coverage-guided plus a sanitizer is the combination that finds the most bugs.")
    lines.append("- **Binary only, Windows**: WinAFL (DynamoRIO/TinyInst instrumentation) "
                 "or Jackalope. Neither installs onto the PATH; they have to be configured "
                 "a mano su un harness.")
    lines.append("- **Binary only, Linux**: AFL++ in QEMU mode (`-Q`), slower "
                 "but it needs no recompilation.")
    lines.append("\n## An often-overlooked prerequisite")
    lines.append("You need a **harness** that takes the input from the file to the parser as directly "
                 "as possible. Fuzzing the whole executable through its GUI yields "
                 "very few executions per second. Find the parsing function with the decompiler "
                 "and write a harness that calls only that.")

    if binary and os.path.isfile(binary):
        lines.append(f"\n## Notes on `{os.path.basename(binary)}`")
        try:
            with open(binary, "rb") as fh:
                magic = fh.read(4)
            if magic[:2] == b"MZ":
                lines.append("PE: on Windows consider WinAFL with TinyInst; first check with "
                             "`attack_surface_summary` which input format it parses.")
            elif magic == b"\x7fELF":
                lines.append("ELF: AFL++ QEMU mode is the fastest route without sources.")
        except OSError:
            pass
    return _cap("\n".join(lines))


if __name__ == "__main__":
    mcp.run()
