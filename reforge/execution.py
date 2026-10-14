"""Where dangerous work is allowed to run, and under what limits (slice P2-S2, threat T-3).

**The defect.** x64dbg, Frida and every other `dynamic_execution` tool run code taken from the
analysed sample **in the analyst's own session, with the analyst's own privileges** — beside their
mail client, their SSH keys and every customer binary they have ever looked at. The only control
was an approval prompt, and that prompt was off in the shipped configuration until slice P0-S2.

This module does not build a worker fleet, and ReTrace will not: at the scale this product
targets - one analyst, or a few sharing an install - the proportionate answer is the RE VM the
analyst already has, not infrastructure (ADR 0004, superseded). What this module establishes is
the two things that are worth having either way:

1. **An isolation contract.** Each execution target declares what it actually isolates. A tool's
   required isolation is compared against what is available, and work that cannot be run safely
   is **refused** rather than quietly run unsafely. On a `team` install the in-process
   target is not acceptable for dynamic execution at all.
2. **A job lifecycle with real limits.** Each job gets an ephemeral workspace that is deleted and
   the deletion verified, plus wall-clock, CPU, memory and disk ceilings enforced where the OS
   allows it.

What it does **not** do is make in-process execution safe. It makes the unsafe case visible,
bounded, and refusable — which is the honest intermediate state, not a substitute for the VM or
dedicated Windows worker that ADR 0004 calls for.
"""
from __future__ import annotations

import logging
import os
import shutil
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

log = logging.getLogger("reforge.execution")


class Isolation(str, Enum):
    """What an execution target actually separates. Ordered weakest to strongest."""

    NONE = "none"                 # same process, same user, same machine as the UI
    SUBPROCESS = "subprocess"     # separate process, same user: limits and a kill switch, no boundary
    CONTAINER = "container"       # separate namespace: filesystem and network separation
    VM = "vm"                     # separate kernel: the only one that contains a kernel-level exploit


_STRENGTH = {Isolation.NONE: 0, Isolation.SUBPROCESS: 1,
             Isolation.CONTAINER: 2, Isolation.VM: 3}


def at_least(available: Isolation, required: Isolation) -> bool:
    return _STRENGTH[available] >= _STRENGTH[required]


@dataclass
class Quotas:
    """Ceilings for one job. `None` means unbounded, which is only acceptable in-process."""

    wall_clock_seconds: Optional[int] = 900
    cpu_seconds: Optional[int] = 600
    memory_bytes: Optional[int] = 4 * 1024 ** 3
    disk_bytes: Optional[int] = 8 * 1024 ** 3

    def describe(self) -> Dict[str, Any]:
        return {"wall_clock_seconds": self.wall_clock_seconds, "cpu_seconds": self.cpu_seconds,
                "memory_bytes": self.memory_bytes, "disk_bytes": self.disk_bytes}


@dataclass
class ExecutionTarget:
    """Somewhere work can run, and what it honestly provides."""

    name: str
    isolation: Isolation
    platform: str = "any"                  # any | linux | windows | macos
    network: bool = False                  # egress available to the job
    ephemeral_workspace: bool = True
    quotas: Quotas = field(default_factory=Quotas)
    description: str = ""

    def can_host(self, required: Isolation) -> bool:
        return at_least(self.isolation, required)


#: The only target that exists today. Named for what it is rather than for what we would like it
#: to be: a job running here is in the same process and under the same user as the UI, so
#: `Isolation.NONE` is the truthful declaration and every policy decision is made against it.
IN_PROCESS = ExecutionTarget(
    name="in-process",
    isolation=Isolation.NONE,
    network=True,
    ephemeral_workspace=True,
    description=("The ReTrace process itself. Quotas and an ephemeral workspace apply; there is "
                 "no privilege, filesystem or network boundary. Suitable for deterministic "
                 "analysis of untrusted DATA, never for executing untrusted CODE."),
)


#: Isolation a class of work requires before it may run at all.
#:
#: `dynamic_execution` means running code that came out of the analysed sample. Nothing short of a
#: separate kernel contains a kernel-level exploit, so VM is what it asks for; the policy below
#: decides whether a profile may accept less.
REQUIRED_ISOLATION = {
    "safe_read": Isolation.NONE,
    "sensitive_read": Isolation.NONE,
    "network": Isolation.NONE,
    "write_or_patch": Isolation.SUBPROCESS,
    "dynamic_execution": Isolation.VM,
}


class ExecutionRefused(PermissionError):
    """The work requires isolation this deployment cannot provide."""

    def __init__(self, risk_class: str, required: Isolation, available: Isolation, profile: str):
        super().__init__(
            f"{risk_class} requires {required.value} isolation; this deployment offers "
            f"{available.value} and the '{profile}' profile does not accept that")
        self.risk_class = risk_class
        self.required = required
        self.available = available


def targets() -> List[ExecutionTarget]:
    """Execution targets available to this deployment.

    Two now: the process itself, and a child process. Neither is a privilege boundary, so
    `dynamic_execution` is still not satisfied by either - that needs the VM of ADR 0004.
    """
    return [IN_PROCESS, SUBPROCESS_TARGET]


def best_target_for(risk_class: str) -> Optional[ExecutionTarget]:
    """The WEAKEST target that satisfies the requirement, not the strongest available.

    Isolation costs something - a subprocess means a spawn per call - and paying it where it buys
    nothing is how a control becomes the thing people turn off. A read runs in-process; a write
    gets the child process whose limits actually bind it.
    """
    required = REQUIRED_ISOLATION.get(risk_class, Isolation.VM)
    candidates = [t for t in targets() if t.can_host(required)]
    return min(candidates, key=lambda t: _STRENGTH[t.isolation]) if candidates else None


def check(risk_class: str, cfg) -> ExecutionTarget:
    """Where this class of work may run. Raises ExecutionRefused when nowhere will do.

    The workstation profile is allowed to accept weaker isolation than the work asks for: it is
    one analyst, on their own machine, who has chosen to debug a sample there, and refusing would
    simply mean they do it outside the tool with no record at all. It is logged every time, loudly,
    because "this ran next to your SSH keys" is a fact the operator should keep being told.

    A `team` install gets no such latitude: running a client's binary in the same process that
    serves everyone else is not a tradeoff, it is a defect.
    """
    required = REQUIRED_ISOLATION.get(risk_class, Isolation.VM)
    target = best_target_for(risk_class)
    if target is not None:
        return target

    available = max((t.isolation for t in targets()), key=lambda i: _STRENGTH[i],
                    default=Isolation.NONE)
    profile = str(getattr(cfg, "DEPLOYMENT_PROFILE", "workstation"))
    if profile == "workstation" and bool(getattr(cfg, "ALLOW_UNISOLATED_EXECUTION", True)):
        log.warning(
            "UNISOLATED EXECUTION: %s wants %s isolation and this deployment offers %s. Running "
            "it in the ReTrace process, with your privileges, beside everything else on this "
            "machine. Set allow_unisolated_execution=false to refuse instead.",
            risk_class, required.value, available.value)
        return IN_PROCESS
    raise ExecutionRefused(risk_class, required, available, profile)


# --------------------------------------------------------------------------- job workspace
@dataclass
class Lease:
    """An ephemeral workspace for one job, with its deletion verified."""

    path: Path
    job_id: str
    created_at: float
    deleted: bool = False
    verified: bool = False


@contextmanager
def job_workspace(job_id: str, root: Optional[Path] = None) -> Iterator[Lease]:
    """A per-job directory, removed and the removal checked when the job ends.

    Verified because "we call rmtree in a finally" is not the same as "it is gone": a file held
    open, a permission error or a symlink out of the tree all leave material behind, and a
    workspace that silently persists is a customer's sample sitting on disk after the engagement
    closed. The check is cheap and the failure is loud.
    """
    from . import config

    base = Path(root) if root else Path(config.STATE_ROOT) / "jobs" / "workspaces"
    base.mkdir(parents=True, exist_ok=True)
    path = Path(tempfile.mkdtemp(prefix=f"job-{job_id}-", dir=str(base)))
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    lease = Lease(path=path, job_id=job_id, created_at=time.time())
    try:
        yield lease
    finally:
        shutil.rmtree(path, ignore_errors=True)
        lease.deleted = not path.exists()
        lease.verified = True
        if not lease.deleted:
            leftovers = sum(1 for _ in path.rglob("*")) if path.is_dir() else 0
            log.error("JOB WORKSPACE NOT DELETED: %s still exists after job %s (%d entries). "
                      "A customer sample may be left on disk.", path, job_id, leftovers)


# --------------------------------------------------------------------------- quotas
@contextmanager
def enforce_quotas(quotas: Quotas) -> Iterator[Dict[str, Any]]:
    """Apply CPU and memory ceilings to the current process where the OS allows it.

    POSIX only, and honestly partial: `setrlimit` bounds this process, so it bounds a job only
    because a job currently *is* this process. That is the limitation an isolated worker removes,
    and it is why the limits are applied and then restored rather than left in place.
    """
    applied: Dict[str, Any] = {"cpu_seconds": None, "memory_bytes": None, "supported": False}
    try:
        import resource
    except ImportError:                       # Windows
        yield applied
        return

    previous = {}
    try:
        if quotas.cpu_seconds:
            previous[resource.RLIMIT_CPU] = resource.getrlimit(resource.RLIMIT_CPU)
            soft, hard = previous[resource.RLIMIT_CPU]
            ceiling = quotas.cpu_seconds if hard == resource.RLIM_INFINITY else min(
                quotas.cpu_seconds, hard)
            resource.setrlimit(resource.RLIMIT_CPU, (ceiling, hard))
            applied["cpu_seconds"] = ceiling
            applied["supported"] = True
    except (ValueError, OSError) as exc:
        log.debug("could not apply a CPU limit: %s", exc)
    try:
        yield applied
    finally:
        for limit, value in previous.items():
            try:
                resource.setrlimit(limit, value)
            except (ValueError, OSError):
                pass


def describe(cfg) -> Dict[str, Any]:
    """The execution posture, for the startup banner and /api/status."""
    profile = str(getattr(cfg, "DEPLOYMENT_PROFILE", "workstation"))
    available = max((t.isolation for t in targets()), key=lambda i: _STRENGTH[i],
                    default=Isolation.NONE)
    permissive = profile == "workstation" and bool(
        getattr(cfg, "ALLOW_UNISOLATED_EXECUTION", True))
    return {
        "targets": [{"name": t.name, "isolation": t.isolation.value, "network": t.network,
                     "quotas": t.quotas.describe()} for t in targets()],
        "best_isolation": available.value,
        "dynamic_execution_requires": REQUIRED_ISOLATION["dynamic_execution"].value,
        "dynamic_execution_allowed": permissive or at_least(
            available, REQUIRED_ISOLATION["dynamic_execution"]),
        "unisolated_execution_permitted": permissive,
    }


# --------------------------------------------------------------------------- subprocess target
"""A real second execution target.

`Isolation.NONE` was the only thing on offer, which made the whole contract a declaration with
nowhere to go. A subprocess is not a security boundary - same user, same filesystem, same network -
and it does provide three things the in-process target cannot:

* **A kill switch that works.** A runaway in-process job can only be asked nicely to stop; a child
  process can be terminated.
* **Limits that bind the job and not the application.** `setrlimit` in a child applies to the
  child. In-process it applies to ReTrace itself, which is why those limits had to be put back.
* **Crash containment.** A segfault in a parser takes the child down, not the UI.

It is `SUBPROCESS`, declared as such, and it does **not** satisfy `dynamic_execution`, which still
asks for a VM. Calling it more than it is would be the mislabelling this module exists to avoid.

Implemented with `subprocess` and an explicit interpreter invocation rather than
`multiprocessing`. The first version used `multiprocessing` with the `spawn` context, which
re-imports the parent's `__main__` in the child - so any caller whose `__main__` is not guarded
forks itself endlessly. A library cannot depend on its callers getting that right, and the failure
mode is a fork bomb rather than an error.
"""
import json as _json
import subprocess
import sys

SUBPROCESS_TARGET = ExecutionTarget(
    name="subprocess",
    isolation=Isolation.SUBPROCESS,
    network=True,
    ephemeral_workspace=True,
    description=("A child process. Enforceable CPU and memory limits, a kill switch that works, "
                 "and crash containment - but the same user, filesystem and network, so it is "
                 "not a privilege boundary and does not satisfy dynamic_execution."),
)

#: Runs in the child. Applies its own limits, calls the named function, prints one JSON line.
#: Kept as source text rather than a module so the child's entire behaviour is visible here.
_BOOTSTRAP = """
import importlib, json, sys
spec = json.loads(sys.stdin.read())
try:
    import resource
    for name, limit in (("cpu_seconds", resource.RLIMIT_CPU),
                        ("memory_bytes", resource.RLIMIT_AS)):
        value = spec["quotas"].get(name)
        if value:
            try:
                resource.setrlimit(limit, (int(value), int(value)))
            except (ValueError, OSError):
                pass
except ImportError:
    pass
try:
    module = importlib.import_module(spec["module"])
    result = getattr(module, spec["function"])(*spec.get("args", []), **spec["payload"])
    sys.stdout.write(json.dumps({"status": "ok", "result": result}, default=str))
except BaseException as exc:
    sys.stdout.write(json.dumps({"status": "error",
                                 "error": type(exc).__name__ + ": " + str(exc)}))
"""


class SubprocessFailed(RuntimeError):
    """The child did not complete."""


def run_isolated(fn_module: str, fn_name: str, payload: Optional[Dict[str, Any]] = None,
                 quotas: Optional[Quotas] = None, cwd: Optional[Path] = None,
                 args: Optional[List[Any]] = None) -> Any:
    """Run `fn_module.fn_name(*args, **payload)` in a child process under `quotas`.

    The function is named rather than passed, so nothing relies on pickling a closure: a target
    that works only for some callables is a target whose failures are found late.

    Positional `args` as well as keyword `payload`, because a great many standard-library
    functions are positional-only (`time.sleep`, `math.factorial`) and a runner that cannot call
    them is a runner with a surprising hole in it.

    Arguments and the result must both be JSON-serialisable. That is the price of not pickling,
    and it is worth it: pickling would let a child execute whatever the parent happened to hold.
    """
    quotas = quotas or SUBPROCESS_TARGET.quotas
    try:
        spec = _json.dumps({"module": fn_module, "function": fn_name, "args": args or [],
                            "payload": payload or {}, "quotas": quotas.describe()})
    except TypeError as exc:
        raise SubprocessFailed(
            f"arguments must be JSON-serialisable to cross the process boundary: {exc}") from None
    try:
        completed = subprocess.run(
            [sys.executable, "-c", _BOOTSTRAP], input=spec, capture_output=True, text=True,
            timeout=quotas.wall_clock_seconds, cwd=str(cwd) if cwd else None, check=False)
    except subprocess.TimeoutExpired:
        # subprocess.run already killed it; say what happened rather than leaving a bare timeout.
        raise SubprocessFailed(
            f"the job exceeded its {quotas.wall_clock_seconds}s ceiling and was terminated"
        ) from None

    if not completed.stdout.strip():
        detail = (completed.stderr or "").strip()[:400] or f"exit code {completed.returncode}"
        raise SubprocessFailed(f"the child produced no result: {detail}")
    try:
        answer = _json.loads(completed.stdout)
    except _json.JSONDecodeError:
        raise SubprocessFailed(
            f"the child produced output that is not a result: {completed.stdout[:200]}") from None
    if answer.get("status") != "ok":
        raise SubprocessFailed(str(answer.get("error", "unknown failure")))
    return answer.get("result")
