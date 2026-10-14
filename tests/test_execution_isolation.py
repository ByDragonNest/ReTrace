"""Where dangerous work may run, and under what limits (slice P2-S2, threat T-3).

**The defect.** x64dbg, Frida and every other `dynamic_execution` tool run code taken from the
analysed sample **in the analyst's own session, with the analyst's own privileges** — beside their
mail client, their SSH keys and every customer binary they have ever looked at. The only control
was an approval prompt, and that prompt was off in the shipped configuration until P0-S2.

This slice does not build a worker fleet, and ReTrace will not build one: the product targets a
single analyst and small teams, where the proportionate answer is the analyst's own RE VM. What
these tests cover is making the unsafe case visible, bounded and refusable — and refusing it
outright on a shared install.
"""
from __future__ import annotations

import asyncio
import pathlib

import pytest

from reforge import config, execution
from reforge.execution import ExecutionRefused, Isolation


class _Cfg:
    def __init__(self, profile="workstation", permissive=True):
        self.DEPLOYMENT_PROFILE = profile
        self.ALLOW_UNISOLATED_EXECUTION = permissive


# --------------------------------------------------------------------------- the contract
def test_each_target_declares_what_it_actually_isolates():
    """Named for what they are, not for what we would like them to be."""
    assert execution.IN_PROCESS.isolation is Isolation.NONE
    assert "no privilege, filesystem or network boundary" in execution.IN_PROCESS.description
    assert execution.SUBPROCESS_TARGET.isolation is Isolation.SUBPROCESS
    assert "not a privilege boundary" in execution.SUBPROCESS_TARGET.description


def test_isolation_levels_are_ordered():
    assert execution.at_least(Isolation.VM, Isolation.CONTAINER)
    assert execution.at_least(Isolation.SUBPROCESS, Isolation.NONE)
    assert not execution.at_least(Isolation.NONE, Isolation.SUBPROCESS)
    assert not execution.at_least(Isolation.CONTAINER, Isolation.VM)


def test_running_sample_code_asks_for_a_separate_kernel():
    """Nothing short of one contains a kernel-level exploit."""
    assert execution.REQUIRED_ISOLATION["dynamic_execution"] is Isolation.VM


def test_reading_data_needs_no_isolation():
    """The gate must not become a wall: static analysis of untrusted DATA is the normal case."""
    for low_risk in ("safe_read", "sensitive_read", "network"):
        assert execution.check(low_risk, _Cfg()) is execution.IN_PROCESS


def test_the_weakest_sufficient_target_is_chosen_not_the_strongest():
    """Isolation costs a spawn. Paying it where it buys nothing is how a control gets turned off."""
    assert execution.check("safe_read", _Cfg()) is execution.IN_PROCESS
    assert execution.check("write_or_patch", _Cfg()) is execution.SUBPROCESS_TARGET


# --------------------------------------------------------------------------- the decision
def test_a_shared_deployment_refuses_to_run_sample_code_in_the_control_plane():
    """Not a tradeoff on a shared install - a defect."""
    for shared in ("team",):
        with pytest.raises(ExecutionRefused) as exc:
            execution.check("dynamic_execution", _Cfg(shared, permissive=False))
        assert exc.value.required is Isolation.VM
        # The best on offer is a child process since the subprocess target landed. Still not a
        # privilege boundary, so still refused.
        assert exc.value.available is Isolation.SUBPROCESS


def test_a_workstation_may_accept_it_and_is_told_every_time(caplog):
    """Refusing here would just mean the analyst debugs outside the tool, with no record at all."""
    import logging

    with caplog.at_level(logging.WARNING, logger="reforge.execution"):
        target = execution.check("dynamic_execution", _Cfg("workstation", permissive=True))
    assert target is execution.IN_PROCESS
    assert "UNISOLATED EXECUTION" in caplog.text
    assert "with your privileges" in caplog.text


def test_a_workstation_can_refuse_too():
    with pytest.raises(ExecutionRefused):
        execution.check("dynamic_execution", _Cfg("workstation", permissive=False))


def test_the_shared_profiles_cannot_opt_back_in():
    """A setting a shared deployment could flip would not be a control."""
    from reforge.settings import Settings

    assert Settings(deployment_profile="workstation").allow_unisolated_execution is True
    for shared in ("team",):
        assert Settings(deployment_profile=shared,
                        allow_unisolated_execution=True).allow_unisolated_execution is False


def test_an_unknown_risk_class_asks_for_the_strongest_isolation():
    """Unrecognised means unassessed, which must not mean unrestricted."""
    with pytest.raises(ExecutionRefused):
        execution.check("something_new", _Cfg("team", permissive=False))


def test_the_posture_is_reportable():
    described = execution.describe(_Cfg("team", permissive=False))
    assert described["best_isolation"] == "subprocess"
    assert described["dynamic_execution_requires"] == "vm"
    assert described["dynamic_execution_allowed"] is False
    assert described["unisolated_execution_permitted"] is False


# --------------------------------------------------------------------------- enforcement point
def test_the_agent_refuses_before_asking_for_approval():
    """Asking an operator to authorise what the deployment must not do is not a decision to offer."""
    import inspect

    from reforge import agent

    source = inspect.getsource(agent._dispatch)
    check_at = source.index("execution.check(")
    approval_at = source.index("request_approval(")
    assert check_at < approval_at, \
        "the isolation check must run before the approval prompt, not after it"


# --------------------------------------------------------------------------- job workspaces
def test_a_job_gets_its_own_workspace_and_it_is_removed(tmp_path):
    with execution.job_workspace("J-1", root=tmp_path) as lease:
        assert lease.path.is_dir()
        (lease.path / "sample.bin").write_bytes(b"MZ customer sample")
        used = lease.path
    assert not used.exists()
    assert lease.deleted is True and lease.verified is True


def test_the_deletion_is_verified_not_assumed(tmp_path):
    """"We call rmtree in a finally" is not the same as "it is gone"."""
    with execution.job_workspace("J-2", root=tmp_path) as lease:
        pass
    assert lease.verified is True


def test_a_workspace_that_survives_is_reported_loudly(tmp_path, monkeypatch, caplog):
    import logging
    import shutil

    monkeypatch.setattr(shutil, "rmtree", lambda *a, **k: None)   # simulate a failed removal
    with caplog.at_level(logging.ERROR, logger="reforge.execution"):
        with execution.job_workspace("J-3", root=tmp_path) as lease:
            (lease.path / "sample.bin").write_bytes(b"MZ")
    assert lease.deleted is False
    assert "JOB WORKSPACE NOT DELETED" in caplog.text
    assert "customer sample may be left on disk" in caplog.text


def test_the_workspace_is_not_world_readable(tmp_path):
    import os

    with execution.job_workspace("J-4", root=tmp_path) as lease:
        mode = os.stat(lease.path).st_mode & 0o777
    assert mode & 0o077 == 0, f"job workspace is readable by other users (mode {mode:o})"


def test_two_jobs_do_not_share_a_workspace(tmp_path):
    with execution.job_workspace("J-5", root=tmp_path) as a:
        with execution.job_workspace("J-6", root=tmp_path) as b:
            assert a.path != b.path


# --------------------------------------------------------------------------- quotas
def test_quotas_have_finite_defaults():
    quotas = execution.IN_PROCESS.quotas
    for field in ("wall_clock_seconds", "cpu_seconds", "memory_bytes", "disk_bytes"):
        assert getattr(quotas, field) is not None, f"{field} is unbounded"


def test_applying_quotas_restores_the_previous_limits():
    """They bound this process, so leaving them in place would bound everything after."""
    try:
        import resource
    except ImportError:
        pytest.skip("POSIX only")
    before = resource.getrlimit(resource.RLIMIT_CPU)
    with execution.enforce_quotas(execution.Quotas(cpu_seconds=1000)):
        pass
    assert resource.getrlimit(resource.RLIMIT_CPU) == before


def test_a_job_runs_in_an_ephemeral_workspace_and_records_its_deletion(tmp_path, monkeypatch):
    from reforge.job_manager import JobManager

    monkeypatch.setattr(config, "STATE_ROOT", tmp_path)
    seen = {}

    async def handler(job, **_):
        seen["path"] = pathlib.Path(job.workspace)
        seen["path"].joinpath("scratch.bin").write_bytes(b"x")
        return {"ok": True}

    manager = JobManager()
    manager.register("demo", handler)
    job = asyncio.new_event_loop().run_until_complete(manager.run_job(manager.submit("demo", {})))

    assert job.status == "completed"
    assert seen["path"].exists() is False, "the job workspace outlived the job"
    assert job.workspace_deleted is True
    assert job.to_dict()["workspace_deleted"] is True, "the verdict must be auditable after the fact"


def test_a_job_that_will_not_finish_is_stopped(tmp_path, monkeypatch):
    """A ceiling, not a crash: one stuck job must not hold a worker forever."""
    from reforge.job_manager import JobManager

    monkeypatch.setattr(config, "STATE_ROOT", tmp_path)
    monkeypatch.setattr(execution.IN_PROCESS, "quotas", execution.Quotas(wall_clock_seconds=1))

    async def forever(job, **_):
        await asyncio.sleep(30)

    manager = JobManager()
    manager.register("stuck", forever)
    job = asyncio.new_event_loop().run_until_complete(manager.run_job(manager.submit("stuck", {})))

    assert job.status == "failed"
    assert "wall-clock ceiling" in job.error



# --------------------------------------------------------------------------- the subprocess target
# Added after the isolation contract had nowhere to go: NONE was the only target on offer, which
# made the whole thing a declaration. A subprocess is not a security boundary, and it does give
# limits that bind the job rather than the application, a kill switch that works, and crash
# containment.
def test_a_function_runs_in_a_child_and_returns_its_result():
    assert execution.run_isolated("os.path", "basename", {"p": "/tmp/x/sample.bin"}) == "sample.bin"


def test_a_failure_in_the_child_surfaces_as_an_error_not_a_hang():
    with pytest.raises(execution.SubprocessFailed) as exc:
        execution.run_isolated("reforge.execution", "no_such_function", {})
    assert "AttributeError" in str(exc.value)


def test_the_wall_clock_ceiling_terminates_the_child():
    """A ceiling that only logs is not a ceiling."""
    quotas = execution.Quotas(wall_clock_seconds=2, cpu_seconds=None, memory_bytes=None)
    with pytest.raises(execution.SubprocessFailed) as exc:
        # time.sleep is positional-only, which is exactly why run_isolated takes `args`.
        execution.run_isolated("time", "sleep", quotas=quotas, args=[30])
    assert "ceiling" in str(exc.value)


def test_arguments_that_cannot_cross_the_boundary_are_a_clear_error():
    """Not a pickling failure deep in a child, and not a silent coercion."""
    with pytest.raises(execution.SubprocessFailed) as exc:
        execution.run_isolated("os.path", "basename", {"p": object()})
    assert "JSON-serialisable" in str(exc.value)


def test_positional_only_functions_can_be_called():
    assert execution.run_isolated("math", "factorial", args=[10]) == 3628800


def test_the_child_cannot_fork_the_parent():
    """The first version used multiprocessing with `spawn`, which re-imports the caller's
    __main__ in the child - so any caller without a __main__ guard forks itself endlessly. A
    library cannot depend on its callers getting that right, and the failure mode is a fork bomb
    rather than an error."""
    import inspect

    source = inspect.getsource(execution)
    # The docstring explains why multiprocessing is NOT used, so check for its use, not its name.
    assert "import multiprocessing" not in source
    assert "multiprocessing.get_context" not in source
    assert "subprocess.run" in source


def test_limits_applied_in_the_child_do_not_leak_into_this_process():
    """The whole point: in-process limits bind ReTrace, child limits bind the job."""
    try:
        import resource
    except ImportError:
        pytest.skip("POSIX only")
    before = resource.getrlimit(resource.RLIMIT_CPU)
    execution.run_isolated("os.path", "basename", {"p": "/x/y"},
                           execution.Quotas(cpu_seconds=5, memory_bytes=None,
                                            wall_clock_seconds=30))
    assert resource.getrlimit(resource.RLIMIT_CPU) == before


def test_a_subprocess_still_does_not_satisfy_dynamic_execution():
    """Calling it more than it is would be the mislabelling this module exists to avoid."""
    assert not execution.SUBPROCESS_TARGET.can_host(Isolation.VM)
    with pytest.raises(ExecutionRefused):
        execution.check("dynamic_execution", _Cfg("team", permissive=False))
