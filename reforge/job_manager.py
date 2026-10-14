"""Minimal job manager, with optional persistence on disk.

Decouples work from the chat: static analyses, FLOSS, Ghidra imports, source→sink, report
generation, patch diffs and dynamic-trace imports can run as jobs with an explicit state and a
record of input/output/errors/duration.

Jobs run as asyncio tasks; a handler is a coroutine `async (job, **input) -> dict`.
When the manager is given a `persist_dir`, every job is saved as `<id>.json` and reloaded at
start-up (jobs left `running`/`queued` by a previous process are marked as interrupted), so the
history survives restarts.
"""
import asyncio
import json
import time
import uuid
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional

# Stati del ciclo di vita di un job.
QUEUED = "queued"
RUNNING = "running"
COMPLETED = "completed"
FAILED = "failed"
CANCELLED = "cancelled"

# Transizioni consentite (per coerenza e test).
_ALLOWED = {
    QUEUED: {RUNNING, CANCELLED},
    RUNNING: {COMPLETED, FAILED, CANCELLED},
    COMPLETED: set(),
    FAILED: set(),
    CANCELLED: set(),
}

JobHandler = Callable[..., Awaitable[Dict[str, Any]]]


class Job:
    def __init__(self, kind: str, payload: Dict[str, Any], tool: str = ""):
        # Set first so they exist even if __init__ is extended later; the ephemeral workspace and
        # whether its deletion was verified are part of the job's record, not incidental.
        self.workspace: str = ""
        self.workspace_deleted: bool = False
        self.id = "J-" + uuid.uuid4().hex[:8]
        self.kind = kind
        self.tool = tool or kind
        self.input = payload or {}
        self.status = QUEUED
        self.output: Any = None
        self.error: Optional[str] = None
        self.evidence_ids: List[str] = []
        self.created = time.time()
        self.started: Optional[float] = None
        self.finished: Optional[float] = None
        self._task: Optional[asyncio.Task] = None

    @property
    def duration(self) -> Optional[float]:
        if self.started and self.finished:
            return round(self.finished - self.started, 3)
        return None

    def set_status(self, new: str) -> bool:
        if new in _ALLOWED.get(self.status, set()):
            self.status = new
            return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        # `workspace_deleted` is persisted so an operator can audit, after the fact, that a job's
        # scratch space was actually removed.
        return {
            "id": self.id, "kind": self.kind, "tool": self.tool,
            "status": self.status, "input": self.input,
            "output": self.output, "error": self.error,
            "evidence_ids": self.evidence_ids,
            "created": self.created, "started": self.started,
            "finished": self.finished, "duration": self.duration,
            "workspace_deleted": self.workspace_deleted,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Job":
        j = cls(d.get("kind", "?"), d.get("input", {}), d.get("tool", ""))
        j.id = d.get("id", j.id)
        j.workspace_deleted = bool(d.get("workspace_deleted", False))
        j.status = d.get("status", QUEUED)
        j.output = d.get("output")
        j.error = d.get("error")
        j.evidence_ids = d.get("evidence_ids", [])
        j.created = d.get("created", j.created)
        j.started = d.get("started")
        j.finished = d.get("finished")
        # Un job ripreso da disco non ha più un task vivo.
        j._task = None
        return j


class JobManager:
    def __init__(self, persist_dir: Optional[str] = None):
        self._jobs: Dict[str, Job] = {}
        self._handlers: Dict[str, JobHandler] = {}
        self.persist_dir: Optional[Path] = Path(persist_dir) if persist_dir else None
        if self.persist_dir:
            self.persist_dir.mkdir(parents=True, exist_ok=True)

    def set_persist_dir(self, path: str) -> None:
        self.persist_dir = Path(path)
        self.persist_dir.mkdir(parents=True, exist_ok=True)

    def _save(self, job: Job) -> None:
        if not self.persist_dir:
            return
        try:
            p = self.persist_dir / f"{job.id}.json"
            tmp = p.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(job.to_dict(), indent=2, default=str), encoding="utf-8")
            import os
            os.replace(tmp, p)
        except Exception:
            pass

    def load_persisted(self) -> int:
        """Reload the saved jobs. Jobs left running/queued are marked as interrupted."""
        if not self.persist_dir or not self.persist_dir.is_dir():
            return 0
        n = 0
        for p in self.persist_dir.glob("*.json"):
            try:
                d = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            job = Job.from_dict(d)
            if job.status in (QUEUED, RUNNING):
                job.status = FAILED
                job.error = job.error or "Interrupted by a process restart"
                job.finished = job.finished or time.time()
            self._jobs[job.id] = job
            n += 1
        return n

    def register(self, kind: str, handler: JobHandler) -> None:
        self._handlers[kind] = handler

    def get(self, job_id: str) -> Optional[Job]:
        return self._jobs.get(job_id)

    def list(self) -> List[Dict[str, Any]]:
        return [j.to_dict() for j in sorted(self._jobs.values(),
                                            key=lambda x: x.created, reverse=True)]

    def submit(self, kind: str, payload: Optional[Dict[str, Any]] = None,
               tool: str = "") -> Job:
        """Create and start a job. Fails immediately when no handler is registered."""
        job = Job(kind, payload or {}, tool)
        self._jobs[job.id] = job
        self._save(job)
        handler = self._handlers.get(kind)
        if handler is None:
            job.set_status(RUNNING)
            job.started = time.time()
            job.error = f"No handler is registered for job kind '{kind}'"
            job.finished = time.time()
            job.set_status(FAILED)
            self._save(job)
            return job
        try:
            loop = asyncio.get_running_loop()
            job._task = loop.create_task(self._run(job, handler))
        except RuntimeError:
            # Nessun event loop in esecuzione (es. test sincroni): esecuzione differita via run_job.
            pass
        return job

    async def _run(self, job: Job, handler: JobHandler) -> None:
        """Run one job inside an ephemeral workspace, under a wall-clock ceiling.

        The workspace is per job and its deletion is verified: "we call rmtree in a finally" is
        not the same as "it is gone", and a workspace that silently persists is a customer's
        sample left on disk after the engagement closed (slice P2-S2).
        """
        from . import execution

        job.set_status(RUNNING)
        job.started = time.time()
        self._save(job)
        quotas = execution.IN_PROCESS.quotas
        try:
            with execution.job_workspace(job.id) as lease:
                job.workspace = str(lease.path)
                timeout = quotas.wall_clock_seconds
                coro = handler(job, **job.input)
                job.output = await (asyncio.wait_for(coro, timeout) if timeout else coro)
            job.workspace_deleted = lease.deleted
            job.finished = time.time()
            job.set_status(COMPLETED)
        except asyncio.TimeoutError:
            # A ceiling, not a crash: a job that will not finish must not hold a worker forever.
            job.error = (f"exceeded the {quotas.wall_clock_seconds}s wall-clock ceiling for a job "
                         "and was stopped")
            job.finished = time.time()
            job.set_status(FAILED)
        except asyncio.CancelledError:
            job.finished = time.time()
            job.set_status(CANCELLED)
            self._save(job)
            raise
        except Exception as exc:
            job.error = f"{type(exc).__name__}: {exc}"
            job.finished = time.time()
            job.set_status(FAILED)
        self._save(job)
        try:
            from . import observability as _obs

            _obs.METRICS.increment("retrace_jobs_total",
                                   help="Jobs by kind and final status.",
                                   kind=job.kind, status=job.status)
            if job.duration:
                _obs.METRICS.observe("retrace_job_seconds", job.duration,
                                     help="Job duration in seconds.", kind=job.kind)
        except Exception:                    # metrics must never fail a job
            pass

    async def run_job(self, job: Job) -> Job:
        """Run a job awaitably (useful in tests, and when submit had no running loop)."""
        handler = self._handlers.get(job.kind)
        if handler is None:
            return job
        await self._run(job, handler)
        return job

    def cancel(self, job_id: str) -> bool:
        job = self._jobs.get(job_id)
        if not job:
            return False
        if job._task and not job._task.done():
            job._task.cancel()
            return True
        if job.status == QUEUED:
            job.set_status(CANCELLED)
            job.finished = time.time()
            self._save(job)
            return True
        return False


# Istanza globale di processo.
manager = JobManager()
