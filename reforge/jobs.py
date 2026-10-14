"""Registration of the job handlers.

Wires the generic `JobManager` to ReTrace's real analysis functions. Kept apart from the job
manager so the latter stays dependency-free and testable on its own.

Every handler receives `job` and the arguments passed to `submit(...)` (at least `session_id`),
resolves the session through the store and returns a serialisable dict saved in `job.output`.
"""
from typing import Any, Dict

_registered = False


def ensure_registered(store, host, registry) -> None:
    """Register the handlers on the global manager instance, once."""
    global _registered
    if _registered:
        return
    from .job_manager import manager

    async def _static_analysis(job, session_id: str = "", **_) -> Dict[str, Any]:
        from . import static_analysis
        s = store.get(session_id)
        if not s or not getattr(s, "target_path", None):
            raise ValueError("no target is set for this project")
        res = static_analysis.analyze(s.target_path)
        return {"summary": {k: res.get(k) for k in ("file", "format", "arch", "size")},
                "findings": len(res.get("findings", []))}

    async def _source_to_sink(job, session_id: str = "", **_) -> Dict[str, Any]:
        from . import source_to_sink as s2s
        s = store.get(session_id)
        if not s:
            raise ValueError("session not found")
        chains = s2s.from_session(s)
        return {"chains": chains, "count": len(chains)}

    async def _report_generation(job, session_id: str = "", **_) -> Dict[str, Any]:
        from . import report_pt, findings as fx
        s = store.get(session_id)
        if not s:
            raise ValueError("session not found")
        md = await report_pt.generate(s)
        s.report_generated = True
        s.persist()
        return {"length": len(md), "warnings": fx.validate(s)}

    async def _finding_validation(job, session_id: str = "", **_) -> Dict[str, Any]:
        from . import finding_validator as fv
        s = store.get(session_id)
        if not s:
            raise ValueError("session not found")
        return fv.validate_session(s)

    async def _graph_sync(job, session_id: str = "", **_) -> Dict[str, Any]:
        from . import evidence_graph as eg
        s = store.get(session_id)
        if not s:
            raise ValueError("session not found")
        g = eg.for_session(s)
        return g.sync_from_session(s)

    async def _xref_enrich(job, session_id: str = "", **_) -> Dict[str, Any]:
        from . import xref_enrich as xe
        s = store.get(session_id)
        if not s:
            raise ValueError("session not found")
        return await xe.enrich_chains(s, host)

    manager.register("static_analysis", _static_analysis)
    manager.register("source_to_sink", _source_to_sink)
    manager.register("report_generation", _report_generation)
    manager.register("finding_validation", _finding_validation)
    manager.register("graph_sync", _graph_sync)
    manager.register("xref_enrich", _xref_enrich)
    _registered = True
