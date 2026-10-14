"""Per-conversation session state (a "project"): message history, investigation log,
findings, an event queue (drained by SSE), and pending approval futures.
Projects are persisted in SQLite and mirrored to JSON files for compatibility/export.
"""
import asyncio
import json
import time
import uuid
from typing import Any, Dict, List, Optional

from . import config


class Session:
    def __init__(self, sid: Optional[str] = None, name: Optional[str] = None):
        self.id = sid or uuid.uuid4().hex[:12]
        self.name = name
        self.created = time.time()
        self.updated = self.created
        self.target_path: Optional[str] = None       # binary under audit (drives always-on static analysis)
        self.static_done = False                     # static analysis already run for this target
        # {file,format,arch,size,md5,sha256,import_count,mitigations}
        self.target_profile: Optional[Dict[str, Any]] = None
        self.mode = "auto"                           # analysis mode: auto | static | dynamic (selects the prompt)
        self.phase: Optional[str] = None             # workflow phase manual override (None = auto)
        self.report_generated = False       # set once a report has been produced
        self.static_strings: List[str] = []
        self.static_imports: List[str] = []
        self.attack_surface: Dict[str, Any] = {}   # dangerous sinks + input sources — leads, not findings
        # High-signal strings: persisted category overrides {string: category}. These are applied
        # (the string is actually MOVED to the target group) by the local LLM reassignment flow and
        # survive reload / are honoured by every strings consumer, not just the live UI session.
        self.string_overrides: Dict[str, str] = {}
        self.messages: List[Dict[str, Any]] = []           # neutral message history
        self.investigation_log: List[Dict[str, Any]] = []
        self.findings: List[Dict[str, Any]] = []
        self.evidence: List[Dict[str, Any]] = []           # evidence objects (E-0001…)
        self.llm_usage: List[Dict[str, Any]] = []          # per-call token/cost estimates
        self.artifacts: List[Dict[str, Any]] = []          # uploaded artifacts (A-xxxx) registry
        self._ev_seq = 0
        self.loaded_tools: set = set()
        # Events. `events` is the backlog: what was emitted while no stream was attached (and what
        # tests read). Each attached stream gets its own queue through subscribe(), because one
        # shared queue has one consumer: with the project open in two tabs, each event went to
        # whichever tab's reader woke first, and the other tab sat on "Sending…" forever.
        self.events: asyncio.Queue = asyncio.Queue()
        self._subscribers: List[asyncio.Queue] = []
        self.pending: Dict[str, asyncio.Future] = {}
        # --- ownership (slice P2-S1) -----------------------------------------------------
        # Who created the project, and who else may see it. Empty `owner` means a project from
        # before ownership existed: those stay visible to everyone who can read projects at all,
        # because retroactively locking an analyst out of their own work would be the wrong
        # failure. New projects always have an owner.
        self.owner: str = ""
        self.members: Dict[str, str] = {}          # subject -> role name
        #: Row version this instance last saw. None until it has been loaded or saved once, which
        #: is why a brand-new project does not collide with itself on its first write.
        self._db_version: Optional[int] = None
        self.busy = False
        self.task: Optional["asyncio.Task[Any]"] = None   # the running turn's Task (for Stop)
        self.awaiting_reload = False           # dynamic analysis: paused waiting for binary reload
        # --- per-turn agent state. Declared here rather than grown onto the instance by the agent,
        # so the type checker can see them and a typo in `agent.py` is an error, not a new attribute.
        self._call_counts: Dict[str, int] = {}     # identical-call counter (anti-loop), reset per turn
        self._dbg_state: str = "running"           # dbg_state.RUNNING; last verdict on the debuggee
        self._dbg_neg: int = 0                     # consecutive "not debugging" probes

    EVENT_BACKLOG_MAX = 5000      # emitted with no stream attached; oldest dropped beyond this
    EVENT_QUEUE_MAX = 2000        # per attached stream; a stalled tab loses old events, not new ones

    async def emit(self, kind: str, **data: Any) -> None:
        event = {"kind": kind, "ts": time.time(), **data}
        if not self._subscribers:
            if self.events.qsize() >= self.EVENT_BACKLOG_MAX:
                try:
                    self.events.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            await self.events.put(event)
            return
        for q in list(self._subscribers):
            if q.full():
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            q.put_nowait(event)

    def subscribe(self) -> "asyncio.Queue[Dict[str, Any]]":
        """A queue that receives every event from now on. The first subscriber also gets the
        backlog, so a tab that opens mid-turn sees what the turn already said."""
        q: "asyncio.Queue[Dict[str, Any]]" = asyncio.Queue(maxsize=self.EVENT_QUEUE_MAX)
        if not self._subscribers:
            while not q.full():
                try:
                    q.put_nowait(self.events.get_nowait())
                except asyncio.QueueEmpty:
                    break
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: "asyncio.Queue[Dict[str, Any]]") -> None:
        try:
            self._subscribers.remove(q)
        except ValueError:
            pass

    async def request_approval(self, tool: str, args: Dict[str, Any], reason: str,
                               risk_class: str = "", consequence: str = "",
                               risk_level: str = "") -> bool:
        """Pause the turn until the operator decides.

        The risk metadata travels with the event so the UI can present *informed* consent — which
        tool, which operation, on what target, why, and what approving it permits — instead of a
        bare Approve/Deny over a JSON blob. All three fields are optional and default to empty so
        older callers keep working unchanged.
        """
        approval_id = uuid.uuid4().hex[:8]
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        self.pending[approval_id] = fut
        await self.emit("awaiting_approval", approval_id=approval_id, tool=tool, args=args,
                        reason=reason, risk_class=risk_class, consequence=consequence,
                        risk_level=risk_level)
        try:
            return await fut
        finally:
            self.pending.pop(approval_id, None)

    def resolve_approval(self, approval_id: str, approved: bool) -> bool:
        fut = self.pending.get(approval_id)
        if fut and not fut.done():
            fut.set_result(approved)
            return True
        return False

    def log_tool(self, tool: str, args: Dict[str, Any], result: str,
                 is_error: bool, approved: Optional[bool]) -> None:
        self.investigation_log.append({
            "ts": time.time(), "tool": tool, "args": args,
            "result_preview": (result or "")[:500], "is_error": is_error, "approved": approved,
        })

    def add_evidence(self, ev: Dict[str, Any], raw_full: Optional[str] = None) -> str:
        """Store an evidence record, returning its stable ID. Dedups by content hash. Large raw
        outputs are written under the project's workspace and referenced (not kept in the prompt)."""
        h = ev.get("hash")
        if h:
            for e in self.evidence:
                if e.get("hash") == h:
                    return e["id"]
        self._ev_seq += 1
        eid = f"E-{self._ev_seq:04d}"
        rec = {"id": eid, "ts": time.time(), **ev}
        if raw_full and len(raw_full) > 2000:
            try:
                from . import workspace
                d = workspace.project_dir(self.id) / "evidence"
                d.mkdir(parents=True, exist_ok=True)
                p = d / f"{eid}.txt"
                p.write_text(raw_full, encoding="utf-8")
                rec["raw_ref"] = str(p)
            except Exception:
                pass
        self.evidence.append(rec)
        return eid


    def add_llm_usage(self, entry: Dict[str, Any]) -> None:
        """Store a per-model-call usage/cost estimate for this investigation."""
        if entry:
            self.llm_usage.append(entry)

    def usage_summary(self) -> Dict[str, Any]:
        try:
            from .llm_cost import summarize
            return summarize(self.llm_usage)
        except Exception:
            return {"calls": len(getattr(self, "llm_usage", []) or [])}

    def add_finding(self, finding: Dict[str, Any], *, origin: str = "human",
                    tool: str = "", tool_version: str = "") -> bool:
        """Admit a finding, or UPDATE an existing one with the same (title, location).

        Every write goes through `engine.intake.admit()`: structural validation, LLM-enrichment
        sanitising, the evidence gate, anti-false-positive rules, the status cap and risk scoring.
        Before this, those ran only when a report was rendered, so a finding could be *stored*
        claiming CONFIRMED with nothing behind it and only be corrected on the way out.

        `origin` decides how much of the candidate is trusted - an `llm` origin may change prose
        and nothing else. Raises `engine.intake.FindingRejected` for a structurally invalid
        candidate; it is not stored and the caller is told why.

        Returns True if a brand-new finding was added, False if an existing one was updated.
        """
        from .engine import intake as _intake

        def _key(f):
            return ((f.get("title") or "").strip().lower(),
                    (f.get("location") or "").strip().lower())

        key = _key(finding)
        prior = next((f for f in self.findings if _key(f) == key), None)
        sha = (self.target_profile or {}).get("sha256", "") if self.target_profile else ""
        admitted, _blocked = _intake.admit(finding, origin=origin, prior=prior,
                                           binary_sha256=sha, tool=tool, tool_version=tool_version)
        try:
            from . import findings as _fx
            _fx.enrich(admitted)          # legacy read-side fields the report still consumes
        except Exception:
            pass

        if prior is not None:
            prior.clear()
            prior.update(admitted)
            prior["validated"] = True     # touched by an explicit add (e.g. AI validation)
            return False
        self.findings.append(admitted)
        return True

    SCHEMA = 1

    def to_dict(self) -> Dict[str, Any]:
        self.updated = time.time()
        return {
            "schema": self.SCHEMA,
            "id": self.id, "name": self.name, "created": self.created, "updated": self.updated,
            "target_path": self.target_path, "static_done": self.static_done,
            "owner": self.owner, "members": dict(self.members),
            "target_profile": self.target_profile, "mode": self.mode,
            "phase": self.phase, "report_generated": self.report_generated,
            "static_strings": self.static_strings,
            "static_imports": self.static_imports,
            "attack_surface": self.attack_surface,
            "string_overrides": self.string_overrides,
            "messages": self.messages, "investigation_log": self.investigation_log,
            "findings": self.findings, "evidence": self.evidence, "ev_seq": self._ev_seq,
            "llm_usage": self.llm_usage,
            "artifacts": self.artifacts,
            "loaded_tools": sorted(self.loaded_tools),
        }

    def persist(self, *, check_version: bool = True) -> None:
        """Write the project. Raises db.StaleWrite when another writer got there first.

        `check_version=False` is for the caller that has decided to win - after showing the
        operator the conflict, or when reconciling. It is an argument rather than a separate
        method so the decision is visible at the call site.
        """
        payload = self.to_dict()
        try:
            from . import db

            expected = self._db_version if check_version and self._db_version is not None else None
            self._db_version = db.save_project(payload, expected_version=expected)
        except Exception as exc:
            # A stale write is a real answer and must reach the caller; anything else (a locked
            # database, a missing column) must not stop the JSON mirror from being written, which
            # is the copy that has always been the fallback.
            from . import db as _db

            if isinstance(exc, _db.StaleWrite):
                raise
        path = config.PROJECTS_DIR / f"{self.id}.json"
        # Atomic write: tmp file in the same dir, then os.replace (no partial/corrupt files).
        import os
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        os.replace(tmp, path)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Session":
        s = cls(sid=d.get("id"), name=d.get("name"))
        s.created = d.get("created", s.created)
        s.updated = d.get("updated", s.created)
        s.target_path = d.get("target_path")
        s.static_done = d.get("static_done", False)
        s.target_profile = d.get("target_profile")
        s.mode = d.get("mode", "auto")
        s.phase = d.get("phase")
        s.report_generated = d.get("report_generated", False)
        s.static_strings = d.get("static_strings", [])
        s.static_imports = d.get("static_imports", [])
        s.attack_surface = d.get("attack_surface", {})
        s.string_overrides = dict(d.get("string_overrides", {}) or {})
        s.messages = d.get("messages", [])
        s.investigation_log = d.get("investigation_log", [])
        # Projects written before write-time admission (slice P1-S1) hold findings in the legacy
        # shape. Bring them up to the canonical one on load so the rest of the application sees a
        # single model, rather than branching on "was this stored before or after the change".
        # Best-effort by design: a record that cannot be validated is kept and flagged, because
        # refusing to open an old project would be a worse failure than one visible marker.
        from .engine import intake as _intake
        sha = (s.target_profile or {}).get("sha256", "") if s.target_profile else ""
        s.owner = d.get("owner", "") or ""
        s.members = dict(d.get("members") or {})
        # The version as of this load. A save from this instance is then checked against it, so
        # two instances that loaded the same row cannot both write over each other.
        try:
            from . import db as _db

            s._db_version = _db.project_version(s.id)
        except Exception:
            s._db_version = None
        s.findings = [_intake.admit_legacy(f, binary_sha256=sha)
                      for f in d.get("findings", []) if isinstance(f, dict)]
        s.evidence = d.get("evidence", [])
        s.llm_usage = d.get("llm_usage", [])
        s.artifacts = d.get("artifacts", [])
        s._ev_seq = d.get("ev_seq", len(s.evidence))
        s.loaded_tools = set(d.get("loaded_tools", []))
        return s



def can_access(principal, session) -> bool:
    """Whether `principal` may see `session` at all.

    Access is granted by being the owner, by being named a member, or by holding a permission that
    is inherently cross-project (deleting or sharing any project implies seeing it). An ownerless
    project - created before ownership existed - is visible to anyone who can read projects: the
    alternative is locking analysts out of their own history on upgrade.
    """
    from .identity import Permission

    if not principal.can(Permission.PROJECT_READ):
        return False
    owner = getattr(session, "owner", "") or ""
    if not owner:
        return True
    if principal.subject == owner or principal.subject in (getattr(session, "members", {}) or {}):
        return True
    return principal.can(Permission.PROJECT_DELETE) or principal.can(Permission.PROJECT_SHARE)

class SessionStore:
    def __init__(self):
        self._sessions: Dict[str, Session] = {}
        try:
            from . import db
            db.init()
            db.migrate_json_projects(config.PROJECTS_DIR)
        except Exception:
            pass

    def create(self, name: Optional[str] = None, owner: str = "") -> Session:
        s = Session(name=name)
        s.owner = owner or ""
        self._sessions[s.id] = s
        if name:                      # named projects exist on disk immediately
            s.persist()
        return s

    def list_projects_for(self, principal) -> List[Dict[str, Any]]:
        """`list_projects()` filtered to what `principal` may see.

        A query against the `owner` column (migration 1), not a scan that loads and parses every
        project to find out who owns it. The filter lives here rather than in the route so no
        caller can forget it, and falls back to the scan when the column is not there yet.
        """
        from .identity import Permission

        if not principal.can(Permission.PROJECT_READ):
            return []
        # Someone who may delete or share ANY project sees all of them; that is what those
        # permissions mean, and filtering them out here would contradict the model.
        if principal.can(Permission.PROJECT_DELETE) or principal.can(Permission.PROJECT_SHARE):
            return self.list_projects()
        try:
            from . import db

            return db.list_projects_owned_by([principal.subject] if principal.subject else [])
        except Exception:
            # The query needs migration 1. If it is not applied - an old database, a failed
            # migration - fall back to the scan rather than showing the analyst nothing.
            out = []
            for row in self.list_projects():
                session = self.get(row.get("id", ""))
                if session is None or can_access(principal, session):
                    out.append(row)
            return out

    def get(self, sid: str) -> Optional[Session]:
        if sid in self._sessions:
            return self._sessions[sid]
        return self.load(sid)

    def load(self, sid: str) -> Optional[Session]:
        try:
            from . import db
            d = db.load_project(sid)
            if d:
                s = Session.from_dict(d)
                self._sessions[s.id] = s
                return s
        except Exception:
            pass
        path = config.PROJECTS_DIR / f"{sid}.json"
        if not path.is_file():
            return None
        try:
            s = Session.from_dict(json.loads(path.read_text(encoding="utf-8")))
        except Exception:
            # Corrupted/partial file: set it aside so it doesn't keep breaking, don't crash.
            try:
                path.rename(path.with_suffix(".json.corrupt"))
            except Exception:
                pass
            return None
        self._sessions[s.id] = s
        try:
            from . import db
            db.save_project(s.to_dict())
        except Exception:
            pass
        return s

    def list_projects(self) -> List[Dict[str, Any]]:
        try:
            from . import db
            out = db.list_projects()
            if out:
                return out
        except Exception:
            pass
        out = []
        for path in config.PROJECTS_DIR.glob("*.json"):
            try:
                d = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            out.append({"id": d.get("id", path.stem), "name": d.get("name"),
                        "created": d.get("created"), "updated": d.get("updated"),
                        "findings": len(d.get("findings", [])),
                        "messages": len(d.get("messages", [])),
                        "usage": d.get("llm_usage", [])})
        out.sort(key=lambda p: p.get("updated") or 0, reverse=True)
        return out

    def delete(self, sid: str) -> bool:
        self._sessions.pop(sid, None)
        deleted = False
        try:
            from . import db
            deleted = db.delete_project(sid) or deleted
        except Exception:
            pass
        path = config.PROJECTS_DIR / f"{sid}.json"
        if path.is_file():
            path.unlink()
            deleted = True
        return deleted
