"""A turn must leave the UI the way it found it, whichever way it ends.

Reported as: "Sending…" stayed on the status bar after the reply had finished, and a message
already sent could not be sent again. Four ways a turn ends had three different resets, a refused
POST had none, and a stream reconnecting to a restarted server had nothing to resync from.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path

from fastapi.testclient import TestClient

from reforge import config
from reforge import server as s

ROOT = Path(__file__).resolve().parent.parent
APP = (ROOT / "reforge" / "web" / "app.js").read_text(encoding="utf-8")


def _client():
    c = TestClient(s.app)
    c.__enter__()
    c.headers.update({"X-Reforge-Token": config.AUTH_TOKEN})
    return c


def _drain(session):
    out = []
    while True:
        try:
            out.append(session.events.get_nowait())
        except asyncio.QueueEmpty:
            return out


# --------------------------------------------------------------------------- backend
def test_stop_resets_the_status_before_done():
    c = _client()
    try:
        pid = c.post("/api/projects", json={"name": "lifecycle"}).json()["id"]
        session = s.store.get(pid)
        _drain(session)
        assert c.post("/api/stop", json={"session_id": pid}).status_code == 200
        kinds = [(e["kind"], e.get("busy")) for e in _drain(session)]
    finally:
        c.__exit__(None, None, None)
    assert ("stopped", None) in kinds
    assert ("status", False) in kinds, kinds
    assert kinds.index(("status", False)) < kinds.index(("done", None))


def test_project_payload_says_whether_a_turn_is_running():
    c = _client()
    try:
        pid = c.post("/api/projects", json={"name": "lifecycle"}).json()["id"]
        assert c.get(f"/api/projects/{pid}").json()["busy"] is False
        s.store.get(pid).busy = True
        assert c.get(f"/api/projects/{pid}").json()["busy"] is True
    finally:
        s.store.get(pid).busy = False
        c.__exit__(None, None, None)


def test_a_second_message_while_busy_is_refused_with_409():
    c = _client()
    try:
        pid = c.post("/api/projects", json={"name": "lifecycle"}).json()["id"]
        s.store.get(pid).busy = True
        r = c.post("/api/message", json={"session_id": pid, "text": "again"})
    finally:
        s.store.get(pid).busy = False
        c.__exit__(None, None, None)
    assert r.status_code == 409


def test_every_status_text_the_backend_emits_is_english():
    src = (ROOT / "reforge" / "agent.py").read_text(encoding="utf-8")
    texts = re.findall(r'emit\("status",\s*text=f?"([^"]+)"', src)
    assert texts, "no status texts found - the pattern is wrong, not the code"
    for text in texts:
        assert not re.search(r"\b(pronto|cerco|caccia|ragiona|invio)\b", text, re.I), text


# --------------------------------------------------------------------------- SPA
def _handler(kind: str) -> str:
    m = re.search(rf'case "{kind}":([^\n]*)', APP)
    assert m, f"no handler for {kind}"
    return m.group(1)


def test_every_way_a_turn_ends_resets_the_bar():
    for kind in ("done", "error", "stopped"):
        assert "setIdle()" in _handler(kind), f'"{kind}" does not reset the status bar'


def test_a_refused_send_is_shown_and_resets():
    body = APP[APP.index("async function sendMessage("):APP.index("const CANNED = {")]
    assert "if(!r.ok)" in body and "setIdle()" in body and "409" in body


def test_the_stream_resyncs_on_reconnect():
    assert "evSource.onopen" in APP and "resyncTurnState" in APP
    assert "p.busy" in APP


def test_a_user_message_can_be_sent_again():
    assert 'class="msg-resend"' in APP
    assert 'closest(".msg-resend")' in APP
    assert 'e.key==="ArrowUp"' in APP and "lastUserText" in APP
    css = (ROOT / "reforge" / "web" / "styles.css").read_text(encoding="utf-8")
    assert ".msg-resend" in css


def test_a_user_message_is_echoed_to_other_tabs_and_not_duplicated_in_the_sender():
    """The backend emits `user_message`; the sender expects exactly one echo of its own text, so a
    resend of the same text still reaches the other tabs."""
    src = (ROOT / "reforge" / "agent.py").read_text(encoding="utf-8")
    assert 'emit("user_message"' in src
    assert "pendingEcho=text" in APP and "if(pendingEcho===e.text){ pendingEcho=null; break; }" in APP
