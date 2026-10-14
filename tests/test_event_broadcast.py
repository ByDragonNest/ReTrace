"""Every attached stream gets every event.

One `asyncio.Queue` per project meant one consumer: with the project open in two tabs, each event
reached whichever reader woke first, and the other tab stayed on "Sending…" for good. Seen with the
Browser pane and the user's own window open on the same project.
"""
from __future__ import annotations

import asyncio

from reforge.session import Session


def _run(coro):
    return asyncio.run(coro)


def test_two_subscribers_both_receive_every_event():
    async def go():
        s = Session("s", "demo")
        a, b = s.subscribe(), s.subscribe()
        await s.emit("status", text="x"); await s.emit("done")
        return [e["kind"] for e in (a.get_nowait(), a.get_nowait())], [e["kind"] for e in (b.get_nowait(), b.get_nowait())]
    assert _run(go()) == (["status", "done"], ["status", "done"])


def test_an_unsubscribed_stream_stops_receiving():
    async def go():
        s = Session("s", "demo")
        a = s.subscribe(); s.unsubscribe(a)
        await s.emit("done")
        return a.qsize(), s.events.qsize()
    assert _run(go()) == (0, 1)        # back to the backlog once nobody listens


def test_the_backlog_reaches_the_first_subscriber():
    async def go():
        s = Session("s", "demo")
        await s.emit("status", text="emitted before any tab opened")
        q = s.subscribe()
        return q.get_nowait()["kind"], s.events.qsize()
    assert _run(go()) == ("status", 0)


def test_with_no_subscriber_events_still_land_in_the_backlog_for_tests_and_late_tabs():
    async def go():
        s = Session("s", "demo")
        await s.emit("done")
        return s.events.get_nowait()["kind"]
    assert _run(go()) == "done"


def test_a_stalled_tab_loses_old_events_not_new_ones():
    async def go():
        s = Session("s", "demo"); s.EVENT_QUEUE_MAX = 3
        q = s.subscribe()
        for i in range(5):
            await s.emit("n", i=i)
        return [q.get_nowait()["i"] for _ in range(q.qsize())]
    assert _run(go()) == [2, 3, 4]
