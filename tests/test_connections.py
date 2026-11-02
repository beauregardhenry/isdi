"""Database connections are closed by whoever opened them, not left for
garbage collection. A background scan runs outside an app context, so
get_db() opens a connection for its thread; the thread must close it."""

import sqlite3
import threading
import time
import uuid

from isdi.scanner import db


class Tracked(sqlite3.Connection):
    """A connection that records whether it was closed, and in which thread
    it was opened."""

    opened: list = []

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.thread = threading.current_thread().name
        self.closed = False
        Tracked.opened.append(self)

    def close(self):
        self.closed = True
        super().close()


def test_a_background_scan_closes_its_connection(app, client, no_csrf, monkeypatch):
    connect = sqlite3.connect
    monkeypatch.setattr(Tracked, "opened", [])
    monkeypatch.setattr(
        db.sqlite3, "connect", lambda *a, **kw: connect(*a, factory=Tracked, **kw)
    )
    with client.session_transaction() as s:
        s["clientid"] = f"conn_{uuid.uuid4().hex[:8]}"
    main = threading.current_thread().name
    r = client.post(
        "/scan/start",
        data={"device": "test", "device_owner": "Owner", "devid": "testdevice1"},
    )
    job = r.get_json()["job_id"]
    for _ in range(200):
        if client.get(f"/scan/status/{job}").get_json()["status"] != "running":
            break
        time.sleep(0.05)
    # The job is marked done before the thread finishes; wait for it.
    for thread in threading.enumerate():
        if thread is not threading.current_thread() and thread.daemon:
            thread.join(timeout=10)

    in_scan_thread = [c for c in Tracked.opened if c.thread != main]
    assert in_scan_thread, "the scan did not use a connection of its own"
    assert all(c.closed for c in in_scan_thread)


def test_closing_a_thread_without_a_connection_is_harmless():
    done = []

    def worker():
        db.close_thread_db()
        db.close_thread_db()
        done.append(True)

    t = threading.Thread(target=worker)
    t.start()
    t.join()
    assert done == [True]
