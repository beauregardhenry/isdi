"""Consultation answers are stored per client, encrypted, and go with the
client's other records when they are exported or erased."""

import sqlite3

import pytest

from isdi import crypto
from isdi.consultation import store
from isdi.scanner import db


@pytest.fixture
def ctx(app):
    with app.app_context():
        yield


def test_nothing_stored_gives_an_empty_document(ctx):
    assert store.load("c-empty", "taq") == {}
    assert store.load("c-empty", "accounts") == []
    assert store.load("c-empty", "report_name") == ""


def test_a_document_round_trips(ctx):
    store.save("c-rt", "taq", {"devices": {"live_together": "yes"}})
    assert store.load("c-rt", "taq") == {"devices": {"live_together": "yes"}}
    store.save("c-rt", "taq", {"marked_done": True})
    assert store.load("c-rt", "taq") == {"marked_done": True}


def test_each_client_has_their_own_answers(ctx):
    store.save("c-a", "notes", {"client_notes": "A"})
    store.save("c-b", "notes", {"client_notes": "B"})
    assert store.load("c-a", "notes") == {"client_notes": "A"}
    assert store.load("c-b", "notes") == {"client_notes": "B"}


def test_answers_are_encrypted_in_the_file(ctx):
    store.save("c-enc", "notes", {"client_notes": "MARKER-7731"})
    con = sqlite3.connect(db.DATABASE)
    (raw,) = con.execute(
        "SELECT doc FROM consultation_docs WHERE clientid='c-enc' AND kind='notes'"
    ).fetchone()
    con.close()
    assert crypto.is_encrypted(raw) and "MARKER-7731" not in raw


@pytest.mark.parametrize("kind", ["passwords", "", "../etc"])
def test_unknown_kinds_are_refused(ctx, kind):
    with pytest.raises(ValueError):
        store.load("c", kind)
    with pytest.raises(ValueError):
        store.save("c", kind, {})


def test_the_wrong_type_is_refused(ctx):
    with pytest.raises(TypeError):
        store.save("c", "accounts", {"not": "a list"})


def test_load_all_has_every_kind(ctx):
    assert set(store.load_all("c-all")) == set(store.KINDS)


def test_export_and_erase_include_the_consultation(ctx):
    store.save("c-gdpr", "accounts", [{"account_id": 0, "platform": "Mail"}])
    exported = db.export_client("c-gdpr")
    assert exported["consultation"]["accounts"] == [
        {"account_id": 0, "platform": "Mail"}
    ]
    counts = db.erase_client("c-gdpr")
    assert counts["consultation_docs"] == 1
    assert store.load("c-gdpr", "accounts") == []


def test_an_older_database_gets_the_table(ctx, tmp_path):
    con = sqlite3.connect(tmp_path / "old.db")
    con.executescript(
        db.SCHEMA_SQL.split("CREATE TABLE IF NOT EXISTS consultation_docs")[0]
    )
    con.execute("PRAGMA user_version = 7")
    db.migrate(con)
    assert "doc" in db._columns(con, "consultation_docs")
    assert con.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION
