"""The consultation form: client notes are saved and can be edited."""

import json
import re
import uuid

import pytest

from isdi.web.forms import ClientForm
from isdi.scanner import db


def _valid_form_data(**overrides):
    """A complete submission: every required field filled in, using the
    form's own choices, and the optional email left empty."""
    data = {}
    for field in ClientForm():
        if field.type in ("SelectField", "SelectMultipleField"):
            value = next(c.value for c in field.choices if c.value)
            data[field.name] = [value] if field.type == "SelectMultipleField" else value
        elif field.type == "IntegerField":
            data[field.name] = "1"
        else:
            data[field.name] = "x"
    data["referring_professional_email"] = ""
    data.update(overrides)
    return data


@pytest.fixture
def consult_client(app, no_csrf):
    c = app.test_client()
    clientid = f"consult_{uuid.uuid4().hex[:10]}"
    with c.session_transaction() as s:
        s["clientid"] = clientid
    return c, clientid


def _saved(app, clientid):
    with app.app_context():
        return db.get_notes_for_client(clientid)


def test_form_requires_a_session(app):
    r = app.test_client().get("/form/")
    assert r.status_code == 302 and r.headers["Location"].endswith("/")


def test_valid_form_is_saved(app, consult_client):
    c, clientid = consult_client
    r = c.post("/form/", data=_valid_form_data())
    assert r.status_code == 200
    saved = _saved(app, clientid)
    assert saved is not None, "the consult notes were not saved"
    assert saved["referring_professional"] == "x"


def test_valid_email_is_accepted(app, consult_client):
    c, clientid = consult_client
    c.post(
        "/form/",
        data=_valid_form_data(referring_professional_email="pro@example.org"),
    )
    assert _saved(app, clientid)["referring_professional_email"] == "pro@example.org"


def test_invalid_email_is_rejected(app, consult_client):
    c, clientid = consult_client
    r = c.post(
        "/form/", data=_valid_form_data(referring_professional_email="not-an-email")
    )
    assert r.status_code == 200
    assert _saved(app, clientid) is None


def test_missing_required_field_is_rejected(app, consult_client):
    c, clientid = consult_client
    r = c.post("/form/", data=_valid_form_data(referring_professional=""))
    assert r.status_code == 200
    assert _saved(app, clientid) is None


def test_submitted_form_redirects_to_edit_and_saves_changes(app, consult_client):
    c, clientid = consult_client
    c.post("/form/", data=_valid_form_data())
    r = c.get("/form/")
    assert r.status_code == 302 and r.headers["Location"].endswith("/form/edit/")

    assert c.get("/form/edit/").status_code == 200
    with app.app_context():
        pk = db.get_notes_for_client(clientid)["id"]
    assert c.post("/form/edit/", data={"clientnote": pk}).status_code == 200
    c.post("/form/edit/", data=_valid_form_data(referring_professional="changed"))
    assert _saved(app, clientid)["referring_professional"] == "changed"


def test_invalid_edit_is_not_saved(app, consult_client):
    c, clientid = consult_client
    c.post("/form/", data=_valid_form_data())
    with app.app_context():
        pk = db.get_notes_for_client(clientid)["id"]
    c.post("/form/edit/", data={"clientnote": pk})
    r = c.post("/form/edit/", data=_valid_form_data(referring_professional_email="bad"))
    assert r.status_code == 200 and b"Invalid email address." in r.data
    assert _saved(app, clientid)["referring_professional_email"] in (None, "")


def test_checkbox_lists_survive_opening_and_editing(app, consult_client):
    """Lists are stored as JSON; the edit form must show them ticked, and
    saving an unrelated change must keep them."""
    c, clientid = consult_client
    concerns = ["spyware", "location"]
    c.post("/form/", data=_valid_form_data(chief_concerns=concerns))
    assert json.loads(_saved(app, clientid)["chief_concerns"]) == concerns
    pk = _saved(app, clientid)["id"]
    page = c.post("/form/edit/", data={"clientnote": pk}).get_data(as_text=True)
    for value in concerns:
        assert re.search(rf'<input[^>]*checked[^>]*value="{value}"', page) or (
            re.search(rf'<input[^>]*value="{value}"[^>]*checked', page)
        ), f"{value} is not ticked on the edit form"
    assert 'value="glitchy" checked' not in page
    c.post(
        "/form/edit/",
        data=_valid_form_data(chief_concerns=concerns, general_notes="later"),
    )
    saved = _saved(app, clientid)
    assert json.loads(saved["chief_concerns"]) == concerns
    assert saved["general_notes"] == "later"


def test_a_malformed_note_id_shows_the_list(app, consult_client):
    c, _ = consult_client
    for bad in ("x", "1 OR 1=1", "", "99999999"):
        r = c.post("/form/edit/", data={"clientnote": bad})
        assert r.status_code in (200, 302)
        assert b"Traceback" not in r.data


def test_edits_leave_no_old_notes_in_the_file(app, consult_client):
    """The notes are written with secure_delete on, like everything else, so
    the replaced text is overwritten rather than left in free pages."""
    from pathlib import Path

    c, clientid = consult_client
    c.post("/form/", data=_valid_form_data(chief_concerns_other="A" * 20000))
    import sqlite3

    raw = sqlite3.connect(db.DATABASE)
    (old,) = raw.execute(
        "SELECT chief_concerns_other FROM clients_notes WHERE clientid=?",
        (clientid,),
    ).fetchone()
    raw.close()
    probes = [old[i : i + 48].encode() for i in range(0, len(old) - 48, 1000)]
    assert all(p in Path(db.DATABASE).read_bytes() for p in probes)
    pk = _saved(app, clientid)["id"]
    c.post("/form/edit/", data={"clientnote": pk})
    c.post("/form/edit/", data=_valid_form_data(chief_concerns_other="short"))
    assert _saved(app, clientid)["chief_concerns_other"] == "short"
    with app.app_context():
        db.get_db().execute("PRAGMA wal_checkpoint(TRUNCATE)")
    data = Path(db.DATABASE).read_bytes()
    left = sum(p in data for p in probes)
    assert left == 0, f"{left} of {len(probes)} pieces of the old notes remain"
