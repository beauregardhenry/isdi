"""The consultation form: client notes are saved and can be edited."""

import uuid

import pytest

from isdi.web.forms import ClientForm
from isdi.web.model import Client


def _valid_form_data(**overrides):
    """A complete submission: every required field filled in, using the
    form's own choices, and the optional email left empty."""
    data = {}
    for field in ClientForm():
        if field.type in ("SelectField", "SelectMultipleField"):
            value = next(v for v, _ in field.choices if v)
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
        return Client.query.filter_by(clientid=clientid).first()


def test_form_requires_a_session(app):
    r = app.test_client().get("/form/")
    assert r.status_code == 302 and r.headers["Location"].endswith("/")


def test_valid_form_is_saved(app, consult_client):
    c, clientid = consult_client
    r = c.post("/form/", data=_valid_form_data())
    assert r.status_code == 200
    saved = _saved(app, clientid)
    assert saved is not None, "the consult notes were not saved"
    assert saved.referring_professional == "x"


def test_valid_email_is_accepted(app, consult_client):
    c, clientid = consult_client
    c.post(
        "/form/",
        data=_valid_form_data(referring_professional_email="pro@example.org"),
    )
    assert _saved(app, clientid).referring_professional_email == "pro@example.org"


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
        pk = Client.query.filter_by(clientid=clientid).first().id
    assert c.post("/form/edit/", data={"clientnote": pk}).status_code == 200
    c.post("/form/edit/", data=_valid_form_data(referring_professional="changed"))
    assert _saved(app, clientid).referring_professional == "changed"


def test_invalid_edit_is_not_saved(app, consult_client):
    c, clientid = consult_client
    c.post("/form/", data=_valid_form_data())
    with app.app_context():
        pk = Client.query.filter_by(clientid=clientid).first().id
    c.post("/form/edit/", data={"clientnote": pk})
    r = c.post("/form/edit/", data=_valid_form_data(referring_professional_email="bad"))
    assert r.status_code == 200 and b"Invalid email address." in r.data
    assert _saved(app, clientid).referring_professional_email in (None, "")
