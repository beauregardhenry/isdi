"""The consultation record pages: the overview, the questionnaire, notes."""

import re

import pytest

from isdi import audit
from isdi.consultation import store

CLIENT = "20260101_001"  # the conftest client fixture's session client


@pytest.fixture
def stored(app):
    def get(kind, clientid=CLIENT):
        with app.app_context():
            return store.load(clientid, kind)

    return get


@pytest.fixture(autouse=True)
def fresh(app):
    with app.app_context():
        for kind in store.KINDS:
            store.delete(CLIENT, kind)


def test_the_overview_shows_the_client(client):
    page = client.get("/consultation").get_data(as_text=True)
    assert "Consultation record" in page and CLIENT in page
    assert "Fill in the questionnaire" in page


def test_without_a_client_the_pages_go_home(app):
    c = app.test_client()
    for path in ("/consultation", "/consultation/questionnaire"):
        r = c.get(path)
        assert r.status_code == 302 and r.headers["Location"].endswith("/")


def test_the_home_page_links_to_the_record(client):
    assert 'href="/consultation"' in client.get("/").get_data(as_text=True)


def test_the_questionnaire_renders_every_question(client):
    from isdi.consultation.model import TAQ_SECTIONS

    page = client.get("/consultation/questionnaire").get_data(as_text=True)
    for cls in TAQ_SECTIONS.values():
        for text in cls.questions.values():
            assert text.replace("'", "&#39;") in page


def test_questionnaire_answers_are_saved_for_this_client(client, stored, no_csrf):
    r = client.post(
        "/consultation/questionnaire",
        data={
            "devices-live_together": "yes",
            "smarthome-smart_home_setup": ["poc", "me"],
            "legal-legal": ["ro"],
            "marked_done": "y",
        },
    )
    assert r.status_code == 302
    taq = stored("taq")
    assert taq["devices"]["live_together"] == "yes"
    assert taq["smarthome"]["smart_home_setup"] == ["poc", "me"]
    assert taq["legal"]["legal"] == ["ro"]
    assert taq["marked_done"] is True
    assert stored("taq", clientid="20260101_999") == {}


def test_saved_answers_come_back_on_the_form(client, no_csrf):
    client.post(
        "/consultation/questionnaire",
        data={"accounts-pwd_comp": "yes", "accounts-pwd_mgmt": ["paper"]},
    )
    page = client.get("/consultation/questionnaire").get_data(as_text=True)
    assert re.search(
        r'<input checked[^>]*id="accounts-pwd_comp-1"[^>]*value="yes"', page
    )
    assert re.search(
        r'<input checked[^>]*name="accounts-pwd_mgmt"[^>]*value="paper"', page
    )


def test_the_overview_lists_the_risks(client, no_csrf):
    client.post(
        "/consultation/questionnaire",
        data={"sharing-share_phone_plan": "yes", "marked_done": "y"},
    )
    page = client.get("/consultation").get_data(as_text=True)
    assert "Shared phone plan" in page
    assert "complete" in page


def test_an_answer_the_form_does_not_offer_is_dropped(client, stored, no_csrf):
    client.post("/consultation/questionnaire", data={"legal-legal": ["ro", "<script>"]})
    assert stored("taq")["legal"]["legal"] == ["ro"]


def test_notes_are_saved(client, stored, no_csrf):
    client.post(
        "/consultation/notes",
        data={"client_notes": "NOTE-1", "consultant_notes": "NOTE-2"},
    )
    assert stored("notes") == {"client_notes": "NOTE-1", "consultant_notes": "NOTE-2"}
    assert "NOTE-1" in client.get("/consultation").get_data(as_text=True)


def test_saves_are_audited_without_the_answers(app, client, no_csrf):
    client.post("/consultation/notes", data={"client_notes": "SECRET-NOTE"})
    with app.app_context():
        entries = [
            e for e in audit.entries(CLIENT) if e["action"] == "consultation_saved"
        ]
    assert entries and entries[-1]["details"] == {"part": "notes"}
    assert "SECRET-NOTE" not in str(entries)


@pytest.mark.parametrize("path", ["/consultation/notes", "/consultation/questionnaire"])
def test_posts_need_the_csrf_token(client, path):
    assert client.post(path, data={"client_notes": "x"}).status_code == 400


def test_notes_are_escaped(client, no_csrf):
    client.post(
        "/consultation/notes", data={"client_notes": "<script>alert(1)</script>"}
    )
    page = client.get("/consultation").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in page
