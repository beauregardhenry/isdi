"""Account checks: add, edit, delete, listed on the record."""

import pytest

from isdi.consultation import store

CLIENT = "20260101_001"


@pytest.fixture(autouse=True)
def fresh(app):
    with app.app_context():
        store.delete(CLIENT, "accounts")


@pytest.fixture
def accounts(app):
    def get():
        with app.app_context():
            return store.load(CLIENT, "accounts")

    return get


def _add(client, platform="Mail", username="me@example.org", **answers):
    return client.post(
        "/consultation/accounts/new",
        data={"platform": platform, "username": username, **answers},
    )


def test_the_form_shows_every_question(client):
    from isdi.consultation.model import ACCOUNT_SECTIONS

    page = client.get("/consultation/accounts/new").get_data(as_text=True)
    for cls in ACCOUNT_SECTIONS.values():
        for text in cls.questions.values():
            assert text.replace("'", "&#39;") in page


def test_an_account_is_saved_with_its_answers(client, accounts, no_csrf):
    r = _add(
        client,
        **{
            "password_check-know": "yes",
            "two_factor_settings-second_factor_type": ["phone", "email"],
        },
    )
    assert r.status_code == 302
    (a,) = accounts()
    assert (a["account_id"], a["platform"], a["username"]) == (
        0,
        "Mail",
        "me@example.org",
    )
    assert a["password_check"]["know"] == "yes"
    assert a["two_factor_settings"]["second_factor_type"] == ["phone", "email"]


def test_the_service_and_username_are_needed(client, accounts, no_csrf):
    r = _add(client, platform="", username="")
    assert r.status_code == 200 and accounts() == []


def test_the_record_lists_accounts_and_their_risks(client, no_csrf):
    _add(client, **{"recovery_settings-email_access": "yes"})
    page = client.get("/consultation").get_data(as_text=True)
    assert "Accounts checked (1)" in page
    assert "Compromised recovery information" in page


def test_an_account_can_be_edited(client, accounts, no_csrf):
    _add(client)
    page = client.get("/consultation/accounts/0").get_data(as_text=True)
    assert 'value="me@example.org"' in page
    client.post(
        "/consultation/accounts/0",
        data={"platform": "Mail", "username": "new@example.org"},
    )
    assert [a["username"] for a in accounts()] == ["new@example.org"]


def test_ids_are_not_reused_after_a_delete(client, accounts, no_csrf):
    # Sherloc used the list position, so deleting one account moved the
    # next one's answers (and screenshots) onto another id.
    _add(client, username="a")
    _add(client, username="b")
    client.post("/consultation/accounts/0/delete")
    _add(client, username="c")
    assert [(a["account_id"], a["username"]) for a in accounts()] == [
        (1, "b"),
        (2, "c"),
    ]


def test_an_unknown_account_is_not_found(client, no_csrf):
    assert client.get("/consultation/accounts/7").status_code == 404
    assert client.post("/consultation/accounts/7/delete").status_code == 404


def test_delete_needs_the_csrf_token(client, accounts, no_csrf, app, monkeypatch):
    _add(client)
    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", True)
    assert client.post("/consultation/accounts/0/delete").status_code == 400
    assert len(accounts()) == 1


def test_another_clients_accounts_are_not_shown(client_of, app, no_csrf):
    with app.app_context():
        store.save(
            "20260101_777",
            "accounts",
            [{"account_id": 0, "platform": "Other", "username": "x"}],
        )
    page = client_of(CLIENT).get("/consultation").get_data(as_text=True)
    assert "Other" not in page
    assert client_of(CLIENT).get("/consultation/accounts/0").status_code == 404
