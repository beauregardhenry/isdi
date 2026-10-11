"""Screenshots kept with the consultation record: stored encrypted in the
database, shown only to the client's session, deleted and erased with it."""

import io
import sqlite3
import subprocess

import pytest

from isdi import crypto
from isdi.consultation import screenshots, store
from isdi.scanner import db

CLIENT = "20260101_001"
PNG = screenshots.PNG + b"\x00" * 64
TARGET = "account:0:recovery_settings"


@pytest.fixture(autouse=True)
def fresh(app):
    with app.app_context():
        db.get_db().execute("DELETE FROM screenshots")
        db.get_db().commit()
        store.save(
            CLIENT, "accounts", [{"account_id": 0, "platform": "Mail", "username": "x"}]
        )


def _upload(client, data=PNG, target=TARGET, nxt="/consultation/accounts/0"):
    return client.post(
        "/consultation/screenshots",
        data={
            "target": target,
            "source": "upload",
            "next": nxt,
            "image": (io.BytesIO(data), "s.png"),
        },
        content_type="multipart/form-data",
    )


def test_an_uploaded_screenshot_is_kept_and_shown(app, client, no_csrf):
    r = _upload(client)
    assert r.status_code == 302 and r.headers["Location"].endswith(
        "/consultation/accounts/0"
    )
    page = client.get("/consultation/accounts/0").get_data(as_text=True)
    with app.app_context():
        (row,) = screenshots.listing(CLIENT)
    assert f"/consultation/screenshots/{row['id']}" in page
    img = client.get(f"/consultation/screenshots/{row['id']}")
    assert img.data == PNG and img.headers["Content-Type"] == "image/png"
    assert img.headers["Cache-Control"] == "no-store"


def test_the_image_is_encrypted_in_the_database(app, client, no_csrf):
    _upload(client)
    con = sqlite3.connect(db.DATABASE)
    target, data = con.execute("SELECT target, data FROM screenshots").fetchone()
    con.close()
    assert crypto.is_encrypted(target) and crypto.is_encrypted(data)
    assert "recovery_settings" not in target


@pytest.mark.parametrize("data", [b"GIF89a....", b"<svg onload=alert(1)>", b""])
def test_only_png_and_jpeg_are_kept(app, client, no_csrf, data):
    _upload(client, data=data)
    with app.app_context():
        assert screenshots.listing(CLIENT) == []


def test_a_jpeg_is_kept(app, client, no_csrf):
    _upload(client, data=screenshots.JPEG + b"\x00" * 10)
    with app.app_context():
        assert screenshots.listing(CLIENT)[0]["mime"] == "image/jpeg"


@pytest.mark.parametrize(
    "target", ["account:0:password_check", "device:../x", "app:", "anything"]
)
def test_unknown_targets_are_refused(client, no_csrf, target):
    assert _upload(client, target=target).status_code == 400


@pytest.mark.parametrize(
    "nxt", ["https://evil.example/", "//evil.example", "/consultation\\@evil", "/login"]
)
def test_only_consultation_pages_are_returned_to(client, no_csrf, nxt):
    assert _upload(client, nxt=nxt).headers["Location"].endswith("/consultation")


def test_another_client_cannot_see_or_delete_it(app, client, client_of, no_csrf):
    _upload(client)
    with app.app_context():
        shot_id = screenshots.listing(CLIENT)[0]["id"]
    other = client_of("20260101_888")
    assert other.get(f"/consultation/screenshots/{shot_id}").status_code == 404
    assert other.post(f"/consultation/screenshots/{shot_id}/delete").status_code == 404
    with app.app_context():
        assert len(screenshots.listing(CLIENT)) == 1


def test_a_screenshot_can_be_deleted(app, client, no_csrf):
    _upload(client)
    with app.app_context():
        shot_id = screenshots.listing(CLIENT)[0]["id"]
    client.post(
        f"/consultation/screenshots/{shot_id}/delete",
        data={"next": "/consultation/screenshots"},
    )
    with app.app_context():
        assert screenshots.listing(CLIENT) == []


def test_taking_one_from_the_phone(app, client, no_csrf, monkeypatch):
    from isdi.web.view import index

    monkeypatch.setattr(index.android, "devices", lambda: ["R58M123"])
    seen = []

    def fake_run(argv, **kw):
        seen.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout=PNG, stderr=b"")

    monkeypatch.setattr(screenshots, "run", fake_run)
    client.post(
        "/consultation/screenshots",
        data={"target": TARGET, "source": "phone", "serial": "R58M123"},
    )
    assert seen and seen[0][1:] == ["-s", "R58M123", "exec-out", "screencap", "-p"]
    with app.app_context():
        assert screenshots.listing(CLIENT)[0]["source"] == "phone"


def test_a_phone_that_is_not_connected_is_refused(app, client, no_csrf, monkeypatch):
    from isdi.web.view import index

    monkeypatch.setattr(index.android, "devices", lambda: [])
    client.post(
        "/consultation/screenshots",
        data={"target": TARGET, "source": "phone", "serial": "R58M123"},
    )
    with app.app_context():
        assert screenshots.listing(CLIENT) == []


def test_a_locked_phone_is_reported(app, client, no_csrf, monkeypatch):
    from isdi.web.view import index

    monkeypatch.setattr(index.android, "devices", lambda: ["R58M123"])
    monkeypatch.setattr(
        screenshots,
        "run",
        lambda argv, **kw: subprocess.CompletedProcess(argv, 0, stdout=b"", stderr=b""),
    )
    client.post(
        "/consultation/screenshots",
        data={"target": TARGET, "source": "phone", "serial": "R58M123"},
    )
    assert "Is the screen unlocked?" in client.get("/consultation").get_data(
        as_text=True
    )


def test_the_take_button_shows_only_with_a_phone(client, monkeypatch):
    from isdi.web.view import index

    monkeypatch.setattr(index.android, "devices", lambda: [])
    assert "connected Android phone" not in client.get(
        "/consultation/accounts/0"
    ).get_data(as_text=True)
    monkeypatch.setattr(index.android, "devices", lambda: ["R58M123"])
    assert "connected Android phone" in client.get("/consultation/accounts/0").get_data(
        as_text=True
    )


def test_export_and_erase_include_screenshots(app, client, no_csrf):
    _upload(client)
    with app.app_context():
        exported = db.export_client(CLIENT)
        assert exported["screenshots"][0]["target"] == TARGET
        assert db.erase_client(CLIENT)["screenshots"] == 1
        assert screenshots.listing(CLIENT) == []


def test_the_manager_lists_them(client, no_csrf):
    _upload(client)
    page = client.get("/consultation/screenshots").get_data(as_text=True)
    assert TARGET in page and "uploaded" in page
