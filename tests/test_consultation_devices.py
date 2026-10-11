"""Devices in the consultation record: added from one of the client's
scans or by hand, the apps chosen for questions, and the answers."""

import json
import re

import pytest

from isdi.consultation import store
from isdi.scanner import db

CLIENT = "20260101_001"


@pytest.fixture(autouse=True)
def fresh(app):
    with app.app_context():
        store.delete(CLIENT, "devices")


def _scan(app, clientid=CLIENT, apps=None):
    """A saved scan with apps, as ISDi's scan page stores it."""
    apps = apps or {
        "com.spy": (
            ["stalkerware"],
            {"firstInstallTime": "2026-01-02", "versionName": "3.1"},
        ),
        "com.calc": ([], {}),
        "com.android.settings": (["system-app"], {}),
    }
    with app.app_context():
        scanid = db.create_scan(
            {
                "clientid": clientid,
                "serial": "f" * 64,
                "device": "android",
                "device_model": "Pixel 7",
                "device_version": "14",
                "device_manufacturer": "Google",
                "last_full_charge": "",
                "device_primary_user": "kitchen phone",
                "is_rooted": False,
                "rooted_reasons": "[]",
            }
        )
        db.create_mult_appinfo(
            [(scanid, a, json.dumps(f), "", "") for a, (f, _) in apps.items()],
            details={a: d for a, (_, d) in apps.items() if d},
        )
    return scanid


@pytest.fixture
def devices(app):
    def get():
        with app.app_context():
            return store.load(CLIENT, "devices")

    return get


def test_the_client_s_scans_are_offered(app, client):
    _scan(app)
    page = client.get("/consultation/devices/add").get_data(as_text=True)
    assert "kitchen phone" in page and "Pixel 7" in page


def test_another_client_s_scan_cannot_be_added(app, client, no_csrf, devices):
    other = _scan(app, clientid="20260101_555")
    assert (
        client.post("/consultation/devices/add", data={"scanid": other}).status_code
        == 404
    )
    assert devices() == []


def test_adding_a_scan_offers_its_apps_flagged_first(app, client, no_csrf, devices):
    scanid = _scan(app)
    r = client.post("/consultation/devices/add", data={"scanid": scanid})
    assert r.headers["Location"].endswith(f"/consultation/devices/scan-{scanid}/apps")
    (d,) = devices()
    assert (d["key"], d["device_nickname"], d["device_model"]) == (
        f"scan-{scanid}",
        "kitchen phone",
        "Pixel 7",
    )
    page = client.get(f"/consultation/devices/scan-{scanid}/apps").get_data(
        as_text=True
    )
    assert page.index("com.spy") < page.index("com.calc")
    # Flagged apps are offered checked; a preinstalled app alone is not.
    assert 'value="com.spy" id="app-1" checked' in page
    assert (
        'value="com.android.settings"' in page
        and 'value="com.android.settings" id="app-3" checked' not in page
    )


def test_chosen_apps_are_kept_with_their_scan_details(app, client, no_csrf, devices):
    scanid = _scan(app)
    client.post("/consultation/devices/add", data={"scanid": scanid})
    r = client.post(
        f"/consultation/devices/scan-{scanid}/apps",
        data={"app": ["com.spy", "com.notinscan"]},
    )
    assert r.headers["Location"].endswith("/questions")
    (app_,) = devices()[0]["selected_apps"]
    assert app_["appId"] == "com.spy" and app_["flags"] == ["stalkerware"]
    assert (app_["install_time"], app_["app_version"]) == ("2026-01-02", "3.1")


def test_answers_are_saved_and_the_risks_listed(app, client, no_csrf, devices):
    scanid = _scan(app)
    client.post("/consultation/devices/add", data={"scanid": scanid})
    client.post(f"/consultation/devices/scan-{scanid}/apps", data={"app": ["com.spy"]})
    page = client.get(f"/consultation/devices/scan-{scanid}/questions").get_data(
        as_text=True
    )
    assert "Did you know this app was installed?" in page
    client.post(
        f"/consultation/devices/scan-{scanid}/questions",
        data={
            "apps-0-appId": "com.spy",
            "apps-0-title": "",
            "apps-0-install_info-knew_installed": "no",
            "apps-0-permission_info-access": "yes",
            "apps-0-notes-client_notes": "never seen it",
        },
    )
    a = devices()[0]["selected_apps"][0]
    assert a["install_info"]["knew_installed"] == "no"
    assert a["notes"]["client_notes"] == "never seen it"
    record = client.get("/consultation").get_data(as_text=True)
    assert "Devices (1)" in record and "Risk from app: com.spy" in record


def test_choosing_again_keeps_the_answers(app, client, no_csrf, devices):
    scanid = _scan(app)
    client.post("/consultation/devices/add", data={"scanid": scanid})
    client.post(f"/consultation/devices/scan-{scanid}/apps", data={"app": ["com.spy"]})
    client.post(
        f"/consultation/devices/scan-{scanid}/questions",
        data={"apps-0-appId": "com.spy", "apps-0-install_info-installed": "no"},
    )
    client.post(
        f"/consultation/devices/scan-{scanid}/apps",
        data={"app": ["com.spy", "com.calc"]},
    )
    apps = {a["appId"]: a for a in devices()[0]["selected_apps"]}
    assert apps["com.spy"]["install_info"]["installed"] == "no"
    assert set(apps) == {"com.spy", "com.calc"}


def test_a_scan_is_added_only_once(app, client, no_csrf, devices):
    scanid = _scan(app)
    client.post("/consultation/devices/add", data={"scanid": scanid})
    client.post("/consultation/devices/add", data={"scanid": scanid})
    assert len(devices()) == 1
    assert "kitchen phone" not in client.get("/consultation/devices/add").get_data(
        as_text=True
    )


def test_a_device_added_by_hand(client, no_csrf, devices):
    r = client.post(
        "/consultation/devices/manual",
        data={
            "device_nickname": "old phone",
            "device_type": "android",
            "is_rooted": "yes",
            "apps-0-title": "Hidden Tracker",
            "apps-0-spyware": "y",
            "apps-1-title": "Family Locator",
            "apps-1-dualuse": "y",
            "apps-2-title": "  ",
        },
    )
    assert r.headers["Location"].endswith("/consultation/devices/manual-1/questions")
    (d,) = devices()
    assert d["manual"] is True and d["key"] == "manual-1"
    assert [(a["title"], a["flags"]) for a in d["selected_apps"]] == [
        ("Hidden Tracker", ["spyware"]),
        ("Family Locator", ["dual-use"]),
    ]
    assert "Evidence of jailbreaking" in client.get("/consultation").get_data(
        as_text=True
    )


def test_a_device_added_by_hand_opens_with_its_answers(client, no_csrf):
    client.post(
        "/consultation/devices/manual",
        data={
            "device_nickname": "old phone",
            "apps-0-title": "Family Locator",
            "apps-0-dualuse": "y",
        },
    )
    page = client.get("/consultation/devices/manual-1/manual").get_data(as_text=True)
    assert 'value="Family Locator"' in page
    assert re.search(r'<input checked[^>]*id="apps-0-dualuse"', page)
    assert not re.search(r'<input checked[^>]*id="apps-0-spyware"', page)


def test_a_manual_device_needs_a_nickname(client, no_csrf, devices):
    r = client.post("/consultation/devices/manual", data={"device_nickname": ""})
    assert r.status_code == 200 and devices() == []


def test_add_another_app_shows_one_more_row(client, no_csrf, devices):
    page = client.post(
        "/consultation/devices/manual",
        data={"device_nickname": "x", "apps-0-title": "A", "add_app": "1"},
    ).get_data(as_text=True)
    assert 'name="apps-1-title"' in page and devices() == []


def test_removing_a_device_keeps_the_scan(app, client, no_csrf, devices):
    scanid = _scan(app)
    client.post("/consultation/devices/add", data={"scanid": scanid})
    client.post(f"/consultation/devices/scan-{scanid}/delete")
    assert devices() == []
    with app.app_context():
        assert db.get_scan_res_from_db(scanid)


@pytest.mark.parametrize("path", ["apps", "questions", "manual"])
def test_unknown_devices_are_not_found(client, path):
    assert client.get(f"/consultation/devices/scan-999/{path}").status_code == 404


def test_a_listed_app_is_named_from_the_blocklist(app, client, no_csrf, devices):
    # No app-info.db in the tests: the blocklist's title is used.
    scanid = _scan(app, apps={"com.spy2mobile.light": (["stalkerware"], {})})
    client.post("/consultation/devices/add", data={"scanid": scanid})
    assert "Data Backup" in client.get(
        f"/consultation/devices/scan-{scanid}/apps"
    ).get_data(as_text=True)
