"""Android apps holding powers monitoring apps rely on (accessibility,
notification access, device administrator), and the stalkerware list's
date."""

import importlib.util
import json
from datetime import date, datetime, timezone
from pathlib import Path

import pytest

from isdi.scanner import blocklist
from isdi.scanner import parse_dump as pd

DUMP = """\
DUMP OF SERVICE device_policy
Current Device Policy Manager state:
  Immutable state:
    mHasFeature=true
  Enabled Device Admins (User 0, provisioningState: 3):
    com.watch.admin/.AdminReceiver:
      uid=10234
      policies:
        wipe-data
        force-lock
    com.android.work/com.android.work.Admin:
      uid=10111
  Not admins:
    com.not.admin/.Thing:
DUMP OF SETTINGS secure
accessibility_enabled=1
enabled_accessibility_services=com.watch.app/com.watch.app.Svc:com.pw/.Fill
enabled_notification_listeners=com.watch.app/.Listen:null
enabled_input_methods=com.keyboard/.Ime
DUMP OF SETTINGS system
enabled_accessibility_services=com.elsewhere/.Svc
"""


def test_powers_from_the_dump():
    assert pd.special_access_from_dump(DUMP) == {
        "com.watch.app": {"accessibility", "notification-access"},
        "com.pw": {"accessibility"},
        "com.watch.admin": {"device-admin"},
        "com.android.work": {"device-admin"},
    }


@pytest.mark.parametrize(
    "text",
    [
        "",
        "DUMP OF SETTINGS secure\nenabled_accessibility_services=\n",
        "DUMP OF SETTINGS secure\nenabled_notification_listeners=null\n",
        "DUMP OF SERVICE device_policy\n  No device admins\n",
    ],
)
def test_no_powers(text):
    assert pd.special_access_from_dump(text) == {}


def test_an_unreadable_dump_has_no_powers(tmp_path, caplog, monkeypatch):
    monkeypatch.setattr(pd.AndroidDump, "load_file", lambda self: {})
    d = pd.AndroidDump(str(tmp_path / "missing.json"))
    assert d.special_access == {}
    assert "Special access not read" in caplog.text


def _scanner(monkeypatch, flags, powers):
    from isdi.scanner import AndroidScanner

    sc = AndroidScanner()
    monkeypatch.setattr(sc, "get_apps", lambda serial: list(flags))
    monkeypatch.setattr(sc, "get_offstore_apps", lambda serial: [])
    monkeypatch.setattr(
        sc,
        "get_system_apps",
        lambda serial: [a for a, f in flags.items() if "system-app" in f],
    )
    monkeypatch.setattr(sc, "get_device_owner_apps", lambda serial: set())
    monkeypatch.setattr(sc, "app_info_conn", None)
    dump = pd.AndroidDump.__new__(pd.AndroidDump)
    dump.special_access = powers
    sc.ddump = dump
    return sc


def test_system_apps_are_not_flagged(monkeypatch):
    sc = _scanner(
        monkeypatch,
        {"com.google.tts": ["system-app"], "com.user.app": []},
        {
            "com.google.tts": {"accessibility"},
            "com.user.app": {"accessibility", "device-admin"},
            "com.not.installed": {"device-admin"},
        },
    )
    apps = sc.find_spyapps("SERIAL")
    assert apps["com.google.tts"]["flags"] == ["system-app"]
    assert apps["com.user.app"]["flags"] == ["accessibility", "device-admin"]
    assert apps["com.user.app"]["score"] == pytest.approx(0.9)
    assert "com.not.installed" not in apps


def test_flag_descriptions_are_neutral():
    html = blocklist.flag_str(["accessibility", "notification-access", "device-admin"])
    assert html.count('class="text-warning"') == 3
    assert "legitimate" in html and "ordinary" not in html


def test_blocklist_date(monkeypatch):
    monkeypatch.setattr(blocklist, "BLOCKLIST_UPDATED", date(2026, 6, 27))
    assert blocklist.blocklist_status(date(2026, 7, 7)) == {
        "updated": "2026-06-27",
        "age_days": 10,
        "stale": False,
    }
    assert blocklist.blocklist_status(date(2027, 1, 1))["stale"] is True


def test_the_shipped_blocklist_is_dated():
    assert blocklist.BLOCKLIST_UPDATED is not None


@pytest.mark.parametrize(
    "content", [None, "not json", '{"other": 1}', '{"updated": 3}']
)
def test_an_undated_blocklist_counts_as_old(tmp_path, monkeypatch, content):
    meta = tmp_path / "app-flags.meta.json"
    if content is not None:
        meta.write_text(content)
    monkeypatch.setattr(blocklist, "BLOCKLIST_UPDATED", blocklist._load_updated(meta))
    assert blocklist.blocklist_status() == {
        "updated": None,
        "age_days": None,
        "stale": True,
    }


@pytest.mark.parametrize("updated, stale", [(date.today(), False), (None, True)])
def test_home_page_shows_the_date(client, monkeypatch, updated, stale):
    monkeypatch.setattr(blocklist, "BLOCKLIST_UPDATED", updated)
    page = client.get("/").get_data(as_text=True)
    assert 'id="blocklist-date"' in page
    assert ("alert-warning p-2" in page) is stale
    assert ("check for a newer ISDi release" in page) is stale
    if updated:
        assert f"last updated {updated.isoformat()}" in page


def _updater():
    path = Path(__file__).parent.parent / "scripts" / "get-stalkerware-indicators.py"
    spec = importlib.util.spec_from_file_location("get_indicators", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_updater_dates_only_a_changed_list(tmp_path, monkeypatch):
    pytest.importorskip("yaml")
    mod = _updater()
    csv_file, meta = tmp_path / "app-flags.csv", tmp_path / "app-flags.meta.json"
    monkeypatch.setattr(mod, "APP_FLAGS_CSV", csv_file)
    monkeypatch.setattr(mod, "APP_FLAGS_META", meta)
    csv_file.write_text("appId,store,flag,title\r\n")

    before = csv_file.read_bytes()
    mod.update_app_flags({"com.example.spy": "Spy"})
    mod.record_update_date(before)
    today = datetime.now(timezone.utc).date().isoformat()
    assert json.loads(meta.read_text())["updated"] == today

    meta.write_text('{"updated": "2020-01-01"}')
    before = csv_file.read_bytes()
    mod.update_app_flags({"com.example.spy": "Spy"})  # nothing new
    mod.record_update_date(before)
    assert json.loads(meta.read_text())["updated"] == "2020-01-01"
