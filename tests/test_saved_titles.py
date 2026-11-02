"""App names on saved scans. A scan stores each app's name as the results
showed it (schema 10), so reopening the scan and the client summary show
the same names. Many come from the phone, which no store list knows: every
iPhone app, and Android apps installed from outside a store."""

import sqlite3
from types import SimpleNamespace

from isdi.scanner import blocklist, db
from isdi.web.view import scan as scan_view


def _store(tmp_path, rows):
    """A stand-in for app-info.db (the store list)."""
    conn = sqlite3.connect(tmp_path / "app-info.db")
    conn.execute("CREATE TABLE apps (appid TEXT, title TEXT)")
    conn.executemany("INSERT INTO apps VALUES (?, ?)", rows)
    return conn


def test_names_are_kept_with_the_scan(app):
    with app.app_context():
        scanid = db.create_scan(
            {
                "clientid": "titles_1",
                "serial": "s",
                "device": "android",
                **dict.fromkeys(
                    "device_model device_version device_manufacturer "
                    "last_full_charge device_primary_user is_rooted "
                    "rooted_reasons".split()
                ),
            }
        )
        db.create_mult_appinfo(
            [
                (scanid, "com.example.helper", '["offstore-app"]', "", "<new>"),
                (scanid, "com.example.cam", "[]", "", "<new>"),
                (scanid, "com.example.none", "[]", "", "<new>"),
            ],
            titles={
                "com.example.helper": "System Helper",
                "com.example.cam": "Cámara 相机",
                "com.example.none": "",
            },
        )
        rows = db.get_app_info_from_db(scanid)
    apps = scan_view._saved_apps(None, "android", rows)
    assert apps["com.example.helper"]["title"] == "System Helper"
    assert apps["com.example.cam"]["title"] == "Cámara 相机"
    assert apps["com.example.none"]["title"] == ""
    assert apps["com.example.helper"] == blocklist.app_row(
        "System Helper", ["offstore-app"]
    )


def test_older_scans_take_names_from_the_store_list(tmp_path):
    """Rows saved before schema 10 have no name: the store list's is used,
    as the scan did then. A stored name is never replaced."""
    rows = [
        {"appid": "com.example.old", "flags": '["dual-use"]', "title": None},
        {"appid": "com.example.kept", "flags": "[]", "title": "Kept"},
        {"appid": "com.example.offstore", "flags": "[]", "title": None},
    ]
    store = _store(
        tmp_path,
        [("com.example.old", "Old Name"), ("com.example.kept", "Store Name")],
    )
    sc = SimpleNamespace(app_info_conn=store)
    apps = scan_view._saved_apps(sc, "android", rows)
    assert apps["com.example.old"]["title"] == "Old Name"
    assert apps["com.example.old"]["flags"] == ["dual-use"]
    assert apps["com.example.kept"]["title"] == "Kept"
    assert apps["com.example.offstore"]["title"] == ""


def test_an_unreadable_store_list_leaves_names_empty(tmp_path):
    rows = [{"appid": "com.example.old", "flags": "[]", "title": None}]
    broken = sqlite3.connect(tmp_path / "empty.db")  # no apps table
    apps = scan_view._saved_apps(SimpleNamespace(app_info_conn=broken), "android", rows)
    assert apps["com.example.old"]["title"] == ""


def test_damaged_flags_read_as_none(tmp_path):
    rows = [
        {"appid": "a", "flags": "not json", "title": None},
        {"appid": "b", "flags": '{"not": "a list"}', "title": None},
    ]
    apps = scan_view._saved_apps(None, "ios", rows)
    assert apps["a"]["flags"] == [] and apps["b"]["flags"] == []


def test_databases_from_before_names_were_kept_gain_the_column(tmp_path):
    v9 = db.SCHEMA_SQL.replace(",\n  title TEXT", "")
    assert v9 != db.SCHEMA_SQL
    conn = sqlite3.connect(tmp_path / "v9.db")
    conn.executescript(v9)
    conn.execute("PRAGMA user_version = 9")
    conn.commit()
    db.migrate(conn)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(app_info)")}
    assert "title" in cols
    assert conn.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION


def test_names_are_stored_encrypted():
    assert "title" in db.ENCRYPTED_COLUMNS["app_info"]
