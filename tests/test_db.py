"""Scan storage: what gets deleted, what gets reported, which scan is shown.
Deleting a device must remove all of its data and nothing else."""

import csv
import os
import re
import uuid

import pytest

from isdi.config import get_config
from isdi.scanner import db


@pytest.fixture
def ctx(app):
    with app.app_context():
        yield


def _new_client():
    return f"test_{uuid.uuid4().hex[:12]}"


def _scan(clientid, serial, model="Pixel", apps=("org.example.a",)):
    scanid = db.create_scan(
        {
            "clientid": clientid,
            "serial": serial,
            "device": "android",
            "device_model": model,
            "device_version": "14",
            "device_manufacturer": "Google",
            "last_full_charge": "unknown",
            "device_primary_user": "owner",
            "is_rooted": False,
            "rooted_reasons": "[]",
        }
    )
    db.create_mult_appinfo([(scanid, a, '["dual-use"]', "", "<new>") for a in apps])
    return scanid


def _hmac(raw):
    return get_config().hmac_serial(raw)


def test_latest_scan_per_device(ctx):
    cid = _new_client()
    a, b = _hmac(f"A-{cid}"), _hmac(f"B-{cid}")
    _scan(cid, a, model="old")
    newest_a = _scan(cid, a, model="new")
    only_b = _scan(cid, b)
    rows = db.get_client_devices_from_db(cid)
    assert [r["id"] for r in rows] == [only_b, newest_a]
    assert rows[1]["device_model"] == "new"


def test_other_clients_devices_not_listed(ctx):
    cid, other = _new_client(), _new_client()
    _scan(other, _hmac(f"X-{other}"))
    assert db.get_client_devices_from_db(cid) == []


def test_delete_removes_only_that_device(ctx):
    cid = _new_client()
    gone, kept = _hmac(f"G-{cid}"), _hmac(f"K-{cid}")
    gone_ids = [_scan(cid, gone), _scan(cid, gone)]
    kept_id = _scan(cid, kept)
    dump_dir = get_config().DUMP_DIR
    gone_dump = os.path.join(dump_dir, f"{gone}_android.txt")
    kept_dump = os.path.join(dump_dir, f"{kept}_android.txt")
    for path in (gone_dump, kept_dump):
        with open(path, "w") as f:
            f.write("dump")

    assert db.delete_scan_data(gone) is True

    for scanid in gone_ids:
        assert db.get_scan_res_from_db(scanid) is None
        assert db.get_app_info_from_db(scanid) == []
    assert not os.path.exists(gone_dump)
    assert db.get_scan_res_from_db(kept_id) is not None
    assert db.get_app_info_from_db(kept_id) != []
    assert os.path.exists(kept_dump)
    os.remove(kept_dump)


def test_delete_treats_glob_characters_literally(ctx):
    victim = os.path.join(get_config().DUMP_DIR, f"{_hmac(uuid.uuid4().hex)}_ios.json")
    with open(victim, "w") as f:
        f.write("{}")
    db.delete_scan_data("*")
    assert os.path.exists(victim)
    os.remove(victim)


def test_create_report_writes_client_scans(ctx):
    cid = _new_client()
    _scan(cid, _hmac(f"R-{cid}"), apps=("org.example.a", "org.example.b"))
    path = db.create_report(cid)
    assert path == os.path.join(get_config().REPORT_PATH, f"{cid}.csv")
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert sorted(r["appid"] for r in rows) == ["org.example.a", "org.example.b"]
    assert {r["clientid"] for r in rows} == {cid}
    os.remove(path)


def test_create_report_for_client_without_scans(ctx):
    cid = _new_client()
    db.create_report(cid)
    path = os.path.join(get_config().REPORT_PATH, f"{cid}.csv")
    assert os.path.getsize(path) == 0
    os.remove(path)


def test_new_client_id_format(ctx):
    assert re.fullmatch(r"\d{8}_\d{3}", db.new_client_id())
