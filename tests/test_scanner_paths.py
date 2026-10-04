"""Scanner paths the end-to-end tests do not reach: app metadata from the
app-info database, and phone dumps that fail, time out or come back too
small."""

import sqlite3
import subprocess

import pytest

import isdi.scanner as scanner
from isdi.scanner import AndroidScanner, AppScanner, IosScanner
from tests.test_scanner_pipeline import SERIAL


@pytest.fixture
def metadata(monkeypatch):
    """A small app-info database in place of the downloaded one."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.execute(
        "CREATE TABLE apps (appid TEXT, title TEXT, permissions TEXT, "
        "description TEXT, summary TEXT, store_description TEXT)"
    )
    conn.executemany(
        "INSERT INTO apps VALUES (?,?,?,?,?,?)",
        [
            ("com.listed", "Listed", "CAMERA, LOCATION ,,", "Main text", "", ""),
            ("com.summary", "Summ", "", "", "Short summary", ""),
            ("com.other", "Other", None, "", "", "From another column"),
        ],
    )
    monkeypatch.setattr(AppScanner, "app_info_conn", conn)
    return conn


@pytest.fixture
def no_scan_details(monkeypatch):
    """The phone's own details as saved with a scan: none here."""
    from isdi.scanner import db

    monkeypatch.setattr(db, "get_most_recent_scan_id", lambda serial: None)


def test_app_metadata_is_normalised(metadata, no_scan_details):
    details = AndroidScanner().get_multiple_app_details(
        SERIAL, ["com.listed", "com.summary", "com.other", "com.sideloaded"]
    )
    listed, _ = details["com.listed"]
    assert listed["permissions"] == ["CAMERA", "LOCATION"]
    assert listed["descriptionHTML"] == "Main text"
    assert details["com.summary"][0]["descriptionHTML"] == "Short summary"
    other = details["com.other"][0]
    assert other["permissions"] == []
    assert other["descriptionHTML"] == "From another column"
    assert other["summary"] == "Other"  # falls back to the title
    # Not in the metadata (often the sideloaded apps): still listed.
    assert details["com.sideloaded"] == ({}, {})


def test_app_details_without_metadata_or_apps(monkeypatch, no_scan_details):
    monkeypatch.setattr(AppScanner, "app_info_conn", None)
    sc = AndroidScanner()
    assert sc.get_multiple_app_details(SERIAL, []) == {}
    assert sc.get_multiple_app_details(SERIAL, ["com.x"]) == {"com.x": ({}, {})}


def test_a_missing_metadata_database_is_not_fatal(monkeypatch, tmp_path):
    monkeypatch.setattr(AppScanner, "app_info_conn", None)
    monkeypatch.setattr(
        scanner.cfg, "APP_INFO_SQLITE_FILE", f"sqlite:///{tmp_path}/no/such/dir.db"
    )
    AndroidScanner()
    assert AppScanner.app_info_conn is None


@pytest.fixture
def adb_run(monkeypatch):
    """Fake subprocess.run for the Android dump: .stdout per call, or raise
    .error."""

    class Fake:
        stdout = "x=1\n" * 2000
        error = None

    def run(argv, **kw):
        if Fake.error:
            raise Fake.error
        return subprocess.CompletedProcess(argv, 0, stdout=Fake.stdout, stderr="")

    monkeypatch.setattr(scanner.android.subprocess, "run", run)
    yield Fake
    AndroidScanner().discard_dump(SERIAL)


def test_android_dump_succeeds(adb_run):
    assert AndroidScanner()._dump_phone(SERIAL) is True


def test_a_tiny_android_dump_is_a_failure(adb_run, caplog):
    """A header-only dump means adb is not reaching the phone."""
    adb_run.stdout = ""
    assert AndroidScanner()._dump_phone(SERIAL) is False
    assert "too small" in caplog.text


def test_adb_timeouts_leave_that_section_empty(adb_run, caplog):
    adb_run.error = subprocess.TimeoutExpired("adb", 120)
    assert AndroidScanner()._dump_phone(SERIAL) is False
    assert "adb timeout" in caplog.text


def test_an_unwritable_dump_is_a_failure(adb_run, monkeypatch, caplog, tmp_path):
    sc = AndroidScanner()
    blocked = tmp_path / "dump.txt"
    blocked.mkdir()  # a directory where the dump file should go
    monkeypatch.setattr(sc, "dump_path", lambda serial: str(blocked))
    assert sc._dump_phone(SERIAL) is False
    assert "Android dump failed" in caplog.text


@pytest.fixture
def script_dir(tmp_path, monkeypatch):
    """The base scanner dumps with <device>_scan.sh from SCRIPT_DIR."""
    monkeypatch.setattr(scanner.cfg, "SCRIPT_DIR", tmp_path)
    return tmp_path


@pytest.mark.parametrize(
    "script, ok",
    [
        (None, False),  # no script
        ("printf '[]' > \"$2\"", True),
        ("exit 3", False),
        ("true", False),  # ran, but wrote nothing
    ],
)
def test_script_dumps(script_dir, script, ok):
    if script is not None:
        (script_dir / "ios_scan.sh").write_text(script + "\n")
    sc = IosScanner()
    try:
        assert sc._dump_phone("00008030-TEST") is ok
    finally:
        sc.discard_dump("00008030-TEST")


def test_ios_titles_need_a_dump():
    assert IosScanner().get_app_titles("x") == {}
