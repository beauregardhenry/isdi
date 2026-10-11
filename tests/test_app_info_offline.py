"""app-info.db (store titles and descriptions) is optional and fetched only
when ISDi is started, never when it is imported.

It used to be downloaded while the configuration was created, so importing
ISDi (a test, `isdi info`, Sherloc importing the scanner) reached GitHub
until the file was there. When the download failed, opening the database
left an empty file, and app detail pages then failed on "no such table".
"""

import sqlite3
import urllib.request

import pytest
from click.testing import CliRunner

from isdi import config as config_mod
from isdi.scanner import AndroidScanner, AppScanner
import isdi.scanner as scanner


def test_creating_the_config_downloads_nothing(monkeypatch, tmp_path):
    # Recorded, not raised: the download swallows errors.
    calls = []
    monkeypatch.setattr(
        urllib.request, "urlopen", lambda *a, **k: calls.append(a) or 1 / 0
    )
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    cfg = config_mod.Config("test")
    assert calls == []
    assert not (tmp_path / "cache" / "isdi" / "app-info.db").exists()
    assert cfg.APP_INFO_SQLITE_FILE.endswith("app-info.db")


@pytest.fixture
def info_path(monkeypatch, tmp_path):
    monkeypatch.setattr(AppScanner, "app_info_conn", None)
    path = tmp_path / "app-info.db"
    monkeypatch.setattr(scanner.cfg, "APP_INFO_SQLITE_FILE", f"sqlite:///{path}")
    return path


def test_a_missing_database_is_not_created_empty(info_path):
    AndroidScanner()
    assert AppScanner.app_info_conn is None
    assert not info_path.exists()


def test_an_empty_file_is_not_opened(info_path):
    info_path.write_bytes(b"")
    AndroidScanner()
    assert AppScanner.app_info_conn is None


def test_the_database_is_opened_read_only(info_path):
    con = sqlite3.connect(info_path)
    con.execute("create table apps (appid text, title text)")
    con.execute("insert into apps values ('com.x', 'X')")
    con.commit()
    con.close()
    AndroidScanner()
    conn = AppScanner.app_info_conn
    assert conn.execute("select title from apps").fetchone()[0] == "X"
    with pytest.raises(sqlite3.OperationalError):
        conn.execute("insert into apps values ('com.y', 'Y')")


def test_app_details_work_without_the_database(info_path):
    sc = AndroidScanner()
    assert sc.get_multiple_app_details("R58M123", ["com.x"]) == {"com.x": ({}, {})}


@pytest.fixture
def run(app, monkeypatch, passphrase):
    from flask import Flask

    from isdi import cli

    calls = []
    monkeypatch.setattr(Flask, "run", lambda self, **kw: None)
    monkeypatch.setattr(
        config_mod.Config, "ensure_app_info_db", lambda self: calls.append(1)
    )
    monkeypatch.setenv("ISDI_PASSPHRASE", passphrase)

    def invoke(*args):
        res = CliRunner().invoke(cli.cli, ["run", "--test", "--no-browser", *args])
        assert res.exit_code == 0, res.output
        return calls

    return invoke


def test_starting_isdi_fetches_the_database(run):
    assert run() == [1]


def test_offline_skips_the_download(run):
    assert run("--offline") == []


def test_fetch_command(monkeypatch):
    from isdi import cli

    calls = []
    monkeypatch.setattr(
        config_mod.Config, "ensure_app_info_db", lambda self: calls.append(1)
    )
    res = CliRunner().invoke(cli.cli, ["fetch-app-info"])
    assert res.exit_code == 0, res.output
    assert calls == [1]
