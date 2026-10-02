"""Secrets on disk, the app-info.db download, and the CLI's bind address."""

import hashlib
import io
import os
import stat
import urllib.request
from pathlib import Path

import pytest
from click.testing import CliRunner

from isdi import config as config_mod
from isdi.config import Config, get_config

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")


@posix_only
def test_new_secret_is_private_and_random(tmp_path):
    a = config_mod._load_or_create_secret(tmp_path / "a.key")
    b = config_mod._load_or_create_secret(tmp_path / "b.key")
    assert len(a) == 32 and a != b
    assert stat.S_IMODE((tmp_path / "a.key").stat().st_mode) == 0o600


@posix_only
def test_existing_secret_is_kept_and_tightened(tmp_path):
    path = tmp_path / "old.key"
    path.write_bytes(b"k" * 32)
    os.chmod(path, 0o644)
    assert config_mod._load_or_create_secret(path) == b"k" * 32
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


class _Response(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def cache_config(tmp_path, monkeypatch):
    """A Config whose cache dir is tmp_path, with the download stubbed."""
    cfg = Config.__new__(Config)
    cfg.dirs = {"cache": tmp_path}
    cfg.body = b""
    monkeypatch.setattr(
        urllib.request, "urlopen", lambda url, timeout: _Response(cfg.body)
    )
    return cfg


FAKE_DB = b"SQLite format 3\x00" + b"\x00" * 100


def test_download_matching_pinned_hash_is_installed(
    cache_config, tmp_path, monkeypatch
):
    monkeypatch.setattr(
        config_mod, "APP_INFO_DB_SHA256", hashlib.sha256(FAKE_DB).hexdigest()
    )
    cache_config.body = FAKE_DB
    cache_config._ensure_app_info_db()
    assert (tmp_path / "app-info.db").read_bytes() == FAKE_DB
    assert not (tmp_path / "app-info.db.part").exists()


@pytest.mark.parametrize(
    "body",
    [
        b"<html>rate limited</html>",  # not a database
        FAKE_DB[:20],  # truncated
        FAKE_DB,  # a valid SQLite file, but not the pinned one
    ],
)
def test_download_not_matching_pinned_hash_is_discarded(cache_config, tmp_path, body):
    """Must not be kept, or every later start would skip the download
    because the file is non-empty."""
    cache_config.body = body
    cache_config._ensure_app_info_db()
    assert not (tmp_path / "app-info.db").exists()
    assert not (tmp_path / "app-info.db.part").exists()


def test_pinned_hash_is_a_sha256():
    assert len(config_mod.APP_INFO_DB_SHA256) == 64
    int(config_mod.APP_INFO_DB_SHA256, 16)


def test_existing_db_is_not_redownloaded(cache_config, tmp_path, monkeypatch):
    (tmp_path / "app-info.db").write_bytes(b"existing")

    def fail(*a, **k):
        raise AssertionError("should not download")

    monkeypatch.setattr(urllib.request, "urlopen", fail)
    cache_config._ensure_app_info_db()
    assert (tmp_path / "app-info.db").read_bytes() == b"existing"


@pytest.fixture
def run_cli(monkeypatch):
    """Invoke `isdi run --test` without starting a server; return
    (output, host)."""
    from flask import Flask

    from isdi import cli

    bound = {}
    monkeypatch.setattr(
        Flask, "run", lambda self, host, port, **kw: bound.update(host=host)
    )

    def invoke(*args):
        res = CliRunner().invoke(cli.cli, ["run", "--test", "--no-browser", *args])
        assert res.exit_code == 0, res.output
        return res.output, bound["host"]

    return invoke


def test_cli_binds_to_localhost_by_default(run_cli):
    output, host = run_cli()
    assert host == "127.0.0.1"
    assert "other machines on this network" not in output


def test_cli_warns_when_exposed_to_network(run_cli):
    output, host = run_cli("--host", "0.0.0.0")
    assert host == "0.0.0.0"
    assert "other machines on this network can view scan data" in output


def test_cli_reports_package_version():
    from isdi import __version__, cli

    res = CliRunner().invoke(cli.cli, ["--version"])
    assert __version__ in res.output


def test_suite_never_touches_the_users_isdi_data():
    """conftest.py points the config at throwaway directories; if a module
    created a production config first, tests would write to the real
    client database and use the real PII key."""
    cfg = get_config()
    assert cfg.TEST
    home = Path.home()
    for d in (cfg.dirs["data"], cfg.dirs["config"], cfg.database_path):
        assert not Path(d).is_relative_to(home / ".local" / "share"), d
        assert not Path(d).is_relative_to(home / ".config"), d


def test_config_refuses_to_switch_environment():
    with pytest.raises(RuntimeError, match="cannot switch"):
        get_config("production")
