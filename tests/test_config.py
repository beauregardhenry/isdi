"""Secrets on disk, the app-info.db download, and the CLI's bind address."""

import io
import os
import stat
import urllib.request

import pytest
from click.testing import CliRunner

from isdi import config as config_mod
from isdi.config import Config

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


def test_valid_download_is_installed(cache_config, tmp_path):
    cache_config.body = b"SQLite format 3\x00" + b"\x00" * 100
    cache_config._ensure_app_info_db()
    assert (tmp_path / "app-info.db").read_bytes() == cache_config.body
    assert not (tmp_path / "app-info.db.part").exists()


@pytest.mark.parametrize("body", [b"<html>rate limited</html>", b"SQLite"])
def test_bad_download_is_discarded(cache_config, tmp_path, body):
    """A non-database or truncated file must not be kept, or every later
    start would skip the download because the file is non-empty."""
    cache_config.body = body
    cache_config._ensure_app_info_db()
    assert not (tmp_path / "app-info.db").exists()
    assert not (tmp_path / "app-info.db.part").exists()


def test_existing_db_is_not_redownloaded(cache_config, tmp_path, monkeypatch):
    (tmp_path / "app-info.db").write_bytes(b"existing")

    def fail(*a, **k):
        raise AssertionError("should not download")

    monkeypatch.setattr(urllib.request, "urlopen", fail)
    cache_config._ensure_app_info_db()
    assert (tmp_path / "app-info.db").read_bytes() == b"existing"


@pytest.fixture
def run_cli(app, monkeypatch):
    """Invoke `isdi run` without starting a server; return (output, host).
    Depends on `app` so the shared app is created first: only the first
    create_app() gets the routes (see conftest.py)."""
    from flask import Flask

    from isdi import cli

    bound = {}
    monkeypatch.setattr(
        Flask, "run", lambda self, host, port, **kw: bound.update(host=host)
    )

    def invoke(*args):
        res = CliRunner().invoke(cli.cli, ["run", "--no-browser", *args])
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
