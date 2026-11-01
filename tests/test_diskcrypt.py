"""Is the disk holding isdi's data encrypted? (isdi/diskcrypt.py)

DATA_PROTECTION.md asks for full-disk encryption: it is what protects a
deleted dump on an SSD and a lost laptop. isdi now says at start when it
can tell encryption is off. When it cannot tell, it says nothing rather
than raise a false alarm.
"""

import os
import stat
import sys

import pytest

from isdi import diskcrypt


@pytest.fixture(autouse=True)
def plain_env(monkeypatch):
    monkeypatch.delenv("PREFIX", raising=False)
    monkeypatch.setattr(diskcrypt, "_is_wsl", lambda: False)


# --- macOS -------------------------------------------------------------------------


@pytest.fixture
def fdesetup(tmp_path, monkeypatch):
    tool = tmp_path / "fdesetup"

    def answer(out, code=0):
        tool.write_text(
            f"#!{sys.executable}\nimport sys\nsys.stdout.write({out!r})\nsys.exit({code})\n"
        )
        tool.chmod(tool.stat().st_mode | stat.S_IXUSR)

    monkeypatch.setattr(diskcrypt, "FDESETUP", str(tool))
    return answer


@pytest.mark.parametrize(
    "out, code, expected",
    [
        ("FileVault is On.\n", 0, "on"),
        ("FileVault is Off.\n", 0, "off"),
        ("FileVault is On.\nEncryption in progress: Percent completed = 40\n", 2, "on"),
        ("", 1, "unknown"),
        ("fdesetup: something unexpected\n", 0, "unknown"),
    ],
)
def test_macos(fdesetup, out, code, expected, tmp_path):
    fdesetup(out, code)
    assert diskcrypt.status(tmp_path, system="Darwin") == expected


def test_macos_without_the_tool(monkeypatch, tmp_path):
    monkeypatch.setattr(diskcrypt, "FDESETUP", str(tmp_path / "missing"))
    assert diskcrypt.status(tmp_path, system="Darwin") == "unknown"


# --- Linux (a fake /sys) -----------------------------------------------------------


def _block(sysfs, name, uuid=None, slaves=()):
    """A block device under /sys/devices; dm devices get dm/uuid."""
    dev = sysfs / "devices" / "virtual" / "block" / name
    dev.mkdir(parents=True)
    if uuid is not None:
        (dev / "dm").mkdir()
        (dev / "dm" / "uuid").write_text(uuid + "\n")
    (dev / "slaves").mkdir()
    for s in slaves:
        (dev / "slaves" / s).symlink_to(sysfs / "devices" / "virtual" / "block" / s)
    return dev


def _link(sysfs, majmin, dev):
    d = sysfs / "dev" / "block"
    d.mkdir(parents=True, exist_ok=True)
    (d / majmin).symlink_to(dev)


@pytest.fixture
def linux(tmp_path, monkeypatch):
    sysfs = tmp_path / "sys"
    sysfs.mkdir()
    mounts = tmp_path / "mounts"
    mounts.write_text("/dev/root / ext4 rw 0 0\n")
    monkeypatch.setattr(diskcrypt, "SYS", sysfs)
    monkeypatch.setattr(diskcrypt, "MOUNTS", mounts)
    return sysfs, mounts


def test_linux_luks(linux, tmp_path):
    sysfs, _ = linux
    _link(sysfs, "253:0", _block(sysfs, "dm-0", "CRYPT-LUKS2-abc-root"))
    assert diskcrypt.status(tmp_path, system="Linux", dev=(253, 0)) == "on"


def test_linux_lvm_on_luks(linux, tmp_path):
    sysfs, _ = linux
    _block(sysfs, "nvme0n1p3")
    _block(sysfs, "dm-0", "CRYPT-LUKS2-abc-cryptdata", slaves=["nvme0n1p3"])
    _link(sysfs, "253:1", _block(sysfs, "dm-1", "LVM-xyz", slaves=["dm-0"]))
    assert diskcrypt.status(tmp_path, system="Linux", dev=(253, 1)) == "on"


def test_linux_plain_partition(linux, tmp_path):
    sysfs, _ = linux
    _link(sysfs, "259:2", _block(sysfs, "nvme0n1p2"))
    assert diskcrypt.status(tmp_path, system="Linux", dev=(259, 2)) == "off"


def test_linux_lvm_without_luks(linux, tmp_path):
    sysfs, _ = linux
    _block(sysfs, "sda2")
    _link(sysfs, "253:0", _block(sysfs, "dm-0", "LVM-xyz", slaves=["sda2"]))
    assert diskcrypt.status(tmp_path, system="Linux", dev=(253, 0)) == "off"


def test_linux_device_not_in_sys_is_unknown(linux, tmp_path):
    """btrfs subvolumes, ZFS, overlay and tmpfs have no block device here."""
    assert diskcrypt.status(tmp_path, system="Linux", dev=(0, 45)) == "unknown"


def test_linux_ecryptfs_home_is_on(linux, tmp_path):
    sysfs, mounts = linux
    _link(sysfs, "259:2", _block(sysfs, "nvme0n1p2"))
    mounts.write_text(
        f"/dev/root / ext4 rw 0 0\n{tmp_path} {tmp_path} ecryptfs rw 0 0\n"
    )
    assert diskcrypt.status(tmp_path / "isdi", system="Linux", dev=(259, 2)) == "on"


def test_wsl_is_unknown(monkeypatch, linux, tmp_path):
    """WSL's disk is a file on Windows; BitLocker cannot be seen from here."""
    sysfs, _ = linux
    _link(sysfs, "8:32", _block(sysfs, "sdc"))
    monkeypatch.setattr(diskcrypt, "_is_wsl", lambda: True)
    assert diskcrypt.status(tmp_path, system="Linux", dev=(8, 32)) == "unknown"


def test_termux_and_others_are_unknown(monkeypatch, tmp_path):
    assert diskcrypt.status(tmp_path, system="Windows") == "unknown"
    monkeypatch.setenv("PREFIX", "/data/data/com.termux/files/usr")
    assert diskcrypt.status(tmp_path, system="Linux") == "unknown"


def test_a_loop_in_sys_does_not_hang(linux, tmp_path):
    sysfs, _ = linux
    a = _block(sysfs, "dm-0", "LVM-a")
    b = _block(sysfs, "dm-1", "LVM-b", slaves=["dm-0"])
    (a / "slaves" / "dm-1").symlink_to(b)
    _link(sysfs, "253:1", b)
    assert diskcrypt.status(tmp_path, system="Linux", dev=(253, 1)) == "unknown"


# --- the message at start ----------------------------------------------------------


def test_warning_only_when_known_to_be_off():
    assert "FileVault" in diskcrypt.warning("off", system="Darwin")
    assert "LUKS" in diskcrypt.warning("off", system="Linux")
    assert diskcrypt.warning("on", system="Darwin") is None
    assert diskcrypt.warning("unknown", system="Linux") is None


def test_run_warns_and_records_it(app, monkeypatch, passphrase):
    from click.testing import CliRunner
    from flask import Flask

    from isdi import audit, cli

    monkeypatch.setattr(Flask, "run", lambda self, **kw: None)
    monkeypatch.setenv("ISDI_PASSPHRASE", passphrase)
    monkeypatch.setattr(diskcrypt, "status", lambda path, **kw: "off")
    res = CliRunner().invoke(cli.cli, ["run", "--test", "--no-browser", "--offline"])
    assert res.exit_code == 0, res.output
    assert "encryption" in res.output.lower()
    with app.app_context():
        entry = [e for e in audit.entries() if e["action"] == "session_started"][-1]
    assert entry["details"]["disk_encryption"] == "off"
