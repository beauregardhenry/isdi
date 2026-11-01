"""Raw phone data on a RAM disk (`isdi run --ram-dumps`).

Raw dumps, unredacted evidence output and copied APKs are the only client
data isdi writes to disk unencrypted (DATA_PROTECTION.md). On an SSD a
deleted file can outlive its deletion. With --ram-dumps they go to a disk
that lives in memory and is removed when isdi stops.
"""

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from isdi import ramdisk
from isdi.config import get_config


def _on_tmpfs(path) -> bool:
    try:
        return ramdisk._fs_type(Path(path)) in ramdisk.MEMORY_FILESYSTEMS
    except OSError:
        return False


real_shm = pytest.mark.skipif(
    sys.platform != "linux" or not _on_tmpfs("/dev/shm"),
    reason="needs a Linux /dev/shm on tmpfs",
)


@pytest.fixture(autouse=True)
def no_termux(monkeypatch):
    monkeypatch.delenv("PREFIX", raising=False)


# --- Linux -------------------------------------------------------------------------


@real_shm
def test_linux_disk_is_private_in_memory_and_removed():
    disk = ramdisk.create(64, system="Linux")
    try:
        assert disk.path.parent == Path("/dev/shm")
        assert disk.path.name.startswith(ramdisk.PREFIX)
        assert stat.S_IMODE(disk.path.stat().st_mode) == 0o700
        assert _on_tmpfs(disk.path)
        (disk.path / "dump.txt").write_text("phone data")
    finally:
        disk.remove()
    assert not disk.path.exists()
    disk.remove()  # twice is harmless


def _fake_mounts(tmp_path, monkeypatch, line):
    mounts = tmp_path / "mounts"
    mounts.write_text(line)
    monkeypatch.setattr(ramdisk, "MOUNTS", mounts)


def test_linux_refuses_a_shm_that_is_not_in_memory(tmp_path, monkeypatch):
    shm = tmp_path / "shm"
    shm.mkdir()
    monkeypatch.setattr(ramdisk, "SHM", shm)
    _fake_mounts(tmp_path, monkeypatch, f"/dev/sda1 / ext4 rw 0 0\n")
    with pytest.raises(ramdisk.RamDiskError, match="not in memory"):
        ramdisk.create(64, system="Linux")
    assert list(shm.iterdir()) == []


def test_linux_uses_the_longest_mount_point(tmp_path, monkeypatch):
    shm = tmp_path / "shm"
    shm.mkdir()
    monkeypatch.setattr(ramdisk, "SHM", shm)
    _fake_mounts(
        tmp_path, monkeypatch, f"/dev/sda1 / ext4 rw 0 0\ntmpfs {shm} tmpfs rw 0 0\n"
    )
    disk = ramdisk.create(64, system="Linux")
    try:
        assert disk.path.parent == shm
    finally:
        disk.remove()


def test_linux_refuses_without_shm(tmp_path, monkeypatch):
    monkeypatch.setattr(ramdisk, "SHM", tmp_path / "missing")
    with pytest.raises(ramdisk.RamDiskError, match="/dev/shm"):
        ramdisk.create(64, system="Linux")


def test_termux_is_refused(monkeypatch):
    monkeypatch.setenv("PREFIX", "/data/data/com.termux/files/usr")
    with pytest.raises(ramdisk.RamDiskError, match="Termux"):
        ramdisk.create(64, system="Linux")


def test_other_systems_are_refused():
    with pytest.raises(ramdisk.RamDiskError, match="Windows"):
        ramdisk.create(64, system="Windows")


def test_size_must_be_sensible():
    for size in (0, -1, 10**7):
        with pytest.raises(ramdisk.RamDiskError, match="size"):
            ramdisk.create(size, system="Linux")


def test_linux_leftovers_are_removed_except_the_one_in_use(tmp_path, monkeypatch):
    shm = tmp_path / "shm"
    shm.mkdir()
    monkeypatch.setattr(ramdisk, "SHM", shm)
    old = shm / f"{ramdisk.PREFIX}old"
    (old / "sub").mkdir(parents=True)
    (old / "sub" / "dump.txt").write_text("phone data")
    current = shm / f"{ramdisk.PREFIX}current"
    current.mkdir()
    unrelated = shm / "something-else"
    unrelated.mkdir()
    assert ramdisk.cleanup_leftovers(keep=current, system="Linux") == 1
    assert not old.exists() and current.exists() and unrelated.exists()


# --- macOS (fake hdiutil and diskutil) ---------------------------------------------

FAKE_TOOL = """\
import json, os, sys
cfg = json.load(open(os.environ["FAKE_MAC_CONFIG"]))
with open(cfg["log"], "a") as log:
    log.write(json.dumps([os.path.basename(sys.argv[0])] + sys.argv[1:]) + "\\n")
name, args = os.path.basename(sys.argv[0]), sys.argv[1:]
if name == "hdiutil" and args[:2] == ["attach", "-nomount"]:
    sys.stdout.write(cfg["attach_output"])
elif name == "diskutil" and args[:1] == ["erasevolume"]:
    if cfg.get("erase_fails"):
        sys.exit(1)
    os.makedirs(os.path.join(cfg["volumes"], args[2]))
elif name == "hdiutil" and args[:1] == ["detach"]:
    pass
else:
    sys.exit(2)
"""


@pytest.fixture
def mac(tmp_path, monkeypatch):
    volumes = tmp_path / "Volumes"
    volumes.mkdir()
    log = tmp_path / "tools.log"
    cfg = {"log": str(log), "volumes": str(volumes), "attach_output": "/dev/disk9   \n"}
    cfg_path = tmp_path / "mac.json"

    def configure(**kw):
        cfg.update(kw)
        cfg_path.write_text(json.dumps(cfg))

    configure()
    monkeypatch.setenv("FAKE_MAC_CONFIG", str(cfg_path))
    for name in ("hdiutil", "diskutil"):
        tool = tmp_path / name
        tool.write_text(f"#!{sys.executable}\n" + FAKE_TOOL)
        tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setattr(ramdisk, "HDIUTIL", str(tmp_path / "hdiutil"))
    monkeypatch.setattr(ramdisk, "DISKUTIL", str(tmp_path / "diskutil"))
    monkeypatch.setattr(ramdisk, "VOLUMES", volumes)

    class Mac:
        pass

    m = Mac()
    m.volumes, m.configure = volumes, configure
    m.calls = lambda: [json.loads(l) for l in log.read_text().splitlines()]
    return m


def test_macos_disk_is_attached_formatted_and_detached(mac):
    disk = ramdisk.create(512, system="Darwin")
    calls = mac.calls()
    assert calls[0] == ["hdiutil", "attach", "-nomount", f"ram://{512 * 2048}"]
    assert calls[1][:3] == ["diskutil", "erasevolume", "HFS+"]
    name = calls[1][3]
    assert name.startswith(ramdisk.VOLUME_PREFIX) and calls[1][4] == "/dev/disk9"
    assert disk.path == mac.volumes / name / "dumps"
    assert stat.S_IMODE(disk.path.stat().st_mode) == 0o700
    disk.remove()
    assert mac.calls()[-1] == ["hdiutil", "detach", "-force", "/dev/disk9"]


def test_macos_detaches_when_formatting_fails(mac):
    mac.configure(erase_fails=True)
    with pytest.raises(ramdisk.RamDiskError):
        ramdisk.create(512, system="Darwin")
    assert mac.calls()[-1] == ["hdiutil", "detach", "-force", "/dev/disk9"]


@pytest.mark.parametrize(
    "output", ["", "hdiutil: attach failed\n", "/dev/disk9; rm -rf /\n"]
)
def test_macos_refuses_an_unexpected_device(mac, output):
    mac.configure(attach_output=output)
    with pytest.raises(ramdisk.RamDiskError):
        ramdisk.create(512, system="Darwin")
    assert not any(c[:2] == ["diskutil", "erasevolume"] for c in mac.calls())


def test_macos_leftovers_are_detached(mac):
    (mac.volumes / f"{ramdisk.VOLUME_PREFIX}old").mkdir()
    (mac.volumes / "Backup Drive").mkdir()
    assert ramdisk.cleanup_leftovers(system="Darwin") == 1
    detached = [c for c in mac.calls() if c[:2] == ["hdiutil", "detach"]]
    assert detached == [
        [
            "hdiutil",
            "detach",
            "-force",
            str(mac.volumes / f"{ramdisk.VOLUME_PREFIX}old"),
        ]
    ]


# --- isdi run --ram-dumps ----------------------------------------------------------


@pytest.fixture
def run_cmd(app, monkeypatch, passphrase):
    import atexit

    from click.testing import CliRunner
    from flask import Flask

    from isdi import cli

    seen = {}
    monkeypatch.setattr(
        Flask, "run", lambda self, **kw: seen.update(dump_dir=get_config().DUMP_DIR)
    )
    import signal

    at_exit = []
    monkeypatch.setattr(atexit, "register", at_exit.append)
    monkeypatch.setattr(signal, "signal", lambda *a: None)
    monkeypatch.setenv("ISDI_PASSPHRASE", passphrase)
    before = get_config().DUMP_DIR

    def invoke(*args):
        res = CliRunner().invoke(
            cli.cli, ["run", "--test", "--no-browser", "--offline", *args]
        )
        return res, seen, at_exit

    yield invoke
    for fn in at_exit:
        fn()
    get_config().DUMP_DIR = before


@real_shm
def test_run_puts_dumps_in_memory_and_removes_them_on_exit(run_cmd):
    res, seen, at_exit = run_cmd("--ram-dumps")
    assert res.exit_code == 0, res.output
    assert seen["dump_dir"].startswith("/dev/shm/" + ramdisk.PREFIX)
    assert "memory" in res.output
    for fn in list(at_exit):
        fn()
    assert not os.path.exists(seen["dump_dir"])


def test_run_does_not_start_without_a_ram_disk(run_cmd, monkeypatch):
    def refuse(*a, **k):
        raise ramdisk.RamDiskError("not available here")

    monkeypatch.setattr(ramdisk, "create", refuse)
    res, seen, _ = run_cmd("--ram-dumps")
    assert res.exit_code != 0
    assert "not available here" in res.output
    assert "dump_dir" not in seen  # the server never started


def test_ram_dumps_and_debug_do_not_mix(run_cmd):
    res, seen, _ = run_cmd("--ram-dumps", "--debug")
    assert res.exit_code != 0 and "--debug" in res.output
    assert "dump_dir" not in seen


def test_without_the_flag_dumps_stay_where_they_were(run_cmd):
    before = get_config().DUMP_DIR
    res, seen, _ = run_cmd()
    assert res.exit_code == 0, res.output
    assert seen["dump_dir"] == before


# --- start-up cleanup ------------------------------------------------------------


def test_startup_removes_dumps_left_on_the_real_disk_too(tmp_path, monkeypatch):
    """With dumps in memory, leftovers from an earlier run on the real disk
    are still deleted."""
    from isdi.scanner import purge_raw_dumps

    cfg = get_config()
    on_disk = Path(cfg.dumps_dir) / "old_android.txt"
    on_disk.write_text("phone data")
    in_memory = tmp_path / "ram"
    in_memory.mkdir()
    (in_memory / "stale_ios.json").write_text("phone data")
    monkeypatch.setattr(cfg, "DUMP_DIR", str(in_memory))
    assert purge_raw_dumps() == 2
    assert not on_disk.exists() and list(in_memory.iterdir()) == []


# --- end to end: a scan leaves nothing on the real disk ---------------------------


@real_shm
def test_a_scan_leaves_no_phone_data_on_disk(tmp_path, monkeypatch):
    """A fake phone scanned with dumps in memory: its app id appears in no
    file under isdi's folders, during or after the scan."""
    import isdi.scanner as scanner
    from tests.test_scanner_pipeline import FAKE_ADB, SERIAL, STALKER, _fake_tool

    cfg = get_config()
    disk = ramdisk.create(64, system="Linux")
    monkeypatch.setattr(cfg, "DUMP_DIR", str(disk.path))
    try:
        sc = scanner.AndroidScanner()
        monkeypatch.setattr(sc, "cli", _fake_tool(tmp_path, "adb", FAKE_ADB))
        monkeypatch.setattr(scanner.AppScanner, "app_info_conn", None)
        apps = sc.find_spyapps(SERIAL)
        assert STALKER in apps
        assert sc.dump_path(SERIAL).startswith(str(disk.path))
        assert os.path.exists(sc.dump_path(SERIAL))  # in memory, during the scan
        sc.discard_dump(SERIAL)
        marker = STALKER.encode()
        for root in {Path(p) for p in cfg.dirs.values()}:
            for f in root.rglob("*"):
                if f.is_file():
                    assert marker not in f.read_bytes(), f
    finally:
        disk.remove()
