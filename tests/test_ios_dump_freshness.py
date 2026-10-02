"""iOS scans must read the phone each time: a cached app list would hide
apps installed or removed since the previous scan."""

import json
import os
import subprocess
import sys

import pytest

import isdi.scanner as scanner
from isdi.config import get_config

SCRIPT = get_config().SCRIPT_DIR / "ios_scan.sh"


@pytest.fixture
def fake_pmd3(tmp_path):
    """A stub `pymobiledevice3` first on PATH. Write the app ids to
    report into apps.txt; create `fail` to make it exit with an error."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = bin_dir / "pymobiledevice3"
    stub.write_text(f"""#!{sys.executable}
import json, os, sys
here = {str(tmp_path)!r}
if os.path.exists(os.path.join(here, "fail")):
    sys.exit(1)
if sys.argv[1:3] == ["apps", "list"]:
    ids = open(os.path.join(here, "apps.txt")).read().split()
    print(json.dumps({{i: {{"CFBundleIdentifier": i}} for i in ids}}))
else:
    print(json.dumps({{"DeviceClass": "iPhone", "ProductType": "iPhone11,8"}}))
""")
    stub.chmod(0o755)
    env = {k: v for k, v in os.environ.items() if k != "PREFIX"}
    env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"

    def run(*apps, fail=False):
        (tmp_path / "apps.txt").write_text(" ".join(apps))
        marker = tmp_path / "fail"
        if fail:
            marker.touch()
        elif marker.exists():
            marker.unlink()
        out = tmp_path / "dump.json"
        res = subprocess.run(
            ["bash", str(SCRIPT), "UDID-1", str(out)],
            env=env,
            capture_output=True,
            text=True,
        )
        return res, out

    return run


def test_every_run_reads_the_phone(fake_pmd3):
    res, out = fake_pmd3("com.example.a")
    assert res.returncode == 0, res.stderr
    assert list(json.loads(out.read_text())["apps"]) == ["com.example.a"]
    # Immediately after: a newly installed app must show up.
    res, out = fake_pmd3("com.example.a", "com.example.spy")
    assert res.returncode == 0
    assert list(json.loads(out.read_text())["apps"]) == [
        "com.example.a",
        "com.example.spy",
    ]


def test_failed_read_is_an_error_and_writes_nothing(fake_pmd3, tmp_path):
    res, out = fake_pmd3("com.example.a", fail=True)
    assert res.returncode != 0
    assert not out.exists()
    assert not list(tmp_path.glob("dump.json.tmp*"))


def test_failed_read_does_not_report_old_dump_as_success(fake_pmd3):
    fake_pmd3("com.example.a")
    res, _ = fake_pmd3("com.example.a", fail=True)
    assert res.returncode != 0


@pytest.fixture
def ios(monkeypatch):
    """IosScanner with _dump_phone counted and the clock controllable."""
    sc = scanner.IosScanner()
    calls = []

    # Real dumps are far larger than _load_dump's 5000-byte "too small to
    # be real" threshold, which would otherwise trigger another read.
    apps = {
        f"com.example.app{i}": {
            "CFBundleIdentifier": f"com.example.app{i}",
            "Path": "/x" * 20,
        }
        for i in range(60)
    }

    def fake_dump(serial):
        calls.append(serial)
        with open(sc.dump_path(serial), "w") as f:
            json.dump({"apps": apps, "devinfo": {"ProductVersion": "17.6"}}, f)
        return True

    clock = [1000.0]
    monkeypatch.setattr(sc, "_dump_phone", fake_dump)
    monkeypatch.setattr(scanner.time, "monotonic", lambda: clock[0])
    sc.calls, sc.clock = calls, clock
    return sc


def test_one_scan_reads_the_phone_once(ios):
    ios.device_info("UDID-1")
    ios.get_apps("UDID-1")
    assert ios.calls == ["UDID-1"]


def test_each_new_scan_reads_the_phone_again(ios):
    ios.device_info("UDID-1")
    ios.get_apps("UDID-1")
    ios.clock[0] += 5
    ios.device_info("UDID-1")
    assert ios.calls == ["UDID-1", "UDID-1"]


def test_dump_not_reused_for_another_phone_or_after_window(ios):
    ios.device_info("UDID-1")
    ios.get_apps("UDID-2")
    ios.clock[0] += ios.DUMP_REUSE_SECONDS + 1
    ios.get_apps("UDID-2")
    assert ios.calls == ["UDID-1", "UDID-2", "UDID-2"]
