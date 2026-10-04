"""Privacy-check screenshots: shown inline, never written to disk."""

import base64
import subprocess
from pathlib import Path

import pytest

from isdi.scanner import privacy_scan_android as ps

PNG = ps.PNG_SIGNATURE + b"fake image body"


@pytest.fixture
def adb(monkeypatch):
    """Fake subprocess.run for adb; set .stdout or .error before calling."""

    class Fake:
        argv = None
        stdout = PNG
        error = None

    def fake_run(argv, **kw):
        Fake.argv = argv
        if Fake.error:
            raise Fake.error
        return subprocess.CompletedProcess(argv, 0, stdout=Fake.stdout, stderr=b"")

    monkeypatch.setattr(ps, "run", fake_run)
    return Fake


def test_screenshot_is_returned_inline(adb, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    html = ps.take_screenshot("SER 1")
    assert html.startswith("<img") and "data:image/png;base64," in html
    encoded = html.split("base64,", 1)[1].split("'", 1)[0]
    assert base64.b64decode(encoded) == PNG
    assert list(tmp_path.iterdir()) == []


def test_serial_is_one_argument(adb):
    ps.take_screenshot("SER 1")
    assert adb.argv == [ps.adb, "-s", "SER 1", "exec-out", "screencap", "-p"]


def test_non_image_output_is_reported(adb):
    adb.stdout = b"error: device unauthorized"
    html = ps.take_screenshot("SER1")
    assert "screenshotfail" in html and "<img" not in html


def test_adb_failure_is_reported(adb):
    adb.error = subprocess.CalledProcessError(1, ["adb"])
    assert "exit code 1" in ps.take_screenshot("SER1")


def test_error_text_is_escaped(adb):
    adb.error = OSError("<script>alert(1)</script>")
    html = ps.take_screenshot("SER1")
    assert "<script>" not in html and "&lt;script&gt;" in html


def test_legacy_screenshot_file_is_removed(adb, tmp_path, monkeypatch):
    old = tmp_path / "tmp.png"
    old.write_bytes(PNG)
    monkeypatch.setattr(ps, "LEGACY_SCREENSHOT", old)
    assert "data:image/png" in ps.do_privacy_check("SER1", "screenshot")
    assert not old.exists()


def test_screenshot_route_returns_inline_image(adb, client):
    r = client.get("/privacy/android/screenshot", query_string={"serial": "SER1"})
    assert r.status_code == 200
    assert b"data:image/png;base64," in r.data


@pytest.mark.parametrize(
    "activity",
    [
        "com.android.settings/.Settings$PrivacySettingsActivity",
        "com.android.settings/.Settings$AccountsGroupSettingsActivity",
        "com.google.android.apps.maps/com.google.android.maps.MapsActivity",
    ],
)
def test_activity_name_survives_both_shells(monkeypatch, activity):
    """Run the command through a real host shell, join the arguments after
    `shell` the way adb does, and run that through a real sh (standing in
    for the phone's), which expands $variables."""
    seen = []
    monkeypatch.setattr(
        ps, "run_command", lambda cmd, **kw: seen.append(cmd.format(**kw)) or ("", "")
    )
    ps.open_activity("SER1", activity)

    def argv_after_shell_word(command):
        out = subprocess.run(
            ["sh", "-c", 'f() { printf "%s\\n" "$@"; }; f ' + command],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.splitlines()
        return out

    host_argv = argv_after_shell_word(seen[0])
    device_cmd = " ".join(host_argv[host_argv.index("shell") + 1 :])
    assert argv_after_shell_word(device_cmd) == ["am", "start", activity]


@pytest.mark.parametrize(
    "command, image",
    [
        ("gmap", "images/google_maps_sharing.png"),
        ("gphotos", "images/google_photos_sharing.png"),
    ],
)
def test_sharing_checks_show_their_own_example(app, monkeypatch, command, image):
    """Each check shows the example screenshot for its own app (Photos used
    to show the Maps one), and the image ships with the package."""
    monkeypatch.setattr(ps, "open_activity", lambda ser, name: True)
    monkeypatch.setattr(ps, "keycode", lambda ser, evt: None)
    monkeypatch.setattr(ps, "wait", lambda t: None)
    with app.test_request_context():
        html = ps.do_privacy_check("SER1", command)
    assert f"/static/{image}" in html
    assert (Path(app.static_folder) / image).is_file()


@pytest.fixture
def phone_shell(monkeypatch):
    """Record the commands sent to the phone; answer with .out and .err."""

    class Shell:
        sent = []
        out, err = "Starting: Intent { ... }", ""

    Shell.sent = []

    def fake(cmd, **kw):
        Shell.sent.append(cmd.format(**kw))
        return Shell.out, Shell.err

    monkeypatch.setattr(ps, "run_command", fake)
    monkeypatch.setattr(ps, "wait", lambda t: None)
    return Shell


@pytest.mark.parametrize(
    "out, err, opened",
    [
        ("Starting: Intent { cmp=x }", "", True),
        ("", "adb: device offline", False),
        ("Error type 3: Activity class does not exist.", "", False),
    ],
)
def test_open_activity_reports_failure(phone_shell, out, err, opened):
    phone_shell.out, phone_shell.err = out, err
    assert ps.open_activity("SER1", "a/.B") is opened


@pytest.mark.parametrize(
    "command, activity, says",
    [
        ("account", "GoogleSettingsLink", "account email address"),
        ("ACCOUNT", "GoogleSettingsLink", "account email address"),
        ("backup", "PrivacySettingsActivity", "Backup"),
    ],
)
def test_settings_checks_open_their_screen(phone_shell, command, activity, says):
    html = ps.do_privacy_check("SER1", command)
    assert says in html
    assert activity in phone_shell.sent[0] and "-s SER1" in phone_shell.sent[0]


def test_sync_check_says_when_the_phone_has_no_sync_screen(phone_shell):
    assert "Click on the" in ps.do_privacy_check("SER1", "sync")
    phone_shell.out = "Error type 3: Activity class does not exist."
    assert "could not find syncing" in ps.do_privacy_check("SER1", "sync")


def test_sharing_checks_press_menu_after_opening(app, phone_shell):
    with app.test_request_context():
        ps.do_privacy_check("SER1", "gmap")
    assert phone_shell.sent[1].endswith("input keyevent 82")


def test_unknown_checks_and_keys_do_nothing(phone_shell):
    assert "not supported" in ps.do_privacy_check("SER1", "format-phone")
    ps.keycode("SER1", "selfdestruct")
    assert phone_shell.sent == []


def test_without_a_serial_adb_picks_the_only_phone():
    assert ps.thiscli("") == ps.adb
    assert ps.thiscli("A B") == f"{ps.adb} -s 'A B'"


def test_run_command_returns_output_and_errors():
    out, err = ps.run_command("echo {a}; echo {b} >&2", a="out", b="err")
    assert (out.strip(), err.strip()) == ("out", "err")


@pytest.mark.parametrize(
    "error, message",
    [
        (subprocess.TimeoutExpired("adb", 4), "Command timed out"),
        (FileNotFoundError("adb"), "Command not found"),
        (RuntimeError("boom"), "Error: boom"),
    ],
)
def test_run_command_reports_failures(monkeypatch, error, message):
    class FakePopen:
        def __init__(self, *a, **kw):
            if isinstance(error, FileNotFoundError):
                raise error

        def wait(self, t):
            raise error

        def kill(self):
            self.killed = True

    monkeypatch.setattr(ps, "Popen", FakePopen)
    out, err = ps.run_command("adb devices")
    assert out == "" and message in err


def test_screenshot_timeout_is_reported(adb):
    adb.error = subprocess.TimeoutExpired("adb", 30)
    assert "screenshotfail" in ps.take_screenshot("SER1")


def test_privacy_route_errors(client, monkeypatch):
    from isdi.web.view import index

    assert client.get("/privacy/nokia/account").status_code == 400
    monkeypatch.setattr(index.android, "devices", lambda: [])
    r = client.get("/privacy/android/account")
    assert r.status_code == 400 and b"No device serial" in r.data
    r = client.get("/privacy/android/account", query_string={"serial": "a;rm -rf"})
    assert r.status_code == 400 and b"Invalid device serial" in r.data


def test_privacy_route_uses_the_connected_phone(client, monkeypatch, phone_shell):
    from isdi.web.view import index

    monkeypatch.setattr(index.android, "devices", lambda: ["SER9"])
    r = client.get("/privacy/android/backup")
    assert r.status_code == 200 and "-s SER9" in phone_shell.sent[0]
    assert client.get("/privacy").status_code == 200
