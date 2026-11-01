"""Apps that hide their icon and hold powers that monitoring relies on.

Some stalkerware gives every copy its own random package name and
signing key, so no list can match it (scripts/scorecard.py shows them).
What it cannot avoid is how it works: installed outside the Play Store,
no icon in the app list, and accessibility, notification access or
device administrator powers. ISDi asks the phone which apps have an icon
(`cmd package query-activities` for the launcher intent) and flags:

- no-launcher-icon: installed outside the Play Store, not a system app,
  no icon (keyboards, wallpapers and add-ons look the same; a weak sign);
- hidden-with-powers: the same, holding one of those powers.
"""

import json
import os
import stat
import sys

import pytest

import isdi.scanner as scanner
from isdi.scanner import blocklist

SERIAL = "R58M12ABCDE"
HIDDEN = "com.rnd.qxzv"  # off-store, no icon, accessibility
HIDDEN_ADMIN = "com.rnd.admin"  # off-store, no icon, device admin
HIDDEN_PLAIN = "org.example.keyboard"  # off-store, no icon, no powers
VISIBLE = "org.example.screenreader"  # off-store, icon, accessibility
PLAY = "com.example.watchhelper"  # Play Store, no icon, notification access
SYSTEM = "com.android.systemui"  # system, no icon
WORK = "com.example.workonly"  # off-store, accessibility, only in a work profile

APPS = {
    HIDDEN: ("null", ""),
    HIDDEN_ADMIN: ("com.google.android.packageinstaller", ""),
    HIDDEN_PLAIN: ("org.fdroid.fdroid", ""),
    VISIBLE: ("null", ""),
    PLAY: ("com.android.vending", ""),
    SYSTEM: ("null", "SYSTEM "),
    WORK: ("null", ""),
}


def _dumpsys():
    out = ["Packages:"]
    for i, (pkg, (installer, system)) in enumerate(APPS.items()):
        out += [
            f"  Package [{pkg}] (abc{i}):",
            f"    userId={10300 + i}",
            "    versionName=1.0",
            f"    flags=[ {system}HAS_CODE ]",
            f"    installerPackageName={installer}",
            (
                "    User 0: ceDataInode=0 installed=false hidden=false"
                if pkg == WORK
                else "    User 0: ceDataInode=1 installed=true hidden=false"
            ),
            "    User 10: ceDataInode=2 installed=true hidden=false",
        ]
    return "\n".join(out) + "\n"


SECURE = (
    "accessibility_enabled=1\n"
    f"enabled_accessibility_services={HIDDEN}/{HIDDEN}.A:{VISIBLE}/{VISIBLE}.Reader"
    f":{WORK}/{WORK}.A\n"
    f"enabled_notification_listeners={PLAY}/{PLAY}.Listener\n"
)
POLICY = (
    "Current Device Policy Manager state:\n"
    "  Enabled Device Admins (User 0, provisioningState: 0):\n"
    f"    {HIDDEN_ADMIN}/.Admin:\n"
    "      uid=10301\n"
)
# `cmd package query-activities --brief` for the launcher intent.
LAUNCHER_BRIEF = f"""\
3 activities found:
  Activity #0:
    priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
    com.android.settings/.Settings
  Activity #1:
    priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
    {VISIBLE}/.Main
  Activity #2:
    priority=0 preferredOrder=0 match=0x108000 specificIndex=-1 isDefault=false
    com.whatsapp/com.whatsapp.Main
"""

FAKE_ADB = """\
import json, os, sys
cfg = json.load(open(os.environ["FAKE_ADB_CONFIG"]))
args = sys.argv[1:]
with open(cfg["log"], "a") as log:
    log.write(json.dumps(args) + "\\n")
rest = args[2:]
if rest == ["shell", "dumpsys", "package"]:
    sys.stdout.write(cfg["dumpsys"])
elif rest == ["shell", "settings", "list", "secure"]:
    sys.stdout.write(cfg["secure"])
elif rest == ["shell", "dumpsys", "device_policy"]:
    sys.stdout.write(cfg["policy"])
elif rest[:4] == ["shell", "cmd", "package", "query-activities"]:
    sys.stdout.write(cfg["launcher"])
    sys.exit(cfg.get("launcher_exit", 0))
elif rest == ["shell", "dpm", "list-owners"]:
    pass
else:
    sys.stdout.write("x=1\\n" * 400)
"""


@pytest.fixture
def phone(tmp_path, monkeypatch):
    log = tmp_path / "adb.log"
    config = {
        "log": str(log),
        "dumpsys": _dumpsys(),
        "secure": SECURE,
        "policy": POLICY,
        "launcher": LAUNCHER_BRIEF,
    }
    cfg_path = tmp_path / "adb.json"

    def set_launcher(text, exit_code=0):
        config["launcher"], config["launcher_exit"] = text, exit_code
        cfg_path.write_text(json.dumps(config))

    set_launcher(LAUNCHER_BRIEF)
    monkeypatch.setenv("FAKE_ADB_CONFIG", str(cfg_path))
    tool = tmp_path / "adb"
    tool.write_text(f"#!{sys.executable}\n" + FAKE_ADB)
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)
    sc = scanner.AndroidScanner()
    monkeypatch.setattr(sc, "cli", str(tool))
    monkeypatch.setattr(scanner.AppScanner, "app_info_conn", None)
    monkeypatch.setattr(blocklist, "STALKERWARE_SIGNERS", {})
    sc.set_launcher = set_launcher
    sc.adb_log = log
    yield sc
    for ext in ("txt", "json"):
        p = sc.dump_path(SERIAL).rsplit(".", 1)[0] + "." + ext
        if os.path.exists(p):
            os.remove(p)


def test_launcher_apps_are_read_from_the_brief_output(phone):
    assert phone.launcher_apps(SERIAL) == {
        "com.android.settings",
        VISIBLE,
        "com.whatsapp",
    }


def test_launcher_apps_from_the_components_output(phone):
    phone.set_launcher(f"com.android.settings/.Settings\n{VISIBLE}/.Main\n")
    assert phone.launcher_apps(SERIAL) == {"com.android.settings", VISIBLE}


@pytest.mark.parametrize(
    "text, code",
    [
        ("No activities found\n", 0),
        ("", 0),
        ("Error: unknown command 'query-activities'\n", 255),
        ("x=1\n" * 50, 0),
    ],
)
def test_no_answer_means_unknown(phone, text, code):
    phone.set_launcher(text, code)
    assert phone.launcher_apps(SERIAL) is None


def test_hidden_app_with_powers_is_flagged(phone):
    apps = phone.find_spyapps(SERIAL)
    for appid in (HIDDEN, HIDDEN_ADMIN):
        flags = apps[appid]["flags"]
        assert "no-launcher-icon" in flags and "hidden-with-powers" in flags
        assert apps[appid]["class_"] == "alert-primary"
    assert list(apps)[:2] == sorted(
        [HIDDEN, HIDDEN_ADMIN], key=lambda a: (-apps[a]["score"], a)
    )


def test_hidden_app_without_powers_is_a_weak_sign(phone):
    flags = phone.find_spyapps(SERIAL)[HIDDEN_PLAIN]["flags"]
    assert "no-launcher-icon" in flags and "hidden-with-powers" not in flags


def test_apps_with_an_icon_play_store_and_system_apps_are_not_flagged(phone):
    apps = phone.find_spyapps(SERIAL)
    for appid in (VISIBLE, PLAY, SYSTEM, WORK):
        flags = apps[appid]["flags"]
        assert "no-launcher-icon" not in flags, appid
        assert "hidden-with-powers" not in flags, appid


@pytest.mark.parametrize("text", ["No activities found\n", ""])
def test_nothing_is_flagged_when_the_phone_does_not_answer(phone, text):
    phone.set_launcher(text)
    apps = phone.find_spyapps(SERIAL)
    for info in apps.values():
        assert "no-launcher-icon" not in info["flags"]
        assert "hidden-with-powers" not in info["flags"]


def test_one_query_per_scan(phone):
    phone.find_spyapps(SERIAL)
    calls = [json.loads(l) for l in phone.adb_log.read_text().splitlines()]
    queries = [
        c for c in calls if c[2:6] == ["shell", "cmd", "package", "query-activities"]
    ]
    assert len(queries) == 1
    assert queries[0][6:] == [
        "--brief",
        "-a",
        "android.intent.action.MAIN",
        "-c",
        "android.intent.category.LAUNCHER",
    ]


def test_flags_are_weighted_and_explained():
    assert blocklist.score(["hidden-with-powers"]) >= 1.0
    # Shown, but it does not raise an off-store keyboard to red.
    assert blocklist.score(["no-launcher-icon"]) == 0
    html = blocklist.flag_str(["hidden-with-powers", "no-launcher-icon"])
    assert 'class="text-primary"' in html and "icon" in html


def test_client_summary_has_its_own_finding():
    from isdi import client_summary

    scan = {"device": "android", "device_primary_user": "Phone"}
    apps = {
        HIDDEN: {
            "title": "",
            "flags": [
                "offstore-app",
                "accessibility",
                "no-launcher-icon",
                "hidden-with-powers",
            ],
        },
        VISIBLE: {"title": "Reader", "flags": ["accessibility"]},
    }
    for lang in ("en", "es"):
        page = client_summary.build(scan, apps, lang)
        titles = [f["title"] for f in page["findings"]]
        hidden = page["t"]["hidden_title"]
        assert hidden in titles
        [f] = [f for f in page["findings"] if f["title"] == hidden]
        assert f["items"] == [HIDDEN]
        assert titles.index(hidden) < titles.index(page["t"]["powers_title"])


def test_consultation_treats_it_as_a_risk():
    from isdi.consultation import model

    app = model.AppInfo(appId=HIDDEN, flags=["hidden-with-powers"])
    risk = app.flag_risk()
    assert risk is not None and "icon" in risk.description


@pytest.mark.parametrize(
    "entry, expected",
    [
        ({"User 0: ceDataInode": "0 installed=false hidden=false"}, True),
        ({"User 0": {"ceDataInode": "0 installed=false hidden=false"}}, True),
        ({"User 0: installed": "false hidden=false stopped=false"}, True),
        ({"User 0: ceDataInode": "1 installed=true hidden=false"}, False),
        ({"User 10: ceDataInode": "1 installed=false hidden=false"}, False),
        ({}, False),
    ],
)
def test_not_installed_for_the_main_user(monkeypatch, entry, expected):
    from isdi.scanner import parse_dump

    dump = parse_dump.AndroidDump.__new__(parse_dump.AndroidDump)
    dump.df = {"package": {"Packages": {"Package [com.x] (1": entry}}}
    monkeypatch.setattr(
        dump,
        "_get_apps",
        lambda: {"com.x": {"packageKey": "Package [com.x] (1"}},
    )
    assert (dump.not_installed_for_owner() == {"com.x"}) is expected
