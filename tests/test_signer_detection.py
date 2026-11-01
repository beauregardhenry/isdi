"""Stalkerware found by the certificate that signed it.

Vendors rename their packages to get past lists of package names; the
signing certificate stays the same. ISDi copies each app installed
outside the Play Store off the phone, reads its signer
(scanner/apk_signers.py), and compares it with the certificates the
AssoEchap list records (data/stalkerware-signers.csv).
"""

import json
import os
import stat
import sys

import pytest

import isdi.scanner as scanner
from isdi.scanner import blocklist
from tests import apkfactory as f

SERIAL = "R58M12ABCDE"
RENAMED = "com.renamed.helper"  # not on any package list
PLAY = "com.whatsapp"
BIG = "com.big.game"
BROKEN = "com.broken.app"
SNEAKY = "com.sneaky.path"
CLEAN = "org.example.notes"  # sideloaded, signed by someone else

PACKAGES = {
    RENAMED: "null",
    PLAY: "com.android.vending",
    BIG: "com.google.android.packageinstaller",
    BROKEN: "null",
    SNEAKY: "null",
    CLEAN: "org.fdroid.fdroid",
}


def _dumpsys():
    out = ["Packages:"]
    for i, (pkg, installer) in enumerate(PACKAGES.items()):
        out += [
            f"  Package [{pkg}] (abc{i}):",
            f"    userId={10200 + i}",
            "    versionName=1.0",
            f"    installerPackageName={installer}",
            "    User 0: ceDataInode=1 installed=true hidden=false",
        ]
    return "\n".join(out) + "\n"


FAKE_ADB = """\
import json, os, shutil, sys
cfg = json.load(open(os.environ["FAKE_ADB_CONFIG"]))
args = sys.argv[1:]
with open(cfg["log"], "a") as log:
    log.write(json.dumps(args) + "\\n")
if args == ["devices"]:
    print("List of devices attached")
    print(cfg["serial"] + "\\tdevice")
    sys.exit(0)
serial, rest = args[1], args[2:]
if rest == ["shell", "dumpsys", "package"]:
    sys.stdout.write(cfg["dumpsys"])
elif rest[:3] == ["shell", "pm", "path"]:
    pkg = rest[3]
    for line in cfg["paths"].get(pkg, []):
        print(line)
elif rest[:3] == ["shell", "stat", "-c"]:
    print(cfg["sizes"].get(rest[4], 1000))
elif rest[:1] == ["pull"]:
    src, dest = rest[1], rest[2]
    shutil.copy(cfg["apks"][src], dest)
    print(src + ": 1 file pulled")
elif rest == ["shell", "dpm", "list-owners"]:
    pass
else:
    sys.stdout.write("x=1\\n" * 400)
"""


@pytest.fixture(scope="module")
def vendor():
    return f.make_cert("vendor")


@pytest.fixture
def phone(tmp_path, monkeypatch, vendor):
    other = f.make_cert("someone else")
    apks = {}

    def apk(name, data):
        p = tmp_path / "phone" / name
        p.parent.mkdir(exist_ok=True)
        p.write_bytes(data)
        return str(p)

    signed = lambda cert: f.build(
        block=f.signing_block([(f.V2_ID, f.v2_value(cert[0]))])
    )
    paths = {
        RENAMED: [f"package:/data/app/~~x1==/{RENAMED}-a==/base.apk"],
        PLAY: [f"package:/data/app/~~x2==/{PLAY}-b==/base.apk"],
        BIG: [f"package:/data/app/~~x3==/{BIG}-c==/base.apk"],
        BROKEN: [f"package:/data/app/~~x4==/{BROKEN}-d==/base.apk"],
        SNEAKY: ["package:/data/app/x/base.apk $(reboot)"],
        CLEAN: [
            f"package:/data/app/~~x6==/{CLEAN}-e==/split_config.en.apk",
            f"package:/data/app/~~x6==/{CLEAN}-e==/base.apk",
        ],
    }
    for pkg, data in [
        (RENAMED, signed(vendor)),
        (PLAY, signed(vendor)),  # never pulled: installed from the Play Store
        (BIG, signed(vendor)),
        (BROKEN, b"this is not an apk" * 100),
        (CLEAN, signed(other)),
    ]:
        apks[paths[pkg][-1][len("package:") :]] = apk(pkg, data)
    log = tmp_path / "adb.log"
    config = {
        "serial": SERIAL,
        "log": str(log),
        "dumpsys": _dumpsys(),
        "paths": paths,
        "sizes": {paths[BIG][0][len("package:") :]: 900 * 1024 * 1024},
        "apks": apks,
    }
    cfg_path = tmp_path / "adb.json"
    cfg_path.write_text(json.dumps(config))
    monkeypatch.setenv("FAKE_ADB_CONFIG", str(cfg_path))
    tool = tmp_path / "adb"
    tool.write_text(f"#!{sys.executable}\n" + FAKE_ADB)
    tool.chmod(tool.stat().st_mode | stat.S_IXUSR)

    sc = scanner.AndroidScanner()
    monkeypatch.setattr(sc, "cli", str(tool))
    monkeypatch.setattr(scanner.AppScanner, "app_info_conn", None)
    monkeypatch.setattr(
        blocklist, "STALKERWARE_SIGNERS", {f.sha1(vendor[0]): "VendorSpy"}
    )
    sc.adb_log = log
    yield sc
    for ext in ("txt", "json"):
        p = sc.dump_path(SERIAL).rsplit(".", 1)[0] + "." + ext
        if os.path.exists(p):
            os.remove(p)


def _calls(phone):
    return [json.loads(l) for l in phone.adb_log.read_text().splitlines()]


def test_renamed_stalkerware_is_found_by_its_signer(phone):
    apps = phone.find_spyapps(SERIAL)
    flags = apps[RENAMED]["flags"]
    assert "stalkerware-signer" in flags
    assert apps[RENAMED]["title"] == "VendorSpy"
    assert apps[RENAMED]["class_"] == "alert-primary"
    assert next(iter(apps)) == RENAMED  # the riskiest app comes first


def test_play_store_apps_are_not_copied(phone):
    apps = phone.find_spyapps(SERIAL)
    assert "stalkerware-signer" not in apps[PLAY]["flags"]
    touched = [c for c in _calls(phone) if PLAY in " ".join(c[2:])]
    assert touched == []


def test_another_signer_is_not_flagged(phone):
    apps = phone.find_spyapps(SERIAL)
    assert "stalkerware-signer" not in apps[CLEAN]["flags"]
    assert "signer-unchecked" not in apps[CLEAN]["flags"]
    # base.apk is the one read, not a split.
    pulls = [c for c in _calls(phone) if c[2:3] == ["pull"]]
    assert any(c[3].endswith(f"{CLEAN}-e==/base.apk") for c in pulls)
    assert not any("split_config" in c[3] for c in pulls)


def test_large_apps_are_not_copied_and_say_so(phone):
    apps = phone.find_spyapps(SERIAL)
    assert "signer-unchecked" in apps[BIG]["flags"]
    assert not any(c[2:3] == ["pull"] and BIG in c[3] for c in _calls(phone))


def test_unreadable_apk_says_so(phone):
    apps = phone.find_spyapps(SERIAL)
    assert "signer-unchecked" in apps[BROKEN]["flags"]
    assert "stalkerware-signer" not in apps[BROKEN]["flags"]


def test_unexpected_path_is_not_used(phone):
    apps = phone.find_spyapps(SERIAL)
    assert "signer-unchecked" in apps[SNEAKY]["flags"]
    used = [c for c in _calls(phone) if c[2:3] == ["pull"] or c[3:4] == ["stat"]]
    assert used and not any("reboot" in " ".join(c) for c in used)


def test_copies_are_made_in_the_dump_folder_and_deleted(phone):
    from isdi.config import get_config

    phone.find_spyapps(SERIAL)
    pulls = [c for c in _calls(phone) if c[2:3] == ["pull"]]
    assert pulls
    dump_dir = os.path.realpath(get_config().DUMP_DIR)
    for c in pulls:
        assert os.path.realpath(c[4]).startswith(dump_dir + os.sep)
        assert not os.path.exists(c[4])
        assert not os.path.exists(os.path.dirname(c[4]))


def test_copies_left_by_a_crash_are_deleted_at_start():
    from isdi.config import get_config
    from isdi.scanner.base import purge_raw_dumps

    left = os.path.join(get_config().DUMP_DIR, "isdi-apk-crashed")
    os.makedirs(left)
    with open(os.path.join(left, "app.apk"), "wb") as fh:
        fh.write(b"x")
    purge_raw_dumps()
    assert not os.path.exists(left)


def test_unknown_signers_cost_nothing_when_the_list_is_empty(phone, monkeypatch):
    monkeypatch.setattr(blocklist, "STALKERWARE_SIGNERS", {})
    phone.find_spyapps(SERIAL)
    assert not any(c[2:3] == ["pull"] for c in _calls(phone))


def test_signer_flags_are_explained_and_weighted():
    assert blocklist.score(["stalkerware-signer"]) >= 1.0
    assert blocklist.score(["signer-unchecked"]) == 0
    html = blocklist.flag_str(["stalkerware-signer", "signer-unchecked"])
    assert 'class="text-primary"' in html and "certificate" in html


def test_signers_list_is_loaded_from_the_package():
    assert len(blocklist.STALKERWARE_SIGNERS) > 100
    sha, family = next(iter(blocklist.STALKERWARE_SIGNERS.items()))
    assert len(sha) == 40 and sha == sha.upper() and family
    assert len(blocklist.SIGNERS_SHA256) == 64


def test_consultation_and_summary_treat_it_as_known_monitoring():
    from isdi import client_summary
    from isdi.consultation import model

    assert "stalkerware-signer" in model.SPYWARE_FLAGS
    assert "stalkerware-signer" in client_summary.KNOWN_MONITORING
