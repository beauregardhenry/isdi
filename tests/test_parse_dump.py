from isdi.scanner import parse_dump as pdump
import os
import pytest

D = {"a": {"bc1": {"cd11": [1, 3]}, "bc2": {"cd21": [2]}}, "aa": {}}


def test_match_keys_w_one():
    assert pdump._match_keys_w_one(D, "^a$") == ["a"]


def test_match_keys():
    assert pdump.match_keys(D, "^a$//^b.*1$//^.*d11$") == {
        "a": {"bc1": ["cd11"]},
    }
    assert pdump.match_keys(D, "a//^b.*1$//^.*d11$") == {
        "a": {"bc1": ["cd11"]},
        "aa": {},
    }

    assert pdump.match_keys(D, "^a$//^b.*$//^.*d11$") == {
        "a": {"bc1": ["cd11"], "bc2": []},
    }

    # assert pdump.match_keys(D, '^a$//^b.*$//^.*d11$', only_last=True) == {
    #     'a': {'bc2': []},
    # }


def test_prune_leaves():
    keys = pdump.match_keys(D, "^a$//^b.*$//^.*d11$")
    assert pdump.prune_empty_leaves(keys) == {"a": {"bc1": ["cd11"]}}
    assert pdump.prune_empty_leaves(pdump.match_keys(D, "a//^b.*1$//^.*d11$")) == {
        "a": {"bc1": ["cd11"]},
    }


def test_extract():
    keys = pdump.prune_empty_leaves(pdump.match_keys(D, "^a$//^b.*$//^.*d11$"))
    assert keys == {"a": {"bc1": ["cd11"]}}
    assert pdump.extract(D, keys) == [[1, 3]]


def test_get_all_leaves():
    assert sorted(pdump.get_all_leaves(D)) == [1, 2, 3]
    keys = pdump.prune_empty_leaves(pdump.match_keys(D, "^a$//^b.*$//^.*d"))
    assert sorted(pdump.get_all_leaves(keys)) == ["cd11", "cd21"]


@pytest.mark.parametrize(
    "fname, conds",
    [
        (
            "./phone_dumps/test/test1-rc-pixel4_android.txt",
            {
                "in_apps": [
                    ("com.amazon.mShop.android.shopping", "56b26bf"),
                    ("com.aljazeera.mobile", "fa6702e"),
                    ("com.android.sdm.plugins.usccdm", "db6e2b0"),
                ],
                "in_info": [
                    (
                        "com.google.android.uwb.resources",
                        {
                            "firstInstallTime": "1969-12-31 18:00:00",
                            "lastUpdateTime": "1969-12-31 18:00:00",
                            "data_usage": {
                                "data_used": "unknown",
                                "background_data_allowed": "unknown",
                            },
                            "battery_usage": "0 (mAh)",
                        },
                    ),
                    (
                        "com.Slack",
                        {
                            "firstInstallTime": "2023-09-22 15:22:45",
                            "lastUpdateTime": "2025-04-06 01:03:03",
                            "data_usage": {
                                "data_used": "unknown",
                                "background_data_allowed": "unknown",
                            },
                            "battery_usage": "0 (mAh)",
                        },
                    ),
                    (
                        "com.android.providers.downloads",
                        {
                            "firstInstallTime": "2008-12-31 18:00:00",
                            "lastUpdateTime": "2008-12-31 18:00:00",
                            "data_usage": {
                                "data_used": "unknown",
                                "background_data_allowed": "unknown",
                            },
                            "battery_usage": "0 (mAh)",
                        },
                    ),
                ],
            },
        ),
        (
            "./phone_dumps/test/test2-lge-rc.txt",
            {
                "in_apps": [
                    ("com.hy.system.fontserver", "10f809f"),
                    ("com.lge.penprime.overlay", "ba26d8b"),
                    ("com.android.incallui.overlay", "86a753f"),
                ],
                "in_info": [],
            },
        ),
    ],
)
def test_apps(fname, conds):
    if not os.path.exists(fname):
        pytest.skip(f"File {fname} does not exist. Skipping test.")
    ad = pdump.AndroidDump(fname)
    apps = ad.all_apps()
    print(fname, apps[:5])
    # Check if the apps are in the dump
    for app, _ in conds["in_apps"]:
        assert app in apps
    # Check if the app info is correct
    for app, expected in conds["in_info"]:
        info = ad.info(app)
        # print(info)
        for k, v in expected.items():
            assert info[k] == v


class TestIosDump(object):
    # TODO - Write IosDump
    pass


# ---------------------------------------------------------------------------
# Synthetic dumps (tests/fixtures/). These follow the `dumpsys` and
# pymobiledevice3 layouts the parser reads, but are hand-written: the real
# dumps the tests above expect are not in the repository.

import json
import shutil
from pathlib import Path

DATA = Path(__file__).parent / "fixtures"


@pytest.fixture
def android(tmp_path):
    # AndroidDump caches its parse as a .json next to the .txt, so copy.
    shutil.copy(DATA / "android_dump.txt", tmp_path / "dump.txt")
    return pdump.AndroidDump(str(tmp_path / "dump.txt"))


def test_android_lists_all_packages(android):
    assert android.all_apps() == [
        "com.android.settings",
        "com.example.spy",
        "com.whatsapp",
    ]


def test_android_system_apps(android):
    assert android.system_apps() == ["com.android.settings"]


def test_android_offstore_apps(android):
    """Not a system app and not installed by an approved store."""
    assert android.offstore_apps() == ["com.example.spy"]


def test_android_finds_packages_whichever_shape_the_parse_has():
    packages = {"Package [a] (1": {"userId": "1"}}
    find = pdump.AndroidDump._find_packages_section
    assert find({"Packages": packages}) is packages
    assert find(["Dexopt state", {"Packages": packages}]) is packages
    assert find({"Database versions": {}}) is None


def test_android_info(android):
    info = android.info("com.example.spy")
    assert info["userId"] == "10234"
    assert info["versionName"] == "2.1"
    assert info["lastUpdateTime"] == "2026-09-01 12:00:00"
    assert android.info("com.whatsapp")["firstInstallTime"] == "2025-01-01 09:00:00"
    assert android.info("not.installed") == {}


def test_android_data_usage_matches_exact_uid(android):
    """rx 1 MiB + tx 2 MiB for uid 10234; uid 1023's row must not match."""
    assert android.info("com.example.spy")["data_usage"]["data_used"] == "3.00 MB"


def test_empty_proc_net_stats_does_not_hide_netstats(android):
    assert "BPF map content" in android.df["net_stats"]


@pytest.mark.parametrize(
    "uid, expected",
    [("10234", "3.00 MB"), ("u0a234", "3.00 MB"), ("u0a5", "unknown")],
)
def test_data_usage_uid_forms(android, uid, expected):
    usage = pdump.AndroidDump.get_data_usage(android.df, "x", uid)
    assert usage["data_used"] == expected


def test_parse_is_cached_as_json(android, tmp_path):
    cached = json.loads((tmp_path / "dump.json").read_text())
    assert cached == android.df


@pytest.fixture
def ios(tmp_path):
    shutil.copy(DATA / "ios_dump.json", tmp_path / "dump.json")
    return pdump.IosDump(str(tmp_path / "dump.json"))


def test_ios_installed_apps_and_titles(ios):
    assert ios.installed_apps() == ["com.apple.mobilesafari", "com.example.tracker"]
    assert ios.installed_apps_titles() == {
        "com.apple.mobilesafari": "MobileSafari",
        "com.example.tracker": "Tracker",
    }
    assert ios.system_apps() == ["com.apple.mobilesafari"]


def test_ios_device_info_uses_model_table(ios):
    text, m = ios.device_info()
    assert m == {"model": "iPhone XR", "version": "17.6.1"}
    assert text == "iPhone XR (running iOS 17.6.1)"


def test_ios_device_info_unknown_model(tmp_path):
    d = json.loads((DATA / "ios_dump.json").read_text())
    d["devinfo"]["ProductType"] = "iPhone99,9"
    (tmp_path / "new.json").write_text(json.dumps(d))
    text, m = pdump.IosDump(str(tmp_path / "new.json")).device_info()
    assert m["model"] == "iPhone (Model MRY42 LL/A)"


def test_ios_only_whitelisted_device_fields_are_kept(ios):
    assert "SerialNumber" not in ios.deviceinfo


def test_ios_permissions_and_reasons(ios):
    info = ios.info("com.example.tracker")
    assert info["title"] == "Tracker" and info["App Version"] == "3.4"
    assert sorted(info["permissions"]) == [
        ("Camera", "Scan QR codes."),
        ("Location (always)", "We share your location with your family."),
        ("Microphone", "permission granted by system"),
    ]
    assert ios.info("not.installed") is None


def test_ios_unreadable_dump(tmp_path):
    (tmp_path / "bad.json").write_text("{not json")
    d = pdump.IosDump(str(tmp_path / "bad.json"))
    assert d.installed_apps() == [] and len(d) == 0


def test_ios_unknown_permission_is_named_without_touching_package_data(tmp_path):
    from isdi.config import get_config

    shipped = Path(get_config().STATIC_DATA) / "ios_permissions.json"
    before = shipped.read_bytes()
    d = json.loads((DATA / "ios_dump.json").read_text())
    d["apps"]["com.example.tracker"]["Entitlements"]["com.apple.private.tcc.allow"] = [
        "kTCCServiceSomethingNew"
    ]
    (tmp_path / "new.json").write_text(json.dumps(d))
    info = pdump.IosDump(str(tmp_path / "new.json")).info("com.example.tracker")
    assert ("Somethingnew", "permission granted by system") in info["permissions"]
    assert shipped.read_bytes() == before


@pytest.mark.parametrize(
    "product_type, model",
    [
        ("iPhone11,8", "iPhone XR"),  # existing entry, unchanged
        ("iPhone12,1", "iPhone 11"),
        ("iPhone17,3", "iPhone 16"),
    ],
)
def test_ios_model_names(tmp_path, product_type, model):
    d = json.loads((DATA / "ios_dump.json").read_text())
    d["devinfo"]["ProductType"] = product_type
    (tmp_path / "m.json").write_text(json.dumps(d))
    assert pdump.IosDump(str(tmp_path / "m.json")).device_info()[1]["model"] == model
