import itertools
import functools
import json
import operator
import os
import re
import logging
from isdi.config import get_config
from collections import OrderedDict
from functools import reduce
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from rsonlite import simpleparse

config = get_config()


def complexparse(lines: list[str]) -> dict:
    """Binary search how much str can be parsed without error"""

    def _find_length_of_valid_string(text: list, s: int, e: int) -> int:
        """Finds the length of the valid string"""
        if s == e:
            return s
        mid = (s + e) // 2
        try:
            simpleparse("".join(text[:mid]))
            return _find_length_of_valid_string(text, mid + 1, e)
        except Exception:
            return _find_length_of_valid_string(text, s, mid)

    try:
        return simpleparse("".join(lines))
    except IndentationError:
        pass  # parse as much as possible, below
    n = _find_length_of_valid_string(lines, 0, len(lines)) - 1
    logging.info(f"Parsed {n} (out of {len(lines)}) lines.")
    d = simpleparse("".join(lines[:n]))
    if isinstance(d, list):
        d.append({"UNPARSED": lines[n:]})
    else:
        d["UNPARSED"] = lines[n:]
    return d


# Applied to `adb shell` output before it is written to a dump file; ported
# from the sed pipeline in the old scripts/android_scan.sh. [ \t] rather than \s so a
# pattern never spans lines, as with sed.
_EMAIL_RE = re.compile(r"([ \t]*)[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,4}\b")
_DB_EMAIL_RE = re.compile(r"([ \t]*)[a-zA-Z0-9._%+\-]+_gmail\.com")
_NORMALIZE_RES = [
    (re.compile(r"^([ \t]*)lastDisabledCaller: ", re.M), r"\1lastDisabledCaller:\1  "),
    # Put per-user state on its own indented block so it parses as a section.
    (
        re.compile(r"^([ \t]*)User 0: ceDataInode(.*)$", re.M),
        r"\1User 0:\n\1  ceDataInode\2",
    ),
    (re.compile(r"^([ \t]*)(Excluded packages:)", re.M), r"  \1\2"),
    (re.compile(r"^([ \t]*)#(.*)$", re.M), r"\1\2"),
]


def redact_emails(text: str) -> str:
    """Replace account emails (and <name>_gmail.com database names)."""
    return _DB_EMAIL_RE.sub(r"\1<db_email>", _EMAIL_RE.sub(r"\1<email>", text))


def normalize_dumpsys(text: str) -> str:
    """Rewrite dumpsys lines that the indentation parser would misread."""
    for pattern, repl in _NORMALIZE_RES:
        text = pattern.sub(repl, text)
    return text


def _match_keys_w_one(d, key: str) -> list:
    """Returns a list of keys that matches @key"""
    sk = re.compile(key)
    if not d:
        return []
    if isinstance(d, list):
        d = d[0]
    ret = [k for k in d if sk.match(k) is not None]
    return ret


def match_keys(d, keys: str | list) -> OrderedDict | list:
    """d is a dictionary, and finds all keys that matches @keys
    Returns a list of lists
    """
    if isinstance(keys, str):
        keys = keys.split("//")
    # Handle non-dictionary input
    if not isinstance(d, (dict, list)):
        return OrderedDict() if len(keys) > 1 else []
    ret = _match_keys_w_one(d, keys[0])
    if len(keys) == 1:
        return ret
    result = OrderedDict()
    for k in ret:
        # Only recurse if d[k] is a dictionary or list
        if isinstance(d, list):
            d = d[0]
            continue
        if isinstance(d[k], (dict, list)):
            result[k] = match_keys(d[k], keys[1:])
        else:
            # If we've reached a leaf node but still have keys to match, skip it
            result[k] = OrderedDict() if len(keys) > 1 else d[k]
    return result


def get_all_leaves(d: dict) -> list:
    """Returns all leaves in a dictionary"""
    if not isinstance(d, dict):
        return d
    return list(itertools.chain(*(get_all_leaves(v) for v in d.values())))


def retrieve(dict_: dict, nest: list) -> str | dict:
    """
    Navigates dictionaries like dict_[nest0][nest1][nest2]...
    gracefully.
    """
    try:
        return reduce(operator.getitem, nest, dict_)
    except KeyError as e:
        logging.error(
            f"KeyError: {e} for dict_.keys={list(dict_.keys())} and nest={nest}"
        )
        return ""
    except TypeError as e:
        logging.error(
            f"TypeError: {e} for dict_.keys={list(dict_.keys())} and nest={nest}"
        )
        return ""


################ CUSTOM ANDROID PARSING #########################
def parse_procstats(text: str) -> dict:
    """Parses the output of `adb shell dumsys procstats`"""
    apps: Dict[str, dict] = {}
    current_app: Optional[dict] = None

    app_re = re.compile(r"^\s*\* ([^ ]+) / ([^ ]+) / (v\d+):")
    stat_re = re.compile(
        r"^\s+([\w\s]+): ([\d\.]+%) \(([^/]+)/([^/]+)/([^)]+)\s+over\s+(\d+)\)"
    )

    for line in text.splitlines():
        app_match = app_re.match(line)
        stat_match = stat_re.match(line)

        if app_match:
            name, uid, version = app_match.groups()
            current_app = {"process": name, "uid": uid, "version": version, "stats": {}}
            apps[current_app["process"]] = current_app

        elif stat_match and current_app:
            stat_type, percent, ram, swap, zram, over = stat_match.groups()
            current_app["stats"][stat_type.strip()] = {
                "percent": percent,
                "ram": ram.split("-"),
                "swap": swap.split("-"),
                "zram": zram.split("-"),
                "samples": int(over),
            }

    return apps


class PhoneDump(object):
    """A parsed phone dump. Subclasses parse the dump (load_file), once."""

    # package -> powers it holds (special_access_from_dump); Android only.
    special_access: Dict[str, Set[str]] = {}

    def __init__(self, dev_type, fname):
        self.device_type = dev_type
        self.dumpf = fname

    def load_file(self):
        raise NotImplementedError

    def info(self, appid):
        raise NotImplementedError

    def system_apps(self) -> list:
        return []

    def offstore_apps(self) -> list:
        return []


@functools.lru_cache(maxsize=None)
def _package_json(name: str):
    with open(os.path.join(config.STATIC_DATA, name), "r") as fh:
        return json.load(fh)


# Powers an app can be granted that monitoring apps rely on, with the
# secure setting that lists the apps holding each (colon-separated
# "package/component" entries).
SPECIAL_ACCESS_SETTINGS = {
    "enabled_accessibility_services": "accessibility",
    "enabled_notification_listeners": "notification-access",
}
_SECTION_RE = re.compile(r"^DUMP OF (?:SERVICE|SETTINGS) (.+?)\s*$", re.M)
_COMPONENT_RE = re.compile(r"^\s*([A-Za-z][\w.]*)/[^\s:]+:?\s*$")


def _sections(text: str) -> Dict[str, str]:
    """The dump's "DUMP OF SERVICE/SETTINGS <name>" sections, by name."""
    marks = list(_SECTION_RE.finditer(text))
    return {
        m.group(1): text[m.end() : marks[i + 1].start() if i + 1 < len(marks) else None]
        for i, m in enumerate(marks)
    }


def _device_admins(text: str) -> Set[str]:
    """Packages listed under "Enabled Device Admins" in `dumpsys
    device_policy`: one "package/receiver:" line per admin, indented below
    the heading. Lenient about the rest, which differs between Android
    versions."""
    admins: Set[str] = set()
    heading_indent = None
    for line in text.splitlines():
        indent = len(line) - len(line.lstrip())
        if "Enabled Device Admins" in line:
            heading_indent = indent
            continue
        if heading_indent is None or not line.strip():
            continue
        if indent <= heading_indent:
            heading_indent = None
            continue
        m = _COMPONENT_RE.match(line)
        if m:
            admins.add(m.group(1))
    return admins


def special_access_from_dump(text: str) -> Dict[str, Set[str]]:
    """package -> the powers it holds: "accessibility" (can read and act
    on the screen), "notification-access" (reads every notification) and
    "device-admin" (can lock or wipe the phone; harder to uninstall)."""
    sections = _sections(text)
    found: Dict[str, Set[str]] = {}
    for line in sections.get("secure", "").splitlines():
        key, sep, value = line.strip().partition("=")
        flag = SPECIAL_ACCESS_SETTINGS.get(key)
        if not sep or not flag:
            continue
        for component in value.split(":"):
            package = component.split("/", 1)[0].strip()
            if package and package != "null" and "/" in component:
                found.setdefault(package, set()).add(flag)
    for package in _device_admins(sections.get("device_policy", "")):
        found.setdefault(package, set()).add("device-admin")
    return found


class AndroidDump(PhoneDump):
    def __init__(self, fname):
        super(AndroidDump, self).__init__("android", fname)
        self.df = self.load_file()
        self.apps = None
        try:
            with open(self.dumpf.rsplit(".", 1)[0] + ".txt", errors="replace") as fh:
                self.special_access = special_access_from_dump(fh.read())
        except OSError as ex:
            logging.warning("Special access not read: %s", type(ex).__name__)

    @staticmethod
    def custom_parse(service, lines):
        if service == "appops":
            return complexparse(lines)  # nested per-package blocks
        elif service == "procstats":
            return parse_procstats("\n".join(lines))

    def new_parse_dump_file(self, fname: str) -> dict:
        """Parse a dump: one entry per "DUMP OF SERVICE/SETTINGS" section."""
        if not Path(fname).exists():
            logging.error("File: {!r} does not exists".format(fname))
        with open(fname) as fh:
            data = fh.readlines()
        d: Dict[str, Any] = {}
        service = ""
        join_lines: List[str] = []
        custom_parse_services = {"appops", "procstats"}

        def _clean_dictionary(d):
            """remove non-alphanumeric characters from the end of each key in the dictionary"""
            if isinstance(d, list):
                return [_clean_dictionary(i) for i in d]
            if not isinstance(d, dict):
                return d
            keys = list(d.keys())
            for k in keys:
                new_key = re.sub(r"\W+$", "", k)
                # if new_key != k:
                #   print(f"Cleaning key: {k} --> {new_key}")
                d[new_key] = _clean_dictionary(d.pop(k))
            return d

        def _parse(lines):
            if not any(line.strip() for line in lines):
                return {}
            try:
                if service in custom_parse_services:
                    return AndroidDump.custom_parse(service, lines)
                else:
                    r = complexparse(lines)
                    return r
            except Exception as ex:
                # One odd section (rsonlite raises on some indentation) must
                # not lose the whole dump: keep it unparsed and move on.
                # Only the type: the message can quote the dump.
                logging.warning(
                    "Could not parse service %r (%s)", service, type(ex).__name__
                )
                return {"UNPARSED": lines}

        for i, l in enumerate(data):
            if l.startswith("----"):
                continue
            if l.startswith("DUMP OF SERVICE") or l.startswith("DUMP OF SETTINGS"):
                if service:
                    parsed = _parse(join_lines)
                    # Dumps contain both "netstats detail" (renamed below) and
                    # an often-empty /proc "net_stats" section; keep the data.
                    if parsed or not d.get(service):
                        d[service] = parsed
                service = re.sub(r"DUMP OF SERVICE |DUMP OF SETTINGS ", "", l).strip()
                if service == "netstats detail":
                    service = "net_stats"
                join_lines = []
            else:
                join_lines.append(l)
        if len(join_lines) > 0 and len(d.get(service, [])) == 0:
            d[service] = _parse(join_lines)
        return _clean_dictionary(d)

    def load_file(self) -> dict:
        """Parse the dump. Nothing is written next to it: the dump is raw
        client data, deleted once the scan is saved, and a cached copy of
        its parse would outlive it."""
        fname = self.dumpf.rsplit(".", 1)[0] + ".txt"
        try:
            return self.new_parse_dump_file(fname)
        except Exception as ex:
            logging.error("Dump %r could not be parsed: %s", fname, type(ex).__name__)
            raise

    @staticmethod
    def get_data_usage(d, appid, process_uid):
        """Get the data usage for the appid and process_uid"""
        res = {"data_used": "unknown", "background_data_allowed": "unknown"}
        if "net_stats" not in d or not d["net_stats"]:
            return res
        if isinstance(d["net_stats"], list):
            d["net_stats"] = d["net_stats"][0]
        dn = d["net_stats"]
        if process_uid.startswith("u0a"):
            # u0aN is app uid 10000 + N
            process_uid = str(10000 + int(process_uid[3:]))

        # Backgroud data allowed?
        bgdata = dn.get("BPF map content", {}).get("mUidCounterSetMap", [])
        allowed = False
        for l in bgdata:
            entry = next(iter(l.values()), "") if isinstance(l, dict) else l
            if str(entry).startswith(process_uid):
                allowed = True
                break
        # Get the data usage: rows are "uid rxBytes rxPackets txBytes txPackets"
        rxstats = dn.get("BPF map content", {}).get("mAppUidStatsMap", [])

        for l in rxstats:
            s = str(l).split()
            if s and s[0] == process_uid:
                if len(s) != 5:
                    logging.error("Unexpected net_stats row for an app")
                    return res
                else:
                    _uid, rxBytes, _rxPackets, txBytes, _txPackets = s
                    res["data_used"] = "{:.2f} MB".format(
                        (int(rxBytes) + int(txBytes)) / (1024 * 1024)
                    )
                    res["background_data_allowed"] = "yes" if allowed else "not allowed"
                    return res
        return res

    @staticmethod
    def get_battery_stat(d, appid, uidu):
        b = list(
            get_all_leaves(
                match_keys(
                    d,
                    "batterystats//Statistics since last charge//Estimated power use .*"
                    "//^Uid {}:.*".format(uidu),
                )
            )
        )
        if not b:
            return "0 (mAh)"
        _, sep, usage = str(b[0]).partition(":")
        return usage if sep else "unknown"

    @staticmethod
    def _find_packages_section(section):
        """The parsed `dumpsys package` output is a dict or a list depending
        on which other sections the phone prints; find "Packages" in either."""
        items = section if isinstance(section, list) else [section]
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("Packages"), dict):
                return item["Packages"]
        return None

    def _get_apps(self) -> dict:
        if self.apps:
            return self.apps
        d = self.df
        if not d:
            logging.error("self.df is empty")
            return {}
        if "package" not in d:
            logging.error(
                f"'package' is not a key in self.df, where keys = {list(d.keys())}"
            )
            return {}
        app_d = self._find_packages_section(d["package"])
        if app_d is None:
            logging.error("No 'Packages' section in the package dump")
            return {}
        # get_all_leaves(match_keys(d, "^package$//^Packages//^Package .*"))
        packages = {}
        for k, v in app_d.items():
            m = re.match(r"Package \[(?P<appId>.*)\] \((?P<h>.*)", k)
            if not m:
                logging.error(f"{k} is not an appId")
                continue
                # k is a valid appId
            appId, h = m.groups()
            if "firstInstallTime" not in v:
                t = v.get("User 0", {})
                if isinstance(t, list):
                    t = t[0]
                v["firstInstallTime"] = t.get("firstInstallTime", "")
            packages[appId] = {
                "packageKey": k,
                "flags": v.get("flags", ""),
                "installerPackageName": v.get("installerPackageName", ""),
                "userId": v.get("userId", ""),
                "firstInstallTime": v.get("firstInstallTime", ""),
                "lastUpdateTime": v.get("lastUpdateTime", ""),
            }
        self.apps = packages
        return self.apps

    def all_apps(self) -> list:
        """returns all apps"""
        a = self._get_apps()
        return list(a.keys())

    def system_apps(self) -> list:
        """Return system apps: flags=[ SYSTEM ]"""
        a = self._get_apps()
        system_apps = []
        for appid, meta in a.items():
            flags = meta.get("flags", "")
            if isinstance(flags, list):
                if any("SYSTEM" in str(flag) for flag in flags):
                    system_apps.append(appid)
            else:
                if "SYSTEM" in str(flags):
                    system_apps.append(appid)
        return system_apps

    def offstore_apps(self) -> list:
        approved_installers = {
            "com.android.vending",
            "com.dti.att",  # AT&T phones have this installer
            "com.facebook.system",  # Some phones sell themselves to Facebook
        }
        a = self._get_apps()
        sys_apps = self.system_apps()
        return [
            k
            for k, v in a.items()
            if k not in sys_apps
            and v["installerPackageName"] not in approved_installers
        ]

    def info(self, appid):
        d = self.df
        if not d:
            return {}
        a = self._get_apps()
        if appid not in a:
            logging.error(f"AppId {appid} not found ({len(a)} apps in the dump)")
            return {}
        app = self._find_packages_section(d["package"])[a[appid]["packageKey"]]
        res = {
            k: app.get(k, "")
            for k in [
                "userId",
                "firstInstallTime",
                "lastUpdateTime",
                "versionCode",
                "versionName",
                "install permissions",
                "declared permissions",
                "runtime permissions",
            ]
        }

        if "userId" not in res:
            logging.error("UserID not found for %s", appid)
            return {}
        process_uid = res["userId"]
        # del res["userId"]
        # memory = match_keys(d, "meminfo//Total PSS by process//.*: {}.*".format(appid))
        uidu_match = list(
            get_all_leaves(
                match_keys(d, "procstats//CURRENT STATS//* {} / .*".format(appid))
            )
        )
        logging.info(f"UIDU match found: {uidu_match}")
        if uidu_match:
            uidu = uidu_match[-1].split(" / ")
        else:
            uidu = "Not Found"
        if len(uidu) > 1:
            uidu = uidu[1]
        else:
            uidu = uidu[0]
        res["data_usage"] = self.get_data_usage(d, appid, process_uid)
        res["battery_usage"] = self.get_battery_stat(d, appid, uidu)  # (mAh)
        return res


class IosDump(PhoneDump):
    # COLS = ['ApplicationType', 'BuildMachineOSBuild', 'CFBundleDevelopmentRegion',
    #    'CFBundleDisplayName', 'CFBundleExecutable', 'CFBundleIdentifier',
    #    'CFBundleInfoDictionaryVersion', 'CFBundleName',
    #    'CFBundleNumericVersion', 'CFBundlePackageType',
    #    'CFBundleShortVersionString', 'CFBundleSupportedPlatforms',
    #    'CFBundleVersion', 'DTCompiler', 'DTPlatformBuild', 'DTPlatformName',
    #    'DTPlatformVersion', 'DTSDKBuild', 'DTSDKName', 'DTXcode',
    #    'DTXcodeBuild', 'Entitlements', 'IsDemotedApp', 'IsUpgradeable',
    #    'LSRequiresIPhoneOS', 'MinimumOSVersion', 'Path', 'SequenceNumber',
    #    'UIDeviceFamily', 'UIRequiredDeviceCapabilities',
    #    'UISupportedInterfaceOrientations']
    # INDEX = 'CFBundleIdentifier'
    def __init__(self, fname):
        self.dumpf = fname
        super(IosDump, self).__init__("ios", fname)
        self.df, self.deviceinfo = self.load_file()
        self.device_class = self.deviceinfo.get("DeviceClass", "iPhone/iPad")

        # Bundled data files, read once per process.
        # A copy: get_permissions adds the permissions it meets.
        self.permissions_map = dict(_package_json("ios_permissions.json"))
        self.model_make_map = _package_json("ios_device_identifiers.json")

    def __nonzero__(self):
        return len(self.df) > 0

    def __len__(self):
        return len(self.df)

    def load_file(self):
        try:
            logging.info(f"fname is: {self.dumpf}")
            with open(self.dumpf, "r") as app_data:
                d = json.load(app_data)
        except Exception as ex:
            logging.error(f"Could not load the json file: {self.dumpf}. Exception={ex}")
            return [], {}

        apps = list(d.get("apps", {}).values())
        for app in apps:
            if "appId" not in app:
                app["appId"] = app.get("CFBundleIdentifier", "")
        self.appinfo = apps

        self.deviceinfo = {
            k: d["devinfo"].get(k, "")
            for k in [
                "DeviceClass",
                "ProductType",
                "ModelNumber",
                "RegionInfo",
                "ProductVersion",
            ]
        }
        return self.appinfo, self.deviceinfo

    def check_unseen_permissions(self, permissions):
        for permission in permissions:
            if not permission:
                continue  # Empty permission, skip
            if permission not in self.permissions_map:
                # Keep it for this dump only: the map ships with the package,
                # which may be read-only and must not change at runtime.
                logging.info(f"Unknown iOS permission {permission!r}")
                self.permissions_map[permission] = permission.replace("kTCCService", "")

    def get_permissions(self, app: dict) -> list:
        """
        Returns a list of tuples (permission, developer-provided reason for permission).
        Could modify this function to include whether or not the permission can be adjusted
        in Settings.
        """
        system_permissions = retrieve(
            app, ["Entitlements", "com.apple.private.tcc.allow"]
        )
        adjustable_system_permissions = retrieve(
            app, ["Entitlements", "com.apple.private.tcc.allow.overridable"]
        )
        third_party_permissions = list(set(app.keys()) & set(self.permissions_map))
        self.check_unseen_permissions(
            list(system_permissions) + list(adjustable_system_permissions)
        )

        # (permission used, developer reason for requesting the permission)
        all_permissions = list(
            set(
                map(
                    lambda x: (
                        self.permissions_map[x],
                        app.get(x, "permission granted by system"),
                    ),
                    list(
                        set(system_permissions)
                        | set(adjustable_system_permissions)
                        | set(third_party_permissions)
                    ),
                )
            )
        )
        return all_permissions

    def device_info(self):
        m = {}
        try:
            m["model"] = self.model_make_map[self.deviceinfo["ProductType"]]
        except KeyError:
            m["model"] = "{DeviceClass} (Model {ModelNumber} {RegionInfo})".format(
                **self.deviceinfo
            )
        m["version"] = self.deviceinfo["ProductVersion"]
        return "{model} (running iOS {version})".format(**m), m

    def info(self, appid):
        """
        Returns dict containing the following:
        'permission': tuple (all permissions of appid, developer
        reasons for requesting the permissions)
        'title': the human-friendly name of the app.
        (Whether the phone is jailbroken is checked per phone, in
        IosScanner.isrooted, not per app.)
        """
        res = {"title": ""}
        # app = self.df.iloc[appidx,:].dropna()
        # self.df is a list of app dictionaries, find the matching app
        app = next((a for a in self.df if a.get("CFBundleIdentifier") == appid), None)
        if not app:
            logging.warning(f"App with bundle identifier {appid} not found")
            return None

        party = app.get("ApplicationType", "").lower()
        permissions = []
        if party in ["system", "user", "hidden"]:
            logging.info(
                f"{app.get('CFBundleName', '')} ({app.get('CFBundleIdentifier', '')}) is a {party} app and has permissions:"
            )
            # permissions are an array that returns the permission id and an explanation.
            permissions = self.get_permissions(app)
        res["permissions"] = [(p.capitalize(), r) for p, r in permissions]
        res["title"] = app.get("CFBundleExecutable", "")
        res["App Version"] = app.get("CFBundleVersion", "")
        res["Install Date"] = """
        Apple does not officially record iOS app installation dates.  To view when
        '{}' was *last used*: [Settings -> General -> {} Storage].  To view the
        *purchase date* of '{}', follow these instructions:
        https://www.ipvtechresearch.org/post/guides/apple/.  These are the
        closest possible approximations to installation date available to
        end-users.  """.format(res["title"], self.device_class, res["title"])

        res["Battery Usage"] = (
            "To see recent battery usage of '{title}': "
            "[Settings -> Battery -> Battery Usage].".format(**res)
        )
        res["Data Usage"] = (
            "To see recent data usage (not including Wifi) of '{}': [Settings -> Cellular -> Cellular Data].".format(
                res["title"]
            )
        )

        return res

    def system_apps(self):
        if not self.df:
            return []
        return [
            app.get("CFBundleIdentifier", "")
            for app in self.df
            if app.get("ApplicationType") == "System" and app.get("CFBundleIdentifier")
        ]

    def installed_apps_titles(self) -> Dict[str, str]:
        if not self.df:
            return {}
        return {
            app.get("appId", ""): app.get("CFBundleExecutable", "")
            for app in self.df
            if app.get("appId")
        }

    def installed_apps(self):
        # return self.df.index
        if self.df is None:
            return []
        logging.info(f"parse_dump (installed_apps): >> {len(self.df)}")
        return [app.get("appId", "") for app in self.df if app.get("appId")]
