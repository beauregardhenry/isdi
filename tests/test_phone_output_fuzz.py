"""Whatever else the phone sends must not stop a scan.

The dump parsers were fuzzed in #71 and #72. This covers the rest of what
the phone (or an app on it) supplies:

- APK files, read for their signer. The stalkerware author builds the
  file, so a crafted one that crashed the reader would fail the whole
  scan and hide the app. Fuzzing (16,000 damaged APKs) found Python's zip
  reader raising NotImplementedError (a newer "version needed to
  extract"), which signer_certs did not catch; a broken compressed
  stream raises zlib.error.
- iPhone configuration profiles, whose identifiers the parser looked up
  in a dict without checking they could be.
- Special access settings and procstats, plain text.
"""

import random
import struct

import pytest

from tests import apkfactory as F
from isdi.scanner import apk_signers as A
from isdi.scanner import ios_management, parse_dump


@pytest.fixture(scope="module")
def signed():
    cert, key = F.make_cert("fuzz")
    return {
        "v1": F.build(v1=(cert, key)),
        "v2": F.build(block=F.signing_block([(A.V2_ID, F.v2_value(cert))])),
        "v3": F.build(block=F.signing_block([(A.V3_ID, F.v3_value(cert))])),
        "all": F.build(
            v1=(cert, key),
            block=F.signing_block(
                [(A.V2_ID, F.v2_value(cert)), (A.V3_ID, F.v3_value(cert))]
            ),
        ),
    }


def _read(tmp_path, data):
    p = tmp_path / "app.apk"
    p.write_bytes(data)
    return A.signer_sha1s(p)


def _central_entry(data, name):
    """Offset of the central directory header for `name`."""
    i = 0
    while True:
        i = data.index(b"PK\x01\x02", i)
        n = struct.unpack_from("<H", data, i + 28)[0]
        if data[i + 46 : i + 46 + n] == name:
            return i
        i += 4


def test_a_newer_zip_version_is_unreadable_not_a_crash(tmp_path, signed):
    """The fuzzer's case: a signature file whose "version needed to
    extract" is above what Python supports raises NotImplementedError."""
    b = bytearray(signed["v1"])
    struct.pack_into(
        "<H", b, _central_entry(signed["v1"], b"META-INF/CERT.EC") + 6, 0xFF
    )
    with pytest.raises(A.ApkError):
        _read(tmp_path, bytes(b))


@pytest.mark.parametrize("method", [99, 12, 14])  # AES, bzip2, lzma markers
def test_an_unsupported_compression_method_is_unreadable(tmp_path, signed, method):
    b = bytearray(signed["v1"])
    struct.pack_into(
        "<H", b, _central_entry(signed["v1"], b"META-INF/CERT.EC") + 10, method
    )
    with pytest.raises(A.ApkError):
        _read(tmp_path, bytes(b))


def test_a_broken_compressed_signature_is_unreadable(tmp_path, signed):
    # Stored bytes declared as deflated: the inflater rejects them.
    b = bytearray(signed["v1"])
    struct.pack_into("<H", b, _central_entry(signed["v1"], b"META-INF/CERT.EC") + 10, 8)
    with pytest.raises(A.ApkError):
        _read(tmp_path, bytes(b))


def test_v2_signers_survive_an_unreadable_v1_part(tmp_path, signed):
    b = bytearray(signed["all"])
    struct.pack_into(
        "<H", b, _central_entry(signed["all"], b"META-INF/CERT.EC") + 6, 0xFF
    )
    assert len(_read(tmp_path, bytes(b))) == 1


def _mutate(rng, data):
    b = bytearray(data)
    for _ in range(rng.randint(1, 6)):
        k = rng.randrange(6)
        if k == 0 and b:
            b[rng.randrange(len(b))] = rng.randrange(256)
        elif k == 1 and len(b) > 4:
            i = rng.randrange(len(b) - 4)
            value = rng.choice(
                [0, 1, 0x7FFFFFFF, 0xFFFFFFFF, len(b), rng.randrange(1 << 32)]
            )
            b[i : i + 4] = struct.pack("<I", value)
        elif k == 2 and len(b) > 8:
            i = rng.randrange(len(b) - 8)
            b[i : i + 8] = struct.pack("<Q", rng.choice([0, 8, 1 << 40, (1 << 64) - 1]))
        elif k == 3:
            b = b[: rng.randrange(len(b) + 1)]
        elif k == 4 and b:
            i = rng.randrange(len(b))
            del b[i : i + rng.randint(1, 64)]
        else:
            i = rng.randrange(len(b) + 1)
            b[i:i] = rng.choice([A._MAGIC, A._EOCD_SIG, b"PK\x01\x02", b"PK\x03\x04"])
    return bytes(b)


def test_randomly_damaged_apks_are_read_or_refused(tmp_path, signed):
    """Every damaged APK either gives its signers or raises ApkError (or
    OSError); signer_certs marks those apps unchecked and goes on."""
    rng = random.Random(20261101)
    seeds = list(signed.values())
    for i in range(1500):
        data = _mutate(rng, rng.choice(seeds))
        try:
            _read(tmp_path, data)
        except (A.ApkError, OSError):
            pass
        except Exception as e:  # pragma: no cover - the failure message
            raise AssertionError(f"case {i}: {e!r}") from e


def test_a_reader_crash_marks_the_app_unchecked(monkeypatch, tmp_path):
    """Belt and braces: whatever the reader raises, the scan goes on."""
    from isdi.scanner import android

    sc = android.AndroidScanner()
    monkeypatch.setattr(sc, "_base_apk", lambda serial, appid: "/data/app/x/base.apk")

    class Done:
        returncode = 0

        def __init__(self, out=""):
            self.stdout, self.stderr = out, ""

    def run_tool(*args, **kw):
        return Done("1000" if "stat" in args else "")

    monkeypatch.setattr(sc, "run_tool", run_tool)
    monkeypatch.setattr(android, "catch_err", lambda p, cmd="": p.stdout)

    def boom(path):
        raise RecursionError("crafted")

    monkeypatch.setattr(android.apk_signers, "signer_sha1s", boom)
    found, unchecked = sc.signer_certs("SER", ["com.example.app"])
    assert found == {} and unchecked == {"com.example.app"}


# --- iPhone profiles ---------------------------------------------------------------

ODD = [None, 0, 1.5, True, "", "x", [], {}, ["x"], {"a": 1}, b"\x00"]


def test_profile_lists_of_any_shape_are_read(monkeypatch):
    rng = random.Random(20261101)
    for _ in range(2000):
        metadata = {
            rng.choice(["p1", "p2", "p3"]): rng.choice(
                ODD + [{"PayloadDisplayName": rng.choice(ODD)}]
            )
            for _ in range(rng.randint(0, 3))
        }
        response = rng.choice(
            [
                rng.choice(ODD),
                {"ProfileMetadata": rng.choice(ODD + [metadata])},
                {
                    "ProfileMetadata": metadata,
                    "OrderedIdentifiers": rng.choice(
                        ODD + [[rng.choice(ODD + ["p1", "p2"]) for _ in range(3)]]
                    ),
                },
            ]
        )
        profiles = ios_management.profiles_from(response)
        assert all(isinstance(p["name"], str) for p in profiles)
        ios_management.supervision_from(
            rng.choice(ODD + [{"IsSupervised": rng.choice(ODD)}])
        )


def test_an_unhashable_ordered_identifier_is_skipped():
    response = {
        "ProfileMetadata": {"p1": {"PayloadDisplayName": "MDM"}},
        "OrderedIdentifiers": [["p1"], {"x": 1}, "p1"],
    }
    assert [p["name"] for p in ios_management.profiles_from(response)] == ["MDM"]


# --- text from adb -----------------------------------------------------------------


def _random_text(rng):
    pieces = [
        "DUMP OF SETTINGS secure\n",
        "DUMP OF SERVICE device_policy\n",
        "enabled_accessibility_services=",
        "enabled_notification_listeners=",
        "com.a/.S",
        ":",
        "/",
        "=",
        "null",
        "\n",
        "  ",
        "Enabled Device Admins (User 0",
        "):\n",
        "    com.b/.Admin:\n",
        "  * com.c / u0a12 / v3:\n",
        "      TOTAL: 50% (1-2-3/4-5-6/7-8-9 over 3)\n",
        "x",
        "\x00",
        "é",
    ]
    return "".join(rng.choice(pieces) for _ in range(rng.randint(0, 60)))


def test_special_access_and_procstats_read_any_text():
    rng = random.Random(20261101)
    for _ in range(2000):
        text = _random_text(rng)
        access = parse_dump.special_access_from_dump(text)
        assert all(isinstance(v, set) for v in access.values())
        parse_dump.parse_procstats(text)
