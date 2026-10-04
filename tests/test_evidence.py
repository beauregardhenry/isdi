"""Evidence copies of scans, evidence packages, and signed exports."""

import base64
import json
import os
import stat
import uuid
from pathlib import Path

import pytest
from click.testing import CliRunner

from isdi import audit, crypto, evidence
from isdi.config import get_config
from isdi.scanner import db
from tests.test_data_protection import (  # noqa: F401
    _database_bytes,
    _phone_dump_files,
    phone,
)
from tests.test_scanner_pipeline import SERIAL, STALKER


def _scan(app, preserve):
    from isdi.web.view import scan as scan_view

    clientid = f"ev_{uuid.uuid4().hex[:8]}"
    with app.test_request_context():
        result, status = scan_view._run_live_scan(
            clientid, "android", "Owner", SERIAL, preserve=preserve
        )
    assert status == 200
    return clientid, result["scanid"], result


def _public():
    return crypto.public_key(get_config().keyfile)


@pytest.fixture
def kept(app, phone):  # noqa: F811
    clientid, scanid, result = _scan(app, preserve=True)
    return clientid, scanid, result


def test_evidence_copy_is_kept_encrypted_and_the_dump_still_deleted(app, kept):
    clientid, scanid, result = kept
    assert result["evidence_sha256"]
    assert _phone_dump_files() == [], "the raw dump file must still be deleted"
    with app.app_context():
        row = evidence.evidence_for_scan(scanid)
        actions = [e["action"] for e in audit.entries(clientid)]
    assert row["dump_sha256"] == result["evidence_sha256"]
    raw = base64.b64decode(row["data"])
    assert f"Package [{STALKER}]".encode() in raw
    assert f"Package [{STALKER}]".encode() not in _database_bytes()
    assert actions == ["scan_saved", "evidence_preserved"]


def test_no_evidence_copy_unless_asked(app, phone):  # noqa: F811
    _, scanid, result = _scan(app, preserve=False)
    with app.app_context():
        assert evidence.evidence_for_scan(scanid) is None
    assert "evidence_sha256" not in result


def test_scan_without_a_dump_records_that_none_was_kept(app, client, no_csrf):
    c = app.test_client()
    with c.session_transaction() as s:
        s["clientid"] = cid = f"ev_{uuid.uuid4().hex[:8]}"
    r = c.post(
        "/scan",
        data={
            "device": "test",
            "device_owner": "o",
            "devid": "testdevice1",
            "preserve_evidence": "1",
        },
    )
    assert r.status_code == 200
    with app.app_context():
        assert "evidence_unavailable" in [e["action"] for e in audit.entries(cid)]


def test_package_contents_and_verification(app, kept, tmp_path):
    clientid, scanid, result = kept
    out = tmp_path / "package"
    with app.app_context():
        evidence.export_package(scanid, out, _public())
    names = sorted(p.name for p in out.iterdir())
    assert names == [
        "audit.json",
        "manifest.json",
        "manifest.sig",
        "results.json",
        f"scan-{scanid}-android.txt",
    ]
    assert stat.S_IMODE(out.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in out.iterdir())

    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["scan"]["operator"] == "Test Operator"
    assert manifest["exported_by"] == "Test Operator"
    assert manifest["raw_dump"]["sha256_recorded_at_scan"] == result["evidence_sha256"]
    dump = (out / f"scan-{scanid}-android.txt").read_bytes()
    assert evidence._sha256(dump) == result["evidence_sha256"]
    results = json.loads((out / "results.json").read_text())
    assert results["scan"]["device_model"] == "Pixel 8"
    trail = json.loads((out / "audit.json").read_text())
    assert [e["action"] for e in trail["entries"]] == [
        "scan_saved",
        "evidence_preserved",
    ]

    v = evidence.verify(out)
    assert v == {
        "ok": True,
        "fingerprint": crypto.fingerprint(_public()),
        "problems": [],
    }
    with app.app_context():
        assert audit.entries(clientid)[-1]["action"] == "evidence_exported"
        assert audit.verify()["ok"]


@pytest.mark.parametrize(
    "tamper, problem",
    [
        (lambda d: (d / "results.json").write_text("{}"), "results.json was changed"),
        (lambda d: (d / "audit.json").unlink(), "audit.json is missing"),
        (
            lambda d: (d / "extra.txt").write_text("x"),
            "extra.txt is not part of the package",
        ),
        (
            lambda d: (d / "manifest.json").write_text(
                (d / "manifest.json").read_text().replace("Test Operator", "Someone")
            ),
            "manifest.json does not match its signature",
        ),
    ],
)
def test_changed_packages_fail_verification(app, kept, tmp_path, tamper, problem):
    _, scanid, _ = kept
    out = tmp_path / "package"
    with app.app_context():
        evidence.export_package(scanid, out, _public())
    tamper(out)
    v = evidence.verify(out)
    assert not v["ok"] and problem in v["problems"]


def test_a_package_resigned_with_another_key_shows_another_fingerprint(
    app, kept, tmp_path
):
    """Anyone can sign with a key of their own; the fingerprint tells whose
    key it was, so it must be compared with the clinic's."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    _, scanid, _ = kept
    out = tmp_path / "package"
    with app.app_context():
        evidence.export_package(scanid, out, _public())
    other = Ed25519PrivateKey.generate()
    data = (out / "manifest.json").read_bytes()
    pub = other.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    (out / "manifest.sig").write_text(
        json.dumps(
            {
                "algorithm": "Ed25519",
                "public_key": base64.b64encode(pub).decode(),
                "signature": base64.b64encode(other.sign(data)).decode(),
            }
        )
    )
    v = evidence.verify(out)
    assert v["ok"] and v["fingerprint"] != crypto.fingerprint(_public())


def test_export_refuses_a_stored_dump_that_no_longer_matches_its_hash(
    app, kept, tmp_path
):
    _, scanid, _ = kept
    with app.app_context():
        db.get_db().execute(
            "UPDATE evidence SET data=? WHERE scanid=?",
            (crypto.encrypt("data", base64.b64encode(b"altered").decode()), scanid),
        )
        with pytest.raises(ValueError, match="does not match its recorded hash"):
            evidence.export_package(scanid, tmp_path / "p", _public())


def test_erasing_a_client_or_device_deletes_its_evidence(
    app, phone, client, no_csrf
):  # noqa: F811
    cid, scanid, _ = _scan(app, preserve=True)
    with app.app_context():
        assert db.erase_client(cid)["evidence"] == 1
        assert evidence.evidence_for_scan(scanid) is None
    cid, scanid, _ = _scan(app, preserve=True)
    client.post("/delete_device", data={"serial": get_config().hmac_serial(SERIAL)})
    with app.app_context():
        assert evidence.evidence_for_scan(scanid) is None


@pytest.fixture
def cli(monkeypatch, passphrase):
    from isdi import cli as cli_mod

    monkeypatch.setenv("ISDI_PASSPHRASE", passphrase)
    return lambda *a, **kw: CliRunner().invoke(cli_mod.cli, list(a), **kw)


def test_cli_evidence_export_and_verify(app, kept, cli, tmp_path, monkeypatch):
    _, scanid, _ = kept
    out = tmp_path / "pkg"
    res = cli("evidence", "export", str(scanid), "-o", str(out))
    assert res.exit_code == 0, res.output
    fp = crypto.fingerprint(_public())
    assert fp in res.output

    monkeypatch.delenv("ISDI_PASSPHRASE")  # verifying needs no passphrase
    res = cli("verify", str(out))
    assert res.exit_code == 0 and fp in res.output and "✓" in res.output
    (out / "results.json").write_text("{}")
    res = cli("verify", str(out))
    assert res.exit_code == 1 and "results.json was changed" in res.output


def test_cli_client_export_is_signed(app, kept, cli, tmp_path):
    clientid, _, _ = kept
    out = tmp_path / "client.json"
    res = cli("export", clientid, "-o", str(out))
    assert res.exit_code == 0, res.output
    assert Path(str(out) + ".sig").exists()
    assert cli("verify", str(out)).exit_code == 0
    out.write_text(out.read_text().replace("Owner", "Other"))
    res = cli("verify", str(out))
    assert res.exit_code == 1 and "does not match its signature" in res.output


def test_cli_signing_key_shows_the_fingerprint(cli):
    res = cli("signing-key")
    assert res.exit_code == 0 and crypto.fingerprint(_public()) in res.output


def test_keyfiles_from_before_signing_get_a_key_at_unlock(tmp_path):
    saved = crypto._state()
    try:
        keyfile = tmp_path / "datakey.json"
        crypto.setup(keyfile, "a long passphrase")
        data = json.loads(keyfile.read_text())
        del data["signing_key"], data["signing_public_key"]
        keyfile.write_text(json.dumps(data))
        crypto.lock()
        crypto.unlock(keyfile, passphrase="a long passphrase")
        public = crypto.public_key(keyfile)
        assert crypto.verify_signature(public, b"x", crypto.sign(b"x"))
        assert stat.S_IMODE(os.stat(keyfile).st_mode) == 0o600
    finally:
        crypto._restore(saved)


ACCOUNT = "survivor.account@example.com"


@pytest.fixture
def phone_with_account(tmp_path, monkeypatch, phone):  # noqa: F811
    """The fake phone, with a signed-in account in its dumpsys output."""
    from tests.test_scanner_pipeline import FAKE_ADB, _fake_tool

    body = FAKE_ADB.replace(
        'sys.stdout.write("x=1\\n" * 400)',
        f'sys.stdout.write("  Account {{name={ACCOUNT}, type=com.google}}\\n"'
        ' + "x=1\\n" * 400)',
    )
    assert body != FAKE_ADB
    monkeypatch.setattr(phone, "cli", _fake_tool(tmp_path, "adb2", body))
    return phone


def _scan_unredacted(app, unredacted):
    from isdi.web.view import scan as scan_view

    clientid = f"ev_{uuid.uuid4().hex[:8]}"
    with app.test_request_context():
        result, status = scan_view._run_live_scan(
            clientid,
            "android",
            "Owner",
            SERIAL,
            preserve=True,
            unredacted=unredacted,
        )
    assert status == 200
    return clientid, result["scanid"]


def test_evidence_copies_are_redacted_unless_asked(app, phone_with_account):
    _, scanid = _scan_unredacted(app, unredacted=False)
    with app.app_context():
        row = evidence.evidence_for_scan(scanid)
    assert row["unredacted"] == 0
    raw = base64.b64decode(row["data"])
    assert ACCOUNT.encode() not in raw and b"<email>" in raw


def test_unredacted_evidence_copy_keeps_the_output_as_received(
    app, phone_with_account, tmp_path
):
    clientid, scanid = _scan_unredacted(app, unredacted=True)
    assert _phone_dump_files() == [], "no dump file, redacted or not, may remain"
    assert ACCOUNT.encode() not in _database_bytes()
    with app.app_context():
        row = evidence.evidence_for_scan(scanid)
        listed = evidence.list_evidence(clientid)
        kept = [
            e for e in audit.entries(clientid) if e["action"] == "evidence_preserved"
        ]
        evidence.export_package(scanid, tmp_path / "pkg", _public())
    assert row["unredacted"] == 1 and listed[0]["unredacted"] == 1
    assert row["dump_name"] == "android-unredacted.txt"
    raw = base64.b64decode(row["data"])
    assert ACCOUNT.encode() in raw and b"<email>" not in raw
    assert kept[0]["details"]["unredacted"] is True

    manifest = json.loads((tmp_path / "pkg" / "manifest.json").read_text())
    assert manifest["raw_dump"]["unredacted"] is True
    assert "unredacted" in manifest["raw_dump"]["note"]
    assert (tmp_path / "pkg" / f"scan-{scanid}-android-unredacted.txt").exists()
    assert evidence.verify(tmp_path / "pkg")["ok"]


def test_unredacted_without_an_evidence_copy_keeps_nothing(app, phone_with_account):
    from isdi.web.view import scan as scan_view

    with app.test_request_context():
        result, _ = scan_view._run_live_scan(
            f"ev_{uuid.uuid4().hex[:8]}",
            "android",
            "Owner",
            SERIAL,
            preserve=False,
            unredacted=True,
        )
    assert _phone_dump_files() == []
    assert phone_with_account.unredacted_serials == set()
    with app.app_context():
        assert evidence.evidence_for_scan(result["scanid"]) is None


def test_the_unredacted_dump_only_exists_during_the_scan(
    app, phone_with_account, monkeypatch
):
    from isdi.scanner import blocklist, raw_path

    seen = []
    real = blocklist.app_title_and_flag

    def spy(*a, **k):
        seen.append(os.path.exists(raw_path(phone_with_account.dump_path(SERIAL))))
        return real(*a, **k)

    monkeypatch.setattr(blocklist, "app_title_and_flag", spy)
    _scan_unredacted(app, unredacted=True)
    assert seen and all(seen)
    assert _phone_dump_files() == []
