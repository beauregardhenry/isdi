"""The data key, the passphrase and recovery key that unlock it, and value
encryption."""

import json
import stat

import pytest

from isdi import crypto


@pytest.fixture
def keyfile(tmp_path):
    """A separate keyfile; the suite's own keys are restored afterwards."""
    saved = (crypto._data_key, crypto._pii_key)
    yield tmp_path / "datakey.json"
    crypto._set_keys(*saved)


def test_setup_unlock_and_round_trip(keyfile):
    recovery = crypto.setup(keyfile, "a long passphrase")
    token = crypto.encrypt("general_notes", "client said X")
    assert token.startswith("enc1:") and "client said X" not in token
    crypto.lock()
    with pytest.raises(crypto.LockedError):
        crypto.decrypt("general_notes", token)
    crypto.unlock(keyfile, passphrase="a long passphrase")
    assert crypto.decrypt("general_notes", token) == "client said X"
    crypto.lock()
    crypto.unlock(keyfile, recovery_key=recovery.lower().replace("-", " "))
    assert crypto.decrypt("general_notes", token) == "client said X"


def test_values_keep_their_type_and_none_stays_none(keyfile):
    crypto.setup(keyfile, "a long passphrase")
    for value in (0, 3, "", "text", ["a", "b"], {"k": 1}, True):
        assert crypto.decrypt("c", crypto.encrypt("c", value)) == value
    assert crypto.encrypt("c", None) is None


def test_same_value_encrypts_differently_each_time(keyfile):
    crypto.setup(keyfile, "a long passphrase")
    assert crypto.encrypt("c", "same") != crypto.encrypt("c", "same")


def test_value_cannot_be_moved_to_another_column(keyfile):
    crypto.setup(keyfile, "a long passphrase")
    token = crypto.encrypt("device_primary_user", "Jane")
    with pytest.raises(ValueError, match="cannot decrypt"):
        crypto.decrypt("general_notes", token)


def test_tampered_value_is_rejected(keyfile):
    crypto.setup(keyfile, "a long passphrase")
    token = crypto.encrypt("c", "value")
    body = token[len(crypto.PREFIX) :]
    flipped = body[:-2] + ("A" if body[-2] != "A" else "B") + body[-1]
    with pytest.raises(ValueError):
        crypto.decrypt("c", crypto.PREFIX + flipped)


def test_plaintext_from_before_encryption_reads_unchanged(keyfile):
    crypto.setup(keyfile, "a long passphrase")
    assert crypto.decrypt("c", "old plaintext") == "old plaintext"
    assert crypto.decrypt("c", 5) == 5


def test_wrong_passphrase_or_recovery_key(keyfile):
    crypto.setup(keyfile, "a long passphrase")
    with pytest.raises(crypto.UnlockError):
        crypto.unlock(keyfile, passphrase="not the passphrase")
    with pytest.raises(crypto.UnlockError):
        crypto.unlock(keyfile, recovery_key=crypto.new_recovery_key())


def test_short_passphrase_is_refused(keyfile):
    with pytest.raises(ValueError, match="at least"):
        crypto.setup(keyfile, "short")
    assert not keyfile.exists()


def test_change_passphrase_keeps_data_and_recovery_key(keyfile):
    recovery = crypto.setup(keyfile, "a long passphrase")
    token = crypto.encrypt("c", "kept")
    crypto.change_passphrase(
        keyfile, "another long one", passphrase="a long passphrase"
    )
    with pytest.raises(crypto.UnlockError):
        crypto.unlock(keyfile, passphrase="a long passphrase")
    crypto.unlock(keyfile, passphrase="another long one")
    assert crypto.decrypt("c", token) == "kept"
    crypto.change_passphrase(keyfile, "third long phrase", recovery_key=recovery)
    crypto.unlock(keyfile, passphrase="third long phrase")
    assert crypto.decrypt("c", token) == "kept"


def test_keyfile_is_private_and_holds_no_key_in_the_clear(keyfile):
    legacy_pii_key = b"\x01" * 32
    crypto.setup(keyfile, "a long passphrase", pii_key=legacy_pii_key)
    assert stat.S_IMODE(keyfile.stat().st_mode) == 0o600
    raw = keyfile.read_bytes()
    assert crypto._data_key not in raw and legacy_pii_key not in raw
    data = json.loads(raw)
    assert data["cipher"] == "AES-256-GCM"
    assert data["passphrase"]["kdf"]["name"] == "scrypt"
    # An existing pseudonymisation key is kept, so stored serials still match.
    assert crypto.pii_key() == legacy_pii_key


def test_production_scrypt_cost_is_strong():
    """The suite lowers it for speed; the shipped default must not be."""
    import ast
    import inspect

    shipped = {
        node.targets[0].id: eval(compile(ast.Expression(node.value), "", "eval"), {})
        for node in ast.parse(inspect.getsource(crypto)).body
        if isinstance(node, ast.Assign)
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id in ("SCRYPT_N", "SCRYPT_R")
    }
    assert shipped["SCRYPT_N"] >= 2**17 and shipped["SCRYPT_R"] >= 8


def test_setup_refuses_to_overwrite_a_keyfile(keyfile):
    crypto.setup(keyfile, "a long passphrase")
    with pytest.raises(FileExistsError):
        crypto.setup(keyfile, "a long passphrase")
