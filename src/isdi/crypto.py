"""Encryption at rest for client data.

All client data in the database is encrypted with one random 256-bit data
key (AES-256-GCM). The data key is never stored in the clear: the keyfile
(config directory, 0600) holds it twice, each copy encrypted with a key
derived by scrypt from

- the operator's passphrase, asked for when ISDi starts, and
- a recovery key, shown once at setup, for when the passphrase is lost.

Without one of the two, the data cannot be read; there is no back door.
The keyfile also holds the HMAC key that pseudonymises device serials,
encrypted with the data key.

Encrypted values are stored as text: "enc1:" + base64(nonce || ciphertext
|| tag). The column name is authenticated with each value (AES-GCM
associated data), so a value cannot be moved to another column unnoticed.
"""

import base64
import json
import os
import secrets
from pathlib import Path
from typing import Any, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

PREFIX = "enc1:"
KEYFILE_VERSION = 1
MIN_PASSPHRASE_LENGTH = 12
# scrypt cost (2**17, r=8: about 128 MiB and half a second per unlock).
# Stored in the keyfile, so it can be raised later without breaking unlock.
SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1

_data_key: Optional[bytes] = None
_pii_key: Optional[bytes] = None


class LockedError(RuntimeError):
    """Client data was read or written before the data key was unlocked."""


class UnlockError(ValueError):
    """Wrong passphrase or recovery key, or a damaged keyfile."""


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _unb64(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"), validate=True)


def _derive(secret: str, kdf: dict) -> bytes:
    return Scrypt(
        salt=_unb64(kdf["salt"]), length=32, n=kdf["n"], r=kdf["r"], p=kdf["p"]
    ).derive(secret.encode("utf-8"))


def _new_kdf() -> dict:
    return {
        "name": "scrypt",
        "salt": _b64(os.urandom(16)),
        "n": SCRYPT_N,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
    }


def _seal(key: bytes, plaintext: bytes, label: bytes) -> str:
    nonce = os.urandom(12)
    return _b64(nonce + AESGCM(key).encrypt(nonce, plaintext, label))


def _open(key: bytes, blob: str, label: bytes) -> bytes:
    raw = _unb64(blob)
    return AESGCM(key).decrypt(raw[:12], raw[12:], label)


def _wrap(secret: str, data_key: bytes) -> dict:
    kdf = _new_kdf()
    return {"kdf": kdf, "key": _seal(_derive(secret, kdf), data_key, b"isdi-data-key")}


def _unwrap(secret: str, wrapped: dict) -> bytes:
    try:
        return _open(_derive(secret, wrapped["kdf"]), wrapped["key"], b"isdi-data-key")
    except (InvalidTag, KeyError, ValueError) as e:
        raise UnlockError("wrong passphrase or recovery key") from e


def new_recovery_key() -> str:
    """160 random bits, as eight groups of four base32 characters."""
    raw = base64.b32encode(secrets.token_bytes(20)).decode("ascii")
    return "-".join(raw[i : i + 4] for i in range(0, len(raw), 4))


def _normalise_recovery_key(key: str) -> str:
    raw = key.replace("-", "").replace(" ", "").upper()
    return "-".join(raw[i : i + 4] for i in range(0, len(raw), 4))


def check_passphrase(passphrase: str) -> None:
    if len(passphrase) < MIN_PASSPHRASE_LENGTH:
        raise ValueError(
            f"The passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters."
        )


def _write_keyfile(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def _read_keyfile(path: Path) -> dict:
    data = json.loads(Path(path).read_text())
    if data.get("version") != KEYFILE_VERSION:
        raise UnlockError(f"unsupported keyfile version {data.get('version')!r}")
    return data


def is_set_up(path: Path) -> bool:
    return Path(path).exists()


def setup(path: Path, passphrase: str, pii_key: Optional[bytes] = None) -> str:
    """Create the keyfile and unlock. Returns the recovery key, which must
    be shown to the operator: it is not stored anywhere.

    pii_key: an existing serial-pseudonymisation key to keep (so stored
    pseudonyms still match); a new one is made otherwise."""
    if is_set_up(path):
        raise FileExistsError(f"{path} already exists")
    check_passphrase(passphrase)
    data_key = AESGCM.generate_key(bit_length=256)
    pii_key = pii_key or secrets.token_bytes(32)
    recovery = new_recovery_key()
    _write_keyfile(
        Path(path),
        {
            "version": KEYFILE_VERSION,
            "cipher": "AES-256-GCM",
            "passphrase": _wrap(passphrase, data_key),
            "recovery": _wrap(recovery, data_key),
            "pii_key": _seal(data_key, pii_key, b"isdi-pii-key"),
        },
    )
    _set_keys(data_key, pii_key)
    return recovery


def unlock(
    path: Path, passphrase: Optional[str] = None, recovery_key: Optional[str] = None
) -> None:
    data = _read_keyfile(path)
    if passphrase is not None:
        data_key = _unwrap(passphrase, data["passphrase"])
    elif recovery_key is not None:
        data_key = _unwrap(_normalise_recovery_key(recovery_key), data["recovery"])
    else:
        raise UnlockError("a passphrase or the recovery key is needed")
    try:
        pii_key = _open(data_key, data["pii_key"], b"isdi-pii-key")
    except InvalidTag as e:
        raise UnlockError("the keyfile is damaged") from e
    _set_keys(data_key, pii_key)


def change_passphrase(
    path: Path,
    new_passphrase: str,
    passphrase: Optional[str] = None,
    recovery_key: Optional[str] = None,
) -> None:
    """Re-wrap the data key with a new passphrase. The data itself is not
    re-encrypted, and the recovery key stays valid."""
    check_passphrase(new_passphrase)
    unlock(path, passphrase=passphrase, recovery_key=recovery_key)
    data = _read_keyfile(path)
    data["passphrase"] = _wrap(new_passphrase, _data_key)
    _write_keyfile(Path(path), data)


def _set_keys(data_key: bytes, pii_key: bytes) -> None:
    global _data_key, _pii_key
    _data_key, _pii_key = data_key, pii_key


def lock() -> None:
    _set_keys(None, None)


def is_unlocked() -> bool:
    return _data_key is not None


def pii_key() -> bytes:
    if _pii_key is None:
        raise LockedError("ISDi is locked: unlock it with the passphrase first")
    return _pii_key


def encrypt(column: str, value: Any) -> Optional[str]:
    """Encrypt a value (any JSON type) for the given column. None stays None
    so that missing values stay missing."""
    if value is None:
        return None
    if _data_key is None:
        raise LockedError("ISDi is locked: unlock it with the passphrase first")
    plaintext = json.dumps(value).encode("utf-8")
    return PREFIX + _seal(_data_key, plaintext, column.encode("utf-8"))


def is_encrypted(value: Any) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)


def decrypt(column: str, value: Any) -> Any:
    """Decrypt a value stored by encrypt(). Anything else (None, ids,
    plaintext from before encryption was added) is returned unchanged."""
    if not is_encrypted(value):
        return value
    if _data_key is None:
        raise LockedError("ISDi is locked: unlock it with the passphrase first")
    try:
        plaintext = _open(_data_key, value[len(PREFIX) :], column.encode("utf-8"))
    except InvalidTag as e:
        raise ValueError(f"cannot decrypt {column}: wrong key or altered data") from e
    return json.loads(plaintext)
