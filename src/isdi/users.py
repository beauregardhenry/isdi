"""Staff accounts for the web interface.

Each person who uses ISDi signs in with their own username and password,
so the audit log records who did what (HIPAA's unique user
identification, 45 CFR 164.312(a)(2)(i)), and a session ends after a
period of inactivity (automatic logoff, 164.312(a)(2)(iii)).

Accounts are managed from the command line (`isdi user ...`) by whoever
holds the passphrase; there is no administrator role in the web interface.

Roles decide which clients an account can open:
- staff: only the clients it started (client_access);
- supervisor: every client.

- Passwords are hashed with scrypt and a random salt; only the hash is
  stored. They must be at least 12 characters, like the passphrase.
- After MAX_FAILED wrong passwords in a row, the account is locked for
  LOCKOUT_MINUTES.
- Disabling an account ends its sessions at their next request.
- The account's full name is encrypted like client data; the username is
  not, since signing in looks it up.
"""

import hashlib
import hmac
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from isdi import crypto

# scrypt cost for password hashes (~32 MB, about 0.1 s): each sign-in
# pays it once. Tests lower it.
PASSWORD_SCRYPT_N = 2**15
MAX_FAILED = 5
LOCKOUT_MINUTES = 15
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,31}$")


STAFF, SUPERVISOR = "staff", "supervisor"
ROLES = (STAFF, SUPERVISOR)


class AccountError(ValueError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(t: datetime) -> str:
    return t.isoformat(timespec="seconds")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    n, r, p = PASSWORD_SCRYPT_N, 8, 1
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=n, r=r, p=p, maxmem=2**27, dklen=32
    )
    return f"scrypt${n}${r}${p}${salt.hex()}${digest.hex()}"


def _password_matches(password: str, stored: str) -> bool:
    _, n, r, p, salt, digest = stored.split("$")
    got = hashlib.scrypt(
        password.encode("utf-8"),
        salt=bytes.fromhex(salt),
        n=int(n),
        r=int(r),
        p=int(p),
        maxmem=2**27,
        dklen=32,
    )
    return hmac.compare_digest(got.hex(), digest)


# Checked against when the username is unknown, so that a wrong username
# takes as long as a wrong password.
_DUMMY_HASH = None


def _dummy_hash() -> str:
    global _DUMMY_HASH
    if _DUMMY_HASH is None or int(_DUMMY_HASH.split("$")[1]) != PASSWORD_SCRYPT_N:
        _DUMMY_HASH = hash_password(secrets.token_hex(16))
    return _DUMMY_HASH


def check_password(password: str) -> None:
    try:
        crypto.check_passphrase(password)
    except ValueError:
        raise AccountError(
            f"The password must be at least {crypto.MIN_PASSPHRASE_LENGTH} "
            "characters."
        )


def check_username(username: str) -> str:
    username = (username or "").strip().lower()
    if not USERNAME_RE.match(username):
        raise AccountError(
            "A username is 2 to 32 characters: lowercase letters, digits, "
            "dots, dashes and underscores, starting with a letter or digit."
        )
    return username


def _db():
    from isdi.scanner.db import get_db

    return get_db()


def get(user_id) -> Optional[dict]:
    from isdi.scanner.db import query_db

    return query_db("SELECT * FROM users WHERE id=?", (user_id,), one=True)


def by_username(username: str) -> Optional[dict]:
    from isdi.scanner.db import query_db

    return query_db(
        "SELECT * FROM users WHERE username=?",
        ((username or "").strip().lower(),),
        one=True,
    )


def list_users() -> list:
    from isdi.scanner.db import query_db

    return query_db(
        "SELECT id, username, name, role, disabled, locked_until, created, "
        "last_login FROM users ORDER BY username"
    )


def count() -> int:
    return _db().execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]


def session_token(user: dict) -> str:
    """Kept in a signed-in session: changes whenever the password does (the
    hash has a new salt each time), which ends the account's other
    sessions. A hash of the hash, so the cookie does not carry it."""
    return hashlib.sha256(user["password_hash"].encode()).hexdigest()[:32]


def label(user: dict) -> str:
    """How the audit log and scans name a user: "Full Name (username)"."""
    return f"{user['name']} ({user['username']})"


def create(username: str, name: str, password: str, role: str = STAFF) -> dict:
    from isdi import audit

    check_role(role)
    username = check_username(username)
    name = (name or "").strip()
    if not name:
        raise AccountError("Give the person's full name.")
    check_password(password)
    if by_username(username):
        raise AccountError(f"There is already an account {username!r}.")
    db = _db()
    now = _iso(_now())
    db.execute(
        "INSERT INTO users (username, name, password_hash, created, "
        "password_changed, role) VALUES (?,?,?,?,?,?)",
        (
            username,
            crypto.encrypt("name", name),
            hash_password(password),
            now,
            now,
            role,
        ),
    )
    db.commit()
    audit.record("user_created", details={"username": username, "role": role})
    return by_username(username)


def require(username: str) -> dict:
    user = by_username(username)
    if not user:
        raise AccountError(f"There is no account {username!r}.")
    return user


def set_password(username: str, password: str) -> None:
    from isdi import audit

    user = require(username)
    check_password(password)
    db = _db()
    db.execute(
        "UPDATE users SET password_hash=?, password_changed=?, failed_attempts=0, "
        "locked_until=NULL WHERE id=?",
        (hash_password(password), _iso(_now()), user["id"]),
    )
    db.commit()
    audit.record("password_changed", details={"username": user["username"]})


def set_disabled(username: str, disabled: bool) -> None:
    from isdi import audit

    user = require(username)
    db = _db()
    db.execute(
        "UPDATE users SET disabled=?, failed_attempts=0, locked_until=NULL "
        "WHERE id=?",
        (int(disabled), user["id"]),
    )
    db.commit()
    audit.record(
        "user_disabled" if disabled else "user_enabled",
        details={"username": user["username"]},
    )


def sign_out_everywhere(user_id: int, at: float) -> None:
    """End every session of this account begun before `at` (the session
    cookie itself cannot be revoked, so the server keeps this time)."""
    db = _db()
    db.execute("UPDATE users SET signed_out_at=? WHERE id=?", (at, user_id))
    db.commit()


def check_role(role: str) -> None:
    if role not in ROLES:
        raise AccountError(f"A role is {' or '.join(ROLES)}.")


def set_role(username: str, role: str) -> None:
    from isdi import audit

    check_role(role)
    user = require(username)
    db = _db()
    db.execute("UPDATE users SET role=? WHERE id=?", (role, user["id"]))
    db.commit()
    audit.record(
        "user_role_changed",
        details={"username": user["username"], "role": [user["role"], role]},
    )


def grant(user_id: int, clientid: str) -> None:
    """Let a staff account open a client (one it started)."""
    db = _db()
    db.execute(
        "INSERT OR IGNORE INTO client_access (user_id, clientid, granted) "
        "VALUES (?,?,?)",
        (user_id, clientid, _iso(_now())),
    )
    db.commit()


def can_open(user: dict, clientid: str) -> bool:
    if user["role"] == SUPERVISOR:
        return True
    row = (
        _db()
        .execute(
            "SELECT 1 FROM client_access WHERE user_id=? AND clientid=?",
            (user["id"], clientid),
        )
        .fetchone()
    )
    return row is not None


def is_locked(user: dict, now: Optional[datetime] = None) -> bool:
    until = user.get("locked_until")
    return bool(until) and datetime.fromisoformat(until) > (now or _now())


def authenticate(username: str, password: str) -> Tuple[Optional[dict], str]:
    """Check a sign-in. Returns (user, "ok") or (None, reason), where reason
    is "unknown", "disabled", "locked" or "wrong". Every attempt is
    recorded in the audit log."""
    from isdi import audit

    user = by_username(username)
    if not user:
        _password_matches(password, _dummy_hash())
        audit.record("login_failed", details={"reason": "unknown"})
        return None, "unknown"
    details = {"username": user["username"]}
    if user["disabled"]:
        audit.record("login_failed", details={**details, "reason": "disabled"})
        return None, "disabled"
    if is_locked(user):
        audit.record("login_failed", details={**details, "reason": "locked"})
        return None, "locked"
    db = _db()
    if not _password_matches(password, user["password_hash"]):
        failed = (user["failed_attempts"] or 0) + 1
        locked_until = None
        if failed >= MAX_FAILED:
            locked_until = _iso(_now() + timedelta(minutes=LOCKOUT_MINUTES))
            failed = 0
        db.execute(
            "UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
            (failed, locked_until, user["id"]),
        )
        db.commit()
        audit.record("login_failed", details={**details, "reason": "wrong"})
        if locked_until:
            audit.record("user_locked", details={**details, "until": locked_until})
        return None, "wrong"
    db.execute(
        "UPDATE users SET failed_attempts=0, locked_until=NULL, last_login=? "
        "WHERE id=?",
        (_iso(_now()), user["id"]),
    )
    db.commit()
    return get(user["id"]), "ok"
