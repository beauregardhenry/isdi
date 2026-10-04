import os
import shutil
import tempfile
import time
from pathlib import Path

import pytest
from flask.testing import FlaskClient

# Keep the suite away from the user's real ISDi data: the database, phone
# dumps, reports and the PII key live under these directories. This must run
# before anything imports isdi, because modules create the config at import.
_TMP = Path(tempfile.mkdtemp(prefix="isdi-tests-"))
os.environ["XDG_DATA_HOME"] = str(_TMP / "data")
os.environ["XDG_CONFIG_HOME"] = str(_TMP / "config")
# The cache only holds the downloaded app-info.db (plus logs); keep it
# between runs so the database is not downloaded every time.
os.environ["XDG_CACHE_HOME"] = str(
    Path(__file__).resolve().parent.parent / ".pytest_cache" / "isdi"
)
os.environ.pop("PREFIX", None)  # Termux paths ignore the XDG variables

from isdi import crypto  # noqa: E402
from isdi.config import get_config  # noqa: E402

TEST_PASSPHRASE = "correct horse battery staple"
# Cheap key derivation, for speed only; the keyfile records the parameters.
crypto.SCRYPT_N = 2**10
crypto.setup(get_config("test").keyfile, TEST_PASSPHRASE)
TEST_OPERATOR = "Test Operator"
os.environ["ISDI_OPERATOR"] = TEST_OPERATOR

from isdi import audit  # noqa: E402

audit.set_operator(TEST_OPERATOR)


@pytest.fixture
def passphrase():
    """The test keyfile's passphrase."""
    return TEST_PASSPHRASE


def pytest_sessionfinish(session, exitstatus):
    shutil.rmtree(_TMP, ignore_errors=True)


from isdi import users  # noqa: E402

users.PASSWORD_SCRYPT_N = 2**10  # for speed only, like crypto.SCRYPT_N
TEST_USERNAME = "tester"
TEST_PASSWORD = "tester password 1234"


class SignedInClient(FlaskClient):
    """Test clients are signed in as TEST_USERNAME, unless created with
    app.test_client(signed_in=False)."""

    def __init__(self, *args, signed_in=True, **kwargs):
        super().__init__(*args, **kwargs)
        if signed_in:
            with self.application.app_context():
                user = users.by_username(TEST_USERNAME)
            with self.session_transaction() as s:
                s["user_id"] = user["id"]
                s["token"] = users.session_token(user)
                s["signed_in_at"] = s["last_seen"] = time.time()


@pytest.fixture(scope="session")
def app():
    """One app for the whole run; creating it initialises the test database."""
    from isdi.app import create_app

    app = create_app(get_config("test"))
    app.config["TESTING"] = True
    app.test_client_class = SignedInClient
    with app.app_context():
        if not users.by_username(TEST_USERNAME):
            users.create(
                TEST_USERNAME, TEST_OPERATOR, TEST_PASSWORD, role=users.SUPERVISOR
            )
    return app


@pytest.fixture
def client(app):
    c = app.test_client()
    with c.session_transaction() as s:
        s["clientid"] = "20260101_001"
    return c


@pytest.fixture
def client_of(app):
    """A signed-in test client working with a given client: scans are
    opened and changed only in their own client's session."""

    def make(clientid):
        c = app.test_client()
        with c.session_transaction() as s:
            s["clientid"] = clientid
        return c

    return make


@pytest.fixture
def no_csrf(app, monkeypatch):
    """For tests of a route's own logic; CSRF itself is covered separately."""
    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", False)
