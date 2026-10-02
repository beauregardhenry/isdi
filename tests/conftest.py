import os
import shutil
import tempfile
from pathlib import Path

import pytest

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

from isdi.config import get_config  # noqa: E402

get_config("test")


def pytest_sessionfinish(session, exitstatus):
    shutil.rmtree(_TMP, ignore_errors=True)


@pytest.fixture(scope="session")
def app():
    """One app for the whole run; creating it initialises the test database."""
    from isdi.app import create_app

    app = create_app(get_config("test"))
    app.config["TESTING"] = True
    return app


@pytest.fixture
def client(app):
    c = app.test_client()
    with c.session_transaction() as s:
        s["clientid"] = "20260101_001"
    return c


@pytest.fixture
def no_csrf(app, monkeypatch):
    """For tests of a route's own logic; CSRF itself is covered separately."""
    monkeypatch.setitem(app.config, "WTF_CSRF_ENABLED", False)
