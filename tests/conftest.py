import pytest

from isdi.config import get_config


@pytest.fixture(scope="session")
def app():
    """One app for the whole run: view modules register their routes on the
    first app only, so a second create_app() would have no routes."""
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
