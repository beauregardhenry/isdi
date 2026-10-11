"""The check for a newer ISDi release (isdi/updates.py), against a local
server that answers the way GitHub's "latest release" address does."""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from isdi import updates


@pytest.fixture
def github(monkeypatch):
    """A local stand-in for github.com: set .status and .location."""

    class Handler(BaseHTTPRequestHandler):
        status, location, methods = 302, "", []

        def do_HEAD(self):
            Handler.methods.append(("HEAD", self.path))
            self.send_response(Handler.status)
            if Handler.location:
                self.send_header("Location", Handler.location)
            self.end_headers()

        def do_GET(self):  # following the redirect would land here
            Handler.methods.append(("GET", self.path))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_port}"
    monkeypatch.setattr(updates, "LATEST_URL", f"{base}/releases/latest")
    for var in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"):
        monkeypatch.delenv(var, raising=False)
    Handler.base = base
    yield Handler
    server.shutdown()


@pytest.mark.parametrize(
    "location, expected",
    [
        ("https://github.com/beauregardhenry/isdi/releases/tag/v2.0.1", "2.0.1"),
        ("/beauregardhenry/isdi/releases/tag/v1.10.0", "1.10.0"),
        ("https://github.com/beauregardhenry/isdi/releases", None),  # no release
        ("https://github.com/x/releases/tag/nightly", None),
    ],
)
def test_reads_the_tag_github_redirects_to(github, location, expected):
    github.location = location
    assert updates.latest_release() == expected
    # One HEAD request; the release page itself is never downloaded.
    assert github.methods == [("HEAD", "/releases/latest")]


@pytest.mark.parametrize("status", [200, 404, 500])
def test_anything_but_a_redirect_is_no_answer(github, status):
    github.status = status
    assert updates.latest_release() is None


def test_an_unreachable_github_is_no_answer(monkeypatch, caplog):
    caplog.set_level("INFO")
    monkeypatch.setattr(updates, "LATEST_URL", "http://127.0.0.1:9/releases/latest")
    for var in ("HTTP_PROXY", "http_proxy"):
        monkeypatch.delenv(var, raising=False)
    assert updates.latest_release(timeout=2) is None
    assert "Release check failed" in caplog.text


@pytest.mark.parametrize(
    "latest, current, newer",
    [
        ("1.9.1", "1.9.0", "1.9.1"),
        ("1.10.0", "1.9.0", "1.10.0"),  # numbers, not text: 10 > 9
        ("1.9.0", "1.9.0", None),
        ("1.8.1", "1.9.0", None),  # a development copy ahead of the release
        (None, "1.9.0", None),  # not checked, or the check failed
        ("1.9.x", "1.9.0", None),
    ],
)
def test_newer_release(monkeypatch, latest, current, newer):
    monkeypatch.setitem(updates._status, "latest", latest)
    assert updates.newer_release(current) == newer


def test_check_remembers_the_answer(github, monkeypatch):
    github.location = "/releases/tag/v99.0.0"
    updates.check()
    assert updates.newer_release("1.0.0") == "99.0.0"
