"""Whether a newer ISDi release exists, so the home page warns only when
there is something to update to (a newer release may carry a newer
stalkerware list).

`isdi run` checks once, in the background, unless started with --offline.
It sends one HEAD request to GitHub's "latest release" address and reads
the tag it redirects to: no client data, no identifier of the clinic;
GitHub sees the computer's IP address and the time, as it does when
app-info.db is downloaded. If the check fails or is skipped, no warning is
shown.
"""

import logging
import re
import threading
import urllib.error
import urllib.request
from typing import Dict, Optional, Tuple

from isdi import __version__

LATEST_URL = "https://github.com/beauregardhenry/isdi/releases/latest"
TIMEOUT = 10.0
_TAG_RE = re.compile(r"/releases/tag/v?(\d+(?:\.\d+)*)/?$")

_lock = threading.Lock()
_status: Dict[str, Optional[str]] = {"latest": None}


def version_key(version: str) -> Tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # read the Location header instead of following it


def latest_release(timeout: float = TIMEOUT) -> Optional[str]:
    """The newest release's version ("1.9.1"), or None if GitHub could not
    be asked or answered something unexpected."""
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(LATEST_URL, method="HEAD")
    try:
        opener.open(request, timeout=timeout)
        return None  # no redirect: no release, or the page changed
    except urllib.error.HTTPError as e:
        if e.code not in (301, 302, 303, 307, 308):
            logging.info("Release check: HTTP %s", e.code)
            return None
        match = _TAG_RE.search(e.headers.get("Location", ""))
        return match.group(1) if match else None
    except Exception as e:
        logging.info("Release check failed (%s)", type(e).__name__)
        return None


def check() -> None:
    """Ask GitHub, and remember the answer for status()."""
    latest = latest_release()
    with _lock:
        _status["latest"] = latest


def start_check() -> threading.Thread:
    """check() in the background, so starting ISDi never waits on it."""
    thread = threading.Thread(target=check, name="isdi-release-check", daemon=True)
    thread.start()
    return thread


def newer_release(current: str = __version__) -> Optional[str]:
    """The newest release's version if it is newer than this copy, else
    None (also when no check was made or it failed)."""
    with _lock:
        latest = _status["latest"]
    if not latest:
        return None
    try:
        return latest if version_key(latest) > version_key(current) else None
    except ValueError:
        return None
