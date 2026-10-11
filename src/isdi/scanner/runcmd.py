import io
import logging
import os
import re
import shlex
import subprocess
from typing import Dict, List, Optional, Sequence, Tuple

# Commands run without a shell (run_command takes an argument list). adb and
# pymobiledevice3 can still pass a value on to the phone's own shell, so
# anything coming from a request must match these before it is used.
# adb serials look like "R58M12ABCDE", "emulator-5554" or "192.168.1.5:5555";
# iOS UDIDs are hex, optionally with a dash. Android package names and iOS
# bundle ids are letters, digits, '_', '-' and '.'.
_SERIAL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:\-]{0,127}")
_APPID_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._\-]{0,254}")
_HMAC_SERIAL_RE = re.compile(r"[0-9a-f]{64}")


# Device serials are pseudonymised in the database; logs must not undo that.
# adb takes the serial after -s, pymobiledevice3 after --udid.
_DEVICE_ARG_RE = re.compile(r"(?<!\S)(-s|--udid)(\s+|=)(?:'[^']*'|\"[^\"]*\"|\S+)")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
# Request lines in the web server's access log: query strings carry serials
# and app ids (?serial=...&appId=...).
_QUERY_RE = re.compile(r"(\s/[^\s?\"]*)\?[^\s\"]*")


def redact(text: str) -> str:
    """Remove device serials (as command arguments or in request query
    strings) and email addresses."""
    text = _DEVICE_ARG_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}<device>", text)
    text = _QUERY_RE.sub(r"\1?<redacted>", text)
    return _EMAIL_RE.sub("<email>", text)


class RedactingFilter(logging.Filter):
    """Applied to ISDi's log handlers as a safety net for messages that
    still carry a command line or an email address."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact(record.getMessage())
        record.args = None
        return True


def is_valid_serial(serial) -> bool:
    return isinstance(serial, str) and _SERIAL_RE.fullmatch(serial) is not None


def is_valid_appid(appid) -> bool:
    return isinstance(appid, str) and _APPID_RE.fullmatch(appid) is not None


def is_valid_hmac_serial(serial) -> bool:
    """Serials stored in the database are hex HMAC-SHA256 digests."""
    return isinstance(serial, str) and _HMAC_SERIAL_RE.fullmatch(serial) is not None


_USB_PERMISSION = "insufficient permissions for device: user in plugdev group"


def catch_err(p: subprocess.Popen[bytes], cmd="", time=10) -> str:
    """Wait for a command and return its output, or "" if it failed (the
    error is logged, never returned: callers treat the result as the
    phone's output, so an error message would be stored as, say, the
    device model). p.returncode tells callers that need it why.

    Output is also treated as a failure when it is a short message saying
    "fail" or "error", or adb's USB-permission error."""
    try:
        p.wait(time)
        logging.debug("Returncode: %s", p.returncode)
        err = p.stderr.read().decode("utf-8") if p.stderr else ""
        out = p.stdout.read().decode("utf-8") if p.stdout else ""
        if _USB_PERMISSION in err or _USB_PERMISSION in out:
            logging.error(
                'adb has no permission for the phone: set "USB for file '
                'transfers" mode on the phone, or check the udev rules.'
            )
            return ""
        if p.returncode != 0:
            logging.warning(
                redact(
                    f"Error running {cmd!r}. Error ({p.returncode}): "
                    f"{err or 'no error output'}"
                )
            )
            return ""
        if len(out) <= 100 and re.search("(?i)(fail|error)", out):
            return ""
        # Device output is personal data: never log it.
        return out
    except Exception as ex:
        logging.error("Exception>>> %s", ex)
        return ""


_ENV_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")


def tool_argv(cli: str) -> Tuple[List[str], Dict[str, str]]:
    """Split a configured tool prefix ("adb", or "PYTHONPATH=... python -m
    pymobiledevice3") into its arguments and leading VAR=value settings.

    The prefix comes from ISDi's configuration, never from a request; it is
    split here so that no shell is needed to run it."""
    words = shlex.split(cli)
    env: Dict[str, str] = {}
    while words and _ENV_ASSIGNMENT.match(words[0]):
        name, _, value = words.pop(0).partition("=")
        env[name] = value
    return words, env


class _Failed:
    """Stands in for a process that could not be started."""

    def __init__(self, error: str):
        self.returncode = 127
        self.stdout = io.BytesIO(b"")
        self.stderr = io.BytesIO(error.encode())

    def wait(self, timeout=None):
        return self.returncode


def run_command(
    args: Sequence[str], nowait: bool = False, env: Optional[Dict[str, str]] = None
) -> subprocess.Popen[bytes]:
    """Run a program with these arguments, without a shell.

    Each argument reaches the program as it is: nothing is expanded, so a
    serial or app id cannot run anything on this computer. `env` adds to
    the environment. Unless nowait is set, the output is read and the
    process waited for; callers read p.stdout and p.stderr afterwards.
    A program that cannot be started gives returncode 127."""
    if isinstance(args, (str, bytes)) or not all(isinstance(a, str) for a in args):
        raise TypeError("run_command takes a list of string arguments, not a command line")
    shown = redact(shlex.join(args))
    try:
        p = subprocess.Popen(
            list(args),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, **env} if env else None,
        )
    except OSError as ex:
        logging.error("Could not run %r: %s", shown, ex)
        return _Failed(str(ex))  # type: ignore[return-value]
    if not nowait:
        # communicate() reads while waiting; wait() alone deadlocks once the
        # output fills the pipe. Callers read p.stdout/p.stderr afterwards.
        out, err = p.communicate()
        p.stdout, p.stderr = io.BytesIO(out), io.BytesIO(err)
        if p.returncode != 0:
            logging.error("Error running command: %r. returncode: %s", shown, p.returncode)
        else:
            logging.debug("Command %r executed successfully.", shown)
    return p
