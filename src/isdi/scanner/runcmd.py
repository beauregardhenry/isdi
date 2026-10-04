import io
import re
import logging
import subprocess

# Device serials and app ids are interpolated into shell commands, so anything
# coming from a request must match these before it reaches run_command().
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


def catch_err(
    p: subprocess.Popen[bytes], cmd="", msg_on_err="", time=10, large_output=False
) -> str:
    """Wait for a command and return its output, or "" if it failed (the
    error is logged, never returned: callers treat the result as the
    phone's output, so an error message would be stored as, say, the
    device model). p.returncode tells callers that need it why."""
    try:
        large_output_var = b""
        if large_output:
            if p.stdout:
                for line in p.stdout:
                    large_output_var += line

        p.wait(time)
        logging.debug("Returncode: %s", p.returncode)
        if p.returncode != 0:

            if p.stderr:
                err_msg = p.stderr.read().decode("utf-8")
            else:
                err_msg = (
                    "stderr was none. This may indicate large issues with process."
                )

            m = "[{}]: Error running {!r}. Error ({}): {}\n{}".format(
                "android", cmd, p.returncode, err_msg, msg_on_err
            )
            if "insufficient permissions for device: user in plugdev group" in err_msg:
                e = 'Error: Please set "USB For File Transfers" mode on your Android device.'
                print(e)
                return ""
            logging.warning(redact(m))
            return ""
        else:
            if large_output:
                s = large_output_var.decode()
            else:
                if p.stdout:
                    s = p.stdout.read().decode()
                else:
                    return ""

            if (
                (len(s) <= 100 and re.search("(?i)(fail|error)", s))
                or "insufficient permissions for device: user in plugdev group; are your udev rules wrong?"
                in s
            ):
                # config.add_to_error(s)
                return ""
            if (
                "insufficient permissions for device: user in plugdev group; are your udev rules wrong?"
                in s
            ):
                logging.error("Need USB for Charging.")
                return ""
            else:
                # Device output is personal data: never log it.
                return s
    except Exception as ex:
        # config.add_to_error(ex)
        logging.error("Exception>>> %s", ex)
        return ""


def run_command(cmd: str, **kwargs) -> subprocess.Popen[bytes]:
    """
    Run a command in a subprocess.

    The command runs through the shell, so callers must shlex.quote() any
    value that did not come from this codebase (serials, app ids, ...).
    Args:
        cmd (str): The command to run.
        **kwargs: Additional keyword arguments to format the command.
    Returns:
        subprocess.Popen: The process object.
    """
    _cmd = cmd.format(**kwargs)
    p = subprocess.Popen(
        _cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
    )
    if not (kwargs.get("nowait", False) or kwargs.get("NOWAIT", False)):
        # communicate() reads while waiting; wait() alone deadlocks once the
        # output fills the pipe. Callers read p.stdout/p.stderr afterwards.
        out, err = p.communicate()
        p.stdout, p.stderr = io.BytesIO(out), io.BytesIO(err)
        if p.returncode != 0:
            logging.error(
                "Error running command: %r. returncode: %s", redact(_cmd), p.returncode
            )
        else:
            logging.debug("Command %r executed successfully.", redact(_cmd))
    return p
