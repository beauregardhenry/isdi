"""Running shell commands."""

import shlex


def test_run_command_does_not_hang_on_large_output():
    """Waiting before reading deadlocks once the output fills the pipe
    buffer (64 KiB on Linux): the child blocks writing, wait() never ends."""
    import sys
    import threading

    from isdi.scanner.runcmd import catch_err, run_command

    result = {}

    def go():
        cmd = "{py} -c {code}"
        p = run_command(
            cmd,
            py=shlex.quote(sys.executable),
            code=shlex.quote("print('x' * 300000)"),
        )
        result["out"] = catch_err(p, cmd=cmd)
        result["rc"] = p.returncode

    t = threading.Thread(target=go, daemon=True)
    t.start()
    t.join(20)
    assert not t.is_alive(), "run_command hung on a large output"
    assert result["rc"] == 0 and len(result["out"].strip()) == 300000


def test_a_failed_command_returns_no_output(caplog):
    """The error is logged, not returned as if the phone had said it."""
    import sys

    from isdi.scanner.runcmd import catch_err, run_command

    cmd = "{py} -c {code}"
    p = run_command(
        cmd,
        py=shlex.quote(sys.executable),
        code=shlex.quote("import sys; print('Pixel 8'); sys.exit(3)"),
    )
    assert catch_err(p, cmd=cmd) == ""
    assert p.returncode == 3
    assert "Error running" in caplog.text


def _proc(returncode=0, out=b"", err=b"", wait_error=None):
    import io

    class P:
        stdout, stderr = io.BytesIO(out), io.BytesIO(err)

        def wait(self, t):
            if wait_error:
                raise wait_error

    p = P()
    p.returncode = returncode
    return p


import pytest  # noqa: E402

from isdi.scanner.runcmd import catch_err  # noqa: E402

LONG_OUTPUT = "x" * 200 + " error somewhere in a long output"


@pytest.mark.parametrize(
    "proc, expected",
    [
        (_proc(out=b"package:com.example\n" * 10), "package:com.example\n" * 10),
        (_proc(returncode=1, out=b"partial", err=b"device offline"), ""),
        (_proc(out=b"Failure [DELETE_FAILED_INTERNAL_ERROR]"), ""),
        (_proc(out=b"Error: no device"), ""),
        (_proc(err=b"insufficient permissions for device: user in plugdev group"), ""),
        # Only short messages count as errors: long output may mention one.
        (_proc(out=LONG_OUTPUT.encode()), LONG_OUTPUT),
        (_proc(wait_error=OSError("gone")), ""),
    ],
)
def test_catch_err(proc, expected):
    assert catch_err(proc, cmd="adb x") == expected


def test_usb_permission_errors_explain_the_fix(caplog):
    catch_err(
        _proc(
            returncode=1,
            err=b"insufficient permissions for device: user in "
            b"plugdev group; are your udev rules wrong?",
        )
    )
    assert "USB for file transfers" in caplog.text


def test_failed_commands_log_the_error_not_the_output(caplog):
    catch_err(_proc(returncode=2, out=b"secret output", err=b"no such device"), cmd="c")
    assert "no such device" in caplog.text and "secret output" not in caplog.text
