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
