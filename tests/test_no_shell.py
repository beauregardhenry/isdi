"""Commands run without a shell.

Serials, app ids and file names used to be quoted into a command string run
with shell=True. One missed quote would let text from a phone or a request
run on the computer. Commands are now argument lists, so there is nothing
for a shell to interpret.
"""

import sys
from pathlib import Path

import pytest

from isdi.scanner import runcmd

SRC = Path(__file__).resolve().parent.parent / "src" / "isdi"


def test_no_module_runs_a_shell():
    offenders = [
        f"{p.relative_to(SRC)}:{n}"
        for p in SRC.rglob("*.py")
        for n, line in enumerate(p.read_text().splitlines(), 1)
        if "shell=True" in line.replace(" ", "")
    ]
    assert offenders == []


def test_arguments_reach_the_program_literally(tmp_path):
    marker = tmp_path / "marker"
    p = runcmd.run_command(
        [
            sys.executable,
            "-c",
            "import sys; print(sys.argv[1])",
            f"$(touch {marker}); `id`",
        ]
    )
    assert runcmd.catch_err(p).strip() == f"$(touch {marker}); `id`"
    assert not marker.exists()


def test_a_command_string_is_refused():
    with pytest.raises(TypeError):
        runcmd.run_command("adb devices")


def test_a_missing_program_is_a_failed_command():
    p = runcmd.run_command(["isdi-no-such-program-xyz"])
    assert p.returncode != 0
    assert runcmd.catch_err(p) == ""


def test_tool_prefix_is_split_into_arguments_and_environment():
    argv, env = runcmd.tool_argv(
        "PYTHONPATH='/a b/site-packages' /usr/bin/python3 -m isdi.scanner.pmd3_wrapper"
    )
    assert argv == ["/usr/bin/python3", "-m", "isdi.scanner.pmd3_wrapper"]
    assert env == {"PYTHONPATH": "/a b/site-packages"}
    assert runcmd.tool_argv("adb") == (["adb"], {})


def test_the_tool_environment_reaches_the_program():
    p = runcmd.run_command(
        [sys.executable, "-c", "import os; print(os.environ['ISDI_TEST_VAR'])"],
        env={"ISDI_TEST_VAR": "x y"},
    )
    assert runcmd.catch_err(p).strip() == "x y"


def test_the_privacy_check_sends_argument_lists(monkeypatch):
    from isdi.scanner import privacy_scan_android as ps

    assert ps.thiscli("A B") == [ps.adb, "-s", "A B"]
    assert ps.thiscli(None) == [ps.adb]
    out, err = ps.run_command(
        [
            sys.executable,
            "-c",
            "import sys; print('out'); print('err', file=sys.stderr)",
        ]
    )
    assert (out.strip(), err.strip()) == ("out", "err")
