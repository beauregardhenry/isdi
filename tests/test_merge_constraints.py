"""Release constraints: one file, with per-Python pins where the tested
versions differ."""

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "merge_constraints", ROOT / "scripts" / "merge_constraints.py"
)
mc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mc)


def test_same_versions_get_one_line_and_different_ones_get_markers():
    merged = mc.merge(
        {
            "3.10": {"flask": "3.1.3", "av": "14.0.0", "tomli": "2.0.1"},
            "3.12": {"flask": "3.1.3", "av": "19.0.1"},
            "3.11": {"flask": "3.1.3", "av": "18.1.0", "tomli": "2.0.1"},
        }
    )
    assert merged.splitlines() == [
        'av==14.0.0; python_version == "3.10"',
        'av==18.1.0; python_version == "3.11"',
        'av==19.0.1; python_version == "3.12"',
        "flask==3.1.3",
        'tomli==2.0.1; python_version == "3.10"',
        'tomli==2.0.1; python_version == "3.11"',
    ]


def test_names_are_normalised_and_unpinned_lines_refused():
    assert mc.read_freeze("# c\nTyping_Extensions==4.16.0\n\n") == {
        "typing-extensions": "4.16.0"
    }
    with pytest.raises(ValueError, match="not a pinned requirement"):
        mc.read_freeze("-e git+https://example.invalid/x\n")


def test_versions_sort_numerically(tmp_path):
    for py in ("3.9", "3.10"):
        (tmp_path / f"freeze-{py}.txt").write_text(f"x=={py}\n")
    out = tmp_path / "constraints.txt"
    mc.main(["x", str(out), *map(str, sorted(tmp_path.glob("freeze-*.txt")))])
    body = [line for line in out.read_text().splitlines() if not line.startswith("#")]
    assert body == [
        'x==3.9; python_version == "3.9"',
        'x==3.10; python_version == "3.10"',
    ]


def test_input_names_must_carry_the_python_version(tmp_path):
    bad = tmp_path / "freeze.txt"
    bad.write_text("x==1\n")
    with pytest.raises(SystemExit, match="expected freeze-"):
        mc.main(["x", str(tmp_path / "o.txt"), str(bad)])
