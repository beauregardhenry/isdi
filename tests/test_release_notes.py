"""Release notes start with the version's CHANGELOG.md section."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "release_notes", ROOT / "scripts" / "release_notes.py"
)
release_notes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release_notes)

CHANGELOG = """# Changes

## 2.1.0

- New thing.
- Other thing.

## 2.0.0

- Old thing.
"""


def test_a_section_is_found_and_ends_at_the_next_one():
    notes = release_notes.section(CHANGELOG, "2.1.0")
    assert notes.startswith("## What changes for staff\n\n- New thing.")
    assert "Old thing" not in notes
    assert release_notes.section(CHANGELOG, "2.0.0").endswith("- Old thing.\n")


def test_missing_or_empty_sections_are_none():
    assert release_notes.section(CHANGELOG, "2.0.1") is None
    assert release_notes.section(CHANGELOG, "2.1") is None
    assert release_notes.section("## 3.0.0\n\n## 2.0.0\n- x\n", "3.0.0") is None


def test_the_script_exits_1_without_a_section(tmp_path, capsys):
    changelog = tmp_path / "CHANGELOG.md"
    changelog.write_text(CHANGELOG)
    assert release_notes.main(["x", "2.1.0", str(changelog)]) == 0
    assert "New thing" in capsys.readouterr().out
    assert release_notes.main(["x", "9.9.9", str(changelog)]) == 1


def test_the_changelog_has_the_released_versions():
    text = (ROOT / "CHANGELOG.md").read_text()
    for version in ("1.5.0", "1.6.0"):
        assert release_notes.section(text, version), version
