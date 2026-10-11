"""The install instructions point at files that exist."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_brew_bundle_has_a_brewfile():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "brew bundle" in readme
    brewfile = (ROOT / "Brewfile").read_text(encoding="utf-8")
    assert 'cask "android-platform-tools"' in brewfile
    assert 'brew "pango"' in brewfile  # WeasyPrint, for PDF reports


def test_readme_documents_the_report_extra():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "isdi-scanner[report]" in readme
    assert "Consultation record" in readme
