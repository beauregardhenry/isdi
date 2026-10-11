"""The Spanish review packet (scripts/translation_review.py): it lists every
Spanish text, stays current, and writes a reviewer's corrections back."""

import csv
import importlib.util
import io
import shutil
from pathlib import Path

import pytest

from isdi import client_summary
from isdi.consultation import i18n

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "translation_review", ROOT / "scripts" / "translation_review.py"
)
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)

PACKET = ROOT / "docs" / "review" / "spanish-review.csv"


def _rows(root=ROOT):
    out = io.StringIO()
    review.export(root, out)
    return list(csv.DictReader(io.StringIO(out.getvalue())))


def test_the_packet_has_every_spanish_text():
    rows = _rows()
    es = client_summary.TEXT["es"]
    expected = len(i18n.ES) + sum(
        len(v) if isinstance(v, list) else 1 for v in es.values()
    )
    assert len(rows) == expected
    by_key = {(r["source"], r["key"]): r for r in rows}
    assert by_key[(str(review.I18N), "Notes")]["spanish"] == "Notas"
    assert by_key[(str(review.SUMMARY), "next[0]")] == {
        "source": str(review.SUMMARY),
        "key": "next[0]",
        "where": "Client summary and take-home copy",
        "english": client_summary.TEXT["en"]["next"][0],
        "spanish": es["next"][0],
        "suggested_spanish": "",
        "notes": "",
    }
    assert all(r["where"] and r["english"] and r["spanish"] for r in rows)


def test_the_committed_packet_is_current():
    out = io.StringIO()
    review.export(ROOT, out)
    assert PACKET.read_text(encoding="utf-8-sig") == out.getvalue(), (
        "Run: python scripts/translation_review.py export "
        "docs/review/spanish-review.csv"
    )
    assert PACKET.read_bytes().startswith(b"\xef\xbb\xbf")  # for Excel


@pytest.fixture
def copy(tmp_path):
    for source in (review.SUMMARY, review.I18N):
        (tmp_path / source).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / source, tmp_path / source)
    return tmp_path


def _suggest(rows, changes):
    for r in rows:
        if r["key"] in changes:
            r["suggested_spanish"] = changes[r["key"]]
    return rows


LONG_KEY = (
    "Someone who knows account passwords may be able to access and/or "
    "manipulate those accounts."
)


def test_corrections_are_written_back(copy):
    changes = {
        "Notes": "Apuntes",
        LONG_KEY: "Quien conoce las contraseñas de las cuentas podría entrar a "
        "ellas o cambiarlas, y también ver todo lo que hay en ellas sin que "
        "nadie lo sepa.",
        "next[0]": "Antes que nada, hable con su intercesor(a).",
        "staff_note": "<strong>Para el personal:</strong> solo en pantalla.",
        "checked_apps": "Las {n} aplicaciones de {phone}.",
    }
    changed, problems = review.apply(copy, _suggest(_rows(copy), changes))
    assert (changed, problems) == (len(changes), [])
    after = {r["key"]: r["spanish"] for r in _rows(copy)}
    for key, new in changes.items():
        assert after[key] == new
    # Everything else is as it was.
    before = {r["key"]: r["spanish"] for r in _rows()}
    assert {k: v for k, v in after.items() if k not in changes} == {
        k: v for k, v in before.items() if k not in changes
    }


def test_a_suggestion_equal_to_the_current_text_changes_nothing(copy):
    rows = _rows(copy)
    rows[0]["suggested_spanish"] = rows[0]["spanish"]
    assert review.apply(copy, rows) == (0, [])
    assert (copy / review.SUMMARY).read_bytes() == (ROOT / review.SUMMARY).read_bytes()


@pytest.mark.parametrize(
    "key, new, problem",
    [
        ("checked_apps", "Las aplicaciones de {phone}.", "keep {n}, {phone}"),
        ("staff_note", "Para el personal: solo en pantalla.", "keep </strong>"),
        ("no such key", "algo", "no such text"),
    ],
)
def test_a_bad_suggestion_changes_nothing(copy, key, new, problem):
    rows = _rows(copy)
    rows = _suggest(rows, {"Notes": "Apuntes", key: new})
    if key == "no such key":
        rows.append(dict(rows[0], key=key, suggested_spanish=new))
    changed, problems = review.apply(copy, rows)
    assert changed == 0 and len(problems) == 1 and problem in problems[0]
    for source in (review.SUMMARY, review.I18N):
        assert (copy / source).read_bytes() == (ROOT / source).read_bytes()


def test_the_command_line(copy, tmp_path, capsys):
    packet = tmp_path / "out" / "packet.csv"
    assert review.main(["export", str(packet), "--root", str(copy)]) == 0
    with open(packet, encoding="utf-8-sig", newline="") as f:
        rows = _suggest(list(csv.DictReader(f)), {"Notes": "Apuntes"})
    with open(packet, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, review.COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    assert review.main(["apply", str(packet), "--root", str(copy)]) == 0
    assert "Changed 1 texts" in capsys.readouterr().out
    rows[0]["suggested_spanish"] = "{oops}"
    with open(packet, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, review.COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    assert review.main(["apply", str(packet), "--root", str(copy)]) == 1
    assert "Nothing was changed" in capsys.readouterr().err
