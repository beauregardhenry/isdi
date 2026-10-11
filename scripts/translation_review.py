#!/usr/bin/env python3
"""The Spanish review packet: every Spanish text ISDi shows a client, next to
its English, as a spreadsheet a reviewer can correct.

    python scripts/translation_review.py export docs/review/spanish-review.csv
    python scripts/translation_review.py apply corrected.csv

`export` writes one row per text: where it is used, the English, the current
Spanish, and empty "suggested_spanish" and "notes" columns for the reviewer.
`apply` reads a reviewed file back and writes each suggested_spanish into the
source (src/isdi/client_summary.py and src/isdi/consultation/i18n.py), then
runs black on them. A suggestion is refused if it drops or adds a
placeholder such as {phone} or an HTML tag such as <strong>; nothing is
written unless every suggestion is accepted.

Both read the source files as text (with the ast module), so they work on a
checkout without ISDi installed. The file is UTF-8 with a byte-order mark so
that Excel shows the accents correctly.
"""

import argparse
import ast
import csv
import json
import re
import subprocess
import sys
import tokenize
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
SUMMARY = Path("src/isdi/client_summary.py")
I18N = Path("src/isdi/consultation/i18n.py")
COLUMNS = ["source", "key", "where", "english", "spanish", "suggested_spanish", "notes"]

# Where each client summary text appears.
SUMMARY_WHERE = {
    "h_limits": "Client summary and take-home copy",
    "limits": "Client summary and take-home copy",
    "h_next": "Client summary and take-home copy",
    "next": "Client summary and take-home copy",
    "staff_note": "Client summary, shown to staff only (not printed)",
}

_PLACEHOLDER = re.compile(r"\{[a-z_]*\}|</?[a-z]+>")


def _dict_node(tree: ast.Module, name: str) -> ast.Dict:
    for node in tree.body:
        targets = (
            [node.target]
            if isinstance(node, ast.AnnAssign)
            else node.targets if isinstance(node, ast.Assign) else []
        )
        if any(isinstance(t, ast.Name) and t.id == name for t in targets):
            assert isinstance(node.value, ast.Dict), name
            return node.value
    raise KeyError(name)


def _sub(d: ast.Dict, key: str) -> ast.expr:
    for k, v in zip(d.keys, d.values):
        if isinstance(k, ast.Constant) and k.value == key:
            return v
    raise KeyError(key)


# The section headings in i18n.py ("# --- ... ---"), in reviewers' words.
SECTIONS = {
    "the report page": "headings and labels",
    "answer choices (consultation/choices.py)": "answer choices",
    "questions (consultation/model.py)": "questions",
    "risks (consultation/model.py)": "risks found (name or explanation)",
}


def _comments(text: str) -> List[Tuple[int, int, str]]:
    """Blocks of consecutive comment lines: (first line, last line, text)."""
    lines = iter(text.splitlines(keepends=True))
    blocks: List[Tuple[int, int, str]] = []
    for tok in tokenize.generate_tokens(lambda: next(lines, "")):
        if tok.type != tokenize.COMMENT:
            continue
        line, words = tok.start[0], tok.string.lstrip("# ").rstrip(" -")
        if blocks and blocks[-1][1] == line - 1 and not words.startswith("--"):
            first, _, before = blocks[-1]
            blocks[-1] = (first, line, f"{before} {words}")
        else:
            blocks.append((line, line, words))
    return blocks


def _where(comments: List[Tuple[int, int, str]], line: int) -> str:
    """The section heading ("# --- ... ---") above `line`; then a one-line
    comment under it (a sub-heading), or a longer comment directly above
    `line` (a note on that entry)."""
    section, detail = "", ""
    for first, last, text in comments:
        if first >= line:
            break
        if text.startswith("--"):
            heading = text.strip("- ")
            section, detail = SECTIONS.get(heading, heading), ""
        elif first == last:
            detail = text
        elif last == line - 1:
            return f"{section}: {text}"
    return f"{section}: {detail}" if detail else section


def _items(root: Path):
    """(source, key, where, english, spanish, value node) for every text."""
    text = (root / SUMMARY).read_text(encoding="utf-8")
    tree = ast.parse(text)
    TEXT = _dict_node(tree, "TEXT")
    en, es = _sub(TEXT, "en"), _sub(TEXT, "es")
    assert isinstance(en, ast.Dict) and isinstance(es, ast.Dict)
    for k, node in zip(es.keys, es.values):
        key = ast.literal_eval(k)
        english = ast.literal_eval(_sub(en, key))
        where = SUMMARY_WHERE.get(key, "Client summary")
        if isinstance(node, ast.List):
            for i, item in enumerate(node.elts):
                yield (
                    str(SUMMARY),
                    f"{key}[{i}]",
                    where,
                    english[i],
                    ast.literal_eval(item),
                    item,
                )
        else:
            yield str(SUMMARY), key, where, english, ast.literal_eval(node), node

    text = (root / I18N).read_text(encoding="utf-8")
    comments = _comments(text)
    ES = _dict_node(ast.parse(text), "ES")
    for k, node in zip(ES.keys, ES.values):
        english = ast.literal_eval(k)
        where = "Take-home copy, " + _where(comments, k.lineno)
        yield str(I18N), english, where, english, ast.literal_eval(node), node


def export(root: Path, out) -> int:
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(COLUMNS)
    n = 0
    for source, key, where, english, spanish, _ in _items(root):
        writer.writerow([source, key, where, english, spanish, "", ""])
        n += 1
    return n


def _marks(s: str) -> List[str]:
    return sorted(_PLACEHOLDER.findall(s))


def _literal(value: str, column: int) -> str:
    """`value` as Python string literals, one per line of about 70
    characters, at the given column (implicit concatenation)."""
    chunks: List[str] = []
    for word in re.findall(r"\S+\s*|\s+", value):
        if chunks and len(chunks[-1]) + len(word) <= 66:
            chunks[-1] += word
        else:
            chunks.append(word)
    parts = [json.dumps(c, ensure_ascii=False) for c in chunks or [""]]
    return ("\n" + " " * column).join(parts)


def apply(root: Path, rows: List[Dict[str, str]]) -> Tuple[int, List[str]]:
    """Write each row's suggested_spanish into the source. Returns the
    number changed and the problems found (nothing is written if any)."""
    nodes = {
        (src, key): (spanish, english, node)
        for src, key, _, english, spanish, node in _items(root)
    }
    problems: List[str] = []
    edits: Dict[str, List[Tuple[ast.expr, str]]] = {}
    for n, row in enumerate(rows, start=2):
        new = (row.get("suggested_spanish") or "").strip()
        if not new:
            continue
        found = nodes.get((row.get("source", ""), row.get("key", "")))
        if found is None:
            problems.append(f"line {n}: no such text ({row.get('key')!r})")
            continue
        spanish, english, node = found
        if new == spanish:
            continue
        if _marks(new) != _marks(english):
            problems.append(
                f"line {n}: keep {', '.join(_marks(english)) or 'no placeholders'}"
                f" exactly (found {', '.join(_marks(new)) or 'none'})"
            )
            continue
        edits.setdefault(row["source"], []).append((node, new))
    if problems:
        return 0, problems
    for source, changes in edits.items():
        path = root / source
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
        offsets = [0]
        for line in lines:
            offsets.append(offsets[-1] + len(line.encode("utf-8")))
        data = "".join(lines).encode("utf-8")
        # From the bottom up, so earlier offsets stay valid.
        for node, new in sorted(changes, key=lambda c: -c[0].lineno):
            start = offsets[node.lineno - 1] + node.col_offset
            end = offsets[node.end_lineno - 1] + node.end_col_offset  # type: ignore[operator]
            data = (
                data[:start]
                + _literal(new, node.col_offset).encode("utf-8")
                + data[end:]
            )
        path.write_bytes(data)
        ast.parse(data)  # still valid Python
    if edits:
        subprocess.run(
            [sys.executable, "-m", "black", "-q", *(str(root / s) for s in edits)],
            check=False,
        )
    return sum(len(c) for c in edits.values()), []


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("action", choices=["export", "apply"])
    parser.add_argument("file", help="the CSV file to write or read")
    parser.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.action == "export":
        Path(args.file).parent.mkdir(parents=True, exist_ok=True)
        with open(args.file, "w", encoding="utf-8-sig", newline="") as out:
            n = export(args.root, out)
        print(f"Wrote {n} texts to {args.file}")
        return 0
    with open(args.file, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    changed, problems = apply(args.root, rows)
    for p in problems:
        print(p, file=sys.stderr)
    if problems:
        print("Nothing was changed.", file=sys.stderr)
        return 1
    print(f"Changed {changed} texts. Run the tests, then export the packet again.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
