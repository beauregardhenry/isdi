"""The consultation notes are described in three places that must agree:
the intake form (web/forms/client.py), the clients_notes table
(scanner/db.py SCHEMA_SQL) and the list of encrypted columns. A form field
missing from the encrypted list would be saved in the clear, or not at all."""

import sqlite3
from contextlib import closing

from isdi.scanner import db
from isdi.web.forms import ClientForm

# Columns of clients_notes that are not form fields.
BOOKKEEPING = {"id", "created_at", "clientid"}


def _table_columns(table):
    with closing(sqlite3.connect(":memory:")) as conn:
        conn.executescript(db.SCHEMA_SQL)
        return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def test_every_form_field_is_an_encrypted_column():
    fields = {f.name for f in ClientForm()}
    assert fields == set(db.ENCRYPTED_COLUMNS["clients_notes"])
    assert set(db.NOTES_FIELDS) == fields


def test_the_table_has_exactly_the_form_fields():
    assert _table_columns("clients_notes") == {f.name for f in ClientForm()} | (
        BOOKKEEPING
    )


def test_every_encrypted_column_exists():
    """For every table: a listed column the table lacks would make the
    encrypting migration fail on start."""
    for table, cols in db.ENCRYPTED_COLUMNS.items():
        missing = set(cols) - _table_columns(table)
        assert not missing, f"{table} has no column(s) {sorted(missing)}"
