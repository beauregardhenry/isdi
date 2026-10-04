"""Command-line interface for ISDi.

The commands live in this package's modules, by area:
- server: `run`, `info`, `paths`;
- accounts: `user ...`;
- keys: `change-passphrase`, `signing-key`, `backup`, `restore`, `reset`;
- records: `export`, `erase`, `evidence ...`, `verify`, `audit ...`.
common holds the command group and unlocking; this module the entry point.
"""

import sys

import click

from isdi.cli.common import (  # noqa: F401
    _data,
    _operator_option,
    _set_operator,
    _unlock,
    cli,
)

__all__ = ["main", "cli"]


def main():
    """Main entry point"""
    try:
        cli()
    except KeyboardInterrupt:
        click.echo("\n👋 Goodbye!")
        sys.exit(0)
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        if "--debug" in sys.argv:
            import traceback

            traceback.print_exc()
        sys.exit(1)


# Register the commands (each module adds its own to `cli`).
from isdi.cli import accounts, keys, records, server  # noqa: E402,F401
from isdi.cli.server import _anchor_reminder, _backup_reminder  # noqa: E402,F401
from isdi.cli.keys import RESET_PHRASE  # noqa: E402,F401
