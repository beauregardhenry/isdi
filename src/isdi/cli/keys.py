"""Keys, passwords and backups: change-passphrase, signing-key, backup, restore and reset."""

import click

from isdi.cli.common import (
    _data,
    _operator_option,
    _set_operator,
    cli,
    refuse_while_serving,
)


@cli.command("change-passphrase")
@click.option(
    "--recovery",
    is_flag=True,
    help="Prove access with the recovery key instead of the current passphrase.",
)
def change_passphrase(recovery):
    """Change the passphrase (the data and the recovery key stay the same)."""
    from isdi import crypto
    from isdi.config import get_config

    config = get_config()
    if not crypto.is_set_up(config.keyfile):
        raise click.ClickException("Encryption is not set up yet; run `isdi run`.")
    if recovery:
        proof = {"recovery_key": click.prompt("Recovery key")}
    else:
        proof = {"passphrase": click.prompt("Current passphrase", hide_input=True)}
    new = click.prompt("New passphrase", hide_input=True, confirmation_prompt=True)
    try:
        crypto.change_passphrase(config.keyfile, new, **proof)
    except (crypto.UnlockError, ValueError) as e:
        raise click.ClickException(str(e))
    click.echo("✓ Passphrase changed.")


@cli.command("backup")
@click.option(
    "-o",
    "--output",
    required=True,
    type=click.Path(dir_okay=False, writable=True),
    help="File to write the backup to (a new file).",
)
@_operator_option
def backup_cmd(output, operator):
    """Write an encrypted backup of all ISDi data to one file.

    Restoring it (`isdi restore`) needs the passphrase or the recovery key
    that is valid now. Keep backups away from this computer."""
    import os

    from isdi import audit, backup
    from isdi.config import get_config

    config = get_config()
    if os.path.exists(output):
        raise click.ClickException(f"{output} already exists")
    with _data(config, operator):
        audit.record("backup_made", details={"file": os.path.basename(output)})
        summary = backup.write(output, config.database_path, config.keyfile)
    click.echo(
        f"✓ Wrote {output} ({summary['size']} bytes, SHA-256 {summary['sha256']})."
    )
    click.echo(
        "  It is encrypted. Keep it away from this computer, with the "
        "recovery key stored separately."
    )


@cli.command("restore")
@click.argument("path", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--recovery",
    is_flag=True,
    help="Unlock the backup with the recovery key instead of the passphrase.",
)
@click.option(
    "--replace",
    is_flag=True,
    help="Replace the data already on this computer (kept as a copy).",
)
@_operator_option
def restore_cmd(path, recovery, replace, operator):
    """Restore an encrypted backup made with `isdi backup`.

    Asks for the passphrase (or, with --recovery, the recovery key) that
    was valid when the backup was made. If ISDi already has data here,
    --replace is needed; the current files are kept next to the restored
    ones, renamed."""
    import json
    import os
    import shutil
    import tempfile
    from datetime import datetime, timezone
    from pathlib import Path

    from isdi import backup, crypto
    from isdi.config import get_config

    config = get_config()
    database, keyfile = Path(config.database_path), Path(config.keyfile)
    existing = [p for p in (database, keyfile) if p.exists()]
    if existing:
        refuse_while_serving(config)
    if existing and not replace:
        raise click.ClickException(
            "ISDi already has data on this computer. Use --replace to replace "
            "it (the current files are kept, renamed)."
        )
    try:
        header = backup.read_header(path)
    except (OSError, ValueError) as e:
        raise click.ClickException(f"Cannot read {path}: {e}")
    click.echo(f"Backup made {header['made_at']}.")

    saved = crypto._state()
    workdir = Path(tempfile.mkdtemp(dir=keyfile.parent, prefix=".restore-"))
    try:
        tmp_keyfile = workdir / "datakey.json"
        tmp_keyfile.write_text(json.dumps(header["keyfile"]))
        os.chmod(tmp_keyfile, 0o600)
        secret = (
            {"recovery_key": click.prompt("Recovery key")}
            if recovery
            else {"passphrase": click.prompt("Passphrase", hide_input=True)}
        )
        try:
            crypto.unlock(tmp_keyfile, **secret)
            db_bytes = backup.decrypt(path)
            backup.check_database(db_bytes, workdir)
        except crypto.UnlockError:
            raise click.ClickException(
                "That is not the passphrase or recovery key of this backup."
            )
        except backup.BackupError as e:
            raise click.ClickException(f"Cannot restore: {e}")

        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        for p in existing:
            p.rename(p.with_name(f"{p.name}.before-restore-{stamp}"))
            click.echo(
                f"  Kept the current {p.name} as {p.name}.before-restore-{stamp}"
            )
        database.parent.mkdir(parents=True, exist_ok=True)
        tmp_db = workdir / "database.db"
        fd = os.open(tmp_db, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(db_bytes)
        shutil.move(str(tmp_db), database)
        shutil.move(str(tmp_keyfile), keyfile)

        # The restore is part of the records' history: log it in them.
        import sqlite3

        from isdi import audit
        from isdi.scanner.db import make_dicts

        _set_operator(operator)
        conn = sqlite3.connect(database)
        conn.row_factory = make_dicts
        try:
            audit.record(
                "restored_from_backup",
                details={
                    "file": os.path.basename(path),
                    "backup_made_at": header["made_at"],
                    "replaced_existing_data": bool(existing),
                },
                conn=conn,
            )
        finally:
            conn.close()
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
        crypto._restore(saved)
    click.echo(
        f"✓ Restored the data from {path}. Start ISDi with `isdi run`; it asks "
        "for the passphrase that was valid when the backup was made."
    )


@cli.command("signing-key")
def signing_key():
    """Show this installation's signing public key and its fingerprint."""
    import base64

    from isdi import crypto
    from isdi.config import get_config

    config = get_config()
    if not crypto.is_set_up(config.keyfile):
        raise click.ClickException("Encryption is not set up yet; run `isdi run`.")
    try:
        public = crypto.public_key(config.keyfile)
    except KeyError:
        raise click.ClickException(
            "No signing key yet: start ISDi once (`isdi run`) to create it."
        )
    click.echo(f"Public key:  {base64.b64encode(public).decode()}")
    click.echo(f"Fingerprint: {crypto.fingerprint(public)}")


RESET_PHRASE = "DELETE EVERYTHING"


@cli.command()
@click.option(
    "-o",
    "--backup",
    "backup_file",
    type=click.Path(dir_okay=False, writable=True),
    help="Write an encrypted backup here first (a new file).",
)
@click.option(
    "--no-backup",
    is_flag=True,
    help="Delete without a backup. The data cannot be recovered.",
)
@_operator_option
def reset(backup_file, no_backup, operator):
    """Delete ALL client data: every client, scan, evidence copy, account
    and the audit log.

    Needs the passphrase, a backup first (-o FILE) unless --no-backup is
    given, and typing the confirmation phrase. The keys stay, so a backup
    can be restored later with `isdi restore`. To delete one client's data,
    use `isdi erase CLIENTID` instead."""
    import os
    import shutil

    from isdi import audit, backup
    from isdi.config import get_config

    if bool(backup_file) == no_backup:
        raise click.ClickException(
            "Give either -o FILE (a backup is written first) or --no-backup."
        )
    if backup_file and os.path.exists(backup_file):
        raise click.ClickException(f"{backup_file} already exists")

    config = get_config()
    refuse_while_serving(config)
    with _data(config, operator):
        click.secho(
            "This deletes every client, scan, evidence copy, account and the "
            "audit log.",
            fg="red",
            bold=True,
        )
        if click.prompt(f"Type {RESET_PHRASE} to confirm") != RESET_PHRASE:
            raise click.ClickException("Not confirmed; nothing was deleted.")
        audit.record(
            "data_reset", details={"backup": os.path.basename(backup_file or "")}
        )
        if backup_file:
            summary = backup.write(backup_file, config.database_path, config.keyfile)
            click.echo(f"✓ Wrote the backup {backup_file} ({summary['size']} bytes)")
        from isdi.scanner import db

        db.close_db()

    for dir_path in (
        config.reports_dir,
        config.dumps_dir,
        config.logs_dir,
        config.temp_dir,
    ):
        if dir_path.exists():
            shutil.rmtree(dir_path)
            dir_path.mkdir(parents=True)
    for suffix in ("", "-wal", "-shm", "-journal"):
        path = config.database_path.with_name(config.database_path.name + suffix)
        if path.exists():
            path.unlink()
    click.echo("✓ All client data has been deleted. The keys are kept.")
