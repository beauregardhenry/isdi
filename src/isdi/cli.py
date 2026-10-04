"""Command-line interface for ISDI"""

import sys
import webbrowser
from threading import Timer
from time import perf_counter

import click

from isdi import __version__

__all__ = ["main", "cli"]


@click.group()
@click.version_option(version=__version__)
def cli():
    """ISDi - Stalkerware Scanner

    A privacy and security scanner for mobile devices.
    """
    pass


def _operator_option(f):
    return click.option(
        "--operator",
        envvar="ISDI_OPERATOR",
        help="Your name, recorded with every scan and change (or ISDI_OPERATOR). "
        "Asked for if not given.",
    )(f)


def _set_operator(name):
    """Record who is using ISDi. There are no user accounts, so this is the
    operator's own statement; it goes into every audit entry."""
    from isdi import audit

    while not (name or "").strip():
        name = click.prompt("Your name (recorded with what you do in ISDi)")
    audit.set_operator(name)


ANCHOR_REMINDER_DAYS = 7


def _anchor_reminder(last, now=None):
    """A reminder to anchor the audit log, if the last anchor is old."""
    from datetime import datetime, timezone

    now = now or datetime.now(timezone.utc)
    if last:
        days = (now - datetime.fromisoformat(last["time"])).days
        if days < ANCHOR_REMINDER_DAYS:
            return None
        when = f"{days} days ago"
    else:
        when = "never"
    return (
        f"⚠ The audit log was last anchored {when}. Run `isdi audit anchor -o "
        "FILE` and send the file outside the clinic (see COURT_RECORDS.md)."
    )


@cli.command()
@click.option(
    "--host",
    default=None,
    help="Host to bind to (default: 127.0.0.1). Binding to another address "
    "exposes scan results and device controls to the network.",
)
@click.option("--port", type=int, default=None, help="Port to bind to (default: 6200)")
@click.option("--debug/--no-debug", default=False, help="Enable debug mode")
@click.option("--test", "test_mode", is_flag=True, help="Run in test mode")
@click.option("--no-browser", is_flag=True, help="Do not open browser automatically")
@_operator_option
def run(host, port, debug, test_mode, no_browser, operator):
    """Run the ISDI web server"""
    from isdi.config import get_config
    from isdi.app import create_app

    startup_started = perf_counter()

    # Determine environment
    if test_mode:
        env = "test"
    elif debug:
        env = "development"
    else:
        env = "production"

    config_started = perf_counter()
    config = get_config(env)
    click.echo(f"⏱ Config init: {perf_counter() - config_started:.2f}s")
    _unlock(config)
    _set_operator(operator)

    # Override from command line
    final_host = host or config.host
    final_port = port or config.port
    if final_host not in ("127.0.0.1", "localhost", "::1"):
        click.secho(
            f"⚠ Listening on {final_host}: other machines on this network can "
            "view scan data and control connected devices. There is no login.",
            fg="red",
            err=True,
        )
    browser_host = "127.0.0.1" if final_host in ("0.0.0.0", "::") else final_host

    # Create app
    app_started = perf_counter()
    app = create_app(config)
    click.echo(f"⏱ App factory: {perf_counter() - app_started:.2f}s")
    from isdi import audit

    with app.app_context():
        audit.record(
            "session_started", details={"isdi_version": __version__, "env": env}
        )
        reminder = _anchor_reminder(audit.last_anchor())
    if reminder:
        click.secho(reminder, fg="yellow", err=True)

    # Open browser after short delay
    if not no_browser and not debug and not test_mode:

        def open_browser():
            webbrowser.open(f"http://{browser_host}:{final_port}")

        Timer(1.5, open_browser).start()

    click.echo(f"🔍 Starting ISDI on http://{final_host}:{final_port}")
    click.echo(f'📁 Data directory: {config.dirs["data"]}')
    click.echo(f"📊 Database: {config.database_path}")
    click.echo(f"⏱ Total startup prep: {perf_counter() - startup_started:.2f}s")

    if test_mode:
        click.echo("🧪 Running in TEST mode")
    elif debug:
        click.echo("🐛 Running in DEBUG mode")

    # Setup logging
    config.setup_logger()

    # Run the app
    app.run(
        host=final_host,
        port=final_port,
        debug=config.DEBUG,
        use_reloader=config.DEBUG,
        reloader_type=(
            "stat" if config.DEBUG else None
        ),  # Use stat-based reloader for better reliability
        extra_files=None,
    )


def _unlock(config):
    """Unlock the data key with the passphrase, setting up encryption the
    first time. ISDI_PASSPHRASE is used instead of asking, if set (handy for
    automation, but other programs run by the same user can read it)."""
    import os

    from isdi import crypto
    from isdi.data_protection import read_legacy_pii_key

    env = os.environ.get("ISDI_PASSPHRASE")
    if not crypto.is_set_up(config.keyfile):
        click.secho("\nISDi encrypts all client data.", bold=True)
        click.echo(
            "Choose a passphrase. ISDi asks for it every time it starts, and "
            "without it (or the recovery key shown next) the data cannot be "
            "read by anyone, including you."
        )
        while True:
            passphrase = env or click.prompt(
                "New passphrase", hide_input=True, confirmation_prompt=True
            )
            try:
                crypto.check_passphrase(passphrase)
                break
            except ValueError as e:
                if env:
                    raise click.ClickException(f"ISDI_PASSPHRASE: {e}")
                click.echo(str(e))
        recovery = crypto.setup(
            config.keyfile, passphrase, pii_key=read_legacy_pii_key(config)
        )
        click.secho(f"\nRecovery key: {recovery}\n", bold=True)
        click.echo(
            "Write it down and keep it somewhere safe, away from this computer. "
            "It is the only way to reach the data if the passphrase is lost, and "
            "it will not be shown again."
        )
        if not env:
            while not click.confirm("Have you stored the recovery key?", default=False):
                pass
        return
    if env:
        try:
            crypto.unlock(config.keyfile, passphrase=env)
        except crypto.UnlockError:
            raise click.ClickException("ISDI_PASSPHRASE is not the passphrase.")
        return
    for _ in range(3):
        try:
            crypto.unlock(
                config.keyfile, passphrase=click.prompt("Passphrase", hide_input=True)
            )
            return
        except crypto.UnlockError:
            click.echo("Wrong passphrase.")
    raise click.ClickException(
        "Wrong passphrase. If it is lost: isdi change-passphrase --recovery"
    )


def _data(config, operator=None):
    """Unlock, bring the data up to date (as `isdi run` does: migration,
    removal of plaintext leftovers) and give an app context to use it in."""
    from isdi.app import create_app

    _unlock(config)
    _set_operator(operator)
    return create_app(config).app_context()


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


@cli.command()
@click.argument("clientid")
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False, writable=True),
    help="Write to this file (created owner-readable only) instead of the screen.",
)
@_operator_option
def export(clientid, output, operator):
    """Export everything stored about a client, decrypted, as JSON.

    For a data access or portability request. The export is not encrypted:
    hand it over securely and delete it afterwards."""
    import json
    import os

    from isdi.config import get_config
    from isdi.scanner import db

    from isdi import audit

    config = get_config()
    with _data(config, operator):
        data = db.export_client(clientid)
        if not data["notes"] and not data["scans"]:
            raise click.ClickException(f"Nothing is stored for client {clientid!r}.")
        audit.record(
            "client_exported", clientid=clientid, details={"to_file": bool(output)}
        )
    text = json.dumps(data, indent=2, default=str)
    if output:
        from isdi import crypto
        from isdi.evidence import sign_file

        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        sig = sign_file(output, crypto.public_key(config.keyfile))
        click.echo(
            f"✓ Wrote {output} and its signature {sig}. It is not encrypted: "
            "delete it once handed over.",
            err=True,
        )
    else:
        click.echo(text)


@cli.command()
@click.argument("clientid")
@click.confirmation_option(
    prompt="Permanently delete everything stored about this client?"
)
@_operator_option
def erase(clientid, operator):
    """Delete everything stored about a client: notes, scans and apps."""
    from isdi.config import get_config
    from isdi.scanner import db

    from isdi import audit

    config = get_config()
    with _data(config, operator):
        counts = db.erase_client(clientid)
        if not any(counts.values()):
            raise click.ClickException(f"Nothing is stored for client {clientid!r}.")
        # The entry records that, when and by whom, not what was erased.
        audit.record("client_erased", clientid=clientid, details=counts)
    click.echo(
        "✓ Deleted "
        + ", ".join(f"{n} {table}" for table, n in counts.items() if n)
        + " row(s)."
    )


@cli.group("evidence")
def evidence_group():
    """Evidence copies of scans (kept when "Keep an evidence copy" is ticked)."""


@evidence_group.command("list")
@click.argument("clientid", required=False)
@_operator_option
def evidence_list(clientid, operator):
    """List kept evidence copies (all, or one client's)."""
    from isdi import evidence
    from isdi.config import get_config

    with _data(get_config(), operator):
        rows = evidence.list_evidence(clientid)
    if not rows:
        click.echo("No evidence copies are kept.")
    for r in rows:
        click.echo(
            f"scan {r['scanid']}  client {r['clientid']}  kept {r['created']}  "
            f"{r['size']} bytes  sha256 {r['dump_sha256']}"
            + ("  unredacted" if r["unredacted"] else "")
        )


@evidence_group.command("export")
@click.argument("scanid", type=int)
@click.option(
    "-o",
    "--output",
    required=True,
    type=click.Path(file_okay=False),
    help="New directory to write the package to.",
)
@_operator_option
def evidence_export(scanid, output, operator):
    """Write a signed evidence package for one scan to a new directory.

    The package (raw dump if kept, results, audit trail, manifest and
    signature) is not encrypted: hand it over securely."""
    from isdi import crypto, evidence
    from isdi.config import get_config

    config = get_config()
    with _data(config, operator):
        try:
            evidence.export_package(scanid, output, crypto.public_key(config.keyfile))
        except (LookupError, FileExistsError, ValueError) as e:
            raise click.ClickException(str(e))
    fp = crypto.fingerprint(crypto.public_key(config.keyfile))
    click.echo(f"✓ Wrote {output}. Signed by key {fp}")
    click.echo("  It is not encrypted: hand it over securely.")


@cli.command("verify")
@click.argument("path", type=click.Path(exists=True))
def verify_cmd(path):
    """Check a signed export file or evidence package (no passphrase needed).

    Compare the fingerprint shown with the one the clinic published
    (`isdi signing-key` on the clinic's computer)."""
    from isdi import evidence

    try:
        result = evidence.verify(path)
    except (OSError, ValueError, KeyError) as e:
        raise click.ClickException(f"Cannot verify {path}: {e}")
    click.echo(f"Signed by key {result['fingerprint']}")
    if not result["ok"]:
        for problem in result["problems"]:
            click.echo(f"  ✗ {problem}")
        raise click.ClickException("Verification FAILED")
    click.echo("✓ Signature valid and every file matches the manifest")


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


@cli.group("audit")
def audit_group():
    """The audit log: who did what, and when."""


def _read_anchor(path, public):
    """An anchor file's contents, once its signature is checked against this
    installation's key."""
    import json

    from isdi import crypto, evidence

    try:
        signed = evidence.verify(path)
        anchor = json.loads(open(path, encoding="utf-8").read())
    except (OSError, ValueError, KeyError) as e:
        raise click.ClickException(f"Cannot read anchor {path}: {e}")
    if not signed["ok"]:
        raise click.ClickException(f"Anchor {path} does not match its signature")
    if signed["fingerprint"] != crypto.fingerprint(public):
        raise click.ClickException(
            f"Anchor {path} was signed by another key ({signed['fingerprint']})"
        )
    return anchor


@audit_group.command("verify")
@click.option(
    "--anchor",
    "anchors",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Also check the log against an anchor made earlier (repeatable).",
)
@_operator_option
def audit_verify(anchors, operator):
    """Check that no audit entry was altered, inserted or removed.

    With --anchor, also check that the log still holds the entry the anchor
    recorded, unchanged: a log rebuilt or cut short since then fails."""
    from isdi import audit, crypto
    from isdi.config import get_config

    config = get_config()
    with _data(config, operator):
        result = audit.verify()
        head = audit.head()
        public = crypto.public_key(config.keyfile)
        problems = [
            (path, audit.check_anchor(_read_anchor(path, public))) for path in anchors
        ]
    if not result["ok"]:
        raise click.ClickException(f"Audit log check FAILED: {result['problem']}")
    click.echo(
        f"✓ Audit log intact: {result['entries']} entries"
        + (f" ({result['erased']} with erased details)" if result["erased"] else "")
    )
    if head:
        click.echo(f"  Newest entry: {head['id']}, MAC {head['mac']}")
    for path, problem in problems:
        if problem:
            raise click.ClickException(f"Anchor {path} check FAILED: {problem}")
        click.echo(f"✓ Matches anchor {path}")


@audit_group.command("anchor")
@click.option(
    "-o",
    "--output",
    required=True,
    type=click.Path(dir_okay=False, writable=True),
    help="File to write the anchor to (a signature is written next to it).",
)
@_operator_option
def audit_anchor(output, operator):
    """Write a signed record of the audit log's newest entry.

    Send it somewhere outside the clinic's control, for example by email to
    counsel. It holds no client data. Later, `isdi audit verify --anchor
    FILE` shows whether the log was rewritten or cut short since."""
    import json
    import os

    from isdi import audit, crypto
    from isdi.config import get_config
    from isdi.evidence import sign_file

    config = get_config()
    if os.path.exists(output):
        raise click.ClickException(f"{output} already exists")
    with _data(config, operator):
        anchor = audit.make_anchor()
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(json.dumps(anchor, indent=2) + "\n")
    sig = sign_file(output, crypto.public_key(config.keyfile))
    click.echo(
        f"✓ Wrote {output} and {sig}: entry {anchor['newest_entry']['id']}. "
        "Send both outside the clinic, for example by email to counsel."
    )


@audit_group.command("show")
@click.argument("clientid", required=False)
@_operator_option
def audit_show(clientid, operator):
    """List audit entries (all, or one client's), decrypted, as JSON."""
    import json

    from isdi import audit
    from isdi.config import get_config

    with _data(get_config(), operator):
        rows = audit.entries(clientid)
    click.echo(json.dumps(rows, indent=2, default=str))


@cli.command()
def info():
    """Show configuration and directory information"""
    from isdi.config import get_config

    config = get_config()

    click.echo("ISDI Configuration:")
    click.echo(f"  Environment: {config.env}")
    click.echo(f"\nDirectories:")
    click.echo(f'  Data: {config.dirs["data"]}')
    click.echo(f'  Config: {config.dirs["config"]}')
    click.echo(f'  Cache: {config.dirs["cache"]}')
    click.echo(f"\nData Locations:")
    click.echo(f"  Database: {config.database_path}")
    click.echo(f"  Scans: {config.scans_dir}")
    click.echo(f"  Dumps: {config.dumps_dir}")
    click.echo(f"  Logs: {config.logs_dir}")
    click.echo(f"\nPackage Data:")
    click.echo(f"  Location: {config.package_data}")
    click.echo(f"  Stalkerware DB: {config.stalkerware_path}")


@cli.command()
@click.confirmation_option(prompt="Are you sure you want to reset all data?")
def reset():
    """Reset all user data (scans, reports, database)"""
    import shutil
    from isdi.config import get_config

    config = get_config()

    click.echo("Resetting data...")

    # Remove data directories
    for dir_path in [
        config.scans_dir,
        config.reports_dir,
        config.dumps_dir,
        config.phone_dumps_dir,
    ]:
        if dir_path.exists():
            shutil.rmtree(dir_path)
            dir_path.mkdir(parents=True)
            click.echo(f"  ✓ Cleared {dir_path.name}/")

    # Remove database
    if config.database_path.exists():
        config.database_path.unlink()
        click.echo(f"  ✓ Deleted database")

    # Remove cache
    if config.dirs["cache"].exists():
        shutil.rmtree(config.dirs["cache"])
        config.dirs["cache"].mkdir(parents=True)
        click.echo(f"  ✓ Cleared cache")

    click.echo("\n✓ All data has been reset")


@cli.command()
def paths():
    """Show all configured paths"""
    from isdi.config import get_config
    import json

    config = get_config()

    paths_dict = {
        "directories": {k: str(v) for k, v in config.dirs.items()},
        "data": {
            "database": str(config.database_path),
            "scans": str(config.scans_dir),
            "dumps": str(config.dumps_dir),
            "logs": str(config.logs_dir),
        },
        "package": {
            "data": str(config.package_data),
            "stalkerware": str(config.stalkerware_path),
        },
        "secrets": {
            "keyfile": str(config.keyfile),
            "flask_secret": str(config.flask_secret_file),
        },
    }

    click.echo(json.dumps(paths_dict, indent=2))


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


if __name__ == "__main__":
    main()
