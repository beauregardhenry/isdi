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
        fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        click.echo(
            f"✓ Wrote {output}. It is not encrypted: delete it once handed over.",
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


@cli.group("audit")
def audit_group():
    """The audit log: who did what, and when."""


@audit_group.command("verify")
@_operator_option
def audit_verify(operator):
    """Check that no audit entry was altered, inserted or removed."""
    from isdi import audit
    from isdi.config import get_config

    with _data(get_config(), operator):
        result = audit.verify()
        head = audit.head()
    if not result["ok"]:
        raise click.ClickException(f"Audit log check FAILED: {result['problem']}")
    click.echo(
        f"✓ Audit log intact: {result['entries']} entries"
        + (f" ({result['erased']} with erased details)" if result["erased"] else "")
    )
    if head:
        click.echo(f"  Newest entry: {head['id']}, MAC {head['mac']}")


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
