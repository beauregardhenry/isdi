"""What every command module shares: the command group, the --operator
option, and unlocking the data."""

import click

from isdi import __version__


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
