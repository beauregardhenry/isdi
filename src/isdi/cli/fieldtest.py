"""`isdi field-test`: check ISDi against a connected test phone
(isdi/fieldtest.py)."""

from pathlib import Path

import click

from isdi.cli.common import cli


@cli.command("field-test")
@click.argument("device", type=click.Choice(["android", "ios"]))
@click.option("--serial", help="The phone to test, if more than one is connected.")
@click.option(
    "-o",
    "--output",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Write the report to this file as well.",
)
@click.option("--yes", is_flag=True, help="Do not ask whether this is a test phone.")
def field_test(device, serial, output, yes):
    """Run every check on a connected TEST phone and print what each part
    of ISDi recognised (counts and versions, never app ids, names or
    serial numbers), to send to the maintainers. Never use a client's
    phone: run ISDi's normal scan for that."""
    from isdi import fieldtest

    click.secho(
        "Use a test phone or your own phone, never a client's. The report "
        "holds no app ids, names, serial numbers or account details, but the "
        "test reads the phone like a scan does.",
        fg="yellow",
    )
    if not yes and not click.confirm("Is the connected phone a test phone?"):
        raise click.Abort()
    try:
        report = fieldtest.run(device, serial)
    except fieldtest.NotPrivate as e:
        raise click.ClickException(f"No report was written: {e}.")
    text = fieldtest.render(report)
    click.echo(text)
    if output:
        output.write_text(text, encoding="utf-8")
        click.echo(f"✓ Wrote {output}")
