import click

"""
invenio kerberos mapping add <email> <kerberos id>
invenio kerberos mapping remove <email> <kerberos id>
invenio kerberos mapping get [<email>] → vylistuje email, kerberos id
"""

@click.group()
def kerberos():
    """Kerberos commands."""

@kerberos.group()
def mapping():
    """Manage Kerberos mappings."""

@mapping.command('add')
@click.argument('email')
@click.argument('kerberos_id')
def add_mapping(email, kerberos_id):
    # TODO
    click.echo(f"Mapping added: {email} -> {kerberos_id}")

@mapping.command('remove')
@click.argument('email')
@click.argument('kerberos_id')
def remove_mapping(email, kerberos_id):
    """Remove a Kerberos mapping."""
    # TODO
    click.echo(f"Mapping removed: {email} -> {kerberos_id}")

@mapping.command('get')
@click.option('--email', default=None, help="Filter by email.")
def get_mapping(email):
    """List Kerberos mappings."""
    # TODO
    if email:
        click.echo(f"Listing mapping for: {email}")
    else:
        click.echo("Listing all mappings")