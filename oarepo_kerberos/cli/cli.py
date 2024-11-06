import click
from invenio_db import db
from invenio_accounts.models import UserIdentity, User

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
    user = User.query.filter_by(_email=email).first()

    if not user:
        click.echo(f"User with email {email} not found.")
        return

    deleted_rows = UserIdentity.query.filter_by(id=kerberos_id,id_user=user.id).delete()

    #db.session.commit()

    if deleted_rows > 0:
        click.echo(f"Mapping removed: {email} -> {kerberos_id}")
    else:
        click.echo(f"No mapping found for {email} with Kerberos ID {kerberos_id}.")

@mapping.command('get')
@click.option('--email', default=None, help="Filter by email.")
def get_mapping(email):
    """List Kerberos mappings."""
    query = db.session.query(User.email, UserIdentity.id).join(
        UserIdentity, User.id == UserIdentity.id_user
    )
    if email:
        query = query.filter(User.email == email)

    results = query.all()

    if results:
        print("Output format: email -> kerberos id")
        for user_email, kerberos_id in results:
            click.echo(f"{user_email} -> {kerberos_id}")
    else:
        click.echo("No mappings found.")