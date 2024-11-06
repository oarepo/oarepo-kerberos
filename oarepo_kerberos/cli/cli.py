import click
from invenio_db import db
from invenio_accounts.models import UserIdentity, User
from invenio_accounts.errors import AlreadyLinkedError


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
    """Add kerberos mapping."""
    user = User.query.filter_by(email=email).first()

    if not user:
        click.echo(f"Error: User with email {email} not found.")
        return

    existing_mapping = UserIdentity.get_user(method="kerberos",external_id=kerberos_id)
    if existing_mapping:
        click.echo(f"Error: Mapping to kerberos {kerberos_id} already exists.")
        return

    try:
       UserIdentity.create(user=user, method="kerberos", external_id=kerberos_id)
       db.session.commit()
       click.echo(f"Mapping added: {email} -> {kerberos_id}")
    except AlreadyLinkedError:
       click.echo(f"Error: Already linked.")
    except Exception as e:
       click.echo(f'Error: {e}')


@mapping.command('remove')
@click.argument('email')
@click.argument('kerberos_id')
def remove_mapping(email, kerberos_id):
    """Remove a Kerberos mapping."""
    user = User.query.filter_by(email=email).first()

    if not user:
        click.echo(f"Error: User with email {email} not found.")
        return

    UserIdentity.delete_by_external_id(method="kerberos", external_id=kerberos_id)
    db.session.commit()

    click.echo(f"Mapping removed: {email} -> {kerberos_id}")

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