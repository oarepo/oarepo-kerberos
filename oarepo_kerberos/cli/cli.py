#
# Copyright (C) 2024 CESNET z.s.p.o.
#
# oarepo-kerberos is free software; you can redistribute it and/or
# modify it under the terms of the MIT License; see LICENSE file for more
# details.
#
"""Oarepo kerberos command line tool implementation."""

from __future__ import annotations

import click
from invenio_accounts.errors import AlreadyLinkedError
from invenio_accounts.models import User, UserIdentity
from invenio_db import db


@click.group()
def kerberos() -> None:
    """Kerberos commands."""


@kerberos.group()
def mapping() -> None:
    """Manage Kerberos mappings."""


@mapping.command("add")
@click.argument("email")
@click.argument("kerberos_id")
def add_mapping(email: str, kerberos_id: str) -> None:
    """Add kerberos mapping."""
    user = User.query.filter_by(email=email).first()

    if not user:
        click.echo(f"Error: User with email {email} not found.")
        return

    realm = kerberos_id.split("@")[-1]
    existing_mapping = UserIdentity.get_user(
        method=f"krb-{realm}", external_id=kerberos_id
    )
    if existing_mapping:
        click.echo(f"Error: Mapping to kerberos {kerberos_id} already exists.")
        return

    try:
        UserIdentity.create(user=user, method=f"krb-{realm}", external_id=kerberos_id)
        db.session.commit()
        click.echo(f"Mapping added: {email} -> {kerberos_id}")
    except AlreadyLinkedError:
        click.echo("Error: Already linked.")
    except Exception as e:
        click.echo(f"Error: {e}")


@mapping.command("remove")
@click.argument("email")
@click.argument("kerberos_id")
def remove_mapping(email: str, kerberos_id: str) -> None:
    """Remove a Kerberos mapping."""
    user = User.query.filter_by(email=email).first()

    if not user:
        click.echo(f"Error: User with email {email} not found.")
        return

    realm = kerberos_id.split("@")[-1]
    UserIdentity.delete_by_external_id(method=f"krb-{realm}", external_id=kerberos_id)
    db.session.commit()

    click.echo(f"Mapping removed: {email} -> {kerberos_id}")


@mapping.command("get")
@click.option("--email", default=None, help="Filter by email.")
def get_mapping(email: str | None) -> None:
    """List all Kerberos mappings or specific user mapping."""
    query = db.session.query(User.email, UserIdentity.id).join(
        UserIdentity, User.id == UserIdentity.id_user
    )
    if email:
        query = query.filter(User.email == email)

    results = query.all()

    if results:
        click.echo("Output format: email -> kerberos id")
        for user_email, kerberos_id in results:
            click.echo(f"{user_email} -> {kerberos_id}")
    else:
        click.echo("No mappings found.")
