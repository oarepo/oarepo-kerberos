#
# Copyright (C) 2024 CESNET z.s.p.o.
#
# oarepo-kerberos is free software; you can redistribute it and/or
# modify it under the terms of the MIT License; see LICENSE file for more
# details.
#
from __future__ import annotations

from click.testing import CliRunner
from invenio_accounts.models import UserIdentity

from oarepo_kerberos.cli import kerberos  # Update the import path as needed


def test_add_mapping(users, run_flask_in_background, kerberos_identity):
    """Test adding a Kerberos mapping."""
    runner = CliRunner()

    # Simulate the `add` command
    result = runner.invoke(kerberos, ["mapping", "add", users[0].email, "new_mapping@ANOTHER-EXAMPLE.COM"])

    assert result.exit_code == 0
    assert f"Mapping added: {users[0].email} -> new_mapping@ANOTHER-EXAMPLE.COM" in result.output

    user_identity = UserIdentity.get_user(
        method="krb-ANOTHER-EXAMPLE.COM", external_id="new_mapping@ANOTHER-EXAMPLE.COM"
    )
    assert user_identity is not None


def test_add_existing_mapping(users, run_flask_in_background, kerberos_identity):
    """Test adding a Kerberos mapping but it already exists."""
    runner = CliRunner()

    # Firstly add mapping
    result = runner.invoke(kerberos, ["mapping", "add", users[0].email, "new_mapping@ANOTHER-EXAMPLE.COM"])
    assert result.exit_code == 0
    assert f"Mapping added: {users[0].email} -> new_mapping@ANOTHER-EXAMPLE.COM" in result.output

    # Try to add it again
    result = runner.invoke(kerberos, ["mapping", "add", users[0].email, "new_mapping@ANOTHER-EXAMPLE.COM"])
    assert result.exit_code == 0
    assert "Error: Mapping to kerberos new_mapping@ANOTHER-EXAMPLE.COM already exists." in result.output

    user_identity = UserIdentity.get_user(
        method="krb-ANOTHER-EXAMPLE.COM", external_id="new_mapping@ANOTHER-EXAMPLE.COM"
    )
    assert user_identity is not None


def test_add_mapping_same_realm(users, run_flask_in_background, kerberos_identity):
    """Test adding a Kerberos mapping but to the same realm."""
    runner = CliRunner()

    # Firstly add mapping
    result = runner.invoke(
        kerberos,
        ["mapping", "add", users[0].email, "first_mapping@ANOTHER-EXAMPLE.COM"],
    )
    assert result.exit_code == 0
    assert f"Mapping added: {users[0].email} -> first_mapping@ANOTHER-EXAMPLE.COM" in result.output

    # Try with account in same realm
    result = runner.invoke(
        kerberos,
        ["mapping", "add", users[0].email, "second_mapping@ANOTHER-EXAMPLE.COM"],
    )

    assert result.exit_code == 0
    assert "Error: Already linked." in result.output


def test_remove_non_existing_mapping(users, run_flask_in_background, kerberos_identity):
    """Test removing a non existing Kerberos mapping."""
    runner = CliRunner()

    # non existing mapping
    result = runner.invoke(
        kerberos,
        ["mapping", "remove", users[0].email, "kerberos_mapping@ANOTHER-EXAMPLE.COM"],
    )

    assert result.exit_code == 0
    assert f"Mapping removed: {users[0].email} -> kerberos_mapping@ANOTHER-EXAMPLE.COM" in result.output

    # Verify it was removed from the database
    user_identity = UserIdentity.get_user(
        method="krb-ANOTHER-EXAMPLE.COM",
        external_id="kerberos_mapping@ANOTHER-EXAMPLE.COM",
    )
    assert user_identity is None


def test_remove_existing_mapping(users, run_flask_in_background, kerberos_identity):
    """Test removing a existing Kerberos mapping."""
    runner = CliRunner()

    # Firstly add mapping
    result = runner.invoke(
        kerberos,
        ["mapping", "add", users[0].email, "existing_mapping@ANOTHER-EXAMPLE.COM"],
    )

    assert result.exit_code == 0
    assert f"Mapping added: {users[0].email} -> existing_mapping@ANOTHER-EXAMPLE.COM" in result.output

    # Remove existing mapping
    result = runner.invoke(
        kerberos,
        ["mapping", "remove", users[0].email, "existing_mapping@ANOTHER-EXAMPLE.COM"],
    )

    assert result.exit_code == 0
    assert f"Mapping removed: {users[0].email} -> existing_mapping@ANOTHER-EXAMPLE.COM" in result.output

    # Verify it was removed from the database
    user_identity = UserIdentity.get_user(
        method="krb-ANOTHER-EXAMPLE.COM", external_id="new_mapping@ANOTHER-EXAMPLE.COM"
    )
    assert user_identity is None


def test_get_mapping(users, run_flask_in_background, kerberos_identity):
    """Test listing Kerberos mappings."""
    runner = CliRunner()

    # Simulate the `get` command
    result = runner.invoke(kerberos, ["mapping", "get"])

    assert result.exit_code == 0
    assert f"{users[0].email} -> user@EXAMPLE.COM" in result.output


def test_get_mapping_filtered_by_email(users, run_flask_in_background, kerberos_identity):
    """Test listing Kerberos mappings filtered by email."""
    runner = CliRunner()

    # Simulate the `get` command with email filtering
    result = runner.invoke(kerberos, ["mapping", "get", "--email", users[0].email])

    assert result.exit_code == 0
    assert f"{users[0].email} -> user@EXAMPLE.COM" in result.output

    # Simulate the `get` command with a non-existent email
    result = runner.invoke(kerberos, ["mapping", "get", "--email", "nonexistent@example.com"])

    assert result.exit_code == 0
    assert "No mappings found." in result.output
