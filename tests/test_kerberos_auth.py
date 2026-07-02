#
# Copyright (C) 2024 CESNET z.s.p.o.
#
# oarepo-kerberos is free software; you can redistribute it and/or
# modify it under the terms of the MIT License; see LICENSE file for more
# details.
#
from __future__ import annotations

import base64

import pytest
import requests
from flask_principal import Identity
from invenio_access import any_user


@pytest.fixture
def test_setup(service, datasets_model, users):
    service.create(users[0].identity, {"metadata": {"title": "test"}, "files": {"enabled": False}})
    datasets_model.Record.index.refresh()


def test_kerberos_auth_401_no_user_in_db(
    run_flask_in_background, record_data, datasets_model, kerberos_auth, search_clear
):
    """Test a failed POST request due to non-existing UserIdentity."""
    url = "http://localhost:5000/datasets"
    response = requests.post(url, auth=kerberos_auth, json=record_data, timeout=60)
    assert response.status_code == 401


def test_kerberos_auth_401_optional_auth_no_user_in_db(
    run_flask_in_background, record_data, datasets_model, optional_auth, search_clear
):
    """Test a failed POST request with optional authentication but no UserIdentity."""
    url = "http://localhost:5000/datasets"
    response = requests.post(url, auth=optional_auth, json=record_data, timeout=60)
    assert response.status_code == 401


# TODO: this is not test on disabled auth itself but disabled mutual auth - do we want requests with disabled mutual auth to fail?
def test_kerberos_auth_401_disabled_auth(
    run_flask_in_background, record_data, datasets_model, kerberos_identity, disabled_auth, search_clear
):
    """Test a failed POST request due to disabled client authentication ."""
    url = "http://localhost:5000/datasets"
    response = requests.post(url, auth=disabled_auth, json=record_data, timeout=60)
    assert response.status_code == 401


# TODO: search is allowed for unlogged users, the auth isn't done if it isn't preemptive, causing crash on mutual auth
"""
def test_get_request_200(run_flask_in_background, test_setup, kerberos_auth, kerberos_identity, search_clear):
    url = "http://localhost:5000/datasets"
    response = requests.get(url, auth=kerberos_auth)
    assert response.status_code == 200
"""


def test_get_request_200_forced_auth(
    datasets_model,
    record_data,
    service,
    users,
    run_flask_in_background,
    kerberos_auth_forced,
    kerberos_identity,
    search_clear,
):
    """Test a successful GET request, not authentication."""
    service.create(users[0].identity, record_data)
    datasets_model.Record.index.refresh()

    anonymous = Identity(None)
    anonymous.provides.add(any_user)

    assert service.search(users[0].identity).total == 1
    assert service.search(anonymous).total == 0

    url = "http://localhost:5000/datasets"
    response = requests.get(url, auth=kerberos_auth_forced, timeout=60)
    assert response.status_code == 200
    assert len(response.json()["hits"]["hits"]) == 1


def test_response_unauth(
    run_flask_in_background, record_data, datasets_model, kerberos_auth, kerberos_identity, search_clear
):
    """Test a successful POST request with kerberos authentication."""
    url = "http://localhost:5000/datasets"
    response = requests.post(url, json=record_data, timeout=60)
    assert response.status_code == 401


def test_response_original_login(logged_client, datasets_model, record_data, users, kerberos_identity, search_clear):
    """Test a successful POST request with kerberos authentication."""
    response = logged_client(users[0]).post("/datasets", json=record_data)
    assert response.status_code == 201


def test_kerberos_auth_201(
    run_flask_in_background, client, datasets_model, record_data, kerberos_auth, kerberos_identity, search_clear
):
    """Test a successful POST request with kerberos authentication."""
    url = "http://localhost:5000/datasets"
    response = requests.post(url, auth=kerberos_auth, json=record_data, timeout=60)
    assert response.status_code == 201


def test_kerberos_auth_401_disabled_auth_with_user(
    run_flask_in_background, datasets_model, record_data, disabled_auth, kerberos_identity, search_clear
):
    """Test a failed POST request due to disabled client authentication but with correct UserIdentity."""
    url = "http://localhost:5000/datasets"
    response = requests.post(url, auth=disabled_auth, json=record_data, timeout=60)
    assert response.status_code == 401


def test_kerberos_auth_201_optional_auth_with_user(
    run_flask_in_background, datasets_model, record_data, test_setup, optional_auth, kerberos_identity, search_clear
):
    """Test a successful POST request with optional authentication and correct UserIdentity."""
    url = "http://localhost:5000/datasets"
    response = requests.post(url, auth=optional_auth, json=record_data, timeout=60)
    assert response.status_code == 201


@pytest.mark.parametrize(
    "bad_token",
    [
        # Valid base64 that does not decode to a real GSS/SPNEGO token: ``ctx.step``
        # rejects it with a GSSError (the same family of failure as a bad/expired
        # ticket or a service keytab out of sync with the KDC).
        base64.b64encode(b"this is not a valid gssapi token").decode("ascii"),
        # Not valid base64 at all: ``base64.b64decode`` raises ``binascii.Error``.
        "@@@not-base64@@@",
    ],
    ids=["gsserror", "binascii-error"],
)
def test_kerberos_auth_401_on_invalid_negotiate_token(run_flask_in_background, datasets_model, record_data, bad_token):
    """A malformed/invalid Negotiate token must re-challenge with 401, not 500.

    ``GSSAPI.authenticate`` raises (``GSSError`` for an undecryptable token,
    ``binascii.Error`` for non-base64) when a ``Negotiate`` header is present but
    invalid. ``before_request`` must translate that into a 401 Negotiate challenge
    rather than letting it surface as a 500 Internal Server Error.
    """
    url = "http://localhost:5000/datasets"
    response = requests.post(url, headers={"Authorization": f"Negotiate {bad_token}"}, json=record_data, timeout=60)
    assert response.status_code == 401
    assert "Negotiate" in response.headers.get("WWW-Authenticate", "")
