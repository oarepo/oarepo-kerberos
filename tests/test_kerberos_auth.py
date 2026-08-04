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
    run_flask_in_background, record_data, datasets_model, kerberos_auth_preemptive, search_clear
):
    """Test a failed POST request due to non-existing UserIdentity."""
    url = "http://localhost:5000/datasets"
    response = requests.post(url, auth=kerberos_auth_preemptive(), json=record_data, timeout=60)
    assert response.status_code == 401
    assert "Negotiate" not in response.headers.get("WWW-Authenticate", "")


def test_search_auth(
    datasets_model,
    test_setup,
    record_data,
    service,
    users,
    run_flask_in_background,
    kerberos_auth_preemptive,
    kerberos_identity,
    search_clear,
):
    """Test a successful GET request, not authentication."""
    anonymous = Identity(None)
    anonymous.provides.add(any_user)

    assert service.search(users[0].identity).total == 1
    assert service.search(anonymous).total == 0

    url = "http://localhost:5000/datasets"
    response = requests.get(url, auth=kerberos_auth_preemptive(), timeout=60)
    assert response.status_code == 200
    assert len(response.json()["hits"]["hits"]) == 1


def test_response_unauth(run_flask_in_background, record_data, datasets_model, kerberos_identity, search_clear):
    """Test a successful POST request with kerberos authentication."""
    url = "http://localhost:5000/datasets"
    response = requests.post(url, json=record_data, timeout=60)
    assert response.status_code == 401


def test_response_original_login(logged_client, datasets_model, record_data, users, kerberos_identity, search_clear):
    """Test a successful POST request with kerberos authentication."""
    response = logged_client(users[0]).post("/datasets", json=record_data)
    assert response.status_code == 201


def test_response_bearer_token(run_flask_in_background, datasets_model, record_data, bearer_token, search_clear):
    """Test a successful POST request authenticated with an OAuth2 Bearer token.

    Mirrors ``test_response_original_login`` but authenticates via an
    ``Authorization: Bearer <token>`` header instead of a session login. No
    Kerberos ticket / GSSAPI negotiation is involved, so this runs against the
    plain test client rather than the background HTTP server.
    """
    response = requests.post(
        "http://localhost:5000/datasets",
        json=record_data,
        headers={"Authorization": f"Bearer {bearer_token}"},
        timeout=60,
    )
    assert response.status_code == 201


def test_response_after_bearer_token(
    run_flask_in_background,
    datasets_model,
    record_data,
    kerberos_auth_preemptive,
    bearer_token,
    kerberos_identity,
    test_setup,
    search_clear,
):

    response = requests.get(
        "http://localhost:5000/datasets",
        headers={"Authorization": f"Bearer {bearer_token}"},
        timeout=60,
    )
    assert response.status_code == 200
    assert len(response.json()["hits"]["hits"]) == 1

    response = requests.get(
        "http://localhost:5000/datasets",
        auth=kerberos_auth_preemptive(),
        timeout=60,
    )
    assert response.status_code == 200
    assert len(response.json()["hits"]["hits"]) == 1


def test_kerberos_auth_201(
    run_flask_in_background,
    datasets_model,
    record_data,
    test_setup,
    kerberos_auth_preemptive,
    kerberos_identity,
    search_clear,
):
    """Test a successful POST request with optional authentication and correct UserIdentity."""
    url = "http://localhost:5000/datasets"
    response = requests.post(url, auth=kerberos_auth_preemptive(), json=record_data, timeout=60)
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


def test_action_needs(
    run_flask_in_background,
    user_with_administration_rights,
    datasets_model,
    record_data,
    kerberos_auth_preemptive,
    kerberos_identity,
    search_clear,
):
    url = "http://localhost:5000/datasets"
    response = requests.post(url, auth=kerberos_auth_preemptive(), json=record_data, timeout=60)
    response = requests.put(
        f"http://localhost:5000/datasets/{response.json()['id']}",
        auth=kerberos_auth_preemptive(),
        json=record_data,
        timeout=60,
    )
    assert response.status_code == 200


def test_non_model_endpoint(
    run_flask_in_background,
    datasets_model,
    record_data,
    kerberos_auth_preemptive,
    search_clear,
):
    """A valid ticket without a matching UserIdentity must 401-challenge everywhere.

    ``/users`` is not a model resource, so it has no resource-level error handler to
    turn the provider's ``NegotiateAuthentication`` into a response. The runtime wraps
    that exception in an ``AuthExceptionGroup``; without the global fallback handler it
    would surface as a 500. The fallback must re-challenge with 401 Negotiate instead.
    """
    url = "http://localhost:5000/users"
    response = requests.get(url, auth=kerberos_auth_preemptive(), json=record_data, timeout=60)
    assert response.status_code == 401
