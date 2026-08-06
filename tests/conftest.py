#
# Copyright (C) 2024 CESNET z.s.p.o.
#
# oarepo-kerberos is free software; you can redistribute it and/or
# modify it under the terms of the MIT License; see LICENSE file for more
# details.
#
from __future__ import annotations

import os
import threading  # for creating running server
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, override

import pytest
from flask_principal import ActionNeed, Identity, Need
from invenio_access import ActionUsers
from invenio_access.permissions import authenticated_user
from invenio_accounts.models import UserIdentity
from invenio_app.factory import create_api as _create_api
from invenio_records_permissions import RecordPermissionPolicy
from invenio_records_permissions.generators import (
    AnyUser,
    AuthenticatedUser,
    SystemProcess,
)
from invenio_search.engine import dsl
from oarepo_model.customizations import SetPermissionPolicy
from oarepo_runtime.services.generators import Generator
from requests_kerberos import REQUIRED, HTTPKerberosAuth
from werkzeug.serving import make_server

if TYPE_CHECKING:
    from collections.abc import Collection

    from flask_principal import Identity, Need


# These tests run with a live Kerberos ticket in the environment (from kinit). libpq
# would otherwise try GSSAPI auth against Postgres and fail noisily ("could not initiate
# GSSAPI security context ... Cannot find KDC for realm EXAMPLE.COM") before falling back
# to password auth. The DB connection is not Kerberos-protected, so disable GSS for it.
os.environ.setdefault("PGGSSENCMODE", "disable")

pytest_plugins = [
    "pytest_oarepo.records",
    "pytest_oarepo.fixtures",
    "pytest_oarepo.users",
    "pytest_oarepo.files",
]


class AuthenticatedOnlyVisible(Generator):
    """Read generator whose *query filter* depends on the identity."""

    @override
    def needs(self, **kwargs: Any) -> Collection[Need]:
        """Only authenticated users may read."""
        return [authenticated_user]

    @override
    def query_filter(self, identity: Identity | None = None, **kwargs: Any) -> dsl.query.Query:
        """Match everything for authenticated identities, nothing for anonymous."""
        if identity is not None and authenticated_user in identity.provides:
            return dsl.Q("match_all")
        return dsl.Q("match_none")


class Administration(Generator):
    """Administration permission generator."""

    @override
    def needs(self, **kwargs: Any) -> Collection[Need]:
        return [ActionNeed("administration-access")]

    @override
    def query_filter(self, **kwargs: Any) -> dsl.query.Query:
        return dsl.Q("match_all")


class DatasetsPermissionPolicy(RecordPermissionPolicy):
    """Read visibility is identity-dependent."""

    can_search = (SystemProcess(), AnyUser())
    can_read = (SystemProcess(), AuthenticatedOnlyVisible())
    can_create = (SystemProcess(), AuthenticatedUser())
    can_update = (SystemProcess(), Administration())
    can_delete = (SystemProcess(), AuthenticatedUser())


@pytest.fixture(scope="session")
def datasets_model():
    """Define a second 'restricted-datasets' model with identity-dependent read.

    Same machinery as ``datasets_model`` but with ``RestrictedDatasetsPermissionPolicy``
    (read visible only to authenticated identities). Exposes the ``/restricted-datasets/``
    endpoints used by ``test_search_does_not_apply_kerberos_identity``. Like
    ``datasets_model`` it must be session-scoped and registered exactly once.
    """
    from oarepo_model.api import model
    from oarepo_model.presets.records_resources import records_resources_preset

    restricted_model = model(
        name="datasets",
        version="1.0.0",
        presets=[records_resources_preset],
        types=[
            {
                "Metadata": {
                    "properties": {
                        "title": {"type": "keyword"},
                    },
                },
            }
        ],
        metadata_type="Metadata",
        customizations=[
            SetPermissionPolicy(DatasetsPermissionPolicy),
        ],
    )
    restricted_model.register()
    return restricted_model


@pytest.fixture(scope="module", autouse=True)
def set_kerberos_env():
    """Point krb5/GSSAPI at the local test keytab and KDC for the test process.

    ``KRB5_KTNAME`` is the service keytab used server-side. ``KRB5_CONFIG`` points the
    krb5 *client* at the throwaway KDC (realm EXAMPLE.COM on localhost:2222), which is
    required whenever the client has to acquire a ticket — both the 401-challenge retry
    and preemptive auth (``force_preemptive``). Without it the client falls back to the
    system ``/etc/krb5.conf`` and fails with "Cannot find KDC for realm EXAMPLE.COM".
    ``test-setup.sh`` exports both for ``./run.sh``; setting them here (without
    clobbering an existing ``KRB5_CONFIG``) lets the suite also run straight from an IDE.
    """
    repo_root = Path(__file__).resolve().parent.parent
    previous_config = os.environ.get("KRB5_CONFIG")
    os.environ["KRB5_KTNAME"] = str(repo_root / "tests" / "flask.keytab")
    os.environ.setdefault("KRB5_CONFIG", str(repo_root / "setup_local_kdc" / "krb5-client.conf"))
    yield

    del os.environ["KRB5_KTNAME"]
    if previous_config is None:
        os.environ.pop("KRB5_CONFIG", None)
    else:
        os.environ["KRB5_CONFIG"] = previous_config


@pytest.fixture
def record_data():
    return {"metadata": {"title": "test"}, "files": {"enabled": False}}


@pytest.fixture(scope="module")
def app_config(app_config):
    app_config["GSSAPI_HOSTNAME"] = "localhost"

    # needed for session test
    # The session-based Kerberos tests ride the login session cookie over plain
    # http (the background server has no TLS). Talisman defaults to
    # ``session_cookie_secure=True`` (pytest-invenio only turns off ``force_https``),
    # which stamps ``Secure`` on the cookie and makes ``requests`` rightly refuse
    # to send it back — every follow-up request would be anonymous.
    app_config["APP_DEFAULT_SECURE_HEADERS"]["session_cookie_secure"] = False

    return app_config


@pytest.fixture(scope="module")
def create_app():
    """Application factory fixture."""
    return _create_api


@pytest.fixture
def kerberos_auth_preemptive():
    """Return a fresh preemptive Kerberos auth for each request.

    ``HTTPKerberosAuth`` latches ``auth_done=True`` after the first successful
    mutual authentication and then stops emitting the preemptive
    ``Authorization: Negotiate`` header (see ``__call__``'s
    ``if self.force_preemptive and not self.auth_done`` guard). This server
    authenticates per request (no connection-bound auth), so a single reused
    instance would leave every request after the first anonymous. Hand out a
    factory so each call site — and each loop iteration — gets a new instance.
    """

    def _make() -> HTTPKerberosAuth:
        return HTTPKerberosAuth(mutual_authentication=REQUIRED, force_preemptive=True)

    return _make


@pytest.fixture(autouse=True)
def location(location):
    return location


@pytest.fixture
def kerberos_identity(users, db):
    user = users[0]
    user_identity = UserIdentity(id="user@EXAMPLE.COM", method="krb-EXAMPLE.COM", id_user=user.id)
    db.session.add(user_identity)
    db.session.commit()


@pytest.fixture
def user_with_administration_rights(app, db, users, password):
    """Set administration rights to the first user and return it."""
    actions = app.extensions["invenio-access"].actions
    act = ActionUsers.allow(actions["administration-access"], user_id=users[0].user.id)
    db.session.add(act)
    db.session.commit()


@pytest.fixture
def bearer_token(users, db):
    """Create a personal access token (Bearer token) for ``users[0]``.

    This is the OAuth2 equivalent of the ``kerberos_identity`` mapping: instead of
    linking a Kerberos principal to the Invenio user, it issues a non-expiring
    personal access token. ``invenio_oauth2server``'s API ``before_request`` hook
    reads ``Authorization: Bearer <token>`` and sets ``current_user`` accordingly.
    """
    from invenio_oauth2server.models import Token

    token = Token.create_personal("test-token", users[0].id, scopes=[])
    db.session.commit()
    return token.access_token


@pytest.fixture(scope="module")
def run_flask_in_background(app):
    """Run Flask in a separate thread to handle HTTP requests."""
    http_server = make_server("localhost", 5000, app, threaded=False)

    def run() -> None:
        http_server.serve_forever()

    flask_thread = threading.Thread(target=run)
    flask_thread.daemon = True
    flask_thread.start()

    time.sleep(5)
    try:
        yield
    finally:
        http_server.shutdown()
        flask_thread.join()


@pytest.fixture
def service(app):
    return app.extensions["datasets"].records_service
