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
from flask_principal import Identity, Need
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
from requests_kerberos import DISABLED, OPTIONAL, REQUIRED, HTTPKerberosAuth
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
    """Read generator whose *query filter* genuinely depends on the identity.

    Invenio's own ``AuthenticatedUser.query_filter`` returns ``match_all``
    unconditionally (see invenio_records_permissions.generators), so it does NOT
    actually restrict *search* visibility by identity. This generator does:
    authenticated identities match every record, anonymous identities match none.

    It exists to expose an architectural gap in OarepoKerberosExt: identity is
    established only by downgrading a 401/403 to a Negotiate challenge
    (``after_request``). A search is gated by ``can_search`` (here open to anyone),
    so it returns a *filtered 200*, never a 403 — the challenge never fires and the
    Kerberos ticket-holder is filtered as an anonymous user. See
    ``test_search_does_not_apply_kerberos_identity``.
    """

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


class DatasetsPermissionPolicy(RecordPermissionPolicy):
    """Read visibility is identity-dependent."""

    can_search = (SystemProcess(), AnyUser())
    can_read = (SystemProcess(), AuthenticatedOnlyVisible())
    can_create = (SystemProcess(), AuthenticatedUser())
    can_update = (SystemProcess(), AuthenticatedUser())
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


"""
@pytest.fixture(scope="module")
def extra_entry_points(datasets_model):
    # Depending on the model fixtures forces the runtime models to register their
    # entry points (via sys.meta_path) before the Invenio app is created, so the
    # app discovers the ``/datasets/`` and ``/restricted-datasets/`` services and
    # resources.
    return {
        "invenio_base.apps": [
            "oarepo_kerberos = oarepo_kerberos.ext:OarepoKerberosExt",
        ],
        "invenio_base.api_apps": ["oarepo_kerberos = oarepo_kerberos.ext:OarepoKerberosExt"],
    }
"""


@pytest.fixture(scope="module")
def app_config(app_config):
    app_config["JSONSCHEMAS_HOST"] = "localhost"
    app_config["RECORDS_REFRESOLVER_CLS"] = "invenio_records.resolver.InvenioRefResolver"
    app_config["RECORDS_REFRESOLVER_STORE"] = "invenio_jsonschemas.proxies.current_refresolver_store"
    app_config["GSSAPI_HOSTNAME"] = "localhost"
    app_config["CACHE_TYPE"] = "redis"

    return app_config


@pytest.fixture(scope="module")
def create_app():
    """Application factory fixture."""
    return _create_api


@pytest.fixture
def kerberos_auth():
    """Fixture for Kerberos authentication with mutual authentication required."""
    return HTTPKerberosAuth(mutual_authentication=REQUIRED)


@pytest.fixture
def kerberos_auth_forced():
    return HTTPKerberosAuth(mutual_authentication=REQUIRED, force_preemptive=True)


@pytest.fixture
def disabled_auth():
    """Fixture for no authentication (disabled Kerberos)."""
    return HTTPKerberosAuth(mutual_authentication=DISABLED)


@pytest.fixture
def optional_auth():
    """Fixture for optional Kerberos authentication, if server supports mutual authentication."""
    return HTTPKerberosAuth(mutual_authentication=OPTIONAL)


@pytest.fixture(autouse=True)
def location(location):
    return location


@pytest.fixture
def kerberos_identity(users, db):
    user = users[0]
    user_identity = UserIdentity(id="user@EXAMPLE.COM", method="krb-EXAMPLE.COM", id_user=user.id)
    db.session.add(user_identity)
    db.session.commit()


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
