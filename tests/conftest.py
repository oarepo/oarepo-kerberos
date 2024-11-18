import os
import subprocess
import time
from datetime import datetime
import pytest

from werkzeug.serving import make_server
import threading # for creating running server

from invenio_app.factory import create_api as _create_api
from invenio_accounts.models import UserIdentity, User
from invenio_users_resources.records import UserAggregate
from invenio_db import db as _invenio_db

from requests_kerberos import HTTPKerberosAuth, REQUIRED, OPTIONAL, DISABLED
import logging

logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)

@pytest.fixture(scope='module', autouse=True)
def set_kerberos_env():
    """Set the KRB5_KTNAME environment variable for testing."""
    os.environ['KRB5_KTNAME'] = 'tests/flask.keytab'
    yield

    del os.environ['KRB5_KTNAME']


@pytest.fixture(scope="module")
def extra_entry_points():
    return {
        'invenio_base.apps': [
            "oarepo_kerberos = oarepo_kerberos.ext:OarepoKerberosExt",
        ],
        'invenio_base.api_apps': [
            "oarepo_kerberos = oarepo_kerberos.ext:OarepoKerberosExt"
        ]
    }

@pytest.fixture(scope='module')
def app_config(app_config):
    app_config["JSONSCHEMAS_HOST"] = "localhost"
    app_config["RECORDS_REFRESOLVER_CLS"] = (
        "invenio_records.resolver.InvenioRefResolver"
    )
    app_config["RECORDS_REFRESOLVER_STORE"] = (
        "invenio_jsonschemas.proxies.current_refresolver_store"
    )

    app_config['GSSAPI_HOSTNAME'] = 'localhost'

    app_config['SEARCH_INDEXES'] = {}
    app_config["SEARCH_HOSTS"] = [
        {
            "host": os.environ.get("OPENSEARCH_HOST", "localhost"),
            "port": os.environ.get("OPENSEARCH_PORT", "9200"),
        }
    ]
    app_config["CACHE_TYPE"] = "redis"
    app_config["SQLALCHEMY_DATABASE_URI"] = "postgresql://test:test@127.0.0.1:5432/test"

    return app_config

@pytest.fixture(scope="module")
def create_app():
    """Application factory fixture."""
    return _create_api

@pytest.fixture()
def kerberos_auth():
    """Fixture for Kerberos authentication with mutual authentication required."""
    return HTTPKerberosAuth(mutual_authentication=REQUIRED)

@pytest.fixture()
def disabled_auth():
    """Fixture for no authentication (disabled Kerberos)."""
    return HTTPKerberosAuth(mutual_authentication=DISABLED)

@pytest.fixture()
def optional_auth():
    """Fixture for optional Kerberos authentication, if server supports mutual authentication."""
    return HTTPKerberosAuth(mutual_authentication=OPTIONAL)

@pytest.fixture()
def clean_db():
    try:
        with _invenio_db.session.begin():
            _invenio_db.session.query(UserIdentity).delete()
            _invenio_db.session.query(User).delete()

        _invenio_db.session.commit()
    except Exception as e:
        print(e)


@pytest.fixture()
def users(UserFixture, app, db):
    user1 = UserFixture(
        email="testuser@example.com",
        password="password",
        active=True,
        confirmed=True
    )

    user1.create(app, db)

    db.session.commit()
    UserAggregate.index.refresh()
    return [user1]

@pytest.fixture()
def user_identity(users, app, db):
    try:
        UserIdentity.create(user=users[0],method='krb-EXAMPLE.COM', external_id="user@EXAMPLE.COM")
        db.session.commit()
    except Exception as e:
        print(e)


@pytest.fixture(scope="module")
def create_user_and_identity():
    try:
        user1= User(
            _username="testuser",
            _displayname="Test User",
            _email="testuser@example.com",
            domain="example.com",
            password="hashed_password",
            active=True,
            confirmed_at=datetime.utcnow(),
            version_id=1,
        )

        _invenio_db.session.add(user1)
        _invenio_db.session.commit()
    except Exception as e:
        print(e)
    try:
        user_identity = UserIdentity(id="user@EXAMPLE.COM", method="krb-EXAMPLE.COM", id_user=1)
        _invenio_db.session.add(user_identity)
        _invenio_db.session.commit()
    except Exception as e:
        print(e)

@pytest.fixture(scope='module')
def run_flask_in_background(app):
    """Run Flask in a separate thread to handle HTTP requests."""
    http_server = make_server('localhost', 5000, app, threaded=False)
    def run():
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
