import os

import pytest
from invenio_app.factory import create_api as _create_api
from invenio_users_resources.records import UserAggregate
from requests_kerberos import HTTPKerberosAuth, REQUIRED, OPTIONAL, DISABLED

@pytest.fixture(scope='module', autouse=True)
def set_kerberos_env():
    """Set the KRB5_KTNAME environment variable for testing."""
    os.environ['KRB5_KTNAME'] = 'flask.keytab'
    yield

    del os.environ['KRB5_KTNAME']

@pytest.fixture(scope='module')
def app_config(app_config):
    app_config['GSSAPI_HOSTNAME'] = 'localhost'

    app_config['SEARCH_INDEXES'] = {}
    app_config["SEARCH_HOSTS"] = [
        {
            "host": os.environ.get("OPENSEARCH_HOST", "localhost"),
            "port": os.environ.get("OPENSEARCH_PORT", "9400"),
        }
    ]
    app_config["CACHE_TYPE"] = "redis"
    app_config["INVENIO_CACHE_TYPE"] = "redis"
    app_config["CACHE_REDIS_URL"] = (
        f'redis://{os.environ.get("INVENIO_REDIS_HOST", "127.0.0.1")}:'
        f'{os.environ.get("INVENIO_REDIS_PORT", "6579")}/'
        f'{os.environ.get("INVENIO_REDIS_CACHE_DB", "0")}')
    app_config["ACCOUNTS_SESSION_REDIS_URL"] = (
        f'redis://{os.environ.get("INVENIO_REDIS_HOST", "127.0.0.1")}:'
        f'{os.environ.get("INVENIO_REDIS_PORT", "6579")}/'
        f'{os.environ.get("INVENIO_REDIS_SESSION_DB", "1")}')
    app_config["COMMUNITIES_IDENTITIES_CACHE_REDIS_URL"] = (
        f'redis://{os.environ.get("INVENIO_REDIS_HOST", "127.0.0.1")}:'
        f'{os.environ.get("INVENIO_REDIS_PORT", "6579")}/'
        f'{os.environ.get("INVENIO_REDIS_COMMUNITIES_CACHE_DB", "3")}')

    app_config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:?check_same_thread=False"
    return app_config

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

@pytest.fixture(scope="module")
def create_app():
    """Application factory fixture."""
    return _create_api

@pytest.fixture()
def users(app, db, UserFixture):
    user1 = UserFixture(
        email="user@example.org",
        password="password",
        active=True,
        confirmed=True,
    )
    user1.create(app, db)

    user2 = UserFixture(
        email="user2@example.org",
        password="beetlesmasher",
        username="beetlesmasher",
        active=True,
        confirmed=True,
    )
    user2.create(app, db)

    db.session.commit()
    UserAggregate.index.refresh()
    return [user1, user2]

@pytest.fixture()
def kerberos_auth():
    """Fixture for Kerberos authentication with mutual authentication required."""
    return HTTPKerberosAuth(mutual_authentication=REQUIRED)

@pytest.fixture()
def no_auth():
    """Fixture for no authentication (disabled Kerberos)."""
    return HTTPKerberosAuth(mutual_authentication=DISABLED)

@pytest.fixture()
def forbidden_auth():
    """Fixture for invalid Kerberos authentication to simulate 403 Forbidden."""
    # Example of setting mutual_authentication to OPTIONAL, which might cause a 403
    return HTTPKerberosAuth(mutual_authentication=OPTIONAL)

@pytest.fixture(scope="module")
def client(app):
    """Override the default client setup for testing."""
    with app.test_client() as client:
        yield client
