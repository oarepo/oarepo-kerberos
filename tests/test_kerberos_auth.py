import pytest
import requests
from flask_principal import Identity
from invenio_access import any_user


@pytest.fixture
def test_setup(service, datasets_model, users):
    Record = datasets_model.Record

    title = "ceci ne pas une title"

    user = users[0]
    # Seed a single restricted record (system identity bypasses permissions),
    # then make it live in the search index.
    service.create(user.identity, {"metadata": {"title": title}, "files": {"enabled": False}})
    Record.index.refresh()


def test_kerberos_auth_401_no_user_in_db(run_flask_in_background, test_setup, kerberos_auth, search_clear):
    """Test a failed POST request due to non-existing UserIdentity."""
    url = "http://localhost:5000/datasets"
    response = requests.post(url, auth=kerberos_auth)
    assert response.status_code == 401


def test_kerberos_auth_401_optional_auth_no_user_in_db(
    run_flask_in_background, test_setup, optional_auth, search_clear
):
    """Test a failed POST request with optional authentication but no UserIdentity."""
    url = "http://localhost:5000/datasets"
    response = requests.post(url, auth=optional_auth)
    assert response.status_code == 401


def test_kerberos_auth_401_disabled_auth(run_flask_in_background, test_setup, disabled_auth, search_clear):
    """Test a failed POST request due to disabled client authentication ."""
    url = "http://localhost:5000/datasets"
    response = requests.post(url, auth=disabled_auth)
    assert response.status_code == 401


def test_get_request_200(run_flask_in_background, test_setup, kerberos_auth, kerberos_identity, search_clear):
    """Test a successful GET request, not authentication."""
    url = "http://localhost:5000/datasets"
    response = requests.get(url, auth=kerberos_auth)
    assert response.status_code == 200


def test_get_request_200_forced_auth(
    test_setup,
    service,
    users,
    run_flask_in_background,
    kerberos_auth_forced,
    kerberos_identity,
    search_clear,
):
    """Test a successful GET request, not authentication."""
    anonymous = Identity(None)
    anonymous.provides.add(any_user)

    assert service.search(users[0].identity).total == 1
    assert service.search(anonymous).total == 0

    url = "http://localhost:5000/datasets"
    response = requests.get(url, auth=kerberos_auth_forced)
    assert response.status_code == 200
    assert len(response.json()["hits"]["hits"]) == 1


def test_kerberos_auth_201(run_flask_in_background, test_setup, kerberos_auth, kerberos_identity, search_clear):
    """Test a successful POST request with kerberos authentication."""
    url = "http://localhost:5000/datasets"
    response = requests.post(url, auth=kerberos_auth)
    assert response.status_code == 201


def test_kerberos_auth_401_disabled_auth_with_user(
    run_flask_in_background, test_setup, disabled_auth, kerberos_identity, search_clear
):
    """Test a failed POST request due to disabled client authentication but with correct UserIdentity."""
    url = "http://localhost:5000/datasets"
    response = requests.post(url, auth=disabled_auth)
    assert response.status_code == 401


def test_kerberos_auth_201_optional_auth_with_user(
    run_flask_in_background, test_setup, optional_auth, kerberos_identity, search_clear
):
    """Test a successful POST request with optional authentication and correct UserIdentity."""
    url = "http://localhost:5000/datasets"
    response = requests.post(url, auth=optional_auth)
    assert response.status_code == 201
