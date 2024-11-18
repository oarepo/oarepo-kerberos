from datetime import datetime

from invenio_db import db
from invenio_accounts.models import UserIdentity, User

import requests

def test_kerberos_auth_401_no_user_in_db(run_flask_in_background, kerberos_auth):
    """Test a failed POST request due to non-existing UserIdentity."""

    url = "http://localhost:5000/datasets/"
    response = requests.post(url, auth=kerberos_auth, verify=False)
    assert response.status_code == 401

def test_kerberos_auth_401_optional_auth_no_user_in_db(run_flask_in_background, optional_auth):
    """Test a failed POST request with optional authentication but no UserIdentity."""

    url = "http://localhost:5000/datasets/"
    response = requests.post(url, auth=optional_auth, verify=False)
    assert response.status_code == 401

def test_kerberos_auth_401_disabled_auth(run_flask_in_background, disabled_auth):
    """Test a failed POST request due to disabled client authentication ."""

    url = "http://localhost:5000/datasets/"
    response = requests.post(url, auth=disabled_auth, verify=False)
    assert response.status_code == 401

def test_get_request_200(run_flask_in_background, kerberos_auth, create_user_and_identity, app):
    """Test a successful GET request, not authentication."""

    url = "http://localhost:5000/datasets/"
    with app.app_context():
        print(f"After request funcs: {app.after_request_funcs.get(None)}")
        print("----------------------")
        print(f"Before request funcs: {app.before_request_funcs.get(None)}")

    response = requests.get(url, auth=kerberos_auth, verify=False)
    assert response.status_code == 200

def test_kerberos_auth_200(run_flask_in_background, kerberos_auth, create_user_and_identity, app):
    """Test a successful POST request with kerberos authentication."""

    url = "http://localhost:5000/datasets/"
    with app.app_context():
        print(f"After request funcs: {app.after_request_funcs.get(None)}")
        print("----------------------")
        print(f"Before request funcs: {app.before_request_funcs.get(None)}")
    response = requests.post(url, auth=kerberos_auth, verify=False)
    assert response.status_code == 201


def test_kerberos_auth_401_disabled_auth_with_user(run_flask_in_background, disabled_auth, create_user_and_identity, app):
    """Test a failed POST request due to disabled client authentication but with correct UserIdentity."""

    url = "http://localhost:5000/datasets/"
    with app.app_context():
        print(f"After request funcs: {app.after_request_funcs.get(None)}")
        print("----------------------")
        print(f"Before request funcs: {app.before_request_funcs.get(None)}")
    response = requests.post(url, auth=disabled_auth, verify=False)
    assert response.status_code == 401


def test_kerberos_auth_200_optional_auth_with_user(run_flask_in_background, optional_auth, create_user_and_identity, app):
    """Test a successful POST request with optional authentication and correct UserIdentity."""

    url = "http://localhost:5000/datasets/"
    with app.app_context():
        print(f"After request funcs: {app.after_request_funcs.get(None)}")
        print("----------------------")
        print(f"Before request funcs: {app.before_request_funcs.get(None)}")
    response = requests.post(url, auth=optional_auth, verify=False)
    assert response.status_code == 201

