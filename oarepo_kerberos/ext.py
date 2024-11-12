import base64
import flask_login
from flask import request, g
from flask_gssapi import GSSAPI
from invenio_db import db

from .resources.negotiate import NegotiateAuthentication
from invenio_accounts.models import UserIdentity
from .cli.cli import kerberos

class OarepoKerberosExt(object):
    """
        OarepoKerberosExt is an extension for Flask applications to handle
        Kerberos authentication using GSSAPI. It initializes the GSSAPI,
        manages user authentication, and configures CLI commands for Kerberos.
    """
    def __init__(self, app=None):
        self.gssapi = None
        if app:
            self.init_app(app)

    def init_app(self, app):
        """
        Sets up flask extension.

        Registering extension, initializing GSSAPI, adding lifecycle hooks, registering Kerberos CLI
        """
        app.extensions['oarepo-kerberos'] = self
        app.extensions['oarepo-gssapi'] = GSSAPI(app)
        self.gssapi = app.extensions['oarepo-gssapi']

        # Main handling of authentication
        app.before_request(self.before_request)
        app.after_request(self.after_request)

        app.cli.add_command(kerberos)


    def before_request(self):
        """
        Executed before each request. Authenticates the user via GSSAPI.
        If succeeds, user is logged in.
        """
        print(request)
        username, out_token = self.gssapi.authenticate()
        if username and out_token:
            realm = username.split("@")[-1]
            """
            identity = UserIdentity.query.filter(
                UserIdentity.id==username,
                UserIdentity.method==f'krb-{realm}',
            ).one_or_none()
            """
            identity = db.session.query(UserIdentity).filter(
                UserIdentity.id == username,
                UserIdentity.method == f'krb-{realm}'
            ).one_or_none()

            if identity and flask_login.login_user(identity.user):
                print(f"User {username} authenticated and logged in.")
            else:
                print("No matching identity found for Kerberos user.")
                raise NegotiateAuthentication(401)

        #request.kerberos_out_token = out_token
        g.kerberos_out_token = out_token

    def after_request(self, response):
        """
        Executed after each request. If Kerberos authentication was used,
        adds the 'WWW-Authenticate' header with the Kerberos token to the response.
        """
        print(response)
        if hasattr(g, 'kerberos_out_token') and g.kerberos_out_token:
            print("got out token")
            b64_token = base64.b64encode(g.kerberos_out_token).decode('utf-8')
            auth_data = 'Negotiate {0}'.format(b64_token)
            response.headers['WWW-Authenticate'] = auth_data

        return response