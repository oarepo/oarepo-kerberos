import base64
import flask_login
from flask_login import current_user
from flask import g
from flask_gssapi import GSSAPI

from .resources.negotiate import NegotiateAuthentication
from invenio_accounts.models import UserIdentity
from .cli.cli import kerberos

import logging
log = logging.getLogger(__name__)
logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.INFO)

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
        app.extensions['oarepo-gssapi'] = self.gssapi = GSSAPI(app)

        # Main handling of authentication
        app.before_request(self.before_request)
        app.after_request(self.after_request)

        app.cli.add_command(kerberos)


    def before_request(self):
        """
        Executed before each request. Authenticates the user via GSSAPI.
        If succeeds, user is logged in.
        """
        username, out_token = self.gssapi.authenticate()
        if username and out_token:
            realm = username.split("@")[-1]
            identity = UserIdentity.query.filter(
                UserIdentity.id==username,
                UserIdentity.method==f'krb-{realm}',
            ).one_or_none()

            if identity and flask_login.login_user(identity.user):
                log.debug("User %s authenticated and logged in.", username)
                g.kerberos_out_token = out_token
            else:
                log.debug("No matching identity found for Kerberos user.")
                raise NegotiateAuthentication(401)


    def after_request(self, response):
        """
        Executed after each request. If Kerberos authentication was used,
        adds the 'WWW-Authenticate' header with the Kerberos token to the response.
        Tries to authenticate all the time, by sending 401 with "Negotiate" header
        """
        if hasattr(g, 'kerberos_out_token') and g.kerberos_out_token:
            b64_token = base64.b64encode(g.kerberos_out_token).decode('utf-8')
            auth_data = 'Negotiate {0}'.format(b64_token)
            response.headers['WWW-Authenticate'] = auth_data

        elif response.status_code == 403 or response.status_code == 401:
            if current_user.is_authenticated:
                return response
            response.status_code = 401
            response.headers["WWW-Authenticate"] = "Negotiate"

        return response

def api_finalize_app(app):
    """Finalize app."""
    finalize_app(app)

def finalize_app(app):
    """Finalize app.
    Reordering of after/before requests functions are needed, because initialization is not deterministic
    """
    log.info("Reordering after_request functions")
    if app.after_request_funcs.get(None):
        app.after_request_funcs[None] = sorted(
            app.after_request_funcs[None],
            key=lambda func: 0 if func.__qualname__.startswith('OarepoKerberosExt') else 1
        )
    log.info("Current order of after_request functions: %s",
              [func.__qualname__ for func in app.after_request_funcs[None]])

    log.info("Reordering before_request functions")
    if app.before_request_funcs.get(None):
        app.before_request_funcs[None] = sorted(
            app.before_request_funcs[None],
            key=lambda func: 0 if func.__qualname__.startswith('OarepoKerberosExt') else 1
        )
    log.info("Current before_request functions: %s",
              [func.__qualname__ for func in app.before_request_funcs[None]])



