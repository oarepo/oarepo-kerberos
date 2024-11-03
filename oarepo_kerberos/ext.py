import base64
from os import environ
import flask_login
from flask import request
from flask_gssapi import GSSAPI

from .resources.negotiate import NegotiateAuthentication
from .wsgi import OarepoKerberosMiddleware
from invenio_accounts.models import UserIdentity


class OarepoKerberosExt(object):
    def __init__(self, app=None):
        self.gssapi = None
        if app:
            self.init_app(app)

    def init_app(self, app):
        app.extensions['oarepo-kerberos'] = self
        app.extensions['oarepo-gssapi'] = GSSAPI(app)
        self.gssapi = app.extensions['oarepo-gssapi']
        app.before_request(self.before_request)
        app.after_request(self.after_request)


    def before_request(self):
        print(request)
        username, out_token = self.gssapi.authenticate()
        if username:
            identity = UserIdentity.query.filter(UserIdentity.id==username,UserIdentity.method=='kerberos',).one_or_none()
            if identity and flask_login.login_user(identity.user):
                print(f"User {username} authenticated and logged in.")
            else:
                print("No matching identity found for Kerberos user.")
                raise NegotiateAuthentication(403)

        request.kerberos_out_token = out_token

    def after_request(self, response):
        #print(response)
        if request.kerberos_out_token:
            b64_token = base64.b64encode(request.kerberos_out_token).decode('utf-8')
            auth_data = 'Negotiate {0}'.format(b64_token)
            response.headers['WWW-Authenticate'] = auth_data
        return response