import base64
import gssapi
from invenio_accounts.models import UserIdentity

class OarepoKerberosMiddleware(object):
    def __init__(self, app, previous_wsgi):
        self.app = app
        self.previous_wsgi = previous_wsgi

    def __call__(self, environ, start_response):
        username, out_token = self.authenticate(environ)
        if username:
            with self.app.app_context():
                identity = UserIdentity.query.filter(UserIdentity.id==username,UserIdentity.method=='kerberos',).one_or_none()
                environ['HTTP_REMOTE_USER'] = identity.user.username

        response = self.previous_wsgi(environ, start_response)

        if out_token:
            b64_token = base64.b64encode(out_token).decode('utf-8')
            auth_data = 'Negotiate {0}'.format(b64_token)
            response.headers['WWW-Authenticate'] = auth_data
        return response

    def authenticate(self, environ):
        """Attempts to authenticate the user if a token was provided."""
        if environ.get('HTTP_AUTHORIZATION', '').startswith('Negotiate '):
            in_token = base64.b64decode(environ['HTTP_AUTHORIZATION'][10:])

            try:
                creds = self.app.extensions['gssapi']['creds']
            except KeyError:
                raise RuntimeError('flask-gssapi not configured for this app')

            ctx = gssapi.SecurityContext(creds=creds, usage='accept')

            out_token = ctx.step(in_token)

            if ctx.complete:
                username = ctx.initiator_name
                return str(username), out_token

        return None, None