from flask_resources import HTTPJSONException
from flask_login import current_user
import json

class NegotiateAuthentication(HTTPJSONException):
    def __init__(self,*args, **kwargs):
        if 403 in args:
            self.code = 403
            self.description = 'You do not have permission to access this resource.'
        elif current_user.is_authenticated:
            self.code = 200
            self.description = 'Authenticated successfully.'
        else:
            self.code = 401
            self.description = 'Authentication is required to access this resource.'

        super().__init__(**kwargs)


    def get_headers(self, environ=None, scope=None):
        return [("WWW-Authenticate", "Negotiate")]

    def get_body(self, environ=None, scope=None):
        body = {
            "status": self.code,
            "message": self.get_description(environ)
        }

        return json.dumps(body)
