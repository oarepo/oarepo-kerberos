from flask import current_app
from werkzeug.local import LocalProxy

current_kerberos = LocalProxy(lambda: current_app.extensions["oarepo-kerberos"])
"""Helper proxy to get the current kerberos authentication extension."""