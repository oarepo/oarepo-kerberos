from flask import current_app
from werkzeug.local import LocalProxy

current_kerberos = LocalProxy(lambda: current_app.extensions["oarepo-kerberos"])
current_gssapi = LocalProxy(lambda: current_app.extensions["oarepo-gssapi"])
"""Helper proxy to get the current gssapi."""