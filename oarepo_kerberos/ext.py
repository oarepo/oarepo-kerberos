#
# Copyright (C) 2024 CESNET z.s.p.o.
#
# oarepo-kerberos is free software; you can redistribute it and/or
# modify it under the terms of the MIT License; see LICENSE file for more
# details.
#
"""Flask extension for kerberos authentication."""

from __future__ import annotations

import base64
import logging
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from flask import Flask, Response

import flask_login
from flask import g
from flask_gssapi import GSSAPI
from flask_login import current_user
from invenio_accounts.models import UserIdentity

from .cli.cli import kerberos
from .resources.negotiate import NegotiateAuthentication

log = logging.getLogger(__name__)
logging.basicConfig(format="%(levelname)s:%(message)s", level=logging.INFO)


class OarepoKerberosExt:
    """OarepoKerberosExt is an extension for Flask applications to handle.

    Kerberos authentication using GSSAPI. It initializes the GSSAPI,
    manages user authentication, and configures CLI commands for Kerberos.
    """

    def __init__(self, app: Optional[Flask] = None) -> None:
        """Initialize the extension.

        Args:
            app (Optional[Flask]): The Flask application instance.

        """
        self.gssapi = None
        if app:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        """Initialize the Flask application with the extension.

        Registering extension, initializing GSSAPI, adding lifecycle hooks, registering Kerberos CLI
        Args:
            app (Flask): The Flask application instance.
        """
        app.extensions["oarepo-kerberos"] = self
        app.extensions["oarepo-gssapi"] = self.gssapi = GSSAPI(app)

        # Main handling of authentication
        app.before_request(self.before_request)
        app.after_request(self.after_request)

        app.cli.add_command(kerberos)

    def before_request(self) -> None:
        """Authenticate the user before handling the request.

        Executed before each request. Uses GSSAPI to authenticate the user and log them in if successful.

        Raises:
            NegotiateAuthentication: If authentication fails.

        """
        username, out_token = self.gssapi.authenticate()
        if username and out_token:
            realm = username.split("@")[-1]
            identity = UserIdentity.query.filter(
                UserIdentity.id == username,
                UserIdentity.method == f"krb-{realm}",
            ).one_or_none()

            if identity and flask_login.login_user(identity.user):
                log.debug("User %s authenticated and logged in.", username)
                g.kerberos_out_token = out_token
            else:
                log.debug("No matching identity found for Kerberos user.")
                raise NegotiateAuthentication(401)

    def after_request(self, response: Response) -> Response:
        """Modify the response after handling the request.

        Executed after each request. Adds Kerberos tokens to the response headers or prompts for authentication
        if necessary

        Args:
            response (Response): The HTTP response object.

        Returns:
            Response: The modified HTTP response object.

        """
        if hasattr(g, "kerberos_out_token") and g.kerberos_out_token:
            b64_token = base64.b64encode(g.kerberos_out_token).decode("utf-8")
            auth_data = f"Negotiate {b64_token}"
            response.headers["WWW-Authenticate"] = auth_data

        elif response.status_code == 403 or response.status_code == 401:
            if current_user.is_authenticated:
                return response
            response.status_code = 401
            response.headers["WWW-Authenticate"] = "Negotiate"

        return response


def api_finalize_app(app: Flask) -> None:
    """Finalize app.

    Args:
        app (Flask): The Flask application instance.

    """
    finalize_app(app)


def finalize_app(app: Flask) -> None:
    """Finalize app.

    Reordering of after/before requests functions are needed, because initialization is not deterministic.

    Args:
        app (Flask): The Flask application instance.

    """
    log.info("Reordering after_request functions")
    if app.after_request_funcs.get(None):
        app.after_request_funcs[None] = sorted(
            app.after_request_funcs[None],
            key=lambda func: 0
            if func.__qualname__.startswith("OarepoKerberosExt")
            else 1,
        )
    log.info(
        "Current order of after_request functions: %s",
        [func.__qualname__ for func in app.after_request_funcs[None]],
    )

    log.info("Reordering before_request functions")
    if app.before_request_funcs.get(None):
        app.before_request_funcs[None] = sorted(
            app.before_request_funcs[None],
            key=lambda func: 0
            if func.__qualname__.startswith("OarepoKerberosExt")
            else 1,
        )
    log.info(
        "Current before_request functions: %s",
        [func.__qualname__ for func in app.before_request_funcs[None]],
    )
