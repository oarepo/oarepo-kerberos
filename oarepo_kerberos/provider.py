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
import binascii
import logging
from typing import TYPE_CHECKING, cast

import flask_login
from flask import current_app, g
from flask_login import current_user
from gssapi.raw.misc import GSSError
from invenio_accounts.models import UserIdentity
from oarepo_runtime.ext import AuthProvider

from .resources.negotiate import NegotiateAuthentication

if TYPE_CHECKING:
    from flask import Response

log = logging.getLogger(__name__)
logging.basicConfig(format="%(levelname)s:%(message)s", level=logging.INFO)


class KerberosProvider(AuthProvider):
    """Kerberos authentication provider."""

    def before_request(self) -> str | None:
        """Authenticate the user before handling the request.

        Executed before each request. Uses GSSAPI to authenticate the user and log them in if successful.

        Raises:
            NegotiateAuthentication: If authentication fails.

        """
        gssapi = current_app.extensions.get("oarepo-gssapi")

        if gssapi is None:
            return None
        try:
            username, out_token = gssapi.authenticate()
        except (GSSError, binascii.Error) as exc:  # TODO: claude suggestion
            # A Negotiate header was present but the token could not be validated:
            # a bad/expired/replayed ticket, a malformed (non-base64) token, or a
            # service keytab out of sync with the KDC. These are client/auth
            # conditions, not server faults, so re-challenge with a 401 Negotiate
            # instead of letting the exception surface as a 500.
            log.warning("Kerberos negotiation failed for Negotiate request.", exc_info=True)
            raise NegotiateAuthentication from exc

        if username:  # TODO: originally "username and out_token"
            realm = username.split("@")[-1]
            identity = UserIdentity.query.filter(
                UserIdentity.id == username,
                UserIdentity.method == f"krb-{realm}",
            ).one_or_none()

            if identity and flask_login.login_user(identity.user):  # TODO: test action needs
                log.debug("User %s authenticated and logged in.", username)
                if out_token:
                    g.kerberos_out_token = out_token
            else:
                log.debug("No matching identity found for Kerberos user.")
                raise NegotiateAuthentication
            return cast("str", username)
        return None

    def after_request(self, response: Response) -> Response | None:
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

        elif response.status_code in (401, 403):
            if current_user.is_authenticated:
                return response
            # TODO: response status code is not equal to json message {'message': 'Permission denied.', 'status': 403}
            response.status_code = 401
            response.headers["WWW-Authenticate"] = "Negotiate"

        return response
