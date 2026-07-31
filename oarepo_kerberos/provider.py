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
from typing import TYPE_CHECKING

from flask import current_app, g
from flask_login import current_user
from gssapi.raw.misc import GSSError
from invenio_accounts.models import UserIdentity
from oarepo_runtime.ext import AuthProvider

from .resources.negotiate import NegotiateAuthentication

if TYPE_CHECKING:
    from flask import Response
    from invenio_accounts.models import User

log = logging.getLogger(__name__)


class KerberosProvider(AuthProvider):
    """Kerberos authentication provider."""

    def before_request(self) -> User | None:
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
        except (GSSError, binascii.Error) as exc:
            # A Negotiate header was present but the token could not be validated:
            # a bad/expired/replayed ticket, a malformed (non-base64) token, or a
            # service keytab out of sync with the KDC. These are client/auth
            # conditions, not server faults, so re-challenge with a 401 Negotiate
            # instead of letting the exception surface as a 500.
            log.warning("Kerberos negotiation failed for Negotiate request.", exc_info=True)
            raise NegotiateAuthentication from exc

        if username:
            realm = username.split("@")[-1]
            identity = UserIdentity.query.filter(
                UserIdentity.id == username,
                UserIdentity.method == f"krb-{realm}",
            ).one_or_none()

            if identity is None or identity.user is None:
                log.debug("No matching identity found for Kerberos user.")
                raise NegotiateAuthentication

            log.debug("User %s authenticated.", username)
            if out_token:
                g.kerberos_out_token = out_token
            return identity.user

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
            # TODO: what about after_request of providers after this?
            response.status_code = 401
            response.headers["WWW-Authenticate"] = "Negotiate"

        return response
