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

from flask import current_app, g, request
from flask_login import current_user
from gssapi.raw.misc import GSSError
from invenio_accounts.models import UserIdentity
from oarepo_runtime.ext import AuthProvider

from oarepo_kerberos.errors import (
    AccessDenied,
    ConflictingAuthentication,
    MultiLegNegotiateUnsupported,
    NegotiateAuthentication,
)

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
            ConflictingAuthentication: If the request carries both a session and Negotiate credentials.
            NegotiateAuthentication: If the presented token could not be validated.
            AccessDenied: If the token is valid but no active user is mapped to the principal.
            MultiLegNegotiateUnsupported: If the mechanism needs more than one round trip.

        """
        gssapi = current_app.extensions.get("oarepo-gssapi")

        if gssapi is None:
            return None

        # not asked for auth
        # Every raise below therefore requires this header, which is what lets
        # ``after_request`` recognise its own responses without marking them.
        if not request.headers.get("Authorization", "").startswith("Negotiate "):
            return None

        # A session cookie and a Negotiate token may name different principals.
        if current_user.is_authenticated:
            raise ConflictingAuthentication

        try:
            # As-of aug 2026
            # flask-gssapi returns (None, None) unless ctx.step completed, dropping any continuation token —
            # hence the 501 at the end of this method.
            username, out_token = gssapi.authenticate()

        except (GSSError, binascii.Error) as exc:
            # A Negotiate header was present but the token could not be validated:
            # a bad/expired/replayed ticket, a malformed (non-base64) token, or a
            # service keytab out of sync with the KDC. These are client/auth
            # conditions, not server faults, so re-challenge with a 401 Negotiate
            # instead of letting the exception surface as a 500.
            log.warning("Kerberos negotiation failed for Negotiate request.", exc_info=True)
            raise NegotiateAuthentication from exc

        g.kerberos_out_token = out_token
        # single leg auth is only valid if we get username
        if username:
            realm = username.split("@")[-1]
            identity = UserIdentity.query.filter(
                UserIdentity.id == username,
                UserIdentity.method == f"krb-{realm}",
            ).one_or_none()

            if identity is None or identity.user is None or not identity.user.is_active:
                log.error("No matching identity found for Kerberos user %s.", username)
                g.kerberos_out_token = None
                raise AccessDenied

            log.debug("User %s prepared for login through Kerberos.", username)
            return identity.user
        # should not happen now; kept as warning in case flask-gssapi changes the authenticate logic
        if out_token:
            log.warning("Flask-gssapi produced out_token without successful authentication.")

        log.error("Multiple leg authentication not supported for Kerberos authentication.")
        raise MultiLegNegotiateUnsupported

    def after_request(self, response: Response) -> Response | None:
        """Modify the response after handling the request.

        Executed after each request. Adds Kerberos tokens to the response headers or prompts for authentication
        if necessary

        Args:
            response (Response): The HTTP response object.

        Returns:
            Response: The modified HTTP response object.

        """
        if current_app.extensions.get("oarepo-gssapi") is None:
            return None

        # Should happen only on successful auth for mutual auth usecase, the token isn't produced otherwise
        if hasattr(g, "kerberos_out_token") and g.kerberos_out_token:
            b64_token = base64.b64encode(g.kerberos_out_token).decode("utf-8")
            auth_data = f"Negotiate {b64_token}"
            response.headers["WWW-Authenticate"] = auth_data
            return response

        # RFC 9110 §15.5.2 requires a 401 to carry a challenge and permits several, so append rather than replace.
        if response.status_code == 401:  # noqa PLR2004
            if not any("Negotiate" in value for value in response.headers.getlist("WWW-Authenticate")):
                response.headers.add("WWW-Authenticate", "Negotiate")
            return None

        # Anonymous calls that result in 403 should challenge.
        # ``is_anonymous`` catches session logins, which send no
        # Authorization header, and the header check catches credentials that were
        # presented and found insufficient -- RFC 9110 §15.5.4, do not re-challenge.
        if (
            response.status_code == 403  # noqa PLR2004
            and current_user.is_anonymous
            and "Authorization" not in request.headers
        ):
            challenge = NegotiateAuthentication()
            response.status_code = challenge.code  # type: ignore[reportAttributeAccessIssue]
            response.set_data(challenge.get_body())
            response.headers.update(challenge.get_headers())
            return response

        return None  # so the next provider can handle it
