#
# Copyright (C) 2024 CESNET z.s.p.o.
#
# oarepo-kerberos is free software; you can redistribute it and/or
# modify it under the terms of the MIT License; see LICENSE file for more
# details.
#
"""Custom HTTP Response for Negotiating authentication."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, override

from flask_resources import HTTPJSONException

if TYPE_CHECKING:
    from collections.abc import Mapping


class NegotiateAuthentication(HTTPJSONException):
    """401 challenge that (re-)initiates SPNEGO/Negotiate auth."""

    description = "Authentication is required to access this resource."

    def __init__(self, **kwargs: Any) -> None:
        """Construct."""
        super().__init__(code=401, **kwargs)

    @override
    def get_headers(
        self,
        environ: Any | None = None,
        scope: Mapping[str, Any] | None = None,
    ) -> list[tuple[str, str]]:
        headers = super().get_headers(environ, scope)
        headers.append(("WWW-Authenticate", "Negotiate"))
        return headers  # type:ignore[no-any-return]


class ConflictingAuthentication(HTTPJSONException):
    """400 refusal of a request that carries two sets of credentials."""

    description = (
        "This request carries both a login session and Negotiate credentials. Send only one: "
        "drop the session cookie to authenticate with Kerberos, or omit the Authorization "
        "header to use the session."
    )

    def __init__(self, **kwargs: Any) -> None:
        """Construct."""
        super().__init__(code=400, **kwargs)


class MultiLegNegotiateUnsupported(HTTPJSONException):
    """501 refusal of a negotiation this deployment cannot complete."""

    description = (
        "This SPNEGO exchange needs more than one round trip, which this server does not "
        "implement. Present a credential that authenticates in a single leg, such as a "
        "Kerberos service ticket for this host."
    )

    def __init__(self, **kwargs: Any) -> None:
        """Construct."""
        super().__init__(code=501, **kwargs)


class AccessDenied(HTTPJSONException):
    """403 deny access."""

    description = "Access is denied for this resource."

    def __init__(self, **kwargs: Any) -> None:
        """Construct."""
        super().__init__(code=403, **kwargs)
