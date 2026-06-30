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
    from _typeshed.wsgi import WSGIEnvironment


class NegotiateAuthentication(HTTPJSONException):
    """401 challenge that (re-)initiates SPNEGO/Negotiate auth."""

    description = "Authentication is required to access this resource."

    def __init__(self, **kwargs: Any) -> None:
        """Construct."""
        super().__init__(code=401, **kwargs)

    @override
    def get_headers(
        self,
        environ: WSGIEnvironment | None = None,
        scope: dict[str, Any] | None = None,
    ) -> list[tuple[str, str]]:
        headers = super().get_headers(environ, scope)
        headers.append(("WWW-Authenticate", "Negotiate"))
        return headers
