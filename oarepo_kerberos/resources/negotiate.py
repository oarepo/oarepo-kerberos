#
# Copyright (C) 2024 CESNET z.s.p.o.
#
# oarepo-kerberos is free software; you can redistribute it and/or
# modify it under the terms of the MIT License; see LICENSE file for more
# details.
#
"""Custom HTTP Response for Negotiating authentication."""

from __future__ import annotations

import json
from typing import Any, Optional

from flask_login import current_user
from flask_resources import HTTPJSONException


class NegotiateAuthentication(HTTPJSONException):
    """Custom HTTP exception for Negotiate authentication."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the NegotiateAuthentication exception."""
        if 403 in args:
            self.code = 403
            self.description = "You do not have permission to access this resource."
        elif current_user.is_authenticated:
            self.code = 200
            self.description = "Authenticated successfully."
        else:
            self.code = 401
            self.description = "Authentication is required to access this resource."

        super().__init__(**kwargs)

    def get_headers(
        self, environ: Optional[dict] = None, scope: Optional[dict] = None
    ) -> list[tuple[str, str]]:
        """Get the HTTP headers for the response."""
        return [("WWW-Authenticate", "Negotiate")]

    def get_body(
        self, environ: Optional[dict] = None, scope: Optional[dict] = None
    ) -> str:
        """Get the HTTP body for the response."""
        body = {"status": self.code, "message": self.get_description(environ)}

        return json.dumps(body)
