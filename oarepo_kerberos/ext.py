#
# Copyright (C) 2024 CESNET z.s.p.o.
#
# oarepo-kerberos is free software; you can redistribute it and/or
# modify it under the terms of the MIT License; see LICENSE file for more
# details.
#
"""Flask extension for kerberos authentication."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flask import Flask

from flask_gssapi import GSSAPI

from .cli import kerberos

log = logging.getLogger(__name__)


class KerberosExt:
    """OarepoKerberosExt is an extension for Flask applications to handle.

    Kerberos authentication using GSSAPI. It initializes the GSSAPI,
    manages user authentication, and configures CLI commands for Kerberos.
    """

    def __init__(self, app: Flask | None = None) -> None:
        """Initialize the extension.

        Args:
            app (Optional[Flask]): The Flask application instance.

        """
        self.gssapi: GSSAPI | None = None
        if app:
            self.init_app(app)

    def init_app(self, app: Flask) -> None:
        """Initialize the Flask application with the extension.

        Registering extension, initializing GSSAPI, adding lifecycle hooks, registering Kerberos CLI
        Args:
            app (Flask): The Flask application instance.
        """
        app.extensions["oarepo-kerberos"] = self
        if app.config.get("KERBEROS_ENABLED", False):
            app.extensions["oarepo-gssapi"] = self.gssapi = GSSAPI(app)

        app.cli.add_command(kerberos)
