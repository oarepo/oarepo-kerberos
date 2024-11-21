#
# Copyright (C) 2024 CESNET z.s.p.o.
#
# oarepo-kerberos is free software; you can redistribute it and/or
# modify it under the terms of the MIT License; see LICENSE file for more
# details.
#
"""Proxies for accessing the current OARepo kerberos authentication extension without bringing dependencies."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from oarepo_kerberos.ext import OarepoKerberosExt

from flask import current_app
from werkzeug.local import LocalProxy

current_kerberos: OarepoKerberosExt = LocalProxy(
    lambda: current_app.extensions["oarepo-kerberos"]
)
"""Helper proxy to get the current kerberos authentication extension."""
