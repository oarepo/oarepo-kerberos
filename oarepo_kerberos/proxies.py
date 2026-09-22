# SPDX-FileCopyrightText: 2024 CESNET z.s.p.o
# SPDX-License-Identifier: MIT

"""Proxies for accessing the current OARepo kerberos authentication extension without bringing dependencies."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from oarepo_kerberos.ext import KerberosExt

from flask import current_app
from werkzeug.local import LocalProxy

current_kerberos: KerberosExt = LocalProxy(lambda: current_app.extensions["oarepo-kerberos"])  # ty: ignore[invalid-assignment]
"""Helper proxy to get the current kerberos authentication extension."""
