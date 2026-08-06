#
# Copyright (C) 2024 CESNET z.s.p.o.
#
# oarepo-kerberos is free software; you can redistribute it and/or
# modify it under the terms of the MIT License; see LICENSE file for more
# details.
#
"""Oarepo kerberos library."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("oarepo-kerberos")
except PackageNotFoundError:
    __version__ = "0.0.0dev0+unknown"

"""Version of the library."""
