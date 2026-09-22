# SPDX-FileCopyrightText: 2024 CESNET z.s.p.o
# SPDX-License-Identifier: MIT

"""Oarepo kerberos library."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("oarepo-kerberos")
except PackageNotFoundError:
    __version__ = "0.0.0dev0+unknown"

"""Version of the library."""
