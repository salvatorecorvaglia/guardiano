"""Validate disposable database names before the test runner performs destructive setup."""

import re

from sqlalchemy.engine import make_url


def validate_test_database(url: str) -> None:
    database = make_url(url).database or ""
    if not re.fullmatch(r"[A-Za-z0-9_]+_test", database):
        raise ValueError("Refusing destructive test setup: database name must end in _test")
