"""Existing findings' dedup keys must never change.

A changed key makes every stored finding look new on the next scan: duplicates, reopened history lost,
SLA clocks restarted. These are the keys dedup_key produced before IaC and DAST types were added; the
new types have keys of their own, and these inputs must still give exactly these values.
"""

import pytest

from app.parsers.base import NormalizedFinding as N
from app.services.dedup import dedup_key

GOLDEN = {
    "c6943795ac3c4f747408c9b778050f7617733abcdad5b93d63495d53507bf10b": N(
        type="sast", title="SQLi", severity="high", tool_name="x", file_path="./src/App/db.py",
        line_start=42, cwe=["CWE-89", "CWE-20"], rule_id="r1",
    ),
    "83965d6258309fa67b98567b5b219372c75df96c22dba97ca29661bd68a29394": N(
        type="sast", title="t", severity="low", tool_name="x", file_path="a.js", rule_id="no-eval"
    ),
    "fd8c76a6e04b73fec3c7a8ef35b58dae17fae8b5e36fa960ffb5bee2f420d32b": N(
        type="sast", title="Weak TLS", severity="low", tool_name="x", rule_id="tls"
    ),
    "acd230715e35fffd3ab281bda15dbb0dfe059ec767acd942ffc10195f619fbf0": N(
        type="sca", title="t", severity="high", tool_name="x", package_name="lodash",
        package_version="4.17.20", ecosystem="npm", cve_id="CVE-2021-23337",
    ),
    "3c67fb4edc019704be11d08cb55f4e8d1c3b9554023e66cd0d5530a819949f09": N(
        type="sca", title="t", severity="high", tool_name="x", package_name="Django", package_version="3.2",
        ecosystem="PyPI", vuln_id="GHSA-xxxx",
    ),
}  # fmt: skip


@pytest.mark.parametrize("expected", list(GOLDEN))
def test_existing_keys_are_unchanged(expected):
    assert dedup_key(7, GOLDEN[expected]) == expected


pytestmark = pytest.mark.no_database
