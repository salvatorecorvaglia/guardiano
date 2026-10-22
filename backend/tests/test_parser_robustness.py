"""Hostile or broken reports are refused cleanly, never with a 500.

Each sample report is mutated one node at a time -- every value swapped for None, a number, a string,
an empty or odd list, an empty dict -- and each result must either parse or raise ParseError. What
parses is then carried through the steps ingestion takes before touching the database (sanitising,
dedup keys, component keys), since an exception there is a 500 just the same. About 8,000 documents,
deterministic, a second or so.

The first run found two: a component whose name was a list got through the CycloneDX and OSV parsers
and failed in component_key, because components were never sanitised the way findings are.
"""

import copy
import json

import pytest

from app.parsers.base import ParseError
from app.parsers.detect import parse_report
from app.services.dedup import dedup_key
from app.services.ingestion import sanitize, sanitize_component
from app.services.inventory import component_key
from tests.conftest import REPORT_FIXTURES, sample

SAMPLES_BY_FORMAT = {
    "sarif": ["codeql.sarif", "semgrep.sarif"],
    "semgrep": ["semgrep.json"],
    "gitleaks": ["gitleaks.json"],
    "cyclonedx": ["cyclonedx.json"],
    "trivy": ["trivy.json"],
    "grype": ["grype.json"],
    "osv": ["osv.json"],
    "dependency-check": ["dependency-check.json"],
    "npm-audit": ["npm-audit.json"],
    "guardiano": ["guardiano.json"],
    "checkov": ["checkov.json"],
    "kics": ["kics.json"],
    "zap": ["zap.json"],
    "nuclei": ["nuclei.json"],
}
SAMPLES_BY_FORMAT["trivy"].append("trivy-config.json")
REPLACEMENTS = [None, 5, -1, True, "x", "", [], [None], [5], {}, {"x": None}]


def _paths(node, at=()):
    yield at
    if isinstance(node, dict):
        for key, value in node.items():
            yield from _paths(value, (*at, key))
    elif isinstance(node, list):
        for i, value in enumerate(node[:3]):  # the first few of each list cover every shape
            yield from _paths(value, (*at, i))


def _replaced(doc, at, value):
    if not at:
        return value
    doc = copy.deepcopy(doc)
    parent = doc
    for key in at[:-1]:
        parent = parent[key]
    parent[at[-1]] = value
    return doc


def _ingest_without_database(data, fmt):
    report = parse_report(data, fmt)
    for finding in report.findings:
        dedup_key(1, sanitize(finding))
    for component in report.components:
        if (clean := sanitize_component(component)) is not None:
            component_key(clean)


@pytest.mark.parametrize("fmt", list(SAMPLES_BY_FORMAT))
def test_no_mutation_of_a_report_escapes_as_anything_but_a_parse_error(fmt):
    escaped = []
    for name in SAMPLES_BY_FORMAT[fmt]:
        doc = json.loads((REPORT_FIXTURES / name).read_text())
        for at in _paths(doc):
            for value in REPLACEMENTS:
                for detect in (fmt, None):  # named explicitly, and left to auto-detection
                    try:
                        _ingest_without_database(_replaced(doc, at, value), detect)
                    except ParseError:
                        pass
                    except Exception as exc:  # noqa: BLE001 -- anything else would be a 500
                        escaped.append(f"{name} {list(at)} = {value!r}: {type(exc).__name__}: {exc}")
    assert not escaped, f"{len(escaped)} escaped, e.g.:\n" + "\n".join(escaped[:5])


def test_a_component_whose_name_is_not_a_string_does_not_fail_the_upload(client, auth):
    """The case the mutation run found, end to end: this was a 500. The component is skipped and the
    rest of the report is stored."""
    bom = json.loads(sample("cyclonedx.json"))
    bom["components"][0]["name"] = ["not", "a", "name"]
    r = client.post(
        "/api/v1/scans",
        headers=auth["analyst"],
        files={"file": ("bom.json", json.dumps(bom).encode(), "application/json")},
        data={"asset_name": "robust"},
    )
    assert r.status_code == 201, r.text
