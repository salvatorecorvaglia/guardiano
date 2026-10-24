"""Report identity and normalization checks that require no database server."""

import json

import pytest

from app.parsers.base import ParseError
from app.services.scan_report import IngestOptions, prepare_report

pytestmark = pytest.mark.no_database


def test_sarif_indexed_artifacts_remain_distinct_and_keep_regions():
    report = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "scanner"}},
                "artifacts": [{"location": {"uri": path}} for path in ("a.py", "b.py")],
                "results": [
                    {
                        "ruleId": "R1",
                        "message": {"text": "same issue"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"index": index},
                                    "region": {"startLine": 7},
                                }
                            }
                        ],
                    }
                    for index in range(2)
                ],
            }
        ],
    }
    prepared = prepare_report(json.dumps(report).encode(), 1, IngestOptions())
    assert len(prepared.findings.by_key) == 2
    assert {(f.file_path, f.line_start) for f in prepared.findings.by_key.values()} == {
        ("a.py", 7),
        ("b.py", 7),
    }


def test_large_json_integer_is_a_parse_error():
    with pytest.raises(ParseError, match="valid JSON"):
        prepare_report(b'{"findings":[],"n":' + b"9" * 5000 + b"}", 1, IngestOptions())
