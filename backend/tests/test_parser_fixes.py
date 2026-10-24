"""Parser defects that produced wrong data without failing: a skipped score, a mismatched severity, a
result attributed to the wrong rule, a live result dropped as suppressed."""

import logging

import pytest

from app.parsers import cyclonedx, grype, guardiano_json, sarif, trivy_json
from app.parsers.base import normalize_severity


def _sarif(result: dict, rules: list[dict]) -> dict:
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Scanner", "rules": rules}}, "results": [result]}],
    }


_RULES = [
    {"id": "sql", "properties": {"tags": ["CWE-89"]}},
    {"id": "xss", "properties": {"tags": ["CWE-79"]}},
]


def _location(path="a.py", line=3):
    return [{"physicalLocation": {"artifactLocation": {"uri": path}, "region": {"startLine": line}}}]


# ---- SARIF ----------------------------------------------------------------------------------------


def test_rule_index_minus_one_is_no_rule_not_the_last_rule():
    result = {"ruleId": "unlisted", "ruleIndex": -1, "message": {"text": "m"}, "locations": _location()}
    (finding,) = sarif.parse(_sarif(result, _RULES)).findings
    assert "CWE-79" not in finding.cwe, "the last rule's CWE was attached to an unrelated result"
    assert finding.rule_id == "unlisted"


def test_a_real_rule_index_is_still_followed():
    result = {"ruleIndex": 0, "message": {"text": "m"}, "locations": _location()}
    (finding,) = sarif.parse(_sarif(result, _RULES)).findings
    assert finding.rule_id == "sql" and finding.cwe == ["CWE-89"]


def test_only_an_accepted_suppression_hides_a_result():
    def count(suppressions):
        result = {
            "ruleId": "sql",
            "message": {"text": "m"},
            "locations": _location(),
            "suppressions": suppressions,
        }
        return len(sarif.parse(_sarif(result, _RULES)).findings)

    assert count([{"kind": "inSource"}]) == 0  # no status means accepted
    assert count([{"kind": "inSource", "status": "accepted"}]) == 0
    assert count([{"kind": "external", "status": "rejected"}]) == 1  # somebody said it is real
    assert count([{"kind": "external", "status": "underReview"}]) == 1  # not decided yet


# ---- scores and severities ------------------------------------------------------------------------


def test_a_cvss_score_of_zero_is_a_score():
    report = {
        "SchemaVersion": 2,
        "Results": [
            {
                "Target": "requirements.txt",
                "Type": "pip",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2099-1",
                        "PkgName": "x",
                        "InstalledVersion": "1",
                        "Severity": "LOW",
                        "CVSS": {"nvd": {"V3Score": 0.0, "V2Score": 5.0}},
                    }
                ],
            }
        ],
    }
    (finding,) = trivy_json.parse(report).findings
    assert finding.cvss_score == 0.0, "0.0 fell through to the V2 score as if it were missing"


def test_grype_takes_a_zero_score_from_the_advisory_itself():
    report = {
        "descriptor": {"name": "grype", "version": "0"},
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2099-2",
                    "severity": "Low",
                    "cvss": [{"metrics": {"baseScore": 0.0}}],
                },
                "relatedVulnerabilities": [{"id": "CVE-2099-2", "cvss": [{"metrics": {"baseScore": 9.8}}]}],
                "artifact": {"name": "x", "version": "1", "type": "npm", "purl": "pkg:npm/x@1"},
            }
        ],
    }
    (finding,) = grype.parse(report).findings
    assert finding.cvss_score == 0.0


def test_cyclonedx_takes_severity_and_score_from_the_same_rating():
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{"bom-ref": "c", "name": "x", "version": "1", "purl": "pkg:npm/x@1"}],
        "vulnerabilities": [
            {
                "id": "CVE-2099-3",
                "ratings": [
                    {"method": "CVSSv31", "score": 9.8},
                    {"method": "other", "severity": "low"},
                ],
                "affects": [{"ref": "c"}],
            }
        ],
    }
    (finding,) = cyclonedx.parse(bom).findings
    assert (finding.severity, finding.cvss_score) == ("critical", 9.8), "was ('low', 9.8)"


def test_vendor_severity_words_are_understood():
    assert normalize_severity("Important") == "high"  # Red Hat; used to be read as medium
    assert normalize_severity("unimportant") == "info"


def test_an_unrecognised_severity_is_reported_once(caplog):
    with caplog.at_level(logging.WARNING):
        for _ in range(3):
            assert normalize_severity("bananas-level") == "medium"
    messages = [r.getMessage() for r in caplog.records]
    assert sum("unrecognised severity" in msg for msg in messages) == 1
    assert all("bananas-level" not in msg for msg in messages)


# ---- the native format ----------------------------------------------------------------------------


def test_a_single_reference_given_as_a_string_is_one_reference():
    report = {
        "schema": "guardiano/v1",
        "findings": [{"title": "t", "severity": "low", "references": "https://example.test/advisory"}],
    }
    (finding,) = guardiano_json.parse(report).findings
    assert finding.references == [{"url": "https://example.test/advisory"}]


pytestmark = pytest.mark.no_database
