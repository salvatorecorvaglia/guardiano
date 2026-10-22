import json

import pytest

from app.parsers.base import ParseError, normalize_cwe
from app.parsers.detect import detect_format, parse_report
from app.services.dedup import normalize_path
from tests.conftest import sample


def load(name):
    return json.loads(sample(name))


@pytest.mark.parametrize(
    "name,fmt",
    [
        ("codeql.sarif", "sarif"),
        ("semgrep.sarif", "sarif"),
        ("semgrep.json", "semgrep"),
        ("cyclonedx.json", "cyclonedx"),
        ("trivy.json", "trivy"),
        ("guardiano.json", "guardiano"),
    ],
)
def test_detect_format(name, fmt):
    assert detect_format(load(name)) == fmt


def test_unknown_format_rejected():
    with pytest.raises(ParseError):
        detect_format({"foo": "bar"})
    with pytest.raises(ParseError):
        parse_report([1, 2, 3])


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("79", "CWE-79"),
        (79, "CWE-79"),
        ("CWE-079", "CWE-79"),
        ("external/cwe/cwe-089", "CWE-89"),
        ("CWE-89: SQL Injection", "CWE-89"),
        ("nope", None),
    ],
)
def test_normalize_cwe(raw, expected):
    assert normalize_cwe(raw) == expected


def test_sarif_codeql():
    r = parse_report(load("codeql.sarif"))
    assert (r.tool_name, r.tool_version, r.scan_type) == ("CodeQL", "2.17.6", "sast")
    assert len(r.findings) == 6
    sqli = next(f for f in r.findings if f.rule_id == "js/sql-injection")
    assert sqli.cwe == ["CWE-89", "CWE-90"]
    assert sqli.severity == "high" and sqli.cvss_score == 8.8
    assert sqli.file_path == "src/routes/orders.js" and sqli.line_start == 42
    assert "db.query" in sqli.snippet
    creds = next(f for f in r.findings if f.rule_id == "js/hardcoded-credentials")
    assert creds.severity == "critical"  # security-severity 9.8 wins over level=warning


def test_sarif_semgrep_tags_and_level_fallback():
    r = parse_report(load("semgrep.sarif"))
    redirect = next(f for f in r.findings if "open-redirect" in f.rule_id)
    assert redirect.cwe == ["CWE-601"]
    assert redirect.severity == "medium"  # level=warning, no security-severity
    assert redirect.title.startswith("The application redirects")


def test_semgrep_json():
    r = parse_report(load("semgrep.json"))
    assert r.tool_name == "Semgrep" and len(r.findings) == 5
    sev = {f.rule_id.rsplit(".", 1)[-1]: f.severity for f in r.findings}
    assert sev["sql-injection-db-cursor-execute"] == "high"
    assert sev["insecure-hash-algorithm-md5"] == "low"


def test_cyclonedx():
    r = parse_report(load("cyclonedx.json"))
    assert r.scan_type == "sca" and r.tool_name == "OWASP Dependency-Track"
    assert len(r.findings) == 8
    by_vuln = {f.vuln_id: f for f in r.findings}
    axios = by_vuln["GHSA-cph5-m8f7-6c5x"]
    assert axios.cve_id == "CVE-2021-3749"  # resolved through references
    assert axios.package_name == "axios" and axios.package_version == "0.21.1" and axios.ecosystem == "npm"
    assert axios.fixed_version == "0.21.2"
    log4j = by_vuln["CVE-2021-44228"]
    assert log4j.package_name == "org.apache.logging.log4j:log4j-core"
    assert log4j.severity == "critical" and log4j.cvss_score == 10.0
    assert log4j.cwe == ["CWE-20", "CWE-400", "CWE-502"]


def test_trivy():
    r = parse_report(load("trivy.json"))
    assert r.tool_name == "Trivy" and r.tool_version == "0.55.2"
    assert len(r.findings) == 6
    django = next(f for f in r.findings if f.package_name == "django")
    assert django.severity == "critical" and django.ecosystem == "pypi" and django.cvss_score == 9.8


def test_guardiano_native_validation():
    r = parse_report(load("guardiano.json"))
    assert r.tool_name == "Internal Secret Scanner" and len(r.findings) == 2
    assert r.findings[1].cwe == ["CWE-321"]
    with pytest.raises(ParseError):
        parse_report({"schema": "guardiano/v1", "findings": [{"severity": "high"}]})
    with pytest.raises(ParseError):
        parse_report({"schema": "guardiano/v1", "findings": [{"title": "x", "type": "container"}]})


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("./src/a.js", "src/a.js"),
        ("file:///repo/src/a.js", "repo/src/a.js"),
        ("src\\a.js", "src/a.js"),
        ("%SRCROOT%/src/a.js", "src/a.js"),
        ("/src//a.js", "src/a.js"),
        (None, ""),
    ],
)
def test_normalize_path(raw, expected):
    assert normalize_path(raw) == expected
