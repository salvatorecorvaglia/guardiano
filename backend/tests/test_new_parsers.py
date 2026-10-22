"""Grype, OSV-Scanner, Dependency-Check, npm audit and Gitleaks."""

import json

import pytest
from sqlalchemy import select

from app.models import Asset, Component, Finding
from app.parsers.base import ParseError
from app.parsers.detect import SUPPORTED_FORMATS, detect_format, parse_report
from app.services.ingestion import IngestOptions, ingest_report
from tests.conftest import sample


@pytest.fixture
def asset(db):
    a = Asset(name="svc", tags=[])
    db.add(a)
    db.commit()
    return a


def parsed(name):
    return parse_report(json.loads(sample(name)))


# ---- detection ----------------------------------------------------------------------------------


SAMPLE_FORMATS = {
    "grype.json": "grype",
    "osv.json": "osv",
    "dependency-check.json": "dependency-check",
    "npm-audit.json": "npm-audit",
    "gitleaks.json": "gitleaks",
    "trivy.json": "trivy",
    "cyclonedx.json": "cyclonedx",
    "semgrep.json": "semgrep",
    "guardiano.json": "guardiano",
}


@pytest.mark.parametrize("name,expected_format", SAMPLE_FORMATS.items())
def test_every_sample_is_detected(name, expected_format):
    assert detect_format(json.loads(sample(name))) == expected_format


def test_the_new_formats_are_offered():
    assert set(SUPPORTED_FORMATS) >= {"grype", "osv", "dependency-check", "npm-audit", "gitleaks"}


def test_an_unknown_array_is_rejected_clearly():
    with pytest.raises(ParseError, match="Unrecognised JSON array"):
        detect_format([{"something": "else"}])
    # An empty array is an empty Gitleaks run, which is a legitimate report.
    assert detect_format([]) == "gitleaks"
    assert parse_report([]).findings == []


# ---- Grype --------------------------------------------------------------------------------------


def test_grype(db, asset):
    report = parsed("grype.json")
    assert (report.format, report.tool_name, report.scan_type) == ("grype", "Grype", "sca")
    by_package = {f.package_name: f for f in report.findings}

    lodash = by_package["lodash"]
    # Grype reports the GHSA; the CVE arrives through relatedVulnerabilities.
    assert lodash.cve_id == "CVE-2021-23337" and lodash.vuln_id == "GHSA-35jh-r3h4-6jhm"
    assert (lodash.severity, lodash.cvss_score, lodash.fixed_version) == ("high", 7.2, "4.17.21")
    assert lodash.ecosystem == "npm" and lodash.file_path == "/app/package-lock.json"

    log4j = by_package["org.apache.logging.log4j:log4j-core"]
    assert (log4j.cve_id, log4j.severity, log4j.fixed_version) == ("CVE-2021-44228", "critical", "2.15.0")
    assert log4j.ecosystem == "maven"


# ---- OSV-Scanner --------------------------------------------------------------------------------


def test_osv(db, asset):
    report = parsed("osv.json")
    assert report.tool_name == "OSV-Scanner"
    by_package = {f.package_name: f for f in report.findings}

    lodash = by_package["lodash"]
    assert lodash.cve_id == "CVE-2021-23337" and lodash.vuln_id == "GHSA-35jh-r3h4-6jhm"
    assert (lodash.severity, lodash.cvss_score, lodash.fixed_version) == ("high", 7.2, "4.17.21")
    assert lodash.cwe == ["CWE-77"] and lodash.title == "Command Injection in lodash"

    requests = by_package["requests"]
    assert requests.severity == "medium" and requests.ecosystem == "pypi"  # "MODERATE", "PyPI"
    assert requests.fixed_version == "2.20.0"

    # OSV lists the packages it scanned, so it also feeds the inventory.
    assert {(c.name, c.version) for c in report.components} == {("lodash", "4.17.20"), ("requests", "2.19.1")}


# ---- Dependency-Check ---------------------------------------------------------------------------


def test_dependency_check(db, asset):
    report = parsed("dependency-check.json")
    assert (report.tool_name, report.tool_version) == ("OWASP Dependency-Check", "10.0.4")
    by_cve = {f.cve_id: f for f in report.findings}

    log4j = by_cve["CVE-2021-44228"]
    # group:artifact, the same shape CycloneDX produces, so the two tools deduplicate.
    assert log4j.package_name == "org.apache.logging.log4j:log4j-core"
    assert (log4j.severity, log4j.cvss_score, log4j.cwe) == ("critical", 10.0, ["CWE-502"])
    assert log4j.file_path == "/app/lib/log4j-core-2.14.1.jar"

    # The severity string wins over the score when they disagree, as the tool reported it.
    assert by_cve["CVE-2022-42889"].severity == "high" and by_cve["CVE-2022-42889"].cvss_score == 9.8
    assert {c.licenses[0] for c in report.components if c.licenses} == {"Apache-2.0"}


# ---- npm audit ----------------------------------------------------------------------------------


def test_npm_audit(db, asset):
    report = parsed("npm-audit.json")
    assert report.tool_name == "npm audit"
    by_package = {f.package_name: f for f in report.findings}

    lodash = by_package["lodash"]
    assert lodash.title == "Command Injection in lodash" and lodash.severity == "high"
    assert (lodash.cvss_score, lodash.fixed_version, lodash.cwe) == (7.2, "4.17.21", ["CWE-77"])
    assert lodash.vuln_id == "GHSA-35jh-r3h4-6jhm" and lodash.ecosystem == "npm"
    assert "Upgrade lodash to 4.17.21." in lodash.remediation

    minimist = by_package["minimist"]
    assert minimist.severity == "critical"
    # fixAvailable can be a bare true, which names no version.
    assert minimist.fixed_version is None and "No fixed version" in minimist.remediation


def test_npm_audit_needs_npm_7():
    with pytest.raises(ParseError, match="npm 7"):
        parse_report({"advisories": {}, "auditReportVersion": 1}, "npm-audit")


# ---- Gitleaks -----------------------------------------------------------------------------------


def test_gitleaks_never_stores_the_secret(db, asset):
    raw = sample("gitleaks.json")
    secrets = [f["Secret"] for f in json.loads(raw)]
    report = parse_report(json.loads(raw))
    assert (report.format, report.scan_type, report.tool_name) == ("gitleaks", "sast", "Gitleaks")

    serialised = json.dumps([f.__dict__ for f in report.findings], default=str)
    for secret in secrets:
        assert secret not in serialised, "the secret itself must never be kept"

    aws = report.findings[0]
    assert aws.title == "AWS Access Key" and aws.severity == "critical"
    assert aws.cwe == ["CWE-798"] and aws.rule_id == "aws-access-token"
    assert (aws.file_path, aws.line_start) == ("deploy/terraform/provider.tf", 12)
    # Enough of the line to recognise it, with the whole value blanked -- not the first four
    # characters of it, which for a generic rule are four characters of a live credential.
    assert aws.snippet == "aws_access_key_id = ************"
    assert "Commit: 9f2c1abf8d4e" in aws.description
    assert aws.fingerprint == "deploy/terraform/provider.tf:aws-access-token:12"


def test_gitleaks_redaction_edge_cases():
    from app.parsers.gitleaks import redact

    assert redact("token=abc", "abc") == "token=************"
    assert redact(None, "x") is None
    # Fails closed. Without a Secret to match, or when Gitleaks normalised it so it no longer appears
    # in Match, there is no way to know which part of the line is the credential -- so none of the
    # line is kept. Keeping it is how the raw secret used to reach findings.snippet.
    assert redact("aws_key = AKIAIOSFODNN7EXAMPLE", None) is None
    assert redact("aws_key = AKIAIOSFODNN7EXAMPLE", "") is None
    assert redact("aws_key =  AKIAIOSFODNN7EXAMPLE", "AKIA IOSFODNN7EXAMPLE") is None
    # And nothing of the secret survives, not even a hint of it.
    assert "AKIA" not in redact("aws_key = AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE")


# ---- ingestion ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name,expected",
    [
        ("grype.json", 2),
        ("osv.json", 2),
        ("dependency-check.json", 2),
        ("npm-audit.json", 2),
        ("gitleaks.json", 2),
    ],
)
def test_every_new_format_ingests(db, asset, name, expected):
    scan = ingest_report(db, sample(name), asset, None, IngestOptions())
    assert scan.new_count == expected
    assert len(db.scalars(select(Finding)).all()) == expected
    # Re-ingesting the same report changes nothing: the dedup keys are stable.
    again = ingest_report(db, sample(name), asset, None, IngestOptions())
    assert (again.new_count, again.duplicate_count) == (0, expected)


def test_osv_fills_the_inventory_on_ingest(db, asset):
    ingest_report(db, sample("osv.json"), asset, None, IngestOptions())
    assert {c.name for c in db.scalars(select(Component))} == {"lodash", "requests"}


def test_uploading_each_format_over_the_api(client, auth):
    for name in ("grype.json", "osv.json", "dependency-check.json", "npm-audit.json", "gitleaks.json"):
        r = client.post(
            "/api/v1/scans",
            headers=auth["analyst"],
            files={"file": (name, sample(name), "application/json")},
            data={"asset_name": f"asset-{name}"},
        )
        assert r.status_code == 201, r.text
        assert r.json()["format"] == name.removesuffix(".json")


def test_package_names_match_across_tools(db, asset):
    """The same maven package from CycloneDX and Dependency-Check must be one finding, not two."""
    from app.parsers.detect import parse_report

    dc = parse_report(json.loads(sample("dependency-check.json")))
    names = {f.package_name for f in dc.findings}
    assert "org.apache.logging.log4j:log4j-core" in names  # group:artifact, as CycloneDX reports it
    assert "org.apache.commons:commons-text" in names

    ingest_report(db, sample("cyclonedx.json"), asset, None, IngestOptions())
    before = len(db.scalars(select(Finding)).all())
    scan = ingest_report(db, sample("dependency-check.json"), asset, None, IngestOptions())

    log4j = db.scalars(
        select(Finding).where(Finding.cve_id == "CVE-2021-44228", Finding.asset_id == asset.id)
    ).all()
    assert len(log4j) == 1, "the same CVE on the same package from two tools is one finding"
    assert sorted(log4j[0].tools) == ["OWASP Dependency-Check", "OWASP Dependency-Track"]
    assert scan.new_count == len(db.scalars(select(Finding)).all()) - before
