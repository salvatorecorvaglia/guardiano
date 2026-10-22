"""Infrastructure-as-code and DAST findings: Checkov, KICS, Trivy misconfigurations, ZAP and Nuclei."""

import json

import pytest
from sqlalchemy import select

from app.models import Asset, Finding
from app.parsers.detect import detect_format, load_json
from app.services.ingestion import IngestOptions, ingest_report
from tests.conftest import sample


@pytest.fixture
def asset(db):
    a = Asset(name="svc", tags=[])
    db.add(a)
    db.commit()
    return a


def findings(db, asset, **where):
    stmt = select(Finding).where(Finding.asset_id == asset.id).order_by(Finding.id)
    for key, value in where.items():
        stmt = stmt.where(getattr(Finding, key) == value)
    return db.scalars(stmt).all()


@pytest.mark.parametrize(
    ("name", "fmt"),
    [("checkov.json", "checkov"), ("kics.json", "kics"), ("zap.json", "zap"), ("nuclei.json", "nuclei"),
     ("trivy-config.json", "trivy")],
)  # fmt: skip
def test_formats_are_recognised(name, fmt):
    assert detect_format(json.loads(sample(name))) == fmt


def test_checkov_failed_checks_only(db, asset):
    scan = ingest_report(db, sample("checkov.json"), asset, None, IngestOptions())
    assert (scan.scan_type, scan.tool_name, scan.new_count) == ("iac", "Checkov", 3)
    by_rule = {f.rule_id: f for f in findings(db, asset)}
    s3 = by_rule["CKV_AWS_18"]
    assert s3.type == "iac" and s3.resource == "aws_s3_bucket.logs" and s3.file_path == "infra/s3.tf"
    assert s3.severity == "medium", "open-source Checkov has no severity: medium, not info"
    assert by_rule["CKV_AWS_24"].severity == "high"
    assert "CKV_AWS_19" not in by_rule  # a passed check


def test_kics_one_finding_per_file(db, asset):
    ingest_report(db, sample("kics.json"), asset, None, IngestOptions())
    rows = findings(db, asset)
    assert {f.resource for f in rows} == {"uploads", "payments-api", "payments-worker"}
    s3 = next(f for f in rows if f.resource == "uploads")
    assert s3.cwe == ["CWE-311"] and "Expected:" in s3.description


def test_trivy_misconfigurations_and_secrets(db, asset):
    scan = ingest_report(db, sample("trivy-config.json"), asset, None, IngestOptions())
    assert scan.scan_type == "iac"
    iac = findings(db, asset, type="iac")
    assert {f.rule_id for f in iac} == {"AVD-DS-0002", "AVD-AWS-0086"}, "a PASS is not a finding"
    assert next(f for f in iac if f.rule_id == "AVD-AWS-0086").resource == "aws_s3_bucket.uploads"
    (secret,) = findings(db, asset, type="sast")
    assert secret.cwe == ["CWE-798"] and secret.severity == "critical"
    assert secret.file_path == "config/settings.py"
    assert secret.snippet is None, "the matched line holds the secret; it is never stored"


def test_zap_instances_and_query_values(db, asset):
    ingest_report(db, sample("zap.json"), asset, None, IngestOptions())
    rows = findings(db, asset)
    sqli = [f for f in rows if f.title == "SQL Injection"]
    # ?id=1 and ?id=2 are the same place; POST /refunds is another.
    assert sorted((f.http_method, f.parameter) for f in sqli) == [("GET", "id"), ("POST", "order")]
    get = next(f for f in sqli if f.http_method == "GET")
    assert get.occurrence_count == 1 and get.severity == "high" and get.cwe == ["CWE-89"]
    assert "Use prepared statements." in get.remediation and "<p>" not in get.remediation
    timestamp = next(f for f in rows if f.title.startswith("Timestamp"))
    assert (
        timestamp.severity == "info"
        and timestamp.cwe == []
        and timestamp.url == "https://payments.example.test"
    )


def test_nuclei_results_and_json_lines(db, asset):
    lines = "\n".join(json.dumps(r) for r in json.loads(sample("nuclei.json"))).encode()
    assert isinstance(load_json(lines), list)
    ingest_report(db, lines, asset, None, IngestOptions())
    rows = findings(db, asset)
    assert len(rows) == 4, "each matcher of tech-detect is its own finding"
    log4j = next(f for f in rows if f.cve_id)
    assert log4j.cve_id == "CVE-2021-44228" and log4j.http_method == "POST" and log4j.severity == "critical"
    assert log4j.cvss_score == 10.0 and "CWE-502" in log4j.cwe
    redis = next(f for f in rows if f.rule_id == "redis-default-logins")
    assert redis.url == "tcp://cache.example.test:6379"


def test_a_broken_json_lines_file_is_still_refused(client, auth, asset):
    files = {"file": ("r.jsonl", b'{"template-id": "x", "info": {}}\n{not json', "application/json")}
    r = client.post("/api/v1/scans", files=files, data={"asset_id": asset.id}, headers=auth["analyst"])
    assert r.status_code == 422


def test_close_missing_covers_every_type_the_run_looked_for(db, asset):
    ingest_report(db, sample("trivy-config.json"), asset, None, IngestOptions())
    fixed = json.loads(sample("trivy-config.json"))
    fixed["Results"][0]["Misconfigurations"] = []  # the Dockerfile now sets a USER
    ingest_report(db, json.dumps(fixed).encode(), asset, None, IngestOptions(close_missing=True))
    status = {f.rule_id: f.status for f in findings(db, asset)}
    assert status["AVD-DS-0002"] == "resolved"
    assert status["AVD-AWS-0086"] == "open" and status["aws-access-key-id"] == "open"


def test_a_package_scan_does_not_close_misconfigurations(db, asset):
    """trivy.json looked only at packages: the misconfigurations it did not look for stay open."""
    ingest_report(db, sample("trivy-config.json"), asset, None, IngestOptions())
    ingest_report(db, sample("trivy.json"), asset, None, IngestOptions(close_missing=True))
    assert {f.status for f in findings(db, asset, type="iac")} == {"open"}


def test_an_iac_finding_follows_its_resource_when_lines_move(db, asset):
    ingest_report(db, sample("checkov.json"), asset, None, IngestOptions())
    moved = json.loads(sample("checkov.json"))
    moved[0]["results"]["failed_checks"][0]["file_line_range"] = [30, 41]
    scan = ingest_report(db, json.dumps(moved).encode(), asset, None, IngestOptions())
    assert scan.new_count == 0


def test_the_list_filters_and_counts_the_new_types(client, auth, db, asset):
    for name in ("checkov.json", "zap.json"):
        ingest_report(db, sample(name), asset, None, IngestOptions())
    r = client.get("/api/v1/findings", params={"type": "dast"}, headers=auth["viewer"])
    assert r.status_code == 200 and {i["type"] for i in r.json()["items"]} == {"dast"}
    assert all(i["url"] for i in r.json()["items"])
    counts = client.get("/api/v1/analytics/summary", headers=auth["viewer"]).json()["open_by_type"]
    assert counts["iac"] == 3 and counts["dast"] == 4
