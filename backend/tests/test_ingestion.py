import json
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.models import Asset, Finding, FindingEvent
from app.models.base import utcnow
from app.models.enums import Status
from app.parsers.base import ParseError
from app.services import lifecycle
from app.services.ingestion import IngestOptions, ingest_report
from tests.conftest import sample


@pytest.fixture
def asset(db):
    a = Asset(name="svc", tags=[])
    db.add(a)
    db.commit()
    return a


def native(tool, findings, scan_type="sast"):
    return json.dumps(
        {"schema": "guardiano/v1", "tool": {"name": tool}, "scan_type": scan_type, "findings": findings}
    ).encode()


def findings(db, asset):
    return db.scalars(select(Finding).where(Finding.asset_id == asset.id).order_by(Finding.id)).all()


def test_reingest_same_report_is_all_duplicates(db, asset):
    s1 = ingest_report(db, sample("codeql.sarif"), asset, None, IngestOptions())
    s2 = ingest_report(db, sample("codeql.sarif"), asset, None, IngestOptions())
    assert (s1.new_count, s1.duplicate_count) == (6, 0)
    assert (s2.new_count, s2.duplicate_count) == (0, 6)
    assert len(findings(db, asset)) == 6
    assert all(f.occurrence_count == 2 for f in findings(db, asset))


def test_changed_line_creates_new_finding(db, asset):
    base = {"title": "SQLi", "severity": "high", "cwe": ["CWE-89"], "file_path": "a.py", "line_start": 10}
    ingest_report(db, native("t", [base]), asset, None, IngestOptions())
    s = ingest_report(db, native("t", [{**base, "line_start": 11}]), asset, None, IngestOptions())
    assert s.new_count == 1 and len(findings(db, asset)) == 2


def test_cross_tool_sast_dedup(db, asset):
    ingest_report(db, sample("codeql.sarif"), asset, None, IngestOptions())
    s = ingest_report(db, sample("semgrep.sarif"), asset, None, IngestOptions())
    # Semgrep's tainted-sql-string hits the same file/line/CWE as CodeQL's js/sql-injection.
    assert (s.new_count, s.duplicate_count) == (2, 1)
    sqli = db.scalar(select(Finding).where(Finding.file_path == "src/routes/orders.js"))
    assert sqli.tools == ["CodeQL", "Semgrep OSS"]
    assert sqli.title == "Database query built from user-controlled sources"  # primary tool keeps metadata


def test_cross_tool_sca_dedup(db, asset):
    ingest_report(db, sample("cyclonedx.json"), asset, None, IngestOptions())
    s = ingest_report(db, sample("trivy.json"), asset, None, IngestOptions())
    assert s.duplicate_count == 1  # lodash CVE-2021-23337
    lodash = db.scalar(select(Finding).where(Finding.cve_id == "CVE-2021-23337"))
    assert set(lodash.tools) == {"OWASP Dependency-Track", "Trivy"}


def test_in_report_duplicates_collapse(db, asset):
    f = {"title": "x", "severity": "low", "cwe": ["CWE-1"], "file_path": "a", "line_start": 1}
    s = ingest_report(db, native("t", [f, {**f, "severity": "critical"}]), asset, None, IngestOptions())
    assert s.total_count == 1
    assert findings(db, asset)[0].severity == "critical"


def test_resolved_finding_reopens(db, asset):
    ingest_report(db, sample("semgrep.json"), asset, None, IngestOptions())
    f = findings(db, asset)[0]
    lifecycle.set_status(db, f, Status.resolved, actor=None)
    db.commit()
    s = ingest_report(db, sample("semgrep.json"), asset, None, IngestOptions())
    db.refresh(f)
    assert s.reopened_count == 1 and f.status == "open" and f.closed_at is None
    assert db.scalar(
        select(FindingEvent).where(FindingEvent.finding_id == f.id, FindingEvent.event == "reopened")
    )


def test_false_positive_stays_suppressed(db, asset):
    ingest_report(db, sample("semgrep.json"), asset, None, IngestOptions())
    f = findings(db, asset)[0]
    lifecycle.set_status(db, f, Status.false_positive, actor=None, justification="test code")
    db.commit()
    s = ingest_report(db, sample("semgrep.json"), asset, None, IngestOptions())
    db.refresh(f)
    assert s.reopened_count == 0 and f.status == "false_positive"


def test_expired_risk_acceptance_reopens(db, asset):
    ingest_report(db, sample("semgrep.json"), asset, None, IngestOptions())
    active, expired = findings(db, asset)[:2]
    lifecycle.set_status(
        db,
        active,
        Status.risk_accepted,
        actor=None,
        justification="ok",
        risk_accepted_until=utcnow() + timedelta(days=30),
    )
    lifecycle.set_status(
        db,
        expired,
        Status.risk_accepted,
        actor=None,
        justification="ok",
        risk_accepted_until=utcnow() - timedelta(days=1),
    )
    db.commit()
    s = ingest_report(db, sample("semgrep.json"), asset, None, IngestOptions())
    db.refresh(active)
    db.refresh(expired)
    assert s.reopened_count == 1
    assert active.status == "risk_accepted" and expired.status == "open"


def test_close_missing_auto_resolves_same_tool_only(db, asset):
    a = {"title": "A", "severity": "high", "cwe": ["CWE-1"], "file_path": "a", "line_start": 1}
    b = {"title": "B", "severity": "high", "cwe": ["CWE-2"], "file_path": "b", "line_start": 1}
    other = {"title": "C", "severity": "high", "cwe": ["CWE-3"], "file_path": "c", "line_start": 1}
    ingest_report(db, native("tool1", [a, b]), asset, None, IngestOptions())
    ingest_report(db, native("tool2", [other]), asset, None, IngestOptions())
    s = ingest_report(db, native("tool1", [a]), asset, None, IngestOptions(close_missing=True))
    assert s.auto_resolved_count == 1
    status = {f.title: f.status for f in findings(db, asset)}
    assert status == {"A": "open", "B": "resolved", "C": "open"}


def test_invalid_json(db, asset):
    with pytest.raises(ParseError):
        ingest_report(db, b"{not json", asset, None, IngestOptions())
