"""Preview presentation and gates agree with the subsequent import without inventory writes."""

import pytest
from sqlalchemy import select

from app.models import Asset, Component, ComponentScan, Finding, FindingEvent, FindingScan, GatePolicy
from app.services.ingestion import IngestOptions, ingest_report
from tests.test_triage_rules import finding, native, rule


def inventory(db):
    db.expire_all()
    return {
        model.__tablename__: list(
            db.execute(select(*model.__table__.columns).order_by(*model.__table__.primary_key.columns))
        )
        for model in (Finding, FindingEvent, FindingScan, Component, ComponentScan)
    }


@pytest.mark.parametrize("severity,status", [("critical", "open"), ("low", "false_positive")])
def test_projection_details_counts_gate_and_import_agree(db, severity, status):
    asset = Asset(name="preview-parity")
    db.add(asset)
    db.commit()
    ingest_report(
        db, native(finding("reopen", line=1), finding("missing", line=2)), asset, None, IngestOptions()
    )
    db.scalar(select(Finding).where(Finding.title == "reopen")).status = "resolved"
    rule(db, {"path_glob": "new/*"}, {"severity": severity, "status": status, "justification": "rule"})
    db.add(
        GatePolicy(
            asset_id=asset.id,
            conditions={
                "max_new": {"critical": 0},
                "max_open": {"high": 1},
                "fail_on_reopened": True,
            },
        )
    )
    db.commit()
    before = inventory(db)
    report = native(finding("reopen", line=1), finding("new", path="new/main.py", line=3))
    preview = ingest_report(db, report, asset, None, IngestOptions(preview=True, close_missing=True))
    assert inventory(db) == before
    details = preview.preview_result
    assert details["would_resolve"] == 1 and preview.auto_resolved_count == 0
    assert details["counts"]["new_by_severity"] == {severity: 1}
    assert details["new"][0]["severity"] == severity
    assert details["new"][0]["scanner_severity"] == "high"
    assert details["new"][0]["status"] == status
    actual = ingest_report(db, report, asset, None, IngestOptions(close_missing=True))
    assert actual.auto_resolved_count == details["would_resolve"]
    assert actual.reopened_count == preview.reopened_count == 1
    assert actual.new_count == preview.new_count == 1
    assert actual.gate_result["passed"] == preview.gate_result["passed"]
    assert actual.gate_result["violations"] == preview.gate_result["violations"]
    assert db.scalar(select(Finding).where(Finding.title == "new")).severity == severity


@pytest.mark.parametrize(
    "allow_empty,other_tool,expected", [(False, False, 0), (True, False, 1), (True, True, 0)]
)
def test_empty_and_multitool_resolution_projection(db, allow_empty, other_tool, expected):
    asset = Asset(name="empty-projection")
    db.add(asset)
    db.commit()
    ingest_report(db, native(finding("old")), asset, None, IngestOptions())
    if other_tool:
        db.scalar(select(Finding)).tools = ["Semgrep", "Other"]
        db.commit()
    before = inventory(db)
    preview = ingest_report(
        db,
        native(),
        asset,
        None,
        IngestOptions(
            preview=True,
            close_missing=True,
            allow_empty=allow_empty,
        ),
    )
    assert preview.preview_result["would_resolve"] == expected
    assert inventory(db) == before
    actual = ingest_report(
        db,
        native(),
        asset,
        None,
        IngestOptions(
            close_missing=True,
            allow_empty=allow_empty,
        ),
    )
    assert actual.auto_resolved_count == expected


def test_truncated_details_keep_effective_severity_and_full_counts(db):
    asset = Asset(name="truncated-projection")
    db.add(asset)
    db.commit()
    rule(db, {"path_glob": "app/*"}, {"severity": "low"})
    preview = ingest_report(
        db,
        native(*(finding(str(i), line=i + 1) for i in range(201))),
        asset,
        None,
        IngestOptions(preview=True),
    )
    result = preview.preview_result
    assert result["truncated"] and len(result["new"]) == 200
    assert result["counts"]["new_by_severity"] == {"low": 201}
    assert all(row["severity"] == "low" and row["scanner_severity"] == "high" for row in result["new"])
