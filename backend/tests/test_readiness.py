"""Cross-module regressions found in the production-readiness review."""

import json

import pytest
from sqlalchemy import select

from app.core.testdb import validate_test_database
from app.models import Asset, Finding, GatePolicy, Integration, Job, ReportSchedule, TriageRule
from app.services import reports, sbom, scm, tasks, triage
from app.services.ingestion import IngestOptions, ingest_report
from app.services.scope import Scope
from tests.test_gate import finding, native


@pytest.mark.parametrize("name", ["guardiano", "postgres", "production", "guardiano_test;DROP"])
def test_test_setup_refuses_non_disposable_databases(name):
    with pytest.raises(ValueError, match="Refusing destructive"):
        validate_test_database(f"postgresql://localhost/{name}")


def test_gate_reads_auto_resolutions_and_projects_previews(db):
    asset = Asset(name="gate-readiness")
    db.add(asset)
    db.flush()
    db.add(GatePolicy(asset_id=asset.id, enabled=True, conditions={"max_open": {"critical": 0}}))
    db.commit()
    preview = ingest_report(
        db, native(finding("critical", "critical")), asset, None, IngestOptions(preview=True)
    )
    assert preview.gate_result["passed"] is False
    real = ingest_report(db, native(finding("critical", "critical")), asset, None, IngestOptions())
    assert real.gate_result["passed"] is False
    fixed = ingest_report(db, native(finding("safe", "low")), asset, None, IngestOptions(close_missing=True))
    assert fixed.gate_result["passed"] is True


def test_current_sbom_survives_shared_packages_and_handles_empty_reports(db):
    asset = Asset(name="inventory-readiness")
    db.add(asset)
    db.commit()

    def upload(tool, names):
        data = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"tools": {"components": [{"name": tool}]}},
            "components": [{"bom-ref": n, "name": n, "version": "1"} for n in names],
        }
        return ingest_report(db, json.dumps(data).encode(), asset, None, IngestOptions())

    upload("A", ["shared", "only-A"])
    upload("B", ["shared"])
    upload("B", [])
    assert {c.name for c in sbom.components(db, asset)} == {"shared", "only-A"}
    upload("A", [])
    assert sbom.components(db, asset) == []


def test_manual_report_is_delivered_and_rechecks_the_recipient(client, auth, db, users, monkeypatch):
    from app.core.config import settings
    from app.services import email

    monkeypatch.setattr(settings, "smtp_host", "smtp.test")
    schedule = ReportSchedule(
        name="manual", frequency="weekly", enabled=True, recipient_ids=[users["viewer"].id]
    )
    db.add(schedule)
    db.commit()
    response = client.post(f"/api/v1/report-schedules/{schedule.id}/send", headers=auth["manager"])
    assert response.status_code == 202
    payload = db.scalar(select(Job).where(Job.kind == email.SEND_JOB)).payload
    assert payload == {"kind": "report", "recipient_id": users["viewer"].id, "schedule_id": schedule.id}
    sent = []
    monkeypatch.setattr(email, "send", lambda *args: sent.append(args))
    tasks.send_email(db, payload)
    assert len(sent) == 1
    users["viewer"].is_active = False
    db.commit()
    tasks.send_email(db, payload)
    assert len(sent) == 1
    assert reports.recipients(db, schedule) == []


def test_scm_keeps_other_scanner_failures_blocking(db):
    asset = Asset(name="scm-readiness")
    db.add(asset)
    db.commit()
    integration = Integration(
        name="github",
        kind="github",
        project="owner/repo",
        base_url="https://api.github.com",
        secret_encrypted="unused",
        enabled=True,
        scm_feedback=True,
        asset_id=asset.id,
    )
    db.add(integration)
    db.commit()
    failed = ingest_report(
        db, native(finding("bad"), tool="SAST"), asset, None, IngestOptions(commit_sha="abc123")
    )
    failed.gate_result = {"passed": False, "violations": [{"message": "blocked"}]}
    db.commit()
    ingest_report(db, native(finding("ok"), tool="SCA"), asset, None, IngestOptions(commit_sha="abc123"))
    assert scm.aggregate_outcome(db, integration, "abc123")[0] == "failure"
    ingest_report(db, native(finding("ok"), tool="SAST"), asset, None, IngestOptions(commit_sha="abc123"))
    assert scm.aggregate_outcome(db, integration, "abc123")[0] == "success"


def test_queued_triage_rejects_disabled_actor_and_legacy_jobs(db, users):
    asset = Asset(name="triage-readiness")
    db.add(asset)
    db.commit()
    ingest_report(db, native(finding("open")), asset, None, IngestOptions())
    rule = TriageRule(name="tag", match={"severity": ["high"]}, action={"tags": ["changed"]})
    db.add(rule)
    users["manager"].is_active = False
    db.commit()
    for payload in (
        {"rule_id": rule.id, "team_ids": None, "actor_id": users["manager"].id},
        {"rule_id": rule.id, "team_ids": None, "actor": "legacy"},
    ):
        tasks.apply_triage_rule(db, payload)
    assert db.scalar(select(Finding)).tags == []


def test_rule_severity_changes_have_structured_history(db, users):
    asset = Asset(name="severity-readiness")
    db.add(asset)
    db.commit()
    ingest_report(db, native(finding("open")), asset, None, IngestOptions())
    rule = TriageRule(name="lower", match={"severity": ["high"]}, action={"severity": "low"})
    db.add(rule)
    db.commit()
    triage.apply_to_existing(db, rule.id, Scope(), "manager")
    f = db.scalar(select(Finding))
    assert any(e.from_severity == "high" and e.to_severity == "low" for e in f.events)


def test_retention_keeps_independent_scanner_baselines(db):
    from datetime import timedelta

    from app.models import Scan
    from app.models.base import utcnow
    from app.services import retention

    asset = Asset(name="retention-baselines")
    db.add(asset)
    db.commit()
    for tool in ("scanner-a", "scanner-b"):
        scan = ingest_report(db, native(finding(tool), tool=tool), asset, None, IngestOptions())
        scan.created_at = utcnow() - timedelta(days=400)
        db.commit()
    assert retention.prune_scans(db, 30) == 0
    assert len(db.scalars(select(Scan)).all()) == 2


def test_mfa_enrollment_revokes_old_session_but_issues_working_replacement(client, auth):
    from tests.test_mfa import enrol

    old = dict(auth["admin"])
    enrol(client, auth["admin"])
    assert client.get("/api/v1/auth/me", headers=old).status_code == 401
    assert client.get("/api/v1/auth/me", headers=auth["admin"]).status_code == 200


def test_mfa_guess_budget_survives_new_challenges(client, auth, db, users, monkeypatch):
    from app.core.config import settings
    from tests.test_mfa import enrol, sign_in

    enrol(client, auth["admin"])
    monkeypatch.setattr(settings, "login_max_failures", 2)
    for _ in range(2):
        challenge = sign_in(client).json()["mfa_token"]
        response = client.post(
            "/api/v1/auth/login/mfa", json={"mfa_token": challenge, "code": "invalid-code"}
        )
        assert response.status_code == 401
    challenge = sign_in(client).json()["mfa_token"]
    blocked = client.post("/api/v1/auth/login/mfa", json={"mfa_token": challenge, "code": "invalid-code"})
    assert "Too many" in blocked.json()["detail"]
    db.refresh(users["admin"])
    assert users["admin"].mfa_failed_logins == 2


def test_parser_stops_at_configured_finding_and_component_limits(monkeypatch):
    from app.core.config import settings
    from app.parsers.base import ParseError
    from app.parsers.detect import parse_report

    monkeypatch.setattr(settings, "max_report_findings", 1)
    with pytest.raises(ParseError, match="MAX_REPORT_FINDINGS"):
        parse_report(json.loads(native(finding("a"), finding("b"))))
    monkeypatch.setattr(settings, "max_report_components", 1)
    report = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {"name": "a", "version": "1"},
            {"name": "b", "version": "1"},
        ],
    }
    with pytest.raises(ParseError, match="MAX_REPORT_COMPONENTS"):
        parse_report(report)


def test_job_priority_keeps_notifications_ahead_of_alias_backlog(db):
    from app.services import jobs

    slow = jobs.enqueue(db, "intel.alias", priority=200)
    urgent = jobs.enqueue(db, "email.send")
    db.commit()
    claimed = jobs.claim(db)
    assert claimed.id == urgent.id
    assert claimed.id != slow.id


def test_long_history_is_bounded_and_remaining_events_are_accessible(client, auth, db):
    from app.models import FindingEvent

    asset = Asset(name="long-history")
    db.add(asset)
    db.commit()
    ingest_report(db, native(finding("history")), asset, None, IngestOptions())
    f = db.scalar(select(Finding))
    db.add_all([FindingEvent(finding_id=f.id, event="comment", comment=f"comment {n}") for n in range(205)])
    db.commit()
    detail = client.get(f"/api/v1/findings/{f.id}", headers=auth["admin"]).json()
    assert len(detail["events"]) == 200
    assert detail["events_total"] == 206
    page = client.get(f"/api/v1/findings/{f.id}/events?page=2", headers=auth["admin"]).json()
    assert len(page["items"]) == 6
    assert not {e["id"] for e in detail["events"]} & {e["id"] for e in page["items"]}


@pytest.mark.parametrize("field", ["name", "description"])
def test_team_patch_rejects_null_required_fields(client, auth, field):
    team = client.post("/api/v1/teams", json={"name": "null-safety"}, headers=auth["admin"]).json()
    response = client.patch(f"/api/v1/teams/{team['id']}", json={field: None}, headers=auth["admin"])
    assert response.status_code == 422


def test_legacy_sbom_export_discloses_uncertain_provenance(client, auth, db):
    from app.models import Scan

    asset = Asset(name="legacy-inventory")
    db.add(asset)
    db.commit()
    report = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [{"name": "legacy", "version": "1"}],
    }
    scan = ingest_report(db, json.dumps(report).encode(), asset, None, IngestOptions())
    db.get(Scan, scan.id).inventory_complete = None
    db.commit()
    for format in ("cyclonedx", "spdx"):
        response = client.get(f"/api/v1/assets/{asset.id}/sbom?format={format}", headers=auth["admin"])
        assert response.status_code == 200
        assert "Best-effort legacy inventory" in response.text


def test_legacy_rule_severity_history_is_marked_incomplete(db):
    from app.models import FindingEvent
    from app.services import analytics

    asset = Asset(name="legacy-rule-history")
    db.add(asset)
    db.commit()
    ingest_report(db, native(finding("history")), asset, None, IngestOptions())
    f = db.scalar(select(Finding))
    db.add(FindingEvent(finding_id=f.id, event="rule_applied", comment="Auto-triage: severity high -> low"))
    db.commit()
    assert analytics.trends(db, scope=Scope())["severity_history_complete"] is False


def test_partial_scanner_reports_do_not_claim_complete_inventory():
    from app.parsers.detect import parse_report

    osv = parse_report(
        {
            "results": [
                {
                    "source": {"path": "lock"},
                    "packages": [
                        {"package": {"name": "observed-only", "version": "1", "ecosystem": "npm"}},
                    ],
                }
            ]
        }
    )
    assert len(osv.components) == 1 and not osv.inventory_complete
    trivy = parse_report(
        {
            "SchemaVersion": 2,
            "Results": [
                {"Class": "os-pkgs", "Packages": []},
                {"Class": "lang-pkgs", "Vulnerabilities": []},
            ],
        }
    )
    assert not trivy.inventory_complete
    vex_only = parse_report({"bomFormat": "CycloneDX", "specVersion": "1.5", "vulnerabilities": []})
    assert not vex_only.inventory_complete
    assert parse_report({"bomFormat": "CycloneDX", "components": []}).inventory_complete


def test_ingest_capacity_is_shared_between_database_sessions(db):
    from sqlalchemy import func

    from app.core.config import settings
    from app.core.db import SessionLocal
    from app.services.errors import Busy

    asset = Asset(name="capacity")
    db.add(asset)
    db.commit()
    with SessionLocal() as blocker:
        for slot in range(settings.max_concurrent_ingests):
            blocker.execute(select(func.pg_advisory_xact_lock(0x6769, slot)))
        with pytest.raises(Busy):
            ingest_report(db, native(finding("capacity")), asset, None, IngestOptions())
        db.rollback()
        blocker.rollback()
    assert ingest_report(db, native(finding("capacity")), asset, None, IngestOptions()).new_count == 1


def test_preview_and_real_gate_use_the_same_triaged_severity(db):
    asset = Asset(name="triaged-gate")
    db.add(asset)
    db.flush()
    db.add_all(
        [
            GatePolicy(
                asset_id=asset.id,
                enabled=True,
                conditions={"max_new": {"critical": 0}, "max_open": {"critical": 0}},
            ),
            TriageRule(name="lower", match={"severity": ["critical"]}, action={"severity": "low"}),
        ]
    )
    db.commit()
    report = native(finding("critical", "critical"))
    preview = ingest_report(db, report, asset, None, IngestOptions(preview=True))
    real = ingest_report(db, report, asset, None, IngestOptions())
    assert preview.gate_result["passed"] is True
    assert real.gate_result["passed"] is True


def test_stale_job_owner_cannot_commit_a_batch(db):
    from app.services import jobs

    job = jobs.enqueue(db, "test.stale-owner")
    db.commit()
    claimed = jobs.claim(db)
    token = jobs._claim_context.set((job.id, claimed.claim_token))
    try:
        claimed.claim_token = "replacement-owner"
        db.commit()
        db.add(Asset(name="must-not-commit"))
        with pytest.raises(RuntimeError, match="claim changed"):
            jobs.commit_owned(db)
        db.rollback()
        assert db.scalar(select(Asset).where(Asset.name == "must-not-commit")) is None
    finally:
        jobs._claim_context.reset(token)
