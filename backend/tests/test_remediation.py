"""Security policy, delayed work, and data correctness across request boundaries."""

import json
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier
from unittest.mock import Mock

import pytest
from sqlalchemy import func, select

from app.core.config import settings
from app.core.db import SessionLocal
from app.core.security import create_access_token, create_refresh_token, decode_token
from app.models import (
    Asset,
    AuditLog,
    Finding,
    FindingLink,
    GatePolicy,
    Job,
    Product,
    RefreshSession,
    ReportSchedule,
    Scan,
    User,
)
from app.models.base import utcnow
from app.services import analytics, jobs, reports, sla, tasks, tickets, triage
from app.services.ingestion import IngestOptions, ingest_report
from app.services.queries import findings_query
from app.services.scope import Scope
from tests.test_audit_fixes import sarif
from tests.test_gate import finding, native
from tests.test_mfa import enrol
from tests.trackers_support import integration


def test_sso_requirement_rejects_existing_local_sessions_but_preserves_tokens(
    client, auth, users, monkeypatch
):
    token = client.post(
        "/api/v1/tokens", headers=auth["admin"], json={"name": "ci", "scopes": ["read"]}
    ).json()["token"]
    monkeypatch.setattr(settings, "local_login", False)
    assert client.get("/api/v1/auth/me", headers=auth["admin"]).status_code == 401
    assert client.post("/api/v1/auth/refresh").status_code == 401
    assert client.get("/api/v1/findings", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    sso = create_access_token(users["admin"].id, "admin", users["admin"].token_version, sso=True)
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {sso}"}).status_code == 200


def test_sso_requirement_rejects_legacy_local_refresh(client, users, monkeypatch):
    monkeypatch.setattr(settings, "local_login", False)
    token = create_refresh_token(users["admin"].id, users["admin"].token_version)
    client.cookies.set("guardiano_refresh", token)
    assert client.post("/api/v1/auth/refresh").status_code == 401


def test_sso_refresh_families_continue_when_password_sign_in_is_disabled(client, db, users, monkeypatch):
    user = users["admin"]
    token = create_refresh_token(user.id, user.token_version, session_id="sso-family")
    db.add(
        RefreshSession(
            id="sso-family",
            user_id=user.id,
            is_sso=True,
            current_jti=decode_token(token, "refresh")["jti"],
            expires_at=utcnow() + timedelta(days=1),
        )
    )
    db.commit()
    client.cookies.set("guardiano_refresh", token)
    monkeypatch.setattr(settings, "local_login", False)
    response = client.post("/api/v1/auth/refresh")
    assert response.status_code == 200
    assert decode_token(response.json()["access_token"], "access")["sso"] is True


@pytest.mark.parametrize("endpoint", ["enable", "recovery-codes", "disable"])
def test_mfa_management_has_a_persistent_account_budget(client, auth, db, users, monkeypatch, endpoint):
    if endpoint == "enable":
        assert client.post("/api/v1/auth/mfa/setup", headers=auth["admin"]).status_code == 200
    else:
        enrol(client, auth["admin"])
    monkeypatch.setattr(settings, "login_max_failures", 2)
    body = {"code": "invalid-code"}
    if endpoint == "disable":
        from tests.conftest import PASSWORD

        body["password"] = PASSWORD
    for _ in range(2):
        assert (
            client.post(f"/api/v1/auth/mfa/{endpoint}", headers=auth["admin"], json=body).status_code == 400
        )
    assert client.post(f"/api/v1/auth/mfa/{endpoint}", headers=auth["admin"], json=body).status_code == 429
    db.expire_all()
    assert db.get(User, users["admin"].id).mfa_failed_logins == 2
    assert (
        db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.action == "auth.mfa_failed")) == 2
    )


def test_combined_reports_remove_obsolete_sources_without_resolving_live_findings(db):
    asset = Asset(name="combined-sources")
    db.add(asset)
    db.commit()
    ingest_report(db, sarif("A", "B"), asset, None, IngestOptions())
    doc = json.loads(sarif("A", "B"))
    doc["runs"][0]["results"] = []
    ingest_report(db, json.dumps(doc).encode(), asset, None, IngestOptions(close_missing=True))
    f = db.scalar(select(Finding))
    assert f.tools == ["B"] and f.status == "open"
    ingest_report(db, native(tool="B"), asset, None, IngestOptions(close_missing=True, allow_empty=True))
    db.refresh(f)
    assert f.status == "resolved"


def test_triage_case_matching_is_identical_for_ingestion_preview_and_existing(db):
    asset = Asset(name="case-matching")
    db.add(asset)
    db.commit()
    ingest_report(db, native(finding("case"), tool="Trivy"), asset, None, IngestOptions())
    match = {"tool": "trivy"}
    rows = list(db.scalars(findings_query(triage.prefilter(match, asset.id, Scope()), db=db)))
    assert len(rows) == 1 and triage.matches(match, rows[0])


def test_preview_and_ingestion_agree_when_the_primary_scanner_drops_a_finding(db):
    asset = Asset(name="primary-scanner")
    db.add(asset)
    db.commit()
    report = json.loads(sarif("A", "B"))
    report["runs"][0]["results"][0]["properties"] = {"severity": "critical"}
    report["runs"][1]["results"][0]["properties"] = {"severity": "low"}
    ingest_report(db, json.dumps(report).encode(), asset, None, IngestOptions())
    db.add(GatePolicy(asset_id=asset.id, enabled=True, conditions={"max_open": {"critical": 0}}))
    db.commit()
    report["runs"][0]["results"] = []
    raw = json.dumps(report).encode()
    preview = ingest_report(db, raw, asset, None, IngestOptions(preview=True, close_missing=True))
    assert preview.gate_result["passed"] is True
    assert db.scalar(select(Finding)).severity == "critical"  # preview leaves the inventory intact
    stored = ingest_report(db, raw, asset, None, IngestOptions(close_missing=True))
    assert stored.gate_result["passed"] is True
    assert db.scalar(select(Finding)).severity == "low"


def test_large_integer_is_a_validation_error_without_persisting_an_asset(client, auth, db):
    raw = b'{"findings": [], "metadata":' + b"9" * 5000 + b"}"
    response = client.post(
        "/api/v1/scans",
        headers=auth["analyst"],
        files={"file": ("number.json", raw)},
        data={"asset_name": "bad-number"},
    )
    assert response.status_code == 422
    assert db.scalar(select(Asset).where(Asset.name == "bad-number")) is None


@pytest.mark.parametrize("field,value", [("project", "another/repo"), ("asset_id", None)])
def test_pending_jobs_protect_integration_destinations(client, auth, db, field, value):
    asset = Asset(name="old-destination")
    db.add(asset)
    db.commit()
    tracker = integration(db, asset_id=asset.id)
    jobs.enqueue(db, tickets.AUTO_JOB, {"finding_id": 123, "integration_id": tracker.id})
    db.commit()
    response = client.patch(f"/api/v1/integrations/{tracker.id}", headers=auth["admin"], json={field: value})
    assert response.status_code == 409
    assert (
        client.patch(
            f"/api/v1/integrations/{tracker.id}", headers=auth["admin"], json={"enabled": False}
        ).status_code
        == 200
    )


def test_worker_drops_tickets_for_a_different_asset(db, monkeypatch):
    a, b = Asset(name="a"), Asset(name="b")
    db.add_all([a, b])
    db.commit()
    ingest_report(db, native(finding("private")), a, None, IngestOptions())
    tracker = integration(db, asset_id=b.id)
    create = Mock()
    monkeypatch.setattr(tickets, "create_ticket", create)
    assert tickets.open_auto_ticket(db, db.scalar(select(Finding.id)), tracker.id) is None
    create.assert_not_called()


def test_linked_ticket_destinations_are_immutable_but_credentials_remain_editable(client, auth, db):
    asset = Asset(name="linked-destination")
    db.add(asset)
    db.commit()
    ingest_report(db, native(finding("linked")), asset, None, IngestOptions())
    tracker = integration(db, asset_id=asset.id)
    db.add(
        FindingLink(
            finding_id=db.scalar(select(Finding.id)),
            integration_id=tracker.id,
            system="github",
            external_key="1",
            url="https://example.test/issues/1",
        )
    )
    db.commit()
    assert (
        client.patch(
            f"/api/v1/integrations/{tracker.id}", headers=auth["admin"], json={"project": "other/repo"}
        ).status_code
        == 409
    )
    assert (
        client.patch(
            f"/api/v1/integrations/{tracker.id}",
            headers=auth["admin"],
            json={"token": "replacement", "labels": ["security"]},
        ).status_code
        == 200
    )


def test_scm_worker_drops_old_feedback_after_reassignment(db, monkeypatch):
    a, b = Asset(name="feedback-a"), Asset(name="feedback-b")
    db.add_all([a, b])
    db.commit()
    scan = Scan(asset_id=a.id, tool_name="test", scan_type="sast", format="guardiano", commit_sha="abcd")
    db.add(scan)
    db.commit()
    tracker = integration(db, asset_id=b.id, scm_feedback=True)
    provider = Mock()
    monkeypatch.setattr(tickets, "provider", provider)
    tasks.post_scm_feedback(db, {"scan_id": scan.id, "integration_id": tracker.id})
    provider.assert_not_called()


def test_disabled_manual_reports_do_not_queue_work(client, auth, db, users, monkeypatch):
    monkeypatch.setattr(settings, "smtp_host", "smtp.test")
    schedule = ReportSchedule(
        name="disabled", frequency="weekly", enabled=False, recipient_ids=[users["viewer"].id]
    )
    db.add(schedule)
    db.commit()
    assert (
        client.post(f"/api/v1/report-schedules/{schedule.id}/send", headers=auth["manager"]).status_code
        == 422
    )
    assert db.scalar(select(func.count()).select_from(Job)) == 0


def test_product_report_ranks_within_product_before_limiting(db, users):
    product = Product(name="small-product")
    db.add(product)
    db.flush()
    target = Asset(name="product-risk", product_id=product.id, criticality="low")
    others = [Asset(name=f"outside-{n}", criticality="critical") for n in range(51)]
    db.add_all([target, *others])
    db.commit()
    for asset in [target, *others]:
        ingest_report(db, native(finding("risk")), asset, None, IngestOptions())
    schedule = ReportSchedule(
        name="Product report",
        frequency="weekly",
        enabled=True,
        product_id=product.id,
        recipient_ids=[users["admin"].id],
    )
    db.add(schedule)
    db.commit()
    assert "product-risk" in reports.build(db, schedule, users["admin"]).text
    assert analytics.top_assets(db, 5, scope=Scope(), product_id=product.id)[0]["id"] == target.id


@pytest.mark.parametrize("kind", ["product", "gate"])
def test_simultaneous_creates_are_serialized(client, auth, db, kind):
    from fastapi.testclient import TestClient

    from app.main import app

    barrier = Barrier(2)

    def create(index):
        with TestClient(app) as other:
            barrier.wait(timeout=10)
            if kind == "product":
                return other.post(
                    "/api/v1/products",
                    headers=auth["admin"],
                    json={"name": ["Concurrent", "concurrent"][index]},
                ).status_code
            return other.put(
                "/api/v1/gate-policies",
                headers=auth["admin"],
                json={"asset_id": None, "conditions": {"max_new": {"high": index}}},
            ).status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        statuses = list(executor.map(create, range(2)))
    assert sorted(statuses) == ([201, 409] if kind == "product" else [200, 200])
    model = Product if kind == "product" else GatePolicy
    assert db.scalar(select(func.count()).select_from(model)) == 1


def test_sla_cache_misses_use_the_callers_connection(db, monkeypatch):
    sla.invalidate()

    def no_nested_connection():
        raise AssertionError("A request must not acquire a second connection")

    monkeypatch.setattr(sla, "SessionLocal", no_nested_connection)
    with SessionLocal() as request_db:
        request_db.execute(select(1))
        assert sla.get_policy(request_db).days_for("high", None) is not None
        sla.invalidate()
        list(request_db.scalars(findings_query(triage.prefilter({}, None, Scope()), "due", request_db)))
