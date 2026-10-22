"""Retention: what gets forgotten, what must survive, and that nothing happens until asked."""

from datetime import timedelta

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models import Asset, AuditLog, Finding, FindingEvent, FindingScan, Scan, Webhook, WebhookDelivery
from app.models.base import utcnow
from app.services import retention
from app.services.ingestion import IngestOptions, ingest_report
from tests.conftest import sample

OLD = 400  # days


@pytest.fixture
def asset(db):
    a = Asset(name="svc", tags=[])
    db.add(a)
    db.commit()
    return a


def age(db, scan: Scan, days: int) -> Scan:
    scan.created_at = utcnow() - timedelta(days=days)
    db.commit()
    return scan


# ---- off by default -------------------------------------------------------------------------------


def test_nothing_is_deleted_until_a_rule_is_configured(db, asset):
    old = age(db, ingest_report(db, sample("osv.json"), asset, None, IngestOptions()), OLD)
    db.add(AuditLog(action="user.create", created_at=utcnow() - timedelta(days=OLD)))
    db.commit()

    assert retention.run(db) == {"scans": 0, "webhook_deliveries": 0, "audit_log": 0, "revoked_tokens": 0}
    assert db.get(Scan, old.id) is not None
    assert db.scalars(select(AuditLog)).all() != []


@pytest.mark.parametrize("days", [0, -1])
def test_zero_means_keep_forever(db, asset, days):
    old = age(db, ingest_report(db, sample("osv.json"), asset, None, IngestOptions()), OLD)
    assert retention.prune_scans(db, days) == 0
    assert db.get(Scan, old.id) is not None


# ---- scans ----------------------------------------------------------------------------------------


def test_pruning_a_scan_keeps_its_findings_and_their_history(db, asset):
    """The whole point: an upload record is disposable, the vulnerability it found is not."""
    old = ingest_report(db, sample("osv.json"), asset, None, IngestOptions())
    recent = ingest_report(db, sample("osv.json"), asset, None, IngestOptions())
    age(db, old, OLD)
    findings_before = {f.id for f in db.scalars(select(Finding))}
    events_before = db.scalars(select(FindingEvent)).all()
    assert findings_before and events_before

    assert retention.prune_scans(db, 90) == 1
    db.commit()
    db.expire_all()

    assert db.get(Scan, old.id) is None
    assert db.get(Scan, recent.id) is not None, "a scan inside the window stays"
    assert {f.id for f in db.scalars(select(Finding))} == findings_before, "no finding may be lost"
    assert len(db.scalars(select(FindingEvent)).all()) == len(events_before), "history survives"

    # Only the link rows went with it.
    assert db.scalars(select(FindingScan).where(FindingScan.scan_id == old.id)).all() == []
    orphaned = db.scalars(select(Finding).where(Finding.first_scan_id.is_(None))).all()
    assert orphaned, "first_scan_id is set to null, not cascaded into deleting the finding"
    for f in db.scalars(select(Finding)):
        assert f.first_seen_at is not None and f.last_seen_at is not None


def test_the_newest_scan_of_an_asset_is_never_pruned(db, asset):
    """Otherwise 'last scanned' goes blank and close_missing loses its baseline."""
    only = age(db, ingest_report(db, sample("osv.json"), asset, None, IngestOptions()), OLD * 2)
    assert retention.prune_scans(db, 30) == 0
    assert db.get(Scan, only.id) is not None

    newer = age(db, ingest_report(db, sample("osv.json"), asset, None, IngestOptions()), OLD)
    assert retention.prune_scans(db, 30) == 1, "now there is a newer one, the old one can go"
    db.commit()
    db.expire_all()
    assert db.get(Scan, only.id) is None and db.get(Scan, newer.id) is not None


def test_each_asset_keeps_its_own_newest_scan(db):
    assets = []
    for name in ("one", "two"):
        a = Asset(name=name, tags=[])
        db.add(a)
        db.flush()
        assets.append(a)
        age(db, ingest_report(db, sample("osv.json"), a, None, IngestOptions()), OLD)
    db.commit()
    assert retention.prune_scans(db, 30) == 0
    assert len(db.scalars(select(Scan)).all()) == 2


def test_a_preview_is_prunable_because_it_is_no_baseline(db, asset):
    asset.default_branch = "main"
    db.commit()
    real = ingest_report(db, sample("osv.json"), asset, None, IngestOptions(branch="main"))
    preview = ingest_report(db, sample("trivy.json"), asset, None, IngestOptions(branch="feature/x"))
    assert preview.source == "preview"
    age(db, preview, OLD)
    age(db, real, OLD)

    assert retention.prune_scans(db, 30) == 1, "the preview goes; the newest real scan stays"
    db.commit()
    db.expire_all()
    assert db.get(Scan, preview.id) is None and db.get(Scan, real.id) is not None


# ---- deliveries and the audit log -------------------------------------------------------------------


def test_webhook_deliveries_are_pruned_but_the_webhook_stays(db):
    hook = Webhook(name="hook", url="https://example.test/hook", secret="s", events=["scan.completed"])
    db.add(hook)
    db.flush()
    for days in (OLD, 1):
        db.add(
            WebhookDelivery(
                webhook_id=hook.id,
                event="scan.completed",
                payload={},
                status_code=200,
                attempts=1,
                created_at=utcnow() - timedelta(days=days),
            )
        )
    db.commit()

    assert retention.prune_deliveries(db, 30) == 1
    db.commit()
    assert len(db.scalars(select(WebhookDelivery)).all()) == 1
    assert db.get(Webhook, hook.id) is not None


def test_the_audit_log_is_prunable_but_only_when_asked(db):
    for days in (OLD, 1):
        db.add(AuditLog(action="user.create", created_at=utcnow() - timedelta(days=days)))
    db.commit()

    assert retention.prune_audit_log(db, 0) == 0, "the auditor's record is the last thing to delete"
    assert retention.prune_audit_log(db, 30) == 1
    db.commit()
    assert len(db.scalars(select(AuditLog)).all()) == 1


# ---- the configured sweep ----------------------------------------------------------------------------


def test_the_sweep_applies_every_configured_rule(db, asset, monkeypatch):
    monkeypatch.setattr(settings, "retention_scan_days", 30)
    monkeypatch.setattr(settings, "retention_delivery_days", 30)
    monkeypatch.setattr(settings, "retention_audit_days", 30)

    age(db, ingest_report(db, sample("osv.json"), asset, None, IngestOptions()), OLD)
    ingest_report(db, sample("osv.json"), asset, None, IngestOptions())  # the keeper
    hook = Webhook(name="hook", url="https://example.test/hook", secret="s", events=["scan.completed"])
    db.add(hook)
    db.flush()
    db.add(
        WebhookDelivery(webhook_id=hook.id, event="x", payload={}, created_at=utcnow() - timedelta(days=OLD))
    )
    db.add(AuditLog(action="user.create", created_at=utcnow() - timedelta(days=OLD)))
    db.commit()

    assert retention.run(db) == {"scans": 1, "webhook_deliveries": 1, "audit_log": 1, "revoked_tokens": 0}
    db.commit()
    assert db.scalars(select(Finding)).all(), "findings are never what retention removes"


def test_the_daily_task_runs_the_sweep(db, asset, monkeypatch):
    from app.services.jobs import Worker, schedule_periodic

    monkeypatch.setattr(settings, "retention_scan_days", 30)
    age(db, ingest_report(db, sample("osv.json"), asset, None, IngestOptions()), OLD)
    ingest_report(db, sample("osv.json"), asset, None, IngestOptions())
    db.commit()

    schedule_periodic(db)
    db.commit()
    Worker().run(burst=True)

    db.expire_all()
    assert len(db.scalars(select(Scan)).all()) == 1, "the periodic task pruned the old scan"
