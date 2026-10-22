"""Behavioral regressions for production audit fixes."""

import json
import math
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock

import pytest
from sqlalchemy import select, text

from app.core.config import Settings, settings
from app.core.db import SessionLocal
from app.models import Asset, Component, Finding, Scan
from app.models.base import utcnow
from app.models.enums import Status
from app.parsers.base import NormalizedComponent, ParseError
from app.parsers.detect import parse_report
from app.services import email, intel, inventory, lifecycle, metrics, oidc, tasks, vex
from app.services.ingestion import IngestOptions, ingest_report
from tests.test_gate import finding, native


def sarif(*tools, failed=False):
    return json.dumps(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": tool}},
                    "invocations": [{"executionSuccessful": not failed}],
                    "results": [
                        {
                            "ruleId": "r",
                            "message": {"text": "same"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "a.py"},
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        }
                    ],
                }
                for tool in tools
            ],
        }
    ).encode()


@pytest.mark.parametrize("allow_empty", [False, True])
def test_incomplete_sarif_cannot_resolve_findings(db, allow_empty):
    asset = Asset(name="partial")
    db.add(asset)
    db.commit()
    ingest_report(db, sarif("A"), asset, None, IngestOptions())
    with pytest.raises(ParseError, match="incomplete"):
        ingest_report(
            db,
            sarif("A", failed=True),
            asset,
            None,
            IngestOptions(close_missing=True, allow_empty=allow_empty),
        )
    db.rollback()
    assert db.scalar(select(Finding)).status == "open"
    assert ingest_report(db, sarif("A", failed=True), asset, None, IngestOptions()).duplicate_count == 1


def test_semgrep_errors_and_sarif_notifications_mark_incomplete():
    assert not parse_report({"results": [], "errors": [{"type": "Timeout"}]}).complete_for_resolution
    doc = json.loads(sarif("A"))
    doc["runs"][0]["invocations"][0]["toolExecutionNotifications"] = [{"level": "error"}]
    assert not parse_report(doc).complete_for_resolution


def test_multi_run_sources_survive_dedup_and_single_tool_scan(db):
    asset = Asset(name="sources")
    db.add(asset)
    db.commit()
    assert ingest_report(db, sarif("A", "B"), asset, None, IngestOptions()).new_count == 1
    f = db.scalar(select(Finding))
    assert f.tools == ["A", "B"]
    ingest_report(db, native(finding("other"), tool="A"), asset, None, IngestOptions(close_missing=True))
    db.refresh(f)
    assert f.status == "open" and f.tools == ["B"]


def test_component_identity_does_not_truncate_or_fold_versions(db):
    asset = Asset(name="long-components")
    db.add(asset)
    db.flush()
    scan = Scan(asset_id=asset.id, scan_type="sca", tool_name="test", format="cyclonedx")
    db.add(scan)
    db.flush()
    rows = [
        NormalizedComponent("a" * 300, version="v" * 49 + suffix, ecosystem="e" * 50)
        for suffix in ("1", "2", "A", "a")
    ]
    inventory.record(db, asset, scan, rows, utcnow())
    db.commit()
    assert len(set(inventory.component_key(row) for row in rows)) == 4
    assert len(db.scalars(select(Component)).all()) == 4


def test_queued_webhook_checks_enabled_and_success_before_sending(monkeypatch):
    hook = Mock(enabled=False)
    delivery = Mock(webhook=hook, event="scan.completed", delivered_at=None, attempts=0)
    db = Mock()
    db.get.return_value = delivery
    send = Mock(return_value=(200, None))
    monkeypatch.setattr(tasks.webhooks, "deliver", send)
    tasks.deliver_webhook(db, {"delivery_id": 1})
    send.assert_not_called()
    hook.enabled = True
    tasks.deliver_webhook(db, {"delivery_id": 1})
    tasks.deliver_webhook(db, {"delivery_id": 1})
    send.assert_called_once()


def test_sso_group_removal_demotes_and_revokes_existing_sessions(client, auth, db, users, monkeypatch):
    user = users["admin"]
    user.oidc_subject = "audit-admin"
    db.commit()
    monkeypatch.setattr(settings, "oidc_role_map", "admins:admin")
    oidc.sign_in(db, {"sub": "audit-admin", "groups": []})
    db.commit()
    assert user.role == "viewer"
    assert client.get("/api/v1/auth/me", headers=auth["admin"]).status_code == 401
    monkeypatch.setattr(settings, "oidc_role_map", "")
    assert oidc.role_for({"groups": []}, "manager") == "manager"


@pytest.mark.parametrize("score", ["NaN", "Infinity", "-0.1", "1.1"])
def test_invalid_epss_does_not_replace_a_score(score):
    raw = f"cve,epss,percentile\nCVE-2099-1,{score},0.9\n".encode()
    assert intel.parse_epss(raw, {"CVE-2099-1"}) == []
    rows = intel.parse_epss(b"cve,epss,percentile\nCVE-2099-1,0.5,NaN\n", {"CVE-2099-1"})
    assert rows[0]["epss_percentile"] is None and math.isfinite(rows[0]["epss"])


def test_osv_fix_matches_package_and_rejects_ambiguity():
    def affected(name, version):
        return {"package": {"name": name, "ecosystem": "PyPI"}, "ranges": [{"events": [{"fixed": version}]}]}

    vuln = {"id": "CVE-2099-1", "affected": [affected("other", "99"), affected("actual", "1.2")]}
    doc = {
        "results": [
            {"packages": [{"package": {"name": "actual", "ecosystem": "PyPI"}, "vulnerabilities": [vuln]}]}
        ]
    }
    assert parse_report(doc, "osv").findings[0].fixed_version == "1.2"
    vuln["affected"].append(affected("actual", "2.1"))
    assert parse_report(doc, "osv").findings[0].fixed_version is None


def test_structured_database_credentials_are_encoded():
    from sqlalchemy.engine import make_url

    configured = Settings(_env_file=None, database_url="", postgres_host="db", postgres_password="p@ss:/?#%")
    parsed = make_url(configured.database_url)
    assert parsed.host == "db" and parsed.password == "p@ss:/?#%"
    assert (
        Settings(_env_file=None, database_url="postgresql://explicit/db").database_url
        == "postgresql://explicit/db"
    )


def test_http_methods_have_bounded_metric_labels():
    metrics.reset()
    try:
        for i in range(100):
            metrics.record_request(f"CUSTOM{i}", "unmatched", 404, 0.01)
        assert len(metrics._counters[metrics.REQUESTS]) == 1
    finally:
        metrics.reset()


def test_smtp_transports_require_verified_contexts(monkeypatch):
    import ssl

    monkeypatch.setattr(settings, "smtp_host", "smtp.example.test")
    smtp = Mock()
    smtp.return_value.__enter__ = Mock(return_value=smtp.return_value)
    smtp.return_value.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(email.smtplib, "SMTP_SSL", smtp)
    monkeypatch.setattr(email.smtplib, "SMTP", smtp)
    for mode in ("ssl", "starttls"):
        monkeypatch.setattr(settings, "smtp_security", mode)
        email.send("a@example.test", "subject", "body")
        context = (
            smtp.call_args.kwargs["context"]
            if mode == "ssl"
            else smtp.return_value.starttls.call_args.kwargs["context"]
        )
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname


def test_vex_waits_for_triage_and_preserves_its_decision(db, users):
    import threading
    import time

    asset = Asset(name="vex-race")
    db.add(asset)
    db.flush()
    f = Finding(
        asset_id=asset.id,
        dedup_key="vex-race",
        title="race",
        type="sca",
        severity="high",
        package_name="lib",
        package_version="1",
        ecosystem="npm",
        cve_id="CVE-2099-1",
    )
    db.add(f)
    db.commit()
    fid, aid, actor_id = f.id, asset.id, users["manager"].id
    started = threading.Event()

    def importing():
        from app.models import User

        with SessionLocal() as session:
            asset = session.get(Asset, aid)
            actor = session.get(User, actor_id)
            started.set()
            result = vex.apply(
                session,
                asset,
                [vex.Statement("CVE-2099-1", [vex.Package("npm", "lib", "1")], "not_affected", "supplier")],
                actor,
            )
            session.commit()
            return result

    f = db.get(Finding, fid, with_for_update=True)
    lifecycle.set_status(db, f, Status.resolved, actor=users["manager"], justification="person resolved")
    db.flush()
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(importing)
        try:
            assert started.wait(5)
            deadline = time.monotonic() + 5
            with SessionLocal() as observer:
                while time.monotonic() < deadline:
                    if observer.scalar(
                        text(
                            "SELECT count(*) FROM pg_stat_activity WHERE "
                            "wait_event_type = 'Lock' AND query LIKE '%findings%'"
                        )
                    ):
                        break
                    observer.rollback()
                    time.sleep(0.02)
                else:
                    pytest.fail("VEX did not wait for the finding lock")
        finally:
            db.commit()
        result = future.result(timeout=5)
    db.refresh(f)
    assert f.status == "resolved" and result.changed == 0 and result.already_closed == 1


def test_remote_ticket_dispatch_does_not_lock_finding(db, finding, monkeypatch):
    """A stalled tracker must not block triage; the next sync converges to the new status."""
    import threading
    from concurrent.futures import ThreadPoolExecutor
    from types import SimpleNamespace

    from sqlalchemy import text

    from app.core.db import SessionLocal
    from app.models import FindingLink
    from app.services import tasks
    from tests.trackers_support import integration

    tracker = integration(db)
    link = FindingLink(
        finding_id=finding.id,
        integration_id=tracker.id,
        external_key="123",
        url="https://example.test/123",
        system="github",
    )
    finding.status = "resolved"
    db.add(link)
    db.commit()
    link_id, finding_id = link.id, finding.id
    entered, release = threading.Event(), threading.Event()
    calls = []

    def comment(*args):
        entered.set()
        assert release.wait(5)

    def close(*args):
        calls.append("closed")
        return True

    def reopen(*args):
        calls.append("open")
        return True

    provider = SimpleNamespace(
        comment=comment, close=close, reopen=reopen, fetch_status=lambda *args: SimpleNamespace(name="open")
    )
    monkeypatch.setattr(tasks.tickets, "provider", lambda _: provider)

    def dispatch(payload):
        with SessionLocal() as worker:
            tasks.sync_ticket(worker, {"link_id": link_id, "text": "status", **payload})
            worker.commit()

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(dispatch, {"status": "resolved", "close": True})
        try:
            assert entered.wait(5)
            with SessionLocal() as triager:
                triager.execute(text("SET LOCAL lock_timeout = '500ms'"))
                triager.execute(
                    text("UPDATE findings SET status = 'open' WHERE id = :id"), {"id": finding_id}
                )
                triager.commit()
        finally:
            release.set()
        future.result(timeout=5)
    dispatch({"status": "open", "reopen": True})
    assert calls == ["closed", "open"]
