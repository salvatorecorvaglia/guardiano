"""Outbound webhooks: subscription, payloads, signing, delivery and retries."""

import hashlib
import hmac
import json
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models import Asset, AuditLog, Finding, Webhook, WebhookDelivery
from app.models.base import utcnow
from app.services import events, jobs, webhooks
from app.services.ingestion import IngestOptions, ingest_report

SENT: list[tuple[str, bytes, dict[str, str]]] = []
RESPONSES: list[tuple[int, str | None]] = []


@pytest.fixture(autouse=True)
def fake_transport(monkeypatch):
    """Capture requests instead of making them; RESPONSES drives what the endpoint 'returns'."""
    SENT.clear()
    RESPONSES.clear()

    def _post(url, body, headers):
        SENT.append((url, body, headers))
        return RESPONSES.pop(0) if RESPONSES else (200, None)

    monkeypatch.setattr(webhooks, "_post", _post)


@pytest.fixture
def asset(db):
    a = Asset(name="svc", tags=[])
    db.add(a)
    db.commit()
    return a


def hook(db, **kw):
    defaults = {
        "name": "ops",
        "url": "https://example.test/hook",
        "secret": "s3cret",
        "format": "guardiano",
        "events": [events.SCAN_COMPLETED],
        "min_severity": "high",
        "enabled": True,
    }
    h = Webhook(**{**defaults, **kw})
    db.add(h)
    db.commit()
    return h


def native(*findings, tool="Semgrep"):
    return json.dumps(
        {"schema": "guardiano/v1", "tool": {"name": tool}, "scan_type": "sast", "findings": list(findings)}
    ).encode()


def finding(title="a", severity="high", path="app/a.py", line=1):
    return {"title": title, "severity": severity, "cwe": ["CWE-89"], "file_path": path, "line_start": line}


def deliveries(db, event=None):
    stmt = select(WebhookDelivery).order_by(WebhookDelivery.id)
    if event:
        stmt = stmt.where(WebhookDelivery.event == event)
    return db.scalars(stmt).all()


# ---- subscription -------------------------------------------------------------------------------


def test_only_interested_webhooks_receive_an_event(db, asset):
    other = Asset(name="other", tags=[])
    db.add(other)
    db.commit()
    wanted = hook(db, name="wanted", events=[events.SCAN_COMPLETED])
    hook(db, name="wrong event", events=[events.SLA_BREACHED])
    hook(db, name="disabled", events=[events.SCAN_COMPLETED], enabled=False)
    hook(db, name="other asset", events=[events.SCAN_COMPLETED], asset_id=other.id)
    scoped = hook(db, name="this asset", events=[events.SCAN_COMPLETED], asset_id=asset.id)

    ingest_report(db, native(finding()), asset, None, IngestOptions())
    assert {d.webhook_id for d in deliveries(db)} == {wanted.id, scoped.id}


def test_severity_filter_applies_to_finding_events_only(db, asset):
    high_only = hook(
        db, name="high", events=[events.FINDING_REOPENED, events.SCAN_COMPLETED], min_severity="critical"
    )
    ingest_report(db, native(finding(severity="low")), asset, None, IngestOptions())
    # scan.completed is about the scan, so the severity floor does not apply to it.
    assert [d.event for d in deliveries(db)] == [events.SCAN_COMPLETED]

    ingest_report(db, native(finding(severity="low")), asset, None, IngestOptions())
    f = db.scalar(select(Finding))
    f.status = "resolved"
    db.commit()
    ingest_report(db, native(finding(severity="low")), asset, None, IngestOptions())
    assert not deliveries(db, events.FINDING_REOPENED)  # low is below the webhook's floor

    high_only.min_severity = "low"
    db.commit()
    db.expire_all()
    f = db.scalar(select(Finding))
    f.status = "resolved"
    db.commit()
    ingest_report(db, native(finding(severity="low")), asset, None, IngestOptions())
    assert len(deliveries(db, events.FINDING_REOPENED)) == 1


# ---- payloads -----------------------------------------------------------------------------------


def test_scan_and_gate_payloads(db, asset, monkeypatch):
    monkeypatch.setattr(settings, "public_url", "https://guardiano.test")
    from app.models import GatePolicy

    db.add(GatePolicy(asset_id=None, enabled=True, conditions={"max_new": {"high": 0}}))
    db.commit()
    hook(db, events=[events.SCAN_COMPLETED, events.GATE_FAILED])

    ingest_report(db, native(finding(title="SQLi")), asset, None, IngestOptions(branch="main"))
    scan_event, gate_event = deliveries(db)
    assert scan_event.event == events.SCAN_COMPLETED
    assert scan_event.payload["counts"] == {
        "total": 1,
        "new": 1,
        "duplicate": 0,
        "reopened": 0,
        "auto_resolved": 0,
    }
    assert scan_event.payload["asset"] == "svc" and scan_event.payload["branch"] == "main"
    assert scan_event.payload["url"] == f"https://guardiano.test/scans/{scan_event.payload['scan_id']}"
    new = scan_event.payload["new_findings"]
    assert [f["title"] for f in new] == ["SQLi"]
    assert new[0]["url"].startswith("https://guardiano.test/findings/")

    assert gate_event.event == events.GATE_FAILED
    assert gate_event.payload["violations"] == ["1 new high finding(s), limit 0"]


def test_status_change_event_names_the_actor(client, auth, db, asset):
    hook(db, events=[events.FINDING_STATUS_CHANGED], min_severity="low")
    ingest_report(db, native(finding()), asset, None, IngestOptions())
    f = db.scalar(select(Finding))
    client.patch(f"/api/v1/findings/{f.id}", json={"status": "in_progress"}, headers=auth["analyst"])

    (event,) = deliveries(db, events.FINDING_STATUS_CHANGED)
    assert event.payload["previous_status"] == "open" and event.payload["status"] == "in_progress"
    assert event.payload["actor"] == "Analyst"


def test_preview_scans_announce_themselves_as_previews(db, asset):
    asset.default_branch = "main"
    db.commit()
    hook(db, events=[events.SCAN_COMPLETED])
    ingest_report(db, native(finding()), asset, None, IngestOptions(branch="pr-1"))
    (event,) = deliveries(db)
    assert event.payload["preview"] is True and event.payload["counts"]["new"] == 1
    assert db.scalar(select(Finding)) is None  # still nothing ingested


def test_events_are_capped_per_scan(db, asset):
    hook(db, events=[events.SCAN_COMPLETED])
    many = [finding(title=f"f{i}", line=i) for i in range(30)]
    ingest_report(db, native(*many), asset, None, IngestOptions())
    (event,) = deliveries(db)
    assert event.payload["counts"]["new"] == 30
    assert len(event.payload["new_findings"]) == 20  # the payload stays small


# ---- delivery -----------------------------------------------------------------------------------


def test_delivery_signs_the_exact_body(db, asset):
    h = hook(db, secret="topsecret")
    ingest_report(db, native(finding()), asset, None, IngestOptions())
    assert jobs.Worker(poll_interval=0).run(burst=True) >= 1

    url, body, headers = SENT[0]
    assert url == h.url
    expected = "sha256=" + hmac.new(b"topsecret", body, hashlib.sha256).hexdigest()
    assert headers["X-Guardiano-Signature"] == expected
    assert headers["X-Guardiano-Event"] == events.SCAN_COMPLETED
    envelope = json.loads(body)
    assert envelope["event"] == events.SCAN_COMPLETED and envelope["data"]["asset"] == "svc"

    db.expire_all()
    (delivery,) = deliveries(db)
    assert (delivery.status_code, delivery.error, delivery.attempts) == (200, None, 1)
    assert delivery.delivered_at is not None
    assert db.get(Webhook, h.id).last_status == 200


def test_delivery_carries_a_timestamped_signature(db, asset):
    """t=<time>,v1=HMAC("<time>." + body): a receiver can refuse a request replayed later."""
    hook(db, secret="topsecret")
    ingest_report(db, native(finding()), asset, None, IngestOptions())
    jobs.Worker(poll_interval=0).run(burst=True)

    _, body, headers = SENT[0]
    timestamp = headers["X-Guardiano-Timestamp"]
    assert abs(int(timestamp) - utcnow().timestamp()) < 60
    digest = hmac.new(b"topsecret", f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    assert headers["X-Guardiano-Signature-256"] == f"t={timestamp},v1={digest}"


def test_the_secret_is_encrypted_at_rest_and_shown_once(client, auth, db):
    body = {"name": "ops", "url": "https://example.test/hook", "events": [events.SCAN_COMPLETED]}
    created = client.post("/api/v1/webhooks", json=body, headers=auth["admin"]).json()
    secret = created["secret"]
    assert len(secret) == 64

    row = db.execute(select(Webhook.secret_plaintext, Webhook.secret_encrypted)).one()
    assert row.secret_plaintext is None
    assert row.secret_encrypted and secret not in row.secret_encrypted
    assert db.get(Webhook, created["id"]).secret == secret

    rotated = client.post(f"/api/v1/webhooks/{created['id']}/rotate-secret", headers=auth["admin"]).json()
    db.expire_all()
    assert rotated["secret"] != secret and db.get(Webhook, created["id"]).secret == rotated["secret"]
    assert "secret" not in client.get("/api/v1/webhooks", headers=auth["admin"]).json()[0]


def test_a_secret_stored_before_encryption_keeps_working_and_is_encrypted_at_startup(db, asset):
    """Legacy plaintext secrets remain usable before the first bootstrap."""
    h = hook(db)
    h.secret_encrypted, h.secret_plaintext = None, "legacy"
    db.commit()

    def signature():
        SENT.clear()
        ingest_report(db, native(finding(title=f"t{utcnow().timestamp()}")), asset, None, IngestOptions())
        jobs.Worker(poll_interval=0).run(burst=True)
        _, body, headers = SENT[0]
        assert headers["X-Guardiano-Signature"] == webhooks.sign("legacy", body)

    signature()
    assert webhooks.encrypt_legacy_secrets(db) == 1
    db.expire_all()
    assert db.get(Webhook, h.id).secret_plaintext is None
    signature()  # same secret, now read from the encrypted column
    assert webhooks.encrypt_legacy_secrets(db) == 0  # idempotent


def test_a_secret_that_cannot_be_decrypted_is_reported_not_crashed_on(db, asset):
    h = hook(db)
    h.secret_encrypted = "not-a-fernet-token"
    db.commit()
    RESPONSES.extend([(200, None)] * 6)
    ingest_report(db, native(finding()), asset, None, IngestOptions())
    jobs.Worker(poll_interval=0).run(burst=True)

    assert SENT == []  # nothing is sent unsigned
    db.expire_all()
    assert "rotate it" in db.get(Webhook, h.id).last_error


def test_failed_delivery_is_retried_then_recorded(db, asset):
    h = hook(db)
    RESPONSES.extend([(500, None), (0, "ConnectError: refused"), (200, None)])
    ingest_report(db, native(finding()), asset, None, IngestOptions())

    jobs.Worker(poll_interval=0).run(burst=True)
    db.expire_all()
    (delivery,) = deliveries(db)
    assert (delivery.status_code, delivery.error) == (500, "HTTP 500")
    assert delivery.delivered_at is None
    job = db.scalars(select(jobs.Job).where(jobs.Job.kind == events.DELIVER_JOB)).one()
    assert job.status == "queued" and "HTTP 500" in job.last_error  # retried with backoff

    # Second attempt: connection error. Third: success.
    for _ in range(2):
        job.run_after = utcnow() - timedelta(seconds=1)
        db.commit()
        jobs.run_one()
        db.expire_all()
    (delivery,) = deliveries(db)
    assert (delivery.status_code, delivery.attempts) == (200, 3)
    assert delivery.delivered_at is not None and delivery.error is None
    assert db.get(Webhook, h.id).last_error is None


def test_slack_and_teams_bodies(db, asset, monkeypatch):
    monkeypatch.setattr(settings, "public_url", "https://guardiano.test")
    hook(db, name="slack", format="slack", events=[events.SCAN_COMPLETED])
    hook(db, name="teams", format="teams", events=[events.SCAN_COMPLETED])
    ingest_report(db, native(finding()), asset, None, IngestOptions())
    jobs.Worker(poll_interval=0).run(burst=True)

    slack = json.loads(SENT[0][1])
    assert "Scan #" in slack["text"] and slack["blocks"][0]["type"] == "section"
    assert slack["blocks"][1]["elements"][0]["url"].startswith("https://guardiano.test/scans/")

    teams = json.loads(SENT[1][1])
    card = teams["attachments"][0]["content"]
    assert card["type"] == "AdaptiveCard"
    assert any(fact["title"] == "New" for fact in card["body"][1]["facts"])
    # Both carry a signature, whatever the shape.
    assert SENT[1][2]["X-Guardiano-Signature"].startswith("sha256=")


def test_a_broken_webhook_never_breaks_ingestion(db, asset):
    hook(db)
    RESPONSES.extend([(500, None)] * 6)
    scan = ingest_report(db, native(finding()), asset, None, IngestOptions())
    assert scan.new_count == 1  # the scan is committed regardless
    jobs.Worker(poll_interval=0).run(burst=True)
    db.expire_all()
    assert db.scalar(select(Finding)) is not None


# ---- sla.breached -------------------------------------------------------------------------------


def test_sla_breach_sweep_announces_each_finding_once(db, asset):
    hook(db, events=[events.SLA_BREACHED], min_severity="low")
    # An SLA of 30 days for high: first seen just over 30 days ago means it breached an hour ago.
    ingest_report(
        db, native(finding()), asset, None, IngestOptions(now=utcnow() - timedelta(days=30, hours=1))
    )
    from app.services.tasks import sla_breaches

    sla_breaches(db, {})
    db.commit()
    assert len(deliveries(db, events.SLA_BREACHED)) == 1

    sla_breaches(db, {})  # the overlapping window must not announce it again
    db.commit()
    assert len(deliveries(db, events.SLA_BREACHED)) == 1


def test_a_breach_beyond_the_batch_limit_is_announced_on_a_later_run(db, asset, monkeypatch):
    """LIMIT used to be applied before "already announced" was filtered out, so the same rows filled
    every batch and anything past the limit was never announced."""
    from app.core.config import settings
    from app.services.tasks import sla_breaches

    monkeypatch.setattr(settings, "event_batch_limit", 2)
    hook(db, events=[events.SLA_BREACHED], min_severity="low")
    ingest_report(
        db,
        native(*[finding(title=f"f{i}", line=i) for i in range(1, 6)]),
        asset,
        None,
        IngestOptions(now=utcnow() - timedelta(days=30, hours=1)),
    )
    for _ in range(3):
        sla_breaches(db, {})
        db.commit()
    assert len(deliveries(db, events.SLA_BREACHED)) == 5


def test_a_breach_is_not_reannounced_once_its_deliveries_are_pruned(db, asset):
    """Retention deletes deliveries, which used to be the only record of what was announced."""
    from sqlalchemy import delete

    from app.services.tasks import sla_breaches

    hook(db, events=[events.SLA_BREACHED], min_severity="low")
    ingest_report(
        db, native(finding()), asset, None, IngestOptions(now=utcnow() - timedelta(days=30, hours=1))
    )
    sla_breaches(db, {})
    db.commit()
    db.execute(delete(WebhookDelivery))
    db.commit()

    sla_breaches(db, {})
    db.commit()
    assert deliveries(db, events.SLA_BREACHED) == []


def test_a_breach_nobody_subscribes_to_is_still_marked(db, asset):
    """With no subscriber no delivery row is written, so the old check found nothing and the same
    findings were picked up again every hour."""
    from app.services.tasks import sla_breaches

    ingest_report(
        db, native(finding()), asset, None, IngestOptions(now=utcnow() - timedelta(days=30, hours=1))
    )
    sla_breaches(db, {})
    db.commit()
    assert db.scalar(select(Finding)).sla_breach_due is not None


# ---- API ----------------------------------------------------------------------------------------


def test_webhook_api(client, auth, db):
    body = {
        "name": "ops",
        "url": "https://example.test/hook",
        "events": ["scan.completed"],
        "format": "slack",
    }
    for role in ("viewer", "analyst", "manager"):
        assert client.post("/api/v1/webhooks", json=body, headers=auth[role]).status_code == 403
    r = client.post("/api/v1/webhooks", json=body, headers=auth["admin"])
    assert r.status_code == 201
    created = r.json()
    assert len(created["secret"]) == 64
    wid = created["id"]

    for bad in (
        {**body, "url": "ftp://example.test"},
        {**body, "events": []},
        {**body, "events": ["nonsense"]},
        {**body, "format": "carrier-pigeon"},
    ):
        assert client.post("/api/v1/webhooks", json=bad, headers=auth["admin"]).status_code == 422

    listed = client.get("/api/v1/webhooks", headers=auth["admin"]).json()
    assert "secret" not in listed[0]  # never shown again
    rotated = client.post(f"/api/v1/webhooks/{wid}/rotate-secret", headers=auth["admin"]).json()
    assert rotated["secret"] != created["secret"]

    r = client.post(f"/api/v1/webhooks/{wid}/test", headers=auth["admin"])
    assert r.status_code == 202 and r.json()["event"] == "test"
    assert jobs.Worker(poll_interval=0).run(burst=True) >= 1
    assert json.loads(SENT[0][1])["text"].startswith("🔔")  # the test event renders in Slack form

    page = client.get(f"/api/v1/webhooks/{wid}/deliveries", headers=auth["admin"]).json()
    assert page["total"] == 1 and page["items"][0]["status_code"] == 200

    assert client.delete(f"/api/v1/webhooks/{wid}", headers=auth["admin"]).status_code == 204
    actions = [e.action for e in db.scalars(select(AuditLog).where(AuditLog.action.startswith("webhook.")))]
    assert actions == ["webhook.create", "webhook.update", "webhook.delete"]
    # The audit log records the host, never the full URL (Slack and Teams URLs are secrets).
    entry = db.scalar(select(AuditLog).where(AuditLog.action == "webhook.create"))
    assert entry.changes["host"] == "example.test" and "hook" not in json.dumps(entry.changes)


def test_repointing_a_webhook_is_audited(client, auth, db):
    """Changing where security events are delivered is the change most worth recording: url was
    written by the update loop but left out of the audit snapshot, so it was invisible."""
    created = client.post(
        "/api/v1/webhooks",
        json={"name": "slack", "url": "https://hooks.example.test/T/B/xxx", "events": ["scan.completed"]},
        headers=auth["admin"],
    ).json()
    r = client.patch(
        f"/api/v1/webhooks/{created['id']}",
        json={"url": "https://attacker.example.test/collect"},
        headers=auth["admin"],
    )
    assert r.status_code == 200

    entry = db.scalars(
        select(AuditLog).where(AuditLog.action == "webhook.update").order_by(AuditLog.id.desc())
    ).first()
    assert entry is not None, "repointing a webhook must leave an audit record"
    assert entry.changes["host"] == {"from": "hooks.example.test", "to": "attacker.example.test"}
    # Still only the host: the path of either URL can be a credential.
    assert "collect" not in json.dumps(entry.changes) and "xxx" not in json.dumps(entry.changes)


def test_moving_a_webhook_to_another_asset_is_audited(client, auth, db):
    asset = Asset(name="audited-asset", tags=[])
    db.add(asset)
    db.commit()
    created = client.post(
        "/api/v1/webhooks",
        json={"name": "hook", "url": "https://hooks.example.test/a", "events": ["scan.completed"]},
        headers=auth["admin"],
    ).json()
    client.patch(f"/api/v1/webhooks/{created['id']}", json={"asset_id": asset.id}, headers=auth["admin"])
    entry = db.scalars(
        select(AuditLog).where(AuditLog.action == "webhook.update").order_by(AuditLog.id.desc())
    ).first()
    assert entry is not None and entry.changes["asset_id"] == {"from": None, "to": asset.id}


# ---- finding.assigned, finding.risk_acceptance_expiring, finding.kev_added ---------------------


def _sca(title, cve):
    return {"title": title, "severity": "high", "type": "sca", "cve_id": cve, "package_name": title,
            "package_version": "1.0.0", "ecosystem": "npm"}  # fmt: skip


def _sca_report(*findings):
    return json.dumps({"schema": "guardiano/v1", "tool": {"name": "t"}, "scan_type": "sca",
                       "findings": list(findings)}).encode()  # fmt: skip


def test_assigning_a_finding_is_announced_and_the_default_assignee_is_not(client, auth, db, users, asset):
    hook(db, events=[events.FINDING_ASSIGNED])
    asset.default_assignee_id = users["analyst"].id
    db.commit()
    ingest_report(db, native(finding()), asset, None, IngestOptions())
    assert deliveries(db, events.FINDING_ASSIGNED) == []  # one per new finding would flood the channel

    f = db.scalar(select(Finding))
    to_manager = {"assignee_id": users["manager"].id}
    r = client.patch(f"/api/v1/findings/{f.id}", json=to_manager, headers=auth["analyst"])
    assert r.status_code == 200, r.text
    r = client.patch(f"/api/v1/findings/{f.id}", json={"unassign": True}, headers=auth["analyst"])
    assert r.status_code == 200, r.text

    assigned, unassigned = deliveries(db, events.FINDING_ASSIGNED)
    assert assigned.payload["assignee_email"] == users["manager"].email
    assert assigned.payload["finding_id"] == f.id and assigned.payload["actor"]
    assert unassigned.payload["assignee"] is None


def _accepted(db, asset, days):
    f = db.scalar(select(Finding).where(Finding.asset_id == asset.id))
    f.status, f.status_justification = "risk_accepted", "compensating control in place"
    f.risk_accepted_until = utcnow() + timedelta(days=days)
    db.commit()
    return f


def test_an_ending_risk_acceptance_is_announced_once_per_end_date(db, asset):
    from app.services.tasks import risk_acceptances_expiring

    hook(db, events=[events.RISK_ACCEPTANCE_EXPIRING])
    ingest_report(db, native(finding()), asset, None, IngestOptions())
    f = _accepted(db, asset, days=5)

    for _ in range(2):
        risk_acceptances_expiring(db, {})
        db.commit()
    (d,) = deliveries(db, events.RISK_ACCEPTANCE_EXPIRING)
    assert d.payload["justification"] == "compensating control in place"
    assert d.payload["risk_accepted_until"].startswith(f.risk_accepted_until.date().isoformat())

    # Renewed with a new end date: announced again when that one approaches.
    f.risk_accepted_until = utcnow() + timedelta(days=10)
    db.commit()
    risk_acceptances_expiring(db, {})
    db.commit()
    assert len(deliveries(db, events.RISK_ACCEPTANCE_EXPIRING)) == 2


def test_an_acceptance_far_from_its_end_or_the_warning_turned_off_is_quiet(db, asset, monkeypatch):
    from app.services.tasks import risk_acceptances_expiring

    hook(db, events=[events.RISK_ACCEPTANCE_EXPIRING])
    ingest_report(db, native(finding()), asset, None, IngestOptions())
    f = _accepted(db, asset, days=60)
    risk_acceptances_expiring(db, {})
    assert deliveries(db, events.RISK_ACCEPTANCE_EXPIRING) == []

    f.risk_accepted_until = utcnow() + timedelta(days=3)
    db.commit()
    monkeypatch.setattr(settings, "risk_acceptance_warning_days", 0)
    risk_acceptances_expiring(db, {})
    assert deliveries(db, events.RISK_ACCEPTANCE_EXPIRING) == []


def _kev(*cves):
    return json.dumps({"vulnerabilities": [{"cveID": c, "dueDate": "2026-10-01"} for c in cves]}).encode()


def test_a_cve_newly_added_to_kev_is_announced_for_active_findings_only(db, asset):
    from app.services import intel

    hook(db, events=[events.KEV_ADDED])
    ingest_report(
        db,
        _sca_report(
            _sca("old", "CVE-2021-0001"), _sca("new", "CVE-2026-0002"), _sca("done", "CVE-2026-0003")
        ),
        asset,
        None,
        IngestOptions(),
    )
    done = db.scalar(select(Finding).where(Finding.cve_id == "CVE-2026-0003"))
    done.status = "resolved"
    db.commit()

    # The first sync is the baseline: the whole catalogue would look new, so nothing is announced.
    intel.sync_kev(db, _kev("CVE-2021-0001"))
    db.commit()
    assert deliveries(db, events.KEV_ADDED) == []

    intel.sync_kev(db, _kev("CVE-2021-0001", "CVE-2026-0002", "CVE-2026-0003"))
    db.commit()
    (d,) = deliveries(db, events.KEV_ADDED)
    assert d.payload["cve"] == "CVE-2026-0002" and d.payload["in_kev"] is True

    intel.sync_kev(db, _kev("CVE-2021-0001", "CVE-2026-0002", "CVE-2026-0003"))  # nothing new this time
    db.commit()
    assert len(deliveries(db, events.KEV_ADDED)) == 1


def test_new_events_render_for_slack(db, asset, client, auth, users):
    hook(db, format="slack", events=[events.FINDING_ASSIGNED])
    ingest_report(db, native(finding(title="SQL injection")), asset, None, IngestOptions())
    f = db.scalar(select(Finding))
    to_manager = {"assignee_id": users["manager"].id}
    client.patch(f"/api/v1/findings/{f.id}", json=to_manager, headers=auth["analyst"])
    jobs.Worker(poll_interval=0).run(burst=True)

    slack = json.loads(SENT[0][1])
    assert "Finding assigned: SQL injection" in slack["text"]
    assert "Assigned to" in json.dumps(slack["blocks"])
