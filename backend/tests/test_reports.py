"""Scheduled reports: who gets them, when, and that each copy shows only what its reader may see."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models import Asset, Job, ReportSchedule, Team
from app.services import email, reports
from app.services.ingestion import IngestOptions, ingest_report
from tests.conftest import sample

MONDAY = datetime(2026, 9, 21, 7, tzinfo=UTC)  # a Monday, at the default DIGEST_HOUR_UTC


@pytest.fixture
def smtp(monkeypatch):
    monkeypatch.setattr(settings, "smtp_host", "smtp.test")


@pytest.fixture
def estate(db, users):
    team = Team(name="payments", description="")
    db.add(team)
    db.flush()
    team.members.append(users["analyst"])
    public, private = Asset(name="public-site", tags=[]), Asset(name="card-vault", tags=[], team_id=team.id)
    db.add_all([public, private])
    db.commit()
    for a in (public, private):
        ingest_report(db, sample("osv.json"), a, None, IngestOptions())
    return public, private


def schedule(db, users, **kw):
    s = ReportSchedule(name="Weekly security", frequency="weekly", enabled=True,
                       recipient_ids=[users["analyst"].id, users["viewer"].id], **kw)  # fmt: skip
    db.add(s)
    db.commit()
    return s


def test_when_a_report_is_due(db, users):
    s = schedule(db, users)
    assert reports.due(s, MONDAY)
    assert not reports.due(s, MONDAY + timedelta(hours=1)), "only at the digest hour"
    assert not reports.due(s, MONDAY + timedelta(days=1)), "weekly means Monday"
    s.last_sent_at = MONDAY
    assert not reports.due(s, MONDAY), "never twice in a week"
    assert reports.due(s, MONDAY + timedelta(days=7))
    s.frequency, s.last_sent_at = "monthly", None
    assert reports.due(s, datetime(2026, 10, 1, 7, tzinfo=UTC)) and not reports.due(s, MONDAY)
    s.enabled = False
    assert not reports.due(s, datetime(2026, 10, 1, 7, tzinfo=UTC))


def test_each_recipient_gets_their_own_view(db, users, estate, smtp, monkeypatch):
    from app.services import tasks

    s = schedule(db, users)
    monkeypatch.setattr(tasks, "utcnow", lambda: MONDAY)
    tasks.scheduled_reports(db, {})
    db.commit()
    mail = {}
    monkeypatch.setattr(
        email, "send", lambda to, subject, text, html: mail.update({to: {"subject": subject, "text": text}})
    )
    for job in db.scalars(select(Job).where(Job.kind == email.SEND_JOB)):
        assert "text" not in job.payload
        tasks.send_email(db, job.payload)
    assert set(mail) == {users["analyst"].email, users["viewer"].email}
    assert "card-vault" in mail[users["analyst"].email]["text"], "a team member sees the team's asset"
    assert "card-vault" not in mail[users["viewer"].email]["text"], "nobody else does"
    assert "public-site" in mail[users["viewer"].email]["text"]
    assert mail[users["viewer"].email]["subject"] == "[Guardiano] Weekly security: this week"
    db.expire_all()
    assert db.get(ReportSchedule, s.id).last_sent_at == MONDAY


def test_a_product_report_is_about_that_product(db, users, estate, smtp):
    from app.models import Product

    product = Product(name="Website", description="")
    db.add(product)
    db.flush()
    estate[0].product_id = product.id
    db.commit()
    s = schedule(db, users, product_id=product.id)
    message = reports.build(db, s, users["analyst"])
    assert "Website: where it stands" in message.text and "card-vault" not in message.text


def test_managing_schedules(client, auth, users, smtp):
    body = {"name": "Monthly", "frequency": "monthly", "recipient_ids": [users["viewer"].id]}
    assert client.post("/api/v1/report-schedules", json=body, headers=auth["analyst"]).status_code == 403
    r = client.post("/api/v1/report-schedules", json=body, headers=auth["manager"])
    assert r.status_code == 201, r.text
    sid = r.json()["id"]
    bad = {**body, "recipient_ids": [999999]}
    assert client.post("/api/v1/report-schedules", json=bad, headers=auth["manager"]).status_code == 422
    r = client.post(f"/api/v1/report-schedules/{sid}/send", headers=auth["manager"])
    assert r.status_code == 202 and r.json() == {"queued": 1}
    replaced = {**body, "enabled": False}
    r = client.put(f"/api/v1/report-schedules/{sid}", json=replaced, headers=auth["manager"])
    assert r.json()["enabled"] is False
    assert client.delete(f"/api/v1/report-schedules/{sid}", headers=auth["manager"]).status_code == 204


def test_sending_needs_email(client, auth, db, users):
    s = schedule(db, users)
    assert client.post(f"/api/v1/report-schedules/{s.id}/send", headers=auth["manager"]).status_code == 422
