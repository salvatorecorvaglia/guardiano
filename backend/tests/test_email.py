"""Email: SMTP gating, assignment mail, digests and self-service password reset."""

import json
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models import Asset, AuditLog, Finding, Job, PasswordReset, User
from app.models.base import utcnow
from app.services import email, jobs
from app.services.ingestion import IngestOptions, ingest_report
from tests.conftest import PASSWORD

SENT: list[dict] = []


@pytest.fixture(autouse=True)
def fake_smtp(monkeypatch):
    """Capture messages instead of talking to a mail server."""
    SENT.clear()

    def _send(to, subject, text, html_body=None):
        if not email.enabled():
            return
        SENT.append({"to": to, "subject": subject, "text": text, "html": html_body})

    monkeypatch.setattr(email, "send", _send)


@pytest.fixture
def smtp_on(monkeypatch):
    monkeypatch.setattr(settings, "smtp_host", "smtp.test")
    monkeypatch.setattr(settings, "public_url", "https://guardiano.test")


@pytest.fixture
def asset(db):
    a = Asset(name="svc", tags=[])
    db.add(a)
    db.commit()
    return a


def native(*titles):
    return json.dumps(
        {
            "schema": "guardiano/v1",
            "tool": {"name": "Semgrep"},
            "scan_type": "sast",
            "findings": [
                {"title": t, "severity": "high", "cwe": ["CWE-89"], "file_path": f"{t}.py", "line_start": 1}
                for t in titles
            ],
        }
    ).encode()


def run_jobs():
    jobs.Worker(poll_interval=0).run(burst=True)


# ---- gating -------------------------------------------------------------------------------------


def test_nothing_is_sent_without_smtp(db, client, auth, users, asset):
    assert email.enabled() is False
    ingest_report(db, native("a"), asset, None, IngestOptions())
    f = db.scalar(select(Finding))
    r = client.patch(
        f"/api/v1/findings/{f.id}", json={"assignee_id": users["viewer"].id}, headers=auth["analyst"]
    )
    assert r.status_code == 200
    assert db.scalar(select(Job).where(Job.kind == email.SEND_JOB)) is None
    assert SENT == []


def test_forgot_password_is_unavailable_without_smtp(client, users):
    r = client.post("/api/v1/auth/forgot-password", json={"email": "viewer@test.io"})
    assert r.status_code == 503 and "not configured" in r.json()["detail"]


# ---- assignment ---------------------------------------------------------------------------------


def test_assignment_emails_the_new_owner(client, auth, db, users, asset, smtp_on):
    ingest_report(db, native("SQL injection"), asset, None, IngestOptions())
    f = db.scalar(select(Finding))
    client.patch(
        f"/api/v1/findings/{f.id}", json={"assignee_id": users["viewer"].id}, headers=auth["analyst"]
    )
    run_jobs()

    (message,) = SENT
    assert message["to"] == "viewer@test.io"
    assert "SQL injection" in message["subject"] and "HIGH" in message["subject"]
    assert "Analyst assigned a finding to you" in message["text"]
    assert f"https://guardiano.test/findings/{f.id}" in message["text"]


def test_assignment_email_respects_preferences_and_self_assignment(client, auth, db, users, asset, smtp_on):
    ingest_report(db, native("a", "b"), asset, None, IngestOptions())
    first, second = db.scalars(select(Finding).order_by(Finding.id)).all()

    users["viewer"].notify_on_assignment = False
    db.commit()
    client.patch(
        f"/api/v1/findings/{first.id}", json={"assignee_id": users["viewer"].id}, headers=auth["analyst"]
    )
    # Assigning to yourself needs no email.
    client.patch(
        f"/api/v1/findings/{second.id}", json={"assignee_id": users["analyst"].id}, headers=auth["analyst"]
    )
    run_jobs()
    assert SENT == []


def test_the_asset_default_assignee_does_not_generate_mail(db, users, asset, smtp_on):
    asset.default_assignee_id = users["analyst"].id
    db.commit()
    ingest_report(db, native("a", "b", "c"), asset, None, IngestOptions())
    run_jobs()
    assert SENT == []  # one message per new finding would be unusable


# ---- digests ------------------------------------------------------------------------------------


def _digest_now(db, monkeypatch):
    from app.services.tasks import email_digests

    monkeypatch.setattr(settings, "digest_hour_utc", utcnow().hour)
    email_digests(db, {})
    db.commit()
    run_jobs()


def test_daily_digest_lists_what_is_assigned(db, users, asset, smtp_on, monkeypatch):
    user = users["analyst"]
    user.digest_frequency = "daily"
    ingest_report(db, native("SQL injection", "XSS"), asset, None, IngestOptions())
    for f in db.scalars(select(Finding)):
        f.assignee_id = user.id
    db.commit()

    _digest_now(db, monkeypatch)
    (message,) = SENT
    assert message["to"] == user.email and "daily security summary" in message["subject"]
    assert "Assigned to you (2)" in message["text"] and "SQL injection" in message["text"]
    assert "https://guardiano.test/findings/" in message["html"]
    assert f"/findings?assignee_id={user.id}&status=open&status=in_progress" in message["text"]


def test_digest_goes_out_once_per_period(db, users, asset, smtp_on, monkeypatch):
    user = users["analyst"]
    user.digest_frequency = "daily"
    ingest_report(db, native("a"), asset, None, IngestOptions())
    db.scalar(select(Finding)).assignee_id = user.id
    db.commit()

    _digest_now(db, monkeypatch)
    assert len(SENT) == 1
    _digest_now(db, monkeypatch)  # an hour later, same day
    assert len(SENT) == 1

    db.expire_all()
    db.get(User, user.id).last_digest_at = utcnow() - timedelta(days=1)
    db.commit()
    _digest_now(db, monkeypatch)
    assert len(SENT) == 2


def test_digest_skips_people_with_nothing_and_people_who_opted_out(db, users, asset, smtp_on, monkeypatch):
    users["analyst"].digest_frequency = "daily"  # subscribed, but nothing assigned
    users["manager"].digest_frequency = "off"
    ingest_report(db, native("a"), asset, None, IngestOptions())
    db.scalar(select(Finding)).assignee_id = users["manager"].id
    db.commit()

    _digest_now(db, monkeypatch)
    assert SENT == []


def test_digest_only_runs_at_the_configured_hour(db, users, asset, smtp_on, monkeypatch):
    from app.services.tasks import email_digests

    users["analyst"].digest_frequency = "daily"
    ingest_report(db, native("a"), asset, None, IngestOptions())
    db.scalar(select(Finding)).assignee_id = users["analyst"].id
    db.commit()

    monkeypatch.setattr(settings, "digest_hour_utc", (utcnow().hour + 3) % 24)
    email_digests(db, {})
    db.commit()
    run_jobs()
    assert SENT == []


# ---- password reset -----------------------------------------------------------------------------


def test_password_reset_end_to_end(client, db, users, smtp_on):
    r = client.post("/api/v1/auth/forgot-password", json={"email": "Viewer@test.io"})
    assert r.status_code == 204
    run_jobs()
    (message,) = SENT
    assert message["to"] == "viewer@test.io"

    token = message["text"].split("token=")[1].split()[0]
    stored = db.scalar(select(PasswordReset))
    assert stored.token_hash != token and len(stored.token_hash) == 64  # stored hashed, never in the clear

    new_password = "A-Brand-New-Passw0rd"
    r = client.post("/api/v1/auth/reset-password", json={"token": token, "new_password": new_password})
    assert r.status_code == 204 and not r.content
    assert (
        "guardiano_refresh=" not in r.headers.get("set-cookie", "") or "Max-Age=0" in r.headers["set-cookie"]
    )

    assert (
        client.post("/api/v1/auth/login", json={"email": "viewer@test.io", "password": PASSWORD}).status_code
        == 401
    )
    assert (
        client.post(
            "/api/v1/auth/login", json={"email": "viewer@test.io", "password": new_password}
        ).status_code
        == 200
    )
    # The link is single use.
    assert (
        client.post(
            "/api/v1/auth/reset-password", json={"token": token, "new_password": new_password}
        ).status_code
        == 400
    )
    actions = [
        e.action
        for e in db.scalars(select(AuditLog).where(AuditLog.action.startswith("auth.password_reset")))
    ]
    assert actions == ["auth.password_reset_requested", "auth.password_reset"]


def test_reset_invalidates_existing_sessions(client, db, users, smtp_on):
    old = client.post("/api/v1/auth/login", json={"email": "viewer@test.io", "password": PASSWORD}).json()
    headers = {"Authorization": f"Bearer {old['access_token']}"}
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 200

    client.post("/api/v1/auth/forgot-password", json={"email": "viewer@test.io"})
    run_jobs()
    token = SENT[0]["text"].split("token=")[1].split()[0]
    client.post("/api/v1/auth/reset-password", json={"token": token, "new_password": "Yet-Another-Pass1"})
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401


def test_unknown_or_disabled_accounts_reveal_nothing(client, db, users, smtp_on):
    users["viewer"].is_active = False
    db.commit()
    for address in ("nobody@test.io", "viewer@test.io"):
        assert client.post("/api/v1/auth/forgot-password", json={"email": address}).status_code == 204
    run_jobs()
    assert SENT == []  # no mail, and the caller cannot tell the two cases apart
    assert db.scalar(select(PasswordReset)) is None


def test_expired_and_bogus_tokens_are_refused(client, db, users, smtp_on):
    client.post("/api/v1/auth/forgot-password", json={"email": "viewer@test.io"})
    run_jobs()
    token = SENT[0]["text"].split("token=")[1].split()[0]
    db.scalar(select(PasswordReset)).expires_at = utcnow() - timedelta(minutes=1)
    db.commit()

    for bad in (token, "not-a-real-token-value-at-all"):
        r = client.post("/api/v1/auth/reset-password", json={"token": bad, "new_password": "Whatever-Pass12"})
        assert r.status_code == 400


# ---- preferences --------------------------------------------------------------------------------


def test_preferences_api(client, auth, db, users):
    assert client.get("/api/v1/auth/preferences", headers=auth["viewer"]).json() == {
        "digest_frequency": "off",
        "notify_on_assignment": True,
    }
    r = client.patch("/api/v1/auth/preferences", json={"digest_frequency": "weekly"}, headers=auth["viewer"])
    assert r.status_code == 200 and r.json()["digest_frequency"] == "weekly"
    assert (
        client.patch(
            "/api/v1/auth/preferences", json={"digest_frequency": "hourly"}, headers=auth["viewer"]
        ).status_code
        == 422
    )
    db.expire_all()
    assert db.get(User, users["viewer"].id).digest_frequency == "weekly"
