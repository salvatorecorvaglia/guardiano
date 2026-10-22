"""Business regressions from the project audit, including real PostgreSQL races."""

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from unittest.mock import Mock

import httpcore
import pytest

from app.core import urlguard
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.security import hash_api_token
from app.models import Asset, Component, Finding, LicensePolicy, PasswordReset, Team, User
from app.models.base import utcnow
from app.models.enums import Status
from app.services import events, intel, jobs, lifecycle, mfa, tasks, vex
from app.services.analytics import open_series
from app.services.errors import ValidationFailed
from app.services.scope import GLOBAL
from tests.conftest import PASSWORD


def finding(db, *, asset=None, title="audit", **kw):
    asset = asset or Asset(name=title)
    db.add(asset)
    db.flush()
    f = Finding(asset_id=asset.id, title=title, dedup_key=title, type="sca", severity="high", **kw)
    db.add(f)
    db.commit()
    return f


def test_password_recovery_does_not_authenticate_or_bypass_mfa(client, db, users):
    user = users["viewer"]
    mfa.begin_setup(user)
    user.mfa_enabled = True
    db.add(
        PasswordReset(
            user_id=user.id,
            token_hash=hash_api_token("reset-audit-token-with-at-least-32-characters"),
            expires_at=utcnow() + timedelta(hours=1),
        )
    )
    db.commit()
    result = client.post(
        "/api/v1/auth/reset-password",
        json={
            "token": "reset-audit-token-with-at-least-32-characters",
            "new_password": "A-New-Password-2026",
        },
    )
    assert result.status_code == 204 and not result.content
    result = client.post("/api/v1/auth/login", json={"email": user.email, "password": "A-New-Password-2026"})
    assert result.json()["mfa_required"] is True
    assert (
        client.post(
            "/api/v1/auth/reset-password",
            json={
                "token": "reset-audit-token-with-at-least-32-characters",
                "new_password": "Another-Password-2026",
            },
        ).status_code
        == 400
    )


def test_sso_only_disables_password_recovery(client, monkeypatch):
    monkeypatch.setattr(settings, "local_login", False)
    assert client.post("/api/v1/auth/forgot-password", json={"email": "a@example.test"}).status_code == 403
    assert (
        client.post(
            "/api/v1/auth/reset-password", json={"token": "x" * 32, "new_password": "New-Password-2026"}
        ).status_code
        == 403
    )


def test_refresh_predecessor_cannot_restore_logged_out_session(client, users):
    assert (
        client.post(
            "/api/v1/auth/login", json={"email": users["viewer"].email, "password": PASSWORD}
        ).status_code
        == 200
    )
    predecessor = client.cookies.get("guardiano_refresh")
    assert client.post("/api/v1/auth/refresh").status_code == 200
    assert client.post("/api/v1/auth/logout").status_code == 204
    client.cookies.clear()
    client.cookies.set("guardiano_refresh", predecessor, path="/api/v1/auth")
    assert client.post("/api/v1/auth/refresh").status_code == 401


def test_parallel_recovery_code_consumption_has_one_winner(db, users):
    code = mfa.issue_recovery_codes(db, users["viewer"])[0]
    db.commit()
    uid = users["viewer"].id
    ready = threading.Barrier(2)

    def consume():
        with SessionLocal() as session:
            user = session.get(User, uid)
            ready.wait(timeout=5)
            result = mfa.spend_recovery_code(session, user, code)
            session.commit()
            return result

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(lambda _: consume(), range(2))) == [False, True]


def test_enforced_mfa_is_opt_in_and_browser_only(client, auth, monkeypatch):
    monkeypatch.setattr(settings, "mfa_enforced_roles", "analyst")
    assert client.get("/api/v1/findings", headers=auth["analyst"]).status_code == 403
    assert client.get("/api/v1/auth/mfa", headers=auth["analyst"]).status_code == 200
    assert client.get("/api/v1/findings", headers=auth["viewer"]).status_code == 200


def test_vex_never_merges_namespaces(db):
    f = finding(db, package_name="@b/lib", package_version="1", ecosystem="npm", purl="pkg:npm/%40b/lib@1")
    assert not vex._matches(vex.parse_purl("pkg:npm/%40a/lib@1"), f)
    assert vex._matches(vex.parse_purl("pkg:npm/%40b/lib@1"), f)


@pytest.mark.parametrize(
    "doc",
    [
        {"@context": "openvex", "statements": [{"products": 12}]},
        {"bomFormat": "CycloneDX", "vulnerabilities": [{"analysis": 12}]},
    ],
)
def test_malformed_vex_is_a_validation_error(doc):
    with pytest.raises(ValidationFailed):
        vex.parse(json.dumps(doc).encode())


def test_license_filters_use_complete_verdict(client, auth, db, monkeypatch):
    monkeypatch.setattr(settings, "license_default", "review")
    asset = Asset(name="licenses")
    db.add(asset)
    db.flush()
    for name, lic in [
        ("allowed", ["MIT"]),
        ("denied", ["GPL"]),
        ("review", ["Unlisted"]),
        ("comma", ["License, with comma"]),
    ]:
        db.add(Component(asset_id=asset.id, key=name, name=name, licenses=lic))
    db.add_all([LicensePolicy(licence="mit", rule="allowed"), LicensePolicy(licence="gpl", rule="denied")])
    db.commit()
    for rule, names in [("allowed", ["allowed"]), ("denied", ["denied"]), ("review", ["comma", "review"])]:
        r = client.get("/api/v1/components", params={"licence_rule": rule}, headers=auth["viewer"])
        assert r.status_code == 200, r.text
        assert [x["name"] for x in r.json()["items"]] == names
    row = client.get("/api/v1/components", params={"q": "comma"}, headers=auth["viewer"]).json()["items"][0]
    assert row["licenses"] == ["License, with comma"]


def test_past_closed_days_stay_closed_after_reopen(db):
    now = utcnow()
    f = finding(db, first_seen_at=now - timedelta(days=5))
    lifecycle.set_status(
        db,
        f,
        Status.resolved,
        actor=None,
        now=now - timedelta(days=3),
    )
    db.commit()
    target = (now - timedelta(days=2)).date()
    assert open_series(db, target, target, scope=GLOBAL)[0]["high"] == 0
    lifecycle.reopen(db, f, "new scan", now=now)
    db.commit()
    assert open_series(db, target, target, scope=GLOBAL)[0]["high"] == 0


def test_kev_backlog_survives_feed_advance(db, monkeypatch):
    first = finding(db, title="kev-one", cve_id="CVE-2099-2")
    finding(db, title="kev-two", cve_id="CVE-2099-2")

    def raw(cves):
        return json.dumps({"vulnerabilities": [{"cveID": c} for c in cves]}).encode()

    intel.sync_kev(db, raw(["CVE-2099-1"]))
    db.commit()
    monkeypatch.setattr(settings, "event_batch_limit", 1)
    emitted = []
    monkeypatch.setattr(
        events, "emit", lambda db, event, payload, **kw: emitted.append(payload["finding_id"])
    )
    for _ in range(3):
        intel.sync_kev(db, raw(["CVE-2099-1", "CVE-2099-2"]))
        db.commit()
    assert len(emitted) == 2 and len(set(emitted)) == 2 and first.id in emitted


def test_stale_owner_cannot_finish_reassigned_job(db):
    queued = jobs.enqueue(db, "audit")
    db.commit()
    claim = jobs.claim(db)
    old = claim.claim_token
    future = utcnow() + timedelta(minutes=16)
    jobs.recover_stale(db, future)
    db.commit()
    fresh = jobs.claim(db, future)
    assert fresh.claim_token != old
    jobs._finish(db, queued.id, None, future, old)
    db.commit()
    db.refresh(fresh)
    assert fresh.status == jobs.RUNNING


def test_dispatch_connects_only_to_checked_address(monkeypatch):
    import ipaddress

    monkeypatch.setattr(urlguard, "_addresses", lambda host: [ipaddress.ip_address("93.184.216.34")])
    connected = []
    monkeypatch.setattr(
        httpcore.SyncBackend, "connect_tcp", lambda self, host, *args: connected.append(host) or Mock()
    )
    urlguard.GuardedBackend().connect_tcp("example.test", 443)
    assert connected == ["93.184.216.34"]
    monkeypatch.setattr(urlguard, "_addresses", lambda host: None)
    with pytest.raises(urlguard.BlockedURL):
        urlguard.GuardedBackend().connect_tcp("example.test", 443)


def test_queued_assignment_rechecks_team_access(db, users, monkeypatch):
    team = Team(name="private")
    team.members.append(users["analyst"])
    db.add(team)
    db.flush()
    f = finding(db, asset=Asset(name="private-asset", team_id=team.id), assignee_id=users["analyst"].id)
    payload = {"kind": "assignment", "recipient_id": users["analyst"].id, "finding_id": f.id}
    team.members.clear()
    db.commit()
    sent = Mock()
    monkeypatch.setattr(tasks.email, "send", sent)
    tasks.send_email(db, payload)
    sent.assert_not_called()


def test_job_lease_is_renewed_during_long_handler(db, monkeypatch):
    from app.models import Job

    queued = jobs.enqueue(db, "audit.lease")
    db.commit()
    entered, release = threading.Event(), threading.Event()

    def handler(session, payload):
        entered.set()
        assert release.wait(timeout=5)

    monkeypatch.setitem(jobs._HANDLERS, "audit.lease", handler)
    monkeypatch.setattr(jobs, "RENEW_SECONDS", 0.02)
    with ThreadPoolExecutor(max_workers=1) as pool:
        execution = pool.submit(jobs.run_one)
        try:
            assert entered.wait(timeout=5)
            db.refresh(queued)
            initial = queued.locked_at
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                db.expire_all()
                current = db.get(Job, queued.id)
                if current.locked_at > initial:
                    break
                time.sleep(0.02)
            else:
                pytest.fail("active job lease was not renewed")
        finally:
            release.set()
        assert execution.result(timeout=5)
    db.refresh(queued)
    assert queued.status == jobs.DONE
