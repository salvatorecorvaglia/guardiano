"""Repeated wrong passwords lock the account, not just the address they came from."""

from datetime import timedelta

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models import AuditLog, User
from app.models.base import utcnow
from app.services import lockout
from tests.conftest import PASSWORD, make_user


@pytest.fixture
def victim(db):
    return make_user(db, "victim@test.io", "analyst")


def attempt(client, password, email="victim@test.io"):
    return client.post("/api/v1/auth/login", json={"email": email, "password": password})


def test_the_account_locks_after_repeated_failures(client, db, victim, monkeypatch):
    monkeypatch.setattr(settings, "login_max_failures", 3)
    for _ in range(3):
        assert attempt(client, "wrong").status_code == 401

    db.expire_all()
    assert db.get(User, victim.id).locked_until is not None
    # The right password is refused while locked -- that is the whole point.
    assert attempt(client, PASSWORD).status_code == 401


def test_the_refusal_does_not_say_the_account_is_locked(client, db, victim, monkeypatch):
    """A distinct message would confirm the address has an account behind it."""
    monkeypatch.setattr(settings, "login_max_failures", 1)
    unknown = attempt(client, "wrong", email="nobody@test.io")
    attempt(client, "wrong")
    locked = attempt(client, PASSWORD)
    assert locked.status_code == unknown.status_code == 401
    assert locked.json()["detail"] == unknown.json()["detail"] == "Invalid email or password"


def test_a_lockout_is_recorded_in_the_audit_log(client, db, victim, monkeypatch):
    monkeypatch.setattr(settings, "login_max_failures", 1)
    attempt(client, "wrong")
    actions = [e.action for e in db.scalars(select(AuditLog).where(AuditLog.action.startswith("auth.")))]
    assert "auth.login_locked" in actions


def test_a_successful_sign_in_clears_the_counter(client, db, victim, monkeypatch):
    monkeypatch.setattr(settings, "login_max_failures", 5)
    for _ in range(3):
        attempt(client, "wrong")
    db.expire_all()
    assert db.get(User, victim.id).failed_logins == 3

    assert attempt(client, PASSWORD).status_code == 200
    db.expire_all()
    assert db.get(User, victim.id).failed_logins == 0


def test_the_lock_expires(client, db, victim, monkeypatch):
    monkeypatch.setattr(settings, "login_max_failures", 1)
    attempt(client, "wrong")
    db.expire_all()
    user = db.get(User, victim.id)
    assert user.locked_until is not None

    user.locked_until = utcnow() - timedelta(seconds=1)
    db.commit()
    assert attempt(client, PASSWORD).status_code == 200


def test_guessing_on_does_not_extend_somebody_elses_lock(db, victim, monkeypatch):
    """Otherwise anyone who knows an address could keep its owner out indefinitely."""
    monkeypatch.setattr(settings, "login_max_failures", 1)
    lockout.record_failure(victim)
    first = victim.locked_until
    assert first is not None
    for _ in range(5):
        lockout.record_failure(victim)
    assert victim.locked_until == first


def test_the_lock_grows_with_each_further_failure(victim, monkeypatch):
    monkeypatch.setattr(settings, "login_max_failures", 1)
    monkeypatch.setattr(settings, "login_lockout_seconds", 60)
    monkeypatch.setattr(settings, "login_lockout_max_seconds", 3600)
    spans = []
    for _ in range(4):
        victim.locked_until = None  # as if the previous lock had expired
        lockout.record_failure(victim)
        spans.append((victim.locked_until - utcnow()).total_seconds())
    assert spans[0] < spans[1] < spans[2] < spans[3]


def test_the_lock_is_capped(victim, monkeypatch):
    monkeypatch.setattr(settings, "login_max_failures", 1)
    monkeypatch.setattr(settings, "login_lockout_max_seconds", 120)
    victim.failed_logins = 40
    victim.locked_until = None
    lockout.record_failure(victim)
    assert (victim.locked_until - utcnow()).total_seconds() <= 120


# ---- signing out ---------------------------------------------------------------------------------


def test_logout_stops_the_refresh_token_it_was_given(client, db, victim):
    """Deleting the cookie only asks the browser to forget the token; whoever copied it could
    otherwise keep refreshing with it for the whole REFRESH_TOKEN_TTL_DAYS."""
    assert attempt(client, PASSWORD).status_code == 200
    stolen = client.cookies.get("guardiano_refresh")
    assert stolen

    assert client.post("/api/v1/auth/logout").status_code == 204

    # Present the captured token directly, as somebody who copied it would.
    client.cookies.set("guardiano_refresh", stolen, path="/api/v1/auth")
    assert client.post("/api/v1/auth/refresh").status_code == 401


def test_signing_out_twice_is_not_an_error(client, db, victim):
    assert attempt(client, PASSWORD).status_code == 200
    token = client.cookies.get("guardiano_refresh")
    assert client.post("/api/v1/auth/logout").status_code == 204
    client.cookies.set("guardiano_refresh", token, path="/api/v1/auth")
    assert client.post("/api/v1/auth/logout").status_code == 204


def test_another_session_still_works_after_one_signs_out(client, db, victim):
    """Signing out one device is not "sign out everywhere"."""
    assert attempt(client, PASSWORD).status_code == 200
    first = client.cookies.get("guardiano_refresh")
    assert attempt(client, PASSWORD).status_code == 200
    second = client.cookies.get("guardiano_refresh")
    assert first != second

    client.cookies.set("guardiano_refresh", first, path="/api/v1/auth")
    client.post("/api/v1/auth/logout")

    client.cookies.set("guardiano_refresh", second, path="/api/v1/auth")
    assert client.post("/api/v1/auth/refresh").status_code == 200


def test_the_record_of_a_revoked_token_is_swept_once_it_expires(db, victim):
    from datetime import timedelta

    from app.models import RevokedToken
    from app.services import retention, sessions

    db.add(RevokedToken(jti="a" * 32, user_id=victim.id, expires_at=utcnow() - timedelta(days=1)))
    db.add(RevokedToken(jti="b" * 32, user_id=victim.id, expires_at=utcnow() + timedelta(days=1)))
    db.commit()

    assert retention.run(db)["revoked_tokens"] == 1
    db.commit()
    assert sessions.is_revoked(db, "a" * 32) is False  # expired anyway, so the record is dead weight
    assert sessions.is_revoked(db, "b" * 32) is True
