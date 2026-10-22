"""Two-factor authentication: the TOTP maths, enrolment, sign-in and recovery."""

import time

import pytest
from sqlalchemy import select

from app.core import totp
from app.core.config import settings
from app.core.crypto import decrypt
from app.models import AuditLog, RecoveryCode, User
from tests.conftest import PASSWORD

# RFC 6238 appendix B: the shared secret is the ASCII "12345678901234567890".
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
RFC_VECTORS = [(59, "287082"), (1111111109, "081804"), (1111111111, "050471"), (1234567890, "005924")]


class Clock:
    """A clock the tests can move, so "wait for the next code" costs no real seconds."""

    def __init__(self):
        self.now = time.time()

    def time(self):
        return self.now

    def tick(self, seconds=31):
        self.now += seconds
        return self.now


@pytest.fixture
def clock(monkeypatch):
    """Moves only the TOTP clock; session tokens keep real time."""
    fake = Clock()
    monkeypatch.setattr("app.services.mfa._now", fake.time)
    return fake


def code_now(secret, at=None):
    return totp.code_at(secret, totp.current_step(at or time.time()))


def sign_in(client, email="admin@test.io", password=PASSWORD):
    return client.post("/api/v1/auth/login", json={"email": email, "password": password})


def enrol(client, headers, clock=None):
    """Take an account through enrolment; returns (secret, recovery codes)."""
    setup = client.post("/api/v1/auth/mfa/setup", headers=headers).json()
    at = clock.now if clock else None
    r = client.post("/api/v1/auth/mfa/enable", json={"code": code_now(setup["secret"], at)}, headers=headers)
    assert r.status_code == 200, r.text
    headers["Authorization"] = f"Bearer {r.json()['session']['access_token']}"
    if clock:
        clock.tick()  # a real person's next sign-in uses the next code
    return setup["secret"], r.json()["recovery_codes"]


# ---- the maths ----------------------------------------------------------------------------------


@pytest.mark.parametrize("moment,expected", RFC_VECTORS)
def test_totp_matches_the_rfc_test_vectors(moment, expected):
    """If this passes, any authenticator app agrees with us."""
    assert totp.code_at(RFC_SECRET, totp.current_step(moment)) == expected


def test_a_code_is_accepted_within_the_drift_window_only():
    now = 1_700_000_000
    assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, totp.current_step(now)), now) is not None
    # One step either side is fine; three minutes away is not.
    assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, totp.current_step(now) - 1), now) is not None
    assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, totp.current_step(now) + 1), now) is not None
    assert totp.verify(RFC_SECRET, totp.code_at(RFC_SECRET, totp.current_step(now) - 6), now) is None


def test_a_code_cannot_be_used_twice():
    now = 1_700_000_000
    step = totp.current_step(now)
    code = totp.code_at(RFC_SECRET, step)
    assert totp.verify(RFC_SECRET, code, now, last_step=None) == step
    # The same code again, with that step recorded: refused.
    assert totp.verify(RFC_SECRET, code, now, last_step=step) is None


def test_rubbish_is_rejected_without_raising():
    now = time.time()
    for code in ("", "abcdef", "12345", "1234567", None):
        assert totp.verify(RFC_SECRET, code, now) is None


def test_the_provisioning_uri_is_what_apps_expect():
    uri = totp.provisioning_uri("ABC234", "dana@example.test")
    assert uri.startswith("otpauth://totp/Guardiano%3Adana%40example.test?")
    assert "secret=ABC234" in uri and "issuer=Guardiano" in uri and "period=30" in uri


# ---- enrolment ----------------------------------------------------------------------------------


def test_enrolment_needs_a_working_code_and_stores_the_secret_encrypted(client, auth, db, users):
    status = client.get("/api/v1/auth/mfa", headers=auth["admin"]).json()
    assert status == {"enabled": False, "required": False, "confirmed_at": None, "recovery_codes_left": 0}

    setup = client.post("/api/v1/auth/mfa/setup", headers=auth["admin"]).json()
    assert setup["otpauth_uri"].startswith("otpauth://totp/")
    db.expire_all()
    stored = db.get(User, users["admin"].id)
    assert stored.mfa_enabled is False  # not on until a code proves the app works
    assert stored.mfa_secret != setup["secret"] and decrypt(stored.mfa_secret) == setup["secret"]

    assert (
        client.post("/api/v1/auth/mfa/enable", json={"code": "000000"}, headers=auth["admin"]).status_code
        == 400
    )
    r = client.post(
        "/api/v1/auth/mfa/enable", json={"code": code_now(setup["secret"])}, headers=auth["admin"]
    )
    assert r.status_code == 200 and len(r.json()["recovery_codes"]) == 10

    auth["admin"]["Authorization"] = f"Bearer {r.json()['session']['access_token']}"
    status = client.get("/api/v1/auth/mfa", headers=auth["admin"]).json()
    assert status["enabled"] is True and status["recovery_codes_left"] == 10 and status["confirmed_at"]


def test_recovery_codes_are_stored_hashed(client, auth, db, users):
    _, codes = enrol(client, auth["admin"])
    stored = db.scalars(select(RecoveryCode).where(RecoveryCode.user_id == users["admin"].id)).all()
    hashes = {row.code_hash for row in stored}
    assert len(hashes) == 10
    for code in codes:
        assert code not in hashes
        assert totp.hash_recovery_code(code) in hashes


# ---- signing in ---------------------------------------------------------------------------------


def test_the_password_alone_no_longer_signs_you_in(client, auth, db, clock):
    secret, _ = enrol(client, auth["admin"], clock)

    r = sign_in(client)
    assert r.status_code == 200
    challenge = r.json()
    assert challenge["mfa_required"] is True and "access_token" not in challenge
    assert "guardiano_refresh" not in r.cookies

    # The challenge alone is not a session.
    assert (
        client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {challenge['mfa_token']}"}
        ).status_code
        == 401
    )

    wrong = client.post(
        "/api/v1/auth/login/mfa", json={"mfa_token": challenge["mfa_token"], "code": "000000"}
    )
    assert wrong.status_code == 401 and "not valid" in wrong.json()["detail"]

    ok = client.post(
        "/api/v1/auth/login/mfa",
        json={"mfa_token": challenge["mfa_token"], "code": code_now(secret, clock.now)},
    )
    assert ok.status_code == 200 and ok.json()["user"]["mfa_enabled"] is True
    assert (
        client.get(
            "/api/v1/auth/me", headers={"Authorization": f"Bearer {ok.json()['access_token']}"}
        ).status_code
        == 200
    )

    actions = [e.action for e in db.scalars(select(AuditLog).where(AuditLog.action.startswith("auth.")))]
    assert "auth.mfa_challenged" in actions and "auth.mfa_failed" in actions and "auth.login" in actions


def test_a_recovery_code_works_once(client, auth, db):
    _, codes = enrol(client, auth["admin"])
    challenge = sign_in(client).json()
    r = client.post("/api/v1/auth/login/mfa", json={"mfa_token": challenge["mfa_token"], "code": codes[0]})
    assert r.status_code == 200

    entry = db.scalar(select(AuditLog).where(AuditLog.action == "auth.login", AuditLog.changes != {}))
    assert entry.changes == {"second_factor": "recovery code"}
    assert client.get("/api/v1/auth/mfa", headers=auth["admin"]).json()["recovery_codes_left"] == 9

    # The same code a second time is refused.
    again = sign_in(client).json()
    assert (
        client.post(
            "/api/v1/auth/login/mfa", json={"mfa_token": again["mfa_token"], "code": codes[0]}
        ).status_code
        == 401
    )


def test_a_code_cannot_be_replayed_for_a_second_session(client, auth, clock):
    secret, _ = enrol(client, auth["admin"], clock)
    code = code_now(secret, clock.now)
    first = sign_in(client).json()
    assert (
        client.post(
            "/api/v1/auth/login/mfa", json={"mfa_token": first["mfa_token"], "code": code}
        ).status_code
        == 200
    )

    second = sign_in(client).json()
    replayed = client.post("/api/v1/auth/login/mfa", json={"mfa_token": second["mfa_token"], "code": code})
    assert replayed.status_code == 401, "a code that has been used must not work again"
    assert "already been used" in replayed.json()["detail"]


def test_an_expired_or_forged_challenge_is_refused(client, auth, monkeypatch):
    enrol(client, auth["admin"])
    monkeypatch.setattr(settings, "mfa_challenge_ttl_minutes", -1)  # already expired when issued
    stale = sign_in(client).json()["mfa_token"]
    assert (
        client.post("/api/v1/auth/login/mfa", json={"mfa_token": stale, "code": "123456"}).status_code == 401
    )
    assert (
        client.post("/api/v1/auth/login/mfa", json={"mfa_token": "not-a-token", "code": "123456"}).status_code
        == 401
    )


def test_changing_the_password_invalidates_an_outstanding_challenge(client, auth):
    enrol(client, auth["admin"])
    challenge = sign_in(client).json()["mfa_token"]
    client.post(
        "/api/v1/auth/change-password",
        json={"current_password": PASSWORD, "new_password": "A-New-Passw0rd-Here"},
        headers=auth["admin"],
    )
    r = client.post("/api/v1/auth/login/mfa", json={"mfa_token": challenge, "code": "123456"})
    assert r.status_code == 401


# ---- turning it off, and requiring it -------------------------------------------------------------


def test_disabling_requires_the_password(client, auth, db, users):
    _, codes = enrol(client, auth["admin"])
    assert (
        client.post(
            "/api/v1/auth/mfa/disable", json={"password": "wrong", "code": codes[0]}, headers=auth["admin"]
        ).status_code
        == 400
    )
    assert (
        client.post(
            "/api/v1/auth/mfa/disable", json={"password": PASSWORD, "code": codes[0]}, headers=auth["admin"]
        ).status_code
        == 204
    )

    db.expire_all()
    stored = db.get(User, users["admin"].id)
    assert stored.mfa_enabled is False and stored.mfa_secret is None
    assert db.scalars(select(RecoveryCode)).all() == []  # the old codes go with it
    assert sign_in(client).json().get("access_token")  # the password alone works again


def test_new_recovery_codes_replace_the_old_ones(client, auth, clock):
    secret, old = enrol(client, auth["admin"], clock)
    r = client.post(
        "/api/v1/auth/mfa/recovery-codes",
        json={"code": code_now(secret, clock.now)},
        headers=auth["admin"],
    )
    assert r.status_code == 200
    new = r.json()["recovery_codes"]
    assert set(new).isdisjoint(old)

    challenge = sign_in(client).json()
    assert (
        client.post(
            "/api/v1/auth/login/mfa", json={"mfa_token": challenge["mfa_token"], "code": old[0]}
        ).status_code
        == 401
    )


def test_roles_can_be_told_to_enrol(client, auth, monkeypatch):
    monkeypatch.setattr(settings, "mfa_required_roles", "admin,manager")
    me = client.get("/api/v1/auth/me", headers=auth["admin"]).json()
    assert me["mfa_setup_required"] is True and me["mfa_enabled"] is False
    # Being asked does not lock anybody out: an administrator who cannot enrol yet still gets in.
    assert client.get("/api/v1/findings", headers=auth["admin"]).status_code == 200
    assert client.get("/api/v1/auth/me", headers=auth["viewer"]).json()["mfa_setup_required"] is False

    enrol(client, auth["admin"])
    assert client.get("/api/v1/auth/me", headers=auth["admin"]).json()["mfa_setup_required"] is False


def test_api_tokens_are_not_challenged(client, auth):
    """A token is already a credential of its own; MFA is about interactive sign-in."""
    enrol(client, auth["analyst"])
    token = client.post(
        "/api/v1/tokens", json={"name": "ci", "scopes": ["read"]}, headers=auth["analyst"]
    ).json()["token"]
    assert client.get("/api/v1/findings", headers={"Authorization": f"Bearer {token}"}).status_code == 200
