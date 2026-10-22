"""Single sign-on: the OIDC flow, its verification, and how accounts and roles are decided."""

from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select

from app.core.config import settings
from app.models import AuditLog, OidcState, User
from app.services import oidc
from tests.conftest import PASSWORD

ISSUER = "https://idp.test/realms/guardiano"
CLIENT_ID = "guardiano"

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)

CONFIG = {
    "issuer": ISSUER,
    "authorization_endpoint": f"{ISSUER}/protocol/openid-connect/auth",
    "token_endpoint": f"{ISSUER}/protocol/openid-connect/token",
    "jwks_uri": f"{ISSUER}/protocol/openid-connect/certs",
}


class FakeJwkClient:
    """Serves the public half of the key the tests sign with."""

    def __init__(self, key):
        self.key = key

    def get_signing_key_from_jwt(self, token):
        return type("Key", (), {"key": self.key.public_key()})()


@pytest.fixture(autouse=True)
def sso(monkeypatch):
    """A configured provider, with the network calls replaced but the verification real."""
    monkeypatch.setattr(settings, "oidc_issuer", ISSUER)
    monkeypatch.setattr(settings, "oidc_client_id", CLIENT_ID)
    monkeypatch.setattr(settings, "oidc_client_secret", "shh")
    monkeypatch.setattr(settings, "public_url", "https://guardiano.test")
    monkeypatch.setattr(settings, "oidc_role_map", "guardiano-admins:admin,appsec:manager")
    monkeypatch.setattr(oidc, "discovery", lambda: CONFIG)
    monkeypatch.setattr(oidc, "_jwk_client", lambda: FakeJwkClient(KEY))


def id_token(nonce, *, key=KEY, issuer=ISSUER, audience=CLIENT_ID, sub="idp-user-1", **claims):
    payload = {
        "iss": issuer,
        "sub": sub,
        "aud": audience,
        "nonce": nonce,
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(minutes=5),
        "email": "dana@example.test",
        "email_verified": True,
        "name": "Dana Dev",
        **claims,
    }
    return jwt.encode(payload, key, algorithm="RS256")


def begin(client, db, next_path=None):
    """Start a sign-in and return (state, nonce)."""
    r = client.get(
        "/api/v1/auth/oidc/login" + (f"?next={next_path}" if next_path else ""), follow_redirects=False
    )
    assert r.status_code == 307
    query = parse_qs(urlparse(r.headers["location"]).query)
    state = query["state"][0]
    db.expire_all()
    return state, db.get(OidcState, state).nonce


def error_of(response) -> str:
    """The human-readable reason carried back to the sign-in page."""
    from urllib.parse import unquote

    return unquote(urlparse(response.headers["location"]).query.removeprefix("sso_error="))


def callback(client, monkeypatch, state, token, **params):
    monkeypatch.setattr(oidc, "exchange_code", lambda code, verifier: {"id_token": token})
    return client.get(
        "/api/v1/auth/oidc/callback",
        params={"code": "auth-code", "state": state, **params},
        follow_redirects=False,
    )


# ---- starting the flow --------------------------------------------------------------------------


def test_the_authorization_url_carries_pkce_and_a_recorded_state(client, db):
    r = client.get("/api/v1/auth/oidc/login", follow_redirects=False)
    assert r.status_code == 307
    url = urlparse(r.headers["location"])
    query = {k: v[0] for k, v in parse_qs(url.query).items()}
    assert url.hostname == "idp.test"
    assert query["client_id"] == CLIENT_ID and query["response_type"] == "code"
    assert query["redirect_uri"] == "https://guardiano.test/api/v1/auth/oidc/callback"
    assert query["code_challenge_method"] == "S256" and query["code_challenge"]

    attempt = db.get(OidcState, query["state"])
    assert attempt is not None and attempt.nonce == query["nonce"]
    # The challenge is the hash of the verifier, which never leaves the server.
    assert attempt.code_verifier != query["code_challenge"]


def test_only_local_redirects_are_kept(client, db):
    for target, expected in [
        ("/findings?severity=critical", "/findings?severity=critical"),
        ("https://evil.test/steal", None),
        ("//evil.test", None),
    ]:
        state, _ = begin(client, db, target)
        assert db.get(OidcState, state).redirect_to == expected


def test_sso_endpoints_are_unavailable_when_unconfigured(client, monkeypatch):
    monkeypatch.setattr(settings, "oidc_issuer", "")
    r = client.get("/api/v1/auth/oidc/login", follow_redirects=False)
    assert r.status_code == 503 and "not configured" in r.json()["detail"]


# ---- finishing the flow -------------------------------------------------------------------------


def test_a_first_sign_in_creates_the_account_and_a_session(client, db, monkeypatch):
    state, nonce = begin(client, db, "/assets")
    r = callback(client, monkeypatch, state, id_token(nonce, groups=["appsec"]))
    assert r.status_code == 303 and r.headers["location"] == "https://guardiano.test/assets"
    assert "guardiano_refresh" in r.cookies or "guardiano_refresh" in r.headers.get("set-cookie", "")

    user = db.scalar(select(User).where(User.email == "dana@example.test"))
    assert user is not None and user.oidc_subject == "idp-user-1"
    assert user.full_name == "Dana Dev" and user.role == "manager"  # appsec -> manager
    assert user.last_login_at is not None

    # The session cookie is real: the SPA exchanges it for an access token.
    refreshed = client.post("/api/v1/auth/refresh")
    assert refreshed.status_code == 200 and refreshed.json()["user"]["email"] == "dana@example.test"

    entry = db.scalar(select(AuditLog).where(AuditLog.action == "auth.sso_login"))
    assert entry.target_label == "dana@example.test" and entry.changes == {"role": "manager"}


def test_an_existing_local_account_is_linked_by_email(client, db, users, monkeypatch):
    analyst = users["analyst"]
    state, nonce = begin(client, db)
    callback(client, monkeypatch, state, id_token(nonce, email="analyst@test.io"))

    db.expire_all()
    assert db.scalar(select(User).where(User.email == "analyst@test.io")).id == analyst.id
    assert len(db.scalars(select(User)).all()) == len(users)  # no duplicate account
    assert db.get(User, analyst.id).oidc_subject == "idp-user-1"
    # The password still works: linking an account does not disable local sign-in.
    assert (
        client.post("/api/v1/auth/login", json={"email": "analyst@test.io", "password": PASSWORD}).status_code
        == 200
    )


def test_state_is_single_use_and_expires(client, db, monkeypatch):
    state, nonce = begin(client, db)
    token = id_token(nonce)
    assert callback(client, monkeypatch, state, token).status_code == 303
    # Replaying the same callback must not produce a second session.
    replay = callback(client, monkeypatch, state, token)
    assert "sso_error" in replay.headers["location"]

    state, nonce = begin(client, db)
    db.get(OidcState, state).expires_at = datetime.now(UTC) - timedelta(minutes=1)
    db.commit()
    r = callback(client, monkeypatch, state, id_token(nonce))
    assert "expired" in error_of(r)


@pytest.mark.parametrize(
    "token_kwargs,fragment",
    [
        ({"key": OTHER_KEY}, "Signature verification failed"),  # signed by somebody else
        ({"issuer": "https://evil.test"}, "Invalid issuer"),
        ({"audience": "another-client"}, "Audience doesn't match"),
    ],
)
def test_a_token_that_does_not_check_out_is_refused(client, db, monkeypatch, token_kwargs, fragment):
    state, nonce = begin(client, db)
    r = callback(client, monkeypatch, state, id_token(nonce, **token_kwargs))
    assert r.status_code == 303 and fragment in error_of(r)
    assert db.scalar(select(User).where(User.email == "dana@example.test")) is None


def test_a_token_for_another_attempt_is_refused(client, db, monkeypatch):
    state, _ = begin(client, db)
    r = callback(client, monkeypatch, state, id_token("some-other-nonce"))
    assert "does not match this sign-in attempt" in error_of(r)
    assert db.scalar(select(User).where(User.email == "dana@example.test")) is None


@pytest.mark.parametrize("description", ["User cancelled", "https://evil.test/\r\n?secret=token"])
def test_provider_error_text_is_not_reflected(client, db, caplog, description):
    r = client.get(
        "/api/v1/auth/oidc/callback",
        params={"error": "access_denied", "error_description": description},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert error_of(r) == "The identity provider declined this sign-in attempt"
    assert urlparse(r.headers["location"]).netloc == "guardiano.test"
    assert description not in caplog.text
    assert description not in db.scalars(select(AuditLog)).all()[0].target_label


def test_a_disabled_account_cannot_sign_in(client, db, users, monkeypatch):
    users["analyst"].is_active = False
    db.commit()
    state, nonce = begin(client, db)
    r = callback(client, monkeypatch, state, id_token(nonce, email="analyst@test.io"))
    assert "disabled" in error_of(r)


def test_automatic_creation_can_be_turned_off(client, db, monkeypatch):
    monkeypatch.setattr(settings, "oidc_auto_create", False)
    state, nonce = begin(client, db)
    r = callback(client, monkeypatch, state, id_token(nonce))
    assert "does not exist" in error_of(r)
    assert db.scalar(select(User).where(User.email == "dana@example.test")) is None


# ---- roles --------------------------------------------------------------------------------------


def test_group_claims_decide_the_role():
    assert oidc.role_for({"groups": ["guardiano-admins"]}, None) == "admin"
    assert oidc.role_for({"groups": ["APPSEC"]}, None) == "manager"  # case-insensitive
    assert oidc.role_for({"groups": "appsec guardiano-admins"}, None) == "admin"  # first mapping wins
    # Configured mapping is authoritative, including removal from every mapped group.
    assert oidc.role_for({"groups": ["unrelated"]}, None) == settings.oidc_default_role
    assert oidc.role_for({"groups": []}, "admin") == settings.oidc_default_role


def test_unmatched_groups_apply_default_role_to_existing_admin(client, db, users, monkeypatch):
    admin = users["admin"]
    state, nonce = begin(client, db)
    callback(client, monkeypatch, state, id_token(nonce, email="admin@test.io", groups=[]))
    db.expire_all()
    assert db.get(User, admin.id).role == settings.oidc_default_role


def test_roles_follow_the_provider_when_groups_change(client, db, users, monkeypatch):
    viewer = users["viewer"]
    state, nonce = begin(client, db)
    callback(client, monkeypatch, state, id_token(nonce, email="viewer@test.io", groups=["appsec"]))
    db.expire_all()
    assert db.get(User, viewer.id).role == "manager"


# ---- local sign-in ------------------------------------------------------------------------------


def test_password_sign_in_can_be_switched_off(client, users, monkeypatch):
    monkeypatch.setattr(settings, "local_login", False)
    r = client.post("/api/v1/auth/login", json={"email": "admin@test.io", "password": PASSWORD})
    assert r.status_code == 403 and "single sign-on" in r.json()["detail"]


def test_meta_tells_the_ui_what_is_available(client, monkeypatch):
    meta = client.get("/api/v1/meta").json()
    assert meta["oidc_enabled"] is True and meta["local_login"] is True
    assert meta["oidc_label"] == "Sign in with SSO"
    monkeypatch.setattr(settings, "oidc_issuer", "")
    assert client.get("/api/v1/meta").json()["oidc_enabled"] is False


# ---- identity linking ----------------------------------------------------------------------------


def test_an_unverified_address_cannot_claim_an_existing_account(client, db, users, monkeypatch):
    """Otherwise anyone who can set their own address at the provider takes over that account."""
    admin = users["admin"]
    state, nonce = begin(client, db)
    r = callback(client, monkeypatch, state, id_token(nonce, email="admin@test.io", email_verified=False))
    assert "verified" in error_of(r)

    db.expire_all()
    assert db.get(User, admin.id).oidc_subject is None  # the account was not adopted


def test_a_missing_email_verified_claim_is_not_treated_as_verified(client, db, users, monkeypatch):
    admin = users["admin"]
    state, nonce = begin(client, db)
    payload = id_token(nonce, email="admin@test.io")
    # Rebuild without the claim entirely, which is how a provider that never sends it looks.
    import jwt as pyjwt

    decoded = pyjwt.decode(payload, options={"verify_signature": False}, audience=CLIENT_ID)
    decoded.pop("email_verified")
    r = callback(client, monkeypatch, state, pyjwt.encode(decoded, KEY, algorithm="RS256"))
    assert "verified" in error_of(r)

    db.expire_all()
    assert db.get(User, admin.id).oidc_subject is None


def test_an_account_already_linked_to_another_identity_is_not_relinked(client, db, users, monkeypatch):
    state, nonce = begin(client, db)
    callback(client, monkeypatch, state, id_token(nonce, email="analyst@test.io"))
    db.expire_all()
    assert db.scalar(select(User).where(User.email == "analyst@test.io")).oidc_subject == "idp-user-1"

    state, nonce = begin(client, db)
    r = callback(client, monkeypatch, state, id_token(nonce, sub="idp-user-2", email="analyst@test.io"))
    assert "already linked" in error_of(r)

    db.expire_all()
    assert db.scalar(select(User).where(User.email == "analyst@test.io")).oidc_subject == "idp-user-1"


def test_a_spent_state_is_gone_even_when_the_sign_in_fails(client, db, monkeypatch):
    """take_state deletes the row, but a rollback further down used to put it back, leaving the
    state and its code_verifier replayable for the rest of its ten-minute lifetime."""
    state, nonce = begin(client, db)
    bad = id_token(nonce, issuer="https://somewhere-else.test")
    assert "sso_error" in callback(client, monkeypatch, state, bad).headers["location"]

    db.expire_all()
    assert db.get(OidcState, state) is None, "the attempt must be spent even though sign-in failed"
    # And it cannot be replayed with a good token either.
    r = callback(client, monkeypatch, state, id_token(nonce))
    assert "unknown or has already been used" in error_of(r)


def test_callback_requires_the_initiating_browser(client, db, monkeypatch):
    state, nonce = begin(client, db)
    client.cookies.clear()
    response = callback(client, monkeypatch, state, id_token(nonce))
    assert response.status_code == 303
    assert "sso_error=" in response.headers["location"]
    assert client.cookies.get("guardiano_refresh") is None
    db.expire_all()
    assert db.get(OidcState, state) is not None


def test_empty_public_url_redirect_is_same_origin(client, db, monkeypatch):
    monkeypatch.setattr(settings, "public_url", "")
    monkeypatch.setattr(settings, "oidc_redirect_url", "https://guardiano.test/api/v1/auth/oidc/callback")
    state, nonce = begin(client, db)
    response = callback(client, monkeypatch, state, id_token(nonce))
    assert response.headers["location"].startswith("/")
    assert not response.headers["location"].startswith("//")
