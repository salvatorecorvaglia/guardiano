"""Requests to the identity provider are held to the same rules as every other outbound request.

The issuer is configured by an operator, but the token and key endpoints come from whatever the discovery
document says, and discovery used to follow redirects unchecked. These drive the real functions through
httpx.MockTransport (as test_outbound_limits.py does), since test_sso.py stubs these functions out.
"""

import ipaddress
import json
from datetime import UTC, datetime, timedelta

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.exceptions import PyJWKClientConnectionError

from app.core import urlguard
from app.core.config import settings
from app.services import oidc

ISSUER = "https://idp.test"
METADATA = "http://169.254.169.254/latest/meta-data/"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwks() -> dict:
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key()))
    return {"keys": [{**jwk, "kid": "k1", "use": "sig", "alg": "RS256"}]}


@pytest.fixture
def provider(monkeypatch):
    """Answer the provider's requests with ``routes`` (url -> response); record every request made."""

    # No DNS in tests: names resolve nowhere (allowed), IP literals are checked as themselves.
    def addresses(host):
        try:
            return [ipaddress.ip_address(host)]
        except ValueError:
            return None

    monkeypatch.setattr(urlguard, "_addresses", addresses)
    monkeypatch.setattr(settings, "oidc_issuer", ISSUER)
    monkeypatch.setattr(settings, "oidc_client_id", "guardiano")
    monkeypatch.setattr(settings, "public_url", "https://guardiano.test")
    monkeypatch.setattr(oidc, "_discovery_cache", {})
    monkeypatch.setattr(oidc, "_jwk_clients", {})
    seen: list[str] = []

    def install(routes):
        def handler(request):
            seen.append(f"{request.method} {request.url}")
            answer = routes.get(str(request.url))
            return answer() if callable(answer) else answer or httpx.Response(404)

        transport = httpx.MockTransport(handler)
        monkeypatch.setattr(oidc, "_client", lambda: httpx.Client(transport=transport))
        return seen

    return install


def _config(**overrides) -> dict:
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/auth",
        "token_endpoint": f"{ISSUER}/token",
        "jwks_uri": f"{ISSUER}/certs",
        **overrides,
    }


DISCOVERY = f"{ISSUER}/.well-known/openid-configuration"


def test_discovery_follows_a_redirect_to_another_public_host(provider):
    moved = "https://login.idp.test/.well-known/openid-configuration"
    provider(
        {
            DISCOVERY: httpx.Response(301, headers={"location": moved}),
            moved: httpx.Response(200, json=_config()),
        }
    )
    assert oidc.discovery()["token_endpoint"] == f"{ISSUER}/token"


def test_discovery_does_not_follow_a_redirect_into_the_private_network(provider):
    seen = provider({DISCOVERY: httpx.Response(302, headers={"location": METADATA})})
    with pytest.raises(oidc.SsoError, match="private or reserved"):
        oidc.discovery()
    assert seen == [f"GET {DISCOVERY}"]  # the metadata service was never asked


def test_discovery_gives_up_on_a_redirect_loop(provider):
    provider({DISCOVERY: httpx.Response(302, headers={"location": DISCOVERY})})
    with pytest.raises(oidc.SsoError, match="redirected more than"):
        oidc.discovery()


def test_an_enormous_discovery_document_is_refused(provider):
    provider({DISCOVERY: httpx.Response(200, content=b"{" + b" " * (2 * 1024 * 1024))})
    with pytest.raises(oidc.SsoError, match="limit"):
        oidc.discovery()


def test_a_discovery_document_that_is_not_an_object_is_refused(provider):
    provider({DISCOVERY: httpx.Response(200, json=["not", "a", "config"])})
    with pytest.raises(oidc.SsoError, match="not a JSON object"):
        oidc.discovery()


def test_a_token_endpoint_in_the_private_network_is_never_called(provider):
    token_endpoint = "http://10.0.0.5/token"
    seen = provider({DISCOVERY: httpx.Response(200, json=_config(token_endpoint=token_endpoint))})
    with pytest.raises(oidc.SsoError, match="cannot be used"):
        oidc.exchange_code("code", "verifier")
    assert not any(token_endpoint in s for s in seen)


def test_token_endpoint_failure_does_not_log_exception_details(monkeypatch, caplog):
    monkeypatch.setattr(oidc, "discovery", lambda: _config())
    secret = "client_secret=do-not-log-this"

    def refused(*args, **kwargs):
        raise ValueError(f"Refused URL containing {secret}")

    monkeypatch.setattr(oidc, "_fetch", refused)
    with pytest.raises(oidc.SsoError, match="cannot be used"):
        oidc.exchange_code("code", "verifier")

    assert "OIDC exchange failed an outbound safety check" in caplog.text
    assert secret not in caplog.text


def test_a_token_endpoint_redirect_is_not_followed(provider):
    """The token request carries the client secret; it goes where discovery said and nowhere else."""
    elsewhere = "https://elsewhere.test/token"
    seen = provider(
        {
            DISCOVERY: httpx.Response(200, json=_config()),
            f"{ISSUER}/token": httpx.Response(307, headers={"location": elsewhere}),
        }
    )
    with pytest.raises(oidc.SsoError, match="HTTP 307"):
        oidc.exchange_code("code", "verifier")
    assert not any(elsewhere in s for s in seen)


def test_the_token_response_is_read(provider):
    provider(
        {
            DISCOVERY: httpx.Response(200, json=_config()),
            f"{ISSUER}/token": httpx.Response(200, json={"id_token": "abc"}),
        }
    )
    assert oidc.exchange_code("code", "verifier") == {"id_token": "abc"}


def test_keys_in_the_private_network_are_never_fetched(provider):
    seen = provider({DISCOVERY: httpx.Response(200, json=_config(jwks_uri=METADATA))})
    with pytest.raises(PyJWKClientConnectionError, match="private or reserved"):
        oidc._jwk_client().fetch_data()
    assert not any(METADATA in s for s in seen)


def test_an_enormous_key_set_is_refused(provider):
    provider(
        {
            DISCOVERY: httpx.Response(200, json=_config()),
            f"{ISSUER}/certs": httpx.Response(200, content=b"[" + b" " * (2 * 1024 * 1024)),
        }
    )
    with pytest.raises(PyJWKClientConnectionError, match="limit"):
        oidc._jwk_client().fetch_data()


def test_a_token_is_verified_against_keys_fetched_through_the_guard(provider):
    """End to end: the replaced fetch still feeds PyJWT's key lookup, and keys are cached."""
    seen = provider(
        {
            DISCOVERY: httpx.Response(200, json=_config()),
            f"{ISSUER}/certs": httpx.Response(200, json=_jwks()),
        }
    )
    now = datetime.now(UTC)

    def token(nonce):
        claims = {
            "iss": ISSUER, "aud": "guardiano", "sub": "u1", "nonce": nonce,
            "iat": now, "exp": now + timedelta(minutes=5),
        }  # fmt: skip
        return jwt.encode(claims, KEY, algorithm="RS256", headers={"kid": "k1"})

    assert oidc.verify_id_token(token("n1"), "n1")["sub"] == "u1"
    assert oidc.verify_id_token(token("n2"), "n2")["sub"] == "u1"
    assert seen.count(f"GET {ISSUER}/certs") == 1
