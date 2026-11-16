"""Malformed external fields fail at the boundary without exposing raw provider data."""

import json

import pytest
from pydantic import ValidationError

from app.core.external import DISCOVERY_DOCUMENT, IDENTITY_CLAIMS, JWK_SET, TOKEN_RESPONSE
from app.services import oidc
from app.services.trackers import base

pytestmark = pytest.mark.no_database


@pytest.mark.parametrize(
    "adapter,value",
    [
        (DISCOVERY_DOCUMENT, {"token_endpoint": ["https://provider.test"]}),
        (TOKEN_RESPONSE, {"id_token": 123}),
        (JWK_SET, {"keys": "not-a-list"}),
        (JWK_SET, {"keys": [123]}),
        (IDENTITY_CLAIMS, {"iss": "https://idp.test", "sub": ["admin"]}),
        (IDENTITY_CLAIMS, {"iss": "https://idp.test", "sub": "u1", "email_verified": "true"}),
        (IDENTITY_CLAIMS, {"iss": "https://idp.test", "sub": "u1", "email": "x" * 321}),
    ],
)
def test_boundary_fields_are_strict(adapter, value):
    with pytest.raises(ValidationError):
        adapter.validate_json(json.dumps(value))


@pytest.mark.parametrize("value", [None, 42, "secret-provider-diagnostic"])
def test_tracker_scalar_json_is_a_controlled_error(monkeypatch, value):
    from contextlib import contextmanager

    import httpx

    monkeypatch.setattr(base, "check_url", lambda url: url)

    @contextmanager
    def response(*args, **kwargs):
        yield httpx.Response(200, content=json.dumps(value).encode())

    monkeypatch.setattr(base, "guarded_stream", response)
    with pytest.raises(base.TrackerError, match="not an object or list") as caught:
        base.request("GET", "https://tracker.test")
    assert "secret-provider-diagnostic" not in str(caught.value)


def test_invalid_compressed_tracker_body_is_a_controlled_ambiguous_failure(monkeypatch):
    from contextlib import contextmanager

    import httpx

    class Stream(httpx.SyncByteStream):
        def __iter__(self):
            yield b"invalid gzip"

    @contextmanager
    def response(*args, **kwargs):
        yield httpx.Response(200, headers={"content-encoding": "gzip"}, stream=Stream())

    monkeypatch.setattr(base, "check_url", lambda url: url)
    monkeypatch.setattr(base, "guarded_stream", response)
    with pytest.raises(base.TrackerError, match="invalid encoded") as caught:
        base.request("POST", "https://tracker.test")
    assert caught.value.definitely_not_created is False


def test_invalid_identity_does_not_touch_database():
    class NoDatabase:
        def scalar(self, statement):
            raise AssertionError("invalid claims reached the database")

    with pytest.raises(oidc.SsoError, match="invalid identity claims"):
        oidc.sign_in(NoDatabase(), {"iss": "https://idp.test", "sub": ["u1"]})


@pytest.mark.parametrize(
    "document,message",
    [
        ({"issuer": "https://wrong.test"}, "issuer does not match"),
        ({"token_endpoint": ["secret-provider-diagnostic"]}, "invalid discovery fields"),
        ({"jwks_uri": 123}, "invalid discovery fields"),
    ],
)
def test_discovery_invalid_fields_and_issuer_are_controlled(monkeypatch, document, message):
    from app.core.config import settings

    monkeypatch.setattr(settings, "oidc_issuer", "https://idp.test")
    monkeypatch.setattr(oidc, "_discovery_cache", {})
    monkeypatch.setattr(oidc, "_fetch", lambda *args, **kwargs: (200, json.dumps(document).encode()))
    with pytest.raises(oidc.SsoError, match=message) as caught:
        oidc.discovery()
    assert "secret-provider-diagnostic" not in str(caught.value)


@pytest.mark.parametrize("status,body", [(503, b"secret-provider-diagnostic"), (200, b"not JSON")])
def test_discovery_errors_do_not_reflect_body(monkeypatch, status, body):
    from app.core.config import settings

    monkeypatch.setattr(settings, "oidc_issuer", "https://idp.test")
    monkeypatch.setattr(oidc, "_discovery_cache", {})
    monkeypatch.setattr(oidc, "_fetch", lambda *args, **kwargs: (status, body))
    with pytest.raises(oidc.SsoError) as caught:
        oidc.discovery()
    assert "secret-provider-diagnostic" not in str(caught.value)


def test_jwks_wrong_shape_is_sanitized(monkeypatch):
    from jwt.exceptions import PyJWKClientConnectionError

    monkeypatch.setattr(
        oidc, "_fetch", lambda *args, **kwargs: (200, b'{"keys":"secret-provider-diagnostic"}')
    )
    with pytest.raises(PyJWKClientConnectionError, match="invalid key set") as caught:
        oidc._GuardedJwkClient("https://idp.test/keys").fetch_data()
    assert "secret-provider-diagnostic" not in str(caught.value)


def test_real_guarded_transport_blocks_private_connection_without_network():
    from app.core.urlguard import BlockedURL, guarded_client

    with guarded_client() as client, pytest.raises(BlockedURL):
        client.get("http://127.0.0.1/")


def test_predecoded_body_is_still_size_checked():
    import httpx

    from app.core.urlguard import TooLarge, read_capped

    with pytest.raises(TooLarge):
        read_capped(httpx.Response(200, content=b"123", headers={"content-length": "1"}), 2)
