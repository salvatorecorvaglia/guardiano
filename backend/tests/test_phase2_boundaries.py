"""Regression checks for external identity and response boundaries."""

import gzip
import json
import zlib

import httpx
import pytest
from sqlalchemy import select

from app.core.config import settings
from app.core.urlguard import TooLarge, read_capped
from app.models import User
from app.services import oidc
from tests.conftest import make_user


class Chunks(httpx.SyncByteStream):
    def __init__(self, data):
        self.data = data

    def __iter__(self):
        for pos in range(0, len(self.data), 13):
            yield self.data[pos:pos + 13]


@pytest.mark.no_database
@pytest.mark.parametrize("encoding,compress", [("gzip", gzip.compress), ("deflate", zlib.compress)])
def test_compressed_response_limits(encoding, compress):
    def response(data):
        return httpx.Response(200, headers={"content-encoding": encoding}, stream=Chunks(data))

    assert read_capped(response(compress(b"hello")), 100) == b"hello"
    with pytest.raises(TooLarge):
        read_capped(response(compress(b"x" * (8 * 1024 * 1024))), 1024)
    with pytest.raises(ValueError, match="Truncated"):
        read_capped(response(compress(b"hello")[:-2]), 100)


@pytest.mark.no_database
@pytest.mark.parametrize("body", [[], None, 42, {}, {"id_token": 12}, {"id_token": ""}])
def test_invalid_token_response_is_controlled(monkeypatch, body):
    monkeypatch.setattr(oidc, "discovery", lambda: {"token_endpoint": "https://idp.test/token"})
    monkeypatch.setattr(oidc, "_fetch", lambda *a, **kw: (200, json.dumps(body).encode()))
    with pytest.raises(oidc.SsoError, match="invalid token response"):
        oidc.exchange_code("code", "verifier")


@pytest.mark.no_database
@pytest.mark.parametrize("groups", [12, {"admin": True}, [12]])
def test_invalid_group_claim_is_controlled(groups):
    with pytest.raises(oidc.SsoError, match="group claims"):
        oidc.role_for({settings.oidc_groups_claim: groups}, "viewer")


def test_same_subject_at_new_issuer_cannot_select_old_admin(db, monkeypatch):
    user = make_user(db, "old@test.io", "admin")
    user.oidc_subject, user.oidc_issuer = "same", "https://old.test"
    db.commit()
    monkeypatch.setattr(settings, "oidc_issuer", "https://new.test")
    monkeypatch.setattr(settings, "oidc_role_map", "")
    result = oidc.sign_in(db, {
        "iss": "https://new.test", "sub": "same", "email": "new@test.io", "email_verified": True,
    })
    db.flush()
    assert result.id != user.id and result.role == "viewer"
    assert db.scalar(select(User).where(User.id == user.id)).email == "old@test.io"


def test_legacy_binding_requires_operator_and_is_idempotent(db, monkeypatch, capsys):
    import argparse

    from app.cli import cmd_bind_oidc

    user = make_user(db, "legacy@test.io", "admin")
    user.oidc_subject = "legacy"
    db.commit()
    monkeypatch.setattr(settings, "oidc_issuer", "https://original.test")
    claims = {"iss": "https://original.test", "sub": "legacy", "email": user.email}
    with pytest.raises(oidc.SsoError, match="operator"):
        oidc.sign_in(db, claims)
    db.rollback()
    args = argparse.Namespace(legacy_issuer="https://original.test")
    cmd_bind_oidc(args)
    cmd_bind_oidc(args)
    db.expire_all()
    assert user.oidc_issuer == "https://original.test" and user.token_version == 1
    assert "Bound 0" in capsys.readouterr().out


@pytest.mark.no_database
def test_gzip_bomb_is_rejected_without_allocating_full_expansion():
    import tracemalloc

    compressed = gzip.compress(b"x" * (8 * 1024 * 1024))
    response = httpx.Response(200, headers={"content-encoding": "gzip"}, stream=Chunks(compressed))
    tracemalloc.start()
    try:
        with pytest.raises(TooLarge):
            read_capped(response, 65536)
        assert tracemalloc.get_traced_memory()[1] < 1024 * 1024
    finally:
        tracemalloc.stop()


@pytest.mark.no_database
@pytest.mark.parametrize("encoding,data", [
    ("br", b"unsupported"),
    ("gzip", b"invalid gzip"),
    ("gzip", gzip.compress(b"one") + gzip.compress(b"two")),
])
def test_unsupported_corrupt_and_trailing_encoding_are_refused(encoding, data):
    response = httpx.Response(200, headers={"content-encoding": encoding}, stream=Chunks(data))
    with pytest.raises(ValueError):
        read_capped(response, 1024)


@pytest.mark.no_database
def test_encoded_stream_and_identity_boundary_are_capped():
    assert read_capped(httpx.Response(200, stream=Chunks(b"12345")), 5) == b"12345"
    with pytest.raises(TooLarge):
        read_capped(httpx.Response(200, stream=Chunks(b"123456")), 5)


def test_new_issuer_cannot_relink_old_account_by_verified_email(db, monkeypatch):
    user = make_user(db, "bound@test.io", "admin")
    user.oidc_subject, user.oidc_issuer = "same", "https://old.test"
    db.commit()
    monkeypatch.setattr(settings, "oidc_issuer", "https://new.test")
    monkeypatch.setattr(settings, "oidc_link_by_email", True)
    with pytest.raises(oidc.SsoError, match="already linked"):
        oidc.sign_in(db, {
            "iss": "https://new.test", "sub": "same", "email": user.email, "email_verified": True,
        })
    assert user.oidc_issuer == "https://old.test" and user.role == "admin"
