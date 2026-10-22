import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from app.core.config import settings

_hasher = PasswordHasher()
JWT_ALG = "HS256"
# Public format marker, shared by every generated token; contains no credential material.
TOKEN_PREFIX = "gdn_"


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def _encode(sub: str, kind: str, ttl: timedelta, extra: dict[str, Any] | None = None) -> str:
    now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "sub": sub,
        "typ": kind,
        "iat": now,
        "exp": now + ttl,
        "jti": uuid.uuid4().hex,
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.secret_key, algorithm=JWT_ALG)


def create_access_token(user_id: int, role: str, token_version: int, *, sso: bool = False) -> str:
    return _encode(
        str(user_id),
        "access",
        timedelta(minutes=settings.access_token_ttl_minutes),
        {"role": role, "ver": token_version, "sso": sso},
    )


def create_refresh_token(user_id: int, token_version: int, *, session_id: str | None = None) -> str:
    return _encode(
        str(user_id),
        "refresh",
        timedelta(days=settings.refresh_token_ttl_days),
        {"ver": token_version, **({"sid": session_id} if session_id else {})},
    )


def decode_token(token: str, expected_type: str) -> dict[str, Any] | None:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[JWT_ALG])
    except (jwt.PyJWTError, RecursionError):
        return None
    if payload.get("typ") != expected_type:
        return None
    return payload


def generate_api_token() -> tuple[str, str, str]:
    """Return (plaintext token, display prefix, sha256 hash)."""
    raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
    return raw, raw[:12], hash_api_token(raw)


def hash_api_token(token: str) -> str:
    """Digest a high-entropy random token for indexed lookup, never a user password.

    API and reset tokens contain at least 256 random bits; SHA-256 preserves existing
    token hashes. User passwords are hashed separately with Argon2.
    """
    return hashlib.sha256(token.encode()).hexdigest()
