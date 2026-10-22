"""Two-factor authentication for local sign-in.

Signing in with a password on an account that has a second factor does not produce a session: it produces a
short-lived challenge, which is exchanged for one by proving possession of the authenticator (or spending a
recovery code). Single sign-on accounts are the identity provider's business, so they are never challenged.

The TOTP secret is encrypted at rest, recovery codes are stored hashed and each is usable once, and a TOTP
code is accepted only once so that shoulder-surfing or a replayed request buys nothing.
"""

import logging
import time
from datetime import timedelta
from typing import Any

import jwt
from sqlalchemy import select, update
from sqlalchemy.orm import Session, object_session

from app.core import totp
from app.core.config import settings
from app.core.crypto import decrypt, encrypt
from app.core.security import JWT_ALG
from app.models import RecoveryCode, User
from app.models.base import utcnow

log = logging.getLogger(__name__)

CHALLENGE_TYPE = "mfa"


def _now() -> float:
    """The clock TOTP codes are checked against. A seam, so tests can wait for the next code cheaply."""
    return time.time()


def required_for(user: User) -> bool:
    """Whether this person's role obliges them to set up a second factor."""
    return user.role.lower() in settings.mfa_roles


def setup_required(user: User) -> bool:
    return required_for(user) and not user.mfa_enabled


def challenge_token(user: User) -> str:
    """Proof that the password was right, and nothing more."""
    now = time.time()
    return jwt.encode(
        {
            "sub": str(user.id),
            "typ": CHALLENGE_TYPE,
            "ver": user.token_version,
            "iat": now,
            "exp": now + settings.mfa_challenge_ttl_minutes * 60,
        },
        settings.secret_key,
        algorithm=JWT_ALG,
    )


def read_challenge(db: Session, token: str) -> User | None:
    try:
        payload: dict[str, Any] = jwt.decode(token, settings.secret_key, algorithms=[JWT_ALG])
    except jwt.PyJWTError:
        return None
    if payload.get("typ") != CHALLENGE_TYPE:
        return None
    try:
        user_id = int(payload.get("sub", 0))
    except (TypeError, ValueError, OverflowError):
        return None
    user = db.get(User, user_id, with_for_update=True, populate_existing=True)
    if user is None or not user.is_active or not user.mfa_enabled or payload.get("ver") != user.token_version:
        return None
    return user


def is_locked(user: User) -> bool:
    return user.mfa_locked_until is not None and user.mfa_locked_until > utcnow()


def record_failure(user: User) -> None:
    if is_locked(user):
        return
    user.mfa_failed_logins = (user.mfa_failed_logins or 0) + 1
    if user.mfa_failed_logins >= settings.login_max_failures:
        exponent = min(user.mfa_failed_logins - settings.login_max_failures, 20)
        seconds = min(settings.login_lockout_seconds * 2 ** exponent, settings.login_lockout_max_seconds)
        user.mfa_locked_until = utcnow() + timedelta(seconds=seconds)


def record_success(user: User) -> None:
    user.mfa_failed_logins = 0
    user.mfa_locked_until = None


def begin_setup(user: User) -> tuple[str, str]:
    """A fresh secret, not active until a code from it is verified. Returns (secret, otpauth URI)."""
    secret = totp.generate_secret()
    user.mfa_secret = encrypt(secret)
    user.mfa_enabled = False
    user.mfa_confirmed_at = None
    user.mfa_last_step = None
    return secret, totp.provisioning_uri(secret, user.email)


def check_code(user: User, code: str, now: float | None = None) -> bool:
    """Verify a TOTP code against the stored secret, refusing one already used."""
    db = object_session(user)
    if db is not None:
        db.flush()
        db.refresh(user, with_for_update=True)
    if not user.mfa_secret:
        return False
    step = totp.verify(decrypt(user.mfa_secret), code, now or _now(), last_step=user.mfa_last_step)
    if step is None:
        return False
    user.mfa_last_step = step
    return True


def spent(user: User, code: str, now: float | None = None) -> bool:
    """A real code from a step already used: worth its own message."""
    if not user.mfa_secret:
        return False
    return totp.already_used(decrypt(user.mfa_secret), code, now or _now(), user.mfa_last_step)


def spend_recovery_code(db: Session, user: User, code: str) -> bool:
    consumed = db.execute(
        update(RecoveryCode)
        .where(
            RecoveryCode.user_id == user.id,
            RecoveryCode.code_hash == totp.hash_recovery_code(code),
            RecoveryCode.used_at.is_(None),
        )
        .values(used_at=utcnow())
        .returning(RecoveryCode.id)
    ).first()
    if consumed is None:
        return False
    log.info("user %s signed in with a recovery code", user.id)
    return True


def issue_recovery_codes(db: Session, user: User) -> list[str]:
    """Replace any existing codes. The plain values are returned once and never stored."""
    for old in db.scalars(select(RecoveryCode).where(RecoveryCode.user_id == user.id)):
        db.delete(old)
    codes = totp.generate_recovery_codes()
    db.add_all(RecoveryCode(user_id=user.id, code_hash=totp.hash_recovery_code(c)) for c in codes)
    return codes


def unused_recovery_codes(db: Session, user: User) -> int:
    return len(
        db.scalars(
            select(RecoveryCode).where(RecoveryCode.user_id == user.id, RecoveryCode.used_at.is_(None))
        ).all()
    )


def disable(db: Session, user: User) -> None:
    user.mfa_enabled = False
    user.mfa_secret = None
    user.mfa_confirmed_at = None
    user.mfa_last_step = None
    for code in db.scalars(select(RecoveryCode).where(RecoveryCode.user_id == user.id)):
        db.delete(code)


def challenge_ttl() -> timedelta:
    return timedelta(minutes=settings.mfa_challenge_ttl_minutes)
