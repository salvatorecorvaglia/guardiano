"""Refresh family storage, legacy token revocation, and expiry pruning.

Tracked refresh families survive rotation so logout invalidates all predecessors.
Legacy JWTs use the bounded revocation table for compatibility. User token_version
remains the switch for revoking all devices.
"""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.models import RefreshSession, RevokedToken
from app.models.base import utcnow


def revoke(db: Session, payload: dict[str, Any] | None) -> None:
    """Record a refresh token as spent. A token that cannot be decoded needs no record: it is
    already refused, and writing a row for it would let anyone fill the table."""
    if not payload or not (jti := payload.get("jti")) or not (exp := payload.get("exp")):
        return
    db.execute(
        pg_insert(RevokedToken)
        .values(
            jti=str(jti)[:32],
            user_id=int(payload["sub"]) if str(payload.get("sub", "")).isdigit() else None,
            expires_at=datetime.fromtimestamp(int(exp), tz=UTC),
            created_at=utcnow(),
        )
        .on_conflict_do_nothing(index_elements=["jti"])  # signing out twice is not an error
    )


def is_revoked(db: Session, jti: str | None) -> bool:
    if not jti:
        return False
    return db.scalar(select(RevokedToken.jti).where(RevokedToken.jti == str(jti)[:32])) is not None


def prune(db: Session) -> int:
    """Drop records of tokens that have expired anyway. The caller commits."""
    n = db.execute(delete(RevokedToken).where(RevokedToken.expires_at < utcnow())).rowcount or 0
    return n + (db.execute(delete(RefreshSession).where(RefreshSession.expires_at < utcnow())).rowcount or 0)
