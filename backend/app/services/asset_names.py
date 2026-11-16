"""Shared transactional asset-name identity for interactive writes and ingestion."""

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Asset
from app.services.errors import DomainError


class NameConflict(DomainError):
    status_code = 409


def identity():
    return func.lower(func.btrim(Asset.name))


def lock_name(db: Session, name: str) -> None:
    db.execute(select(func.pg_advisory_xact_lock(0x6765, func.hashtext(func.lower(name.strip())))))


def matches(db: Session, name: str) -> list[Asset]:
    return list(db.scalars(select(Asset).where(identity() == func.lower(name.strip())).limit(2)))


def ensure_available(db: Session, name: str, asset_id: int | None = None) -> None:
    lock_name(db, name)
    if any(row.id != asset_id for row in matches(db, name)):
        raise NameConflict(
            "An asset with this name already exists; resolve any legacy name collisions explicitly"
        )
