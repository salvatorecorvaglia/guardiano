"""Short database transactions around remote dispatch, with ordering across commits."""

import hashlib
from collections.abc import Iterator
from contextlib import contextmanager
from copy import deepcopy

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.db import Base
from app.models import Integration
from app.services import jobs
from app.services.trackers.base import TrackerError


def snapshot[T: Base](row: T) -> T:
    """Copy scalar configuration into a transient model with no lazy database access."""
    return type(row)(**{column.name: deepcopy(getattr(row, column.name)) for column in row.__table__.columns})


@contextmanager
def network_io(db: Session) -> Iterator[None]:
    """Release the data connection before I/O; fence any preceding writes by the job claim."""
    jobs.commit_owned(db)
    try:
        yield
    finally:
        if db.in_transaction():
            raise RuntimeError("Database access during remote dispatch; prepare a detached snapshot first")


@contextmanager
def ordered_dispatch(db: Session, resource: str) -> Iterator[None]:
    """A session lock on an autocommit connection orders writes without an open SQL transaction.

    Try-lock avoids leaving a transaction waiting behind a slow remote call. A busy
    background job follows its normal retry policy. Always unlock before returning
    the connection to the pool; discard it if unlock fails.
    """
    jobs.commit_owned(db)
    key = int.from_bytes(hashlib.sha256(resource.encode()).digest()[:8], "big", signed=True)
    bind = db.get_bind()
    engine = bind.engine
    with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as connection:
        acquired = connection.scalar(text("SELECT pg_try_advisory_lock(:key)"), {"key": key})
        if not acquired:
            raise TrackerError("Another dispatch is in progress; retry shortly")

        def ensure_owned():
            unsigned = key % (1 << 64)
            if not connection.scalar(
                text(
                    "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' "
                    "AND pid = pg_backend_pid() AND granted AND objsubid = 1 "
                    "AND classid::bigint = :hi AND objid::bigint = :lo)"
                ),
                {"hi": unsigned >> 32, "lo": unsigned & 0xFFFFFFFF},
            ):
                raise RuntimeError("Remote dispatch lock was lost; refusing to commit")

        try:
            with jobs.guard_commits(ensure_owned):
                yield
        finally:
            try:
                if not connection.scalar(text("SELECT pg_advisory_unlock(:key)"), {"key": key}):
                    raise RuntimeError("Remote dispatch lock was lost")
            except BaseException:
                connection.invalidate()
                raise


def integration_snapshot(db: Session, integration_id: int) -> Integration | None:
    row = db.get(Integration, integration_id, populate_existing=True)
    return snapshot(row) if row is not None and row.enabled else None
