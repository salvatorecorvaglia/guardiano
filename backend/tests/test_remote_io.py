"""Remote dispatch must release SQL transactions without losing ordering or ownership."""

import pytest
from sqlalchemy import event, text

from app.core.db import SessionLocal, engine
from app.services import jobs
from app.services.remote_io import network_io, ordered_dispatch
from app.services.trackers.base import TrackerError


def test_network_boundary_releases_transaction_and_rejects_database_reads(db):
    db.execute(text("SELECT 1"))
    with network_io(db):
        assert not db.in_transaction()
    with pytest.raises(RuntimeError, match="Database access during remote dispatch"), network_io(db):
        db.execute(text("SELECT 1"))
    db.rollback()


def test_dispatch_ordering_survives_commits_without_an_open_transaction(db):
    captured = []

    def observe(connection, cursor, statement, parameters, context, executemany):
        if "pg_try_advisory_lock" in statement:
            captured.append(connection.connection.driver_connection.info.backend_pid)

    event.listen(engine, "after_cursor_execute", observe)
    try:
        with ordered_dispatch(db, "test-ticket:123"):
            with network_io(db):
                assert not db.in_transaction()
                with engine.connect() as observer:
                    assert (
                        observer.scalar(
                            text("SELECT xact_start FROM pg_stat_activity WHERE pid = :pid"),
                            {"pid": captured[0]},
                        )
                        is None
                    )
                with (
                    SessionLocal() as competitor,
                    pytest.raises(TrackerError, match="dispatch is in progress"),
                    ordered_dispatch(competitor, "test-ticket:123"),
                ):
                    pytest.fail("Competing dispatch acquired the same ticket")
            db.execute(text("SELECT 1"))
            jobs.commit_owned(db)
    finally:
        event.remove(engine, "after_cursor_execute", observe)
    with ordered_dispatch(db, "test-ticket:123"):
        pass  # returning to the pool must release the session lock


def test_dispatch_lock_loss_fences_local_commits(db):
    captured = []

    def observe(connection, cursor, statement, parameters, context, executemany):
        if "pg_try_advisory_lock" in statement:
            captured.append(connection)

    event.listen(engine, "after_cursor_execute", observe)
    try:
        with pytest.raises(RuntimeError, match="lock was lost"), ordered_dispatch(db, "test-ticket:lost"):
            captured[0].execute(text("SELECT pg_advisory_unlock_all()"))
            jobs.commit_owned(db)
    finally:
        event.remove(engine, "after_cursor_execute", observe)
