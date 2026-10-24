"""Contention and history regressions for the final performance work."""

import json
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import OperationalError, TimeoutError
from sqlalchemy.pool import QueuePool

from app.core.config import settings
from app.core.db import SessionLocal
from app.models import Asset, Finding
from app.models.base import utcnow
from app.services import ingestion
from app.services.ingestion import IngestOptions, ingest_report
from benchmarks.pool_probe import PoolProbe
from tests.test_gate import finding, native


@pytest.mark.no_database
def test_pool_probe_observes_real_queue_wait_and_timeout():
    engine = create_engine(
        "sqlite://",
        poolclass=QueuePool,
        pool_size=1,
        max_overflow=0,
        pool_timeout=0.1,
        connect_args={"check_same_thread": False},
    )
    try:
        with PoolProbe(engine.pool) as probe, engine.connect():
            probe.phase = "baseline"

            def acquire():
                with engine.connect():
                    pass

            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(acquire)
                with pytest.raises(TimeoutError):
                    future.result(timeout=3)
        stats = probe.summary()["baseline"]
        assert stats["blocking_checkouts"] == stats["timeouts"] == 1
        assert stats["wait_max_seconds"] >= 0.09
        with engine.connect():  # the instrumented queue was restored
            pass
    finally:
        engine.dispose()


@pytest.mark.parametrize("mode", ["matched", "resolution", "fingerprint"])
def test_ingestion_locks_only_findings_it_can_mutate(db, monkeypatch, mode):
    asset = Asset(name=f"lock-scope-{mode}")
    db.add(asset)
    db.commit()
    ingest_report(db, native(finding("matched"), tool="A"), asset, None, IngestOptions())
    matched = db.scalar(select(Finding))
    matched.fingerprint = "stable-fingerprint"
    closed = Finding(
        asset_id=asset.id,
        dedup_key="closed",
        type="sast",
        title="Closed A",
        severity="high",
        status="resolved",
        tools=["A"],
        first_seen_at=utcnow(),
    )
    unrelated = Finding(
        asset_id=asset.id,
        dedup_key="unrelated",
        type="sca",
        title="Other tool",
        severity="high",
        status="open",
        tools=["B"],
        first_seen_at=utcnow(),
    )
    db.add_all([closed, unrelated])
    db.commit()
    asset_id, matched_id, closed_id, unrelated_id = asset.id, matched.id, closed.id, unrelated.id
    db.rollback()
    monkeypatch.setattr(settings, "dedup_fingerprints", mode == "fingerprint")
    entered, release = threading.Event(), threading.Event()
    original = ingestion.persist_scan

    def hold(session, context):
        entered.set()
        assert release.wait(timeout=10)
        return original(session, context)

    monkeypatch.setattr(ingestion, "persist_scan", hold)
    report = finding("matched", line=2) if mode == "fingerprint" else finding("matched")
    if mode == "fingerprint":
        report["fingerprint"] = "stable-fingerprint"

    raw = native(report, tool="A")
    if mode == "fingerprint":
        raw = json.dumps(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {"driver": {"name": "A"}},
                        "results": [
                            {
                                "message": {"text": "matched"},
                                "properties": {"tags": ["CWE-89"]},
                                "partialFingerprints": {"primaryLocationLineHash": "stable-fingerprint"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "matched.py"},
                                            "region": {"startLine": 2},
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ],
            }
        ).encode()

    def upload():
        with SessionLocal() as session:
            ingest_report(
                session,
                raw,
                session.get(Asset, asset_id),
                None,
                IngestOptions(close_missing=mode == "resolution"),
            )

    def try_lock(ident, blocked):
        with SessionLocal() as session:
            session.execute(text("SET LOCAL lock_timeout = '150ms'"))
            if blocked:
                with pytest.raises(OperationalError, match="lock timeout"):
                    session.scalar(select(Finding).where(Finding.id == ident).with_for_update())
            else:
                assert (
                    session.scalar(select(Finding.id).where(Finding.id == ident).with_for_update()) == ident
                )

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(upload)
        try:
            assert entered.wait(timeout=5)
            try_lock(unrelated_id, False)
            try_lock(matched_id, True)
            try_lock(closed_id, mode == "resolution")
        finally:
            release.set()
        future.result(timeout=10)


def test_batched_upload_rolls_back_every_batch_if_a_later_step_fails(db, monkeypatch):
    from sqlalchemy import func

    from app.models import FindingEvent, FindingScan, Scan
    from app.services import gate

    asset = Asset(name="atomic-batches")
    db.add(asset)
    db.commit()

    def fail_after_batches(*args, **kwargs):
        assert db.scalar(select(func.count()).select_from(Finding)) == 1200
        raise RuntimeError("gate evaluation failed")

    monkeypatch.setattr(gate, "evaluate", fail_after_batches)
    with pytest.raises(RuntimeError, match="gate evaluation failed"):
        ingest_report(db, native(*(finding(f"f{i}") for i in range(1200))), asset, None, IngestOptions())
    db.rollback()
    for model in (Finding, FindingEvent, FindingScan, Scan):
        assert db.scalar(select(func.count()).select_from(model)) == 0
