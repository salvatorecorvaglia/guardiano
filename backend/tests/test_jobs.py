"""Background job queue, periodic scheduling and the admin jobs API."""

import json
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.core.db import SessionLocal
from app.models import Asset, Finding, Job
from app.models.base import utcnow
from app.models.enums import Status
from app.services import jobs, lifecycle
from app.services.ingestion import IngestOptions, ingest_report

CALLS: list[dict] = []


def _ok(db, payload):
    CALLS.append(payload)


def _boom(db, payload):
    raise RuntimeError("boom")


@pytest.fixture(autouse=True)
def _test_handlers(monkeypatch):
    """Registered for this module's tests only. They were registered with @jobs.handler at import,
    into the process-wide registry, and stayed there for every test that ran a worker afterwards."""
    CALLS.clear()
    monkeypatch.setitem(jobs._HANDLERS, "test.ok", _ok)
    monkeypatch.setitem(jobs._HANDLERS, "test.boom", _boom)


def _job(db, job_id) -> Job:
    db.expire_all()
    return db.get(Job, job_id)


def test_enqueue_joins_the_callers_transaction(db):
    jobs.enqueue(db, "test.ok", {"n": 1})
    db.rollback()
    assert db.scalar(select(Job)) is None

    job = jobs.enqueue(db, "test.ok", {"n": 2})
    db.commit()
    assert job.status == "queued" and job.attempts == 0 and job.max_attempts == 5


def test_run_one_executes_and_marks_done(db):
    job = jobs.enqueue(db, "test.ok", {"n": 1})
    db.commit()
    assert jobs.run_one() is True
    assert CALLS == [{"n": 1}]
    j = _job(db, job.id)
    assert j.status == "done" and j.attempts == 1 and j.finished_at and j.locked_at is None
    assert jobs.run_one() is False


def test_failures_back_off_then_die(db):
    job = jobs.enqueue(db, "test.boom", max_attempts=2)
    db.commit()
    before = utcnow()
    assert jobs.run_one()
    j = _job(db, job.id)
    assert j.status == "queued" and j.attempts == 1 and "RuntimeError: boom" in j.last_error
    assert j.run_after >= before + timedelta(seconds=30)
    # Not due yet: the backoff keeps it out of the queue.
    assert jobs.run_one() is False

    j.run_after = utcnow()
    db.commit()
    assert jobs.run_one()
    j = _job(db, job.id)
    assert j.status == "dead" and j.attempts == 2 and j.finished_at


def test_unknown_kind_is_retried_not_lost(db):
    job = jobs.enqueue(db, "test.unknown")
    db.commit()
    assert jobs.run_one()
    j = _job(db, job.id)
    assert j.status == "queued" and "No handler registered" in j.last_error


def test_backoff_is_capped():
    assert jobs.backoff(1) == timedelta(seconds=30)
    assert jobs.backoff(2) == timedelta(seconds=60)
    assert jobs.backoff(50) == timedelta(hours=1)


def test_claim_skips_jobs_locked_by_another_worker(db):
    job = jobs.enqueue(db, "test.ok")
    db.commit()
    with SessionLocal() as other:
        other.scalar(select(Job).where(Job.id == job.id).with_for_update())
        assert jobs.run_one() is False  # locked elsewhere: skipped, not waited on
        other.rollback()
    assert jobs.run_one() is True


def test_recover_stale_requeues_or_kills_orphaned_jobs(db):
    old = utcnow() - jobs.LEASE - timedelta(minutes=1)
    retryable = jobs.enqueue(db, "test.ok")
    exhausted = jobs.enqueue(db, "test.ok", max_attempts=1)
    fresh = jobs.enqueue(db, "test.ok")
    db.flush()
    retryable.status, retryable.attempts, retryable.locked_at = "running", 1, old
    exhausted.status, exhausted.attempts, exhausted.locked_at = "running", 1, old
    fresh.status, fresh.attempts, fresh.locked_at = "running", 1, utcnow()
    db.commit()

    assert jobs.recover_stale(db) == 2
    db.commit()
    assert _job(db, retryable.id).status == "queued"
    assert _job(db, exhausted.id).status == "dead"
    assert _job(db, fresh.id).status == "running"


def registered() -> dict[str, timedelta]:
    """The periodic tasks as registered, so adding one does not need this test edited."""
    jobs.load_tasks()
    return {name: task.interval for name, task in jobs.PERIODIC.items()}


def test_every_expected_periodic_task_is_registered():
    assert {
        "expire_risk_acceptances",
        "prune_jobs",
        "sla_breaches",
        "email_digests",
    } <= set(registered())


def test_periodic_tasks_are_scheduled_once_per_interval(db):
    tasks = registered()
    due_after_2h = {name for name, interval in tasks.items() if interval <= timedelta(hours=2)}
    now = utcnow()

    assert set(jobs.schedule_periodic(db, now)) == set(tasks)
    assert set(jobs.schedule_periodic(db, now + timedelta(minutes=5))) == {
        name for name, interval in tasks.items() if interval <= timedelta(minutes=5)
    }
    assert set(jobs.schedule_periodic(db, now + timedelta(hours=2))) == due_after_2h
    kinds = sorted(j.kind for j in db.scalars(select(Job)))
    assert kinds == sorted(
        [
            *tasks,
            *[name for name, interval in tasks.items() if interval <= timedelta(minutes=5)],
            *due_after_2h,
        ]
    )


def test_worker_burst_reopens_expired_risk_acceptances(db):
    asset = Asset(name="svc", tags=[])
    db.add(asset)
    db.commit()
    doc = {
        "schema": "guardiano/v1",
        "tool": {"name": "t"},
        "findings": [
            {"title": "A", "severity": "high", "cwe": ["CWE-1"], "file_path": "a.py", "line_start": 1}
        ],
    }
    ingest_report(db, json.dumps(doc).encode(), asset, None, IngestOptions())
    f = db.scalar(select(Finding))
    lifecycle.set_status(
        db,
        f,
        Status.risk_accepted,
        actor=None,
        justification="x",
        risk_accepted_until=utcnow() - timedelta(1),
    )
    db.commit()

    assert jobs.Worker(poll_interval=0).run(burst=True) == len(registered())
    db.expire_all()
    assert f.status == "open" and f.events[0].event == "reopened"
    assert {j.status for j in db.scalars(select(Job))} == {"done"}


def test_prune_jobs_keeps_dead_and_recent(db):
    old = utcnow() - timedelta(days=30)
    done_old, done_new, dead_old = (jobs.enqueue(db, "test.ok") for _ in range(3))
    db.flush()
    done_old.status, done_old.finished_at = "done", old
    done_new.status, done_new.finished_at = "done", utcnow()
    dead_old.status, dead_old.finished_at = "dead", old
    db.commit()
    jobs.load_tasks()
    from app.services.tasks import prune_jobs

    prune_jobs(db, {})
    db.commit()
    assert sorted(j.id for j in db.scalars(select(Job))) == sorted([done_new.id, dead_old.id])


def test_admin_jobs_api(client, auth, db):
    dead = jobs.enqueue(db, "test.boom")
    done = jobs.enqueue(db, "test.ok")
    db.flush()
    dead.status, dead.attempts, dead.last_error = "dead", 5, "RuntimeError: boom"
    done.status, done.finished_at = "done", utcnow()
    db.commit()

    for role in ("viewer", "analyst", "manager"):
        assert client.get("/api/v1/admin/jobs", headers=auth[role]).status_code == 403

    r = client.get("/api/v1/admin/jobs", params={"status": "dead"}, headers=auth["admin"])
    assert r.status_code == 200 and [j["id"] for j in r.json()["items"]] == [dead.id]
    stats = client.get("/api/v1/admin/jobs/stats", headers=auth["admin"]).json()
    assert stats["counts"] == {"queued": 0, "running": 0, "done": 1, "dead": 1}

    assert client.post(f"/api/v1/admin/jobs/{done.id}/retry", headers=auth["admin"]).status_code == 409
    r = client.post(f"/api/v1/admin/jobs/{dead.id}/retry", headers=auth["admin"])
    assert r.status_code == 200 and r.json()["status"] == "queued" and r.json()["attempts"] == 0
    assert client.post("/api/v1/admin/jobs/999/retry", headers=auth["admin"]).status_code == 404


def test_admin_jobs_api_rejects_api_tokens(client, auth):
    r = client.post(
        "/api/v1/tokens", json={"name": "ci", "scopes": ["read", "ingest"]}, headers=auth["admin"]
    )
    token = {"Authorization": f"Bearer {r.json()['token']}"}
    assert client.get("/api/v1/admin/jobs", headers=token).status_code == 403


def test_worker_maintenance_continues_during_a_blocking_handler(monkeypatch, tmp_path):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    entered, maintained, release = threading.Event(), threading.Event(), threading.Event()
    worker = jobs.Worker(schedule_interval=0.01, poll_interval=0, heartbeat=tmp_path / "heartbeat")

    def tick():
        if entered.is_set():
            maintained.set()

    def run_one(factory):
        entered.set()
        assert release.wait(timeout=5)
        worker.stop()
        return True

    monkeypatch.setattr(worker, "tick", tick)
    monkeypatch.setattr(jobs, "run_one", run_one)
    with ThreadPoolExecutor(max_workers=1) as pool:
        execution = pool.submit(worker.run)
        try:
            assert entered.wait(timeout=5)
            assert maintained.wait(timeout=5)
        finally:
            release.set()
        assert execution.result(timeout=5) == 1
    assert worker.heartbeat.exists()
