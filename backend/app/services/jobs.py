"""Postgres-backed background jobs and periodic tasks (no broker needed).

- ``enqueue`` joins the caller's transaction, so a job exists exactly when the change that produced it was
  committed. Side effects (HTTP calls, emails) therefore never run for a rolled-back change.
- Workers claim jobs with ``FOR UPDATE SKIP LOCKED``, so any number of worker processes can run side by side.
- A failed job is retried with exponential backoff and becomes ``dead`` after ``max_attempts``.
- A job whose worker died mid-run is requeued once its lease expires, so handlers must be idempotent.
- Periodic tasks are scheduled through a locked row per task, so only one replica enqueues each run.
"""

import logging
import threading
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.core.db import SessionLocal
from app.models import Job, PeriodicTask
from app.models.base import utcnow
from app.parsers.base import truncate

log = logging.getLogger(__name__)

QUEUED, RUNNING, DONE, DEAD = "queued", "running", "done", "dead"
JOB_STATUSES = (QUEUED, RUNNING, DONE, DEAD)
LEASE = timedelta(minutes=15)  # a running job older than this is assumed orphaned by a dead worker
_MAX_BACKOFF_SECONDS = 3600
_ERROR_LIMIT = 4000

JobHandler = Callable[[Session, dict[str, Any]], None]
_HANDLERS: dict[str, JobHandler] = {}
_commit_fences: ContextVar[tuple[Callable[[], None], ...]] = ContextVar("commit_fences", default=())
_claim_context: ContextVar[tuple[int, str] | None] = ContextVar("job_claim", default=None)


def commit_owned(db: Session) -> None:
    """Commit a handler's batch only while it still owns its job; normal callers simply commit."""
    for check in _commit_fences.get():
        check()
    claim_info = _claim_context.get()
    if claim_info is not None:
        job_id, token = claim_info
        owned = db.scalar(
            select(Job.id)
            .where(
                Job.id == job_id,
                Job.status == RUNNING,
                Job.claim_token == token,
            )
            .with_for_update()
        )
        if owned is None:
            raise RuntimeError("Job claim changed; refusing to commit")
    db.commit()


@contextmanager
def guard_commits(check: Callable[[], None]) -> Iterator[None]:
    """Fence intermediate commits by a dispatch lock as well as the worker claim."""
    token = _commit_fences.set((*_commit_fences.get(), check))
    try:
        yield
    finally:
        _commit_fences.reset(token)


@dataclass(frozen=True)
class Periodic:
    name: str
    interval: timedelta
    priority: int = 100


PERIODIC: dict[str, Periodic] = {}


def handler(kind: str) -> Callable[[JobHandler], JobHandler]:
    """Register ``fn(db, payload)`` for a job kind. The worker commits after it returns."""

    def register(fn: JobHandler) -> JobHandler:
        _HANDLERS[kind] = fn
        return fn

    return register


def periodic(name: str, interval: timedelta, *, priority: int = 100) -> Callable[[JobHandler], JobHandler]:
    """Register a handler that the worker enqueues every ``interval`` (job kind == ``name``)."""

    def register(fn: JobHandler) -> JobHandler:
        PERIODIC[name] = Periodic(name, interval, priority)
        return handler(name)(fn)

    return register


def load_tasks() -> None:
    # Task modules register themselves on import; imported lazily to avoid an import cycle.
    import app.services.tasks  # noqa: F401


def enqueue(
    db: Session,
    kind: str,
    payload: dict[str, Any] | None = None,
    *,
    run_after: datetime | None = None,
    max_attempts: int | None = None,
    priority: int = 100,
) -> Job:
    """Add a job to the caller's transaction. Nothing runs until the caller commits."""
    now = utcnow()
    job = Job(
        kind=kind,
        payload=payload or {},
        status=QUEUED,
        attempts=0,
        priority=priority,
        max_attempts=max_attempts or settings.job_max_attempts,
        run_after=run_after or now,
        created_at=now,
    )
    db.add(job)
    return job


def backoff(attempts: int) -> timedelta:
    return timedelta(seconds=min(30 * 2 ** max(attempts - 1, 0), _MAX_BACKOFF_SECONDS))


def claim(db: Session, now: datetime | None = None) -> Job | None:
    """Lock the next due job, mark it running and commit. Returns None when the queue is empty."""
    now = now or utcnow()
    job = db.scalar(
        select(Job)
        .where(Job.status == QUEUED, Job.run_after <= now)
        .order_by(Job.priority, Job.run_after, Job.id)
        .limit(1)
        .with_for_update(skip_locked=True)
    )
    if job is None:
        db.rollback()
        return None
    job.status, job.attempts, job.locked_at = RUNNING, job.attempts + 1, now
    job.claim_token = uuid.uuid4().hex
    db.commit()
    return job


def _finish(
    db: Session, job_id: int, error: str | None, now: datetime, claim_token: str | None = None
) -> None:
    job = db.get(Job, job_id, with_for_update=True)
    if job is None or job.status != RUNNING or job.claim_token != claim_token:
        return
    job.locked_at = None
    job.claim_token = None
    if error is None:
        job.status, job.finished_at = DONE, now
        return
    job.last_error = truncate(error, _ERROR_LIMIT)
    if job.attempts >= job.max_attempts:
        job.status, job.finished_at = DEAD, now
    else:
        job.status, job.run_after = QUEUED, now + backoff(job.attempts)


RENEW_SECONDS = 30.0


def run_one(session_factory: sessionmaker = SessionLocal) -> bool:
    """Claim and execute one job. Returns False when there was nothing to do."""
    load_tasks()
    with session_factory() as db:
        job = claim(db)
        if job is None:
            return False
        job_id, kind, payload, claim_token = job.id, job.kind, dict(job.payload or {}), job.claim_token

    stopped = threading.Event()
    lost = threading.Event()

    def renew():
        while not stopped.wait(RENEW_SECONDS):
            try:
                with session_factory() as lease_db:
                    renewed = lease_db.execute(
                        update(Job)
                        .where(Job.id == job_id, Job.status == RUNNING, Job.claim_token == claim_token)
                        .values(locked_at=utcnow())
                    ).rowcount
                    lease_db.commit()
                    if not renewed:
                        lost.set()
                        return
            except Exception:
                log.exception("could not renew job %s", job_id)
                lost.set()
                return

    lease_thread = threading.Thread(target=renew, daemon=True, name=f"job-lease-{job_id}")
    lease_thread.start()
    error: str | None = None
    context_token = _claim_context.set((job_id, claim_token))
    try:
        with session_factory() as db:
            try:
                fn = _HANDLERS.get(kind)
                if fn is None:
                    # A newer API may enqueue kinds an older worker does not know yet.
                    raise LookupError(f"No handler registered for job kind '{kind}'")
                fn(db, payload)
                if lost.is_set():
                    raise RuntimeError("Job lease lost; refusing to commit")
                owned = db.scalar(
                    select(Job)
                    .where(Job.id == job_id, Job.status == RUNNING, Job.claim_token == claim_token)
                    .with_for_update()
                )
                if owned is None:
                    raise RuntimeError("Job claim changed; refusing to commit")
                # Database effects and completion must survive (or roll back) together.
                _finish(db, job_id, None, utcnow(), claim_token)
                db.commit()
            except Exception as exc:
                db.rollback()
                log.exception("job %s (%s) failed", job_id, kind)
                error = f"{type(exc).__name__}: {exc}"

    finally:
        _claim_context.reset(context_token)
        stopped.set()
        lease_thread.join(timeout=5)
    with session_factory() as db:
        _finish(db, job_id, error, utcnow(), claim_token)
        db.commit()
    if error is None:
        log.info("job %s (%s) done", job_id, kind)
    return True


def recover_stale(db: Session, now: datetime | None = None) -> int:
    """Requeue running jobs whose lease expired (their worker died). The caller commits."""
    now = now or utcnow()
    expired = (Job.status == RUNNING, Job.locked_at < now - LEASE)
    dead = db.execute(
        update(Job)
        .where(*expired, Job.attempts >= Job.max_attempts)
        .values(
            status=DEAD, locked_at=None, claim_token=None, finished_at=now, last_error="Worker lease expired"
        )
    ).rowcount
    requeued = db.execute(
        update(Job)
        .where(*expired)
        .values(
            status=QUEUED, locked_at=None, claim_token=None, run_after=now, last_error="Worker lease expired"
        )
    ).rowcount
    return (dead or 0) + (requeued or 0)


def schedule_periodic(db: Session, now: datetime | None = None) -> list[str]:
    """Enqueue every periodic task whose interval elapsed. Commits per task."""
    load_tasks()
    now = now or utcnow()
    enqueued: list[str] = []
    for task in PERIODIC.values():
        db.execute(pg_insert(PeriodicTask).values(name=task.name).on_conflict_do_nothing())
        row = db.scalar(
            select(PeriodicTask).where(PeriodicTask.name == task.name).with_for_update(skip_locked=True)
        )
        # None: another worker is scheduling this task right now.
        if row is not None and (row.last_run_at is None or row.last_run_at + task.interval <= now):
            enqueue(db, task.name, priority=task.priority)
            row.last_run_at = now
            enqueued.append(task.name)
        db.commit()
    return enqueued


def retry(job: Job, now: datetime | None = None) -> None:
    """Requeue a dead (or queued) job for an immediate run with a fresh attempt budget."""
    job.status, job.attempts, job.run_after = QUEUED, 0, now or utcnow()
    job.locked_at = job.finished_at = job.claim_token = None


class Worker:
    """Runs periodic scheduling and drains the queue until ``stop()`` is called."""

    def __init__(
        self,
        session_factory: sessionmaker = SessionLocal,
        poll_interval: float | None = None,
        schedule_interval: float = 30.0,
        heartbeat: Path | None = None,
    ) -> None:
        self.session_factory = session_factory
        self.poll_interval = settings.worker_poll_seconds if poll_interval is None else poll_interval
        self.schedule_interval = schedule_interval
        self.heartbeat = heartbeat
        self._stop = threading.Event()

    def stop(self, *_: object) -> None:
        self._stop.set()

    def tick(self) -> None:
        with self.session_factory() as db:
            if n := recover_stale(db):
                log.warning("requeued %d job(s) orphaned by a dead worker", n)
            db.commit()
            schedule_periodic(db)

    def run(self, burst: bool = False) -> int:
        """Process jobs; with ``burst`` drain the queue once and return. Returns the number of jobs run."""
        load_tasks()
        processed = 0
        maintenance_stop = threading.Event()

        def maintain():
            while not maintenance_stop.is_set():
                try:
                    self.tick()
                    if self.heartbeat is not None:
                        self.heartbeat.touch()
                except Exception:
                    log.exception("worker maintenance failed")
                maintenance_stop.wait(self.schedule_interval)

        maintenance = None
        if burst:
            self.tick()
        else:
            maintenance = threading.Thread(target=maintain, daemon=True, name="worker-maintenance")
            maintenance.start()
        try:
            while not self._stop.is_set():
                try:
                    worked = run_one(self.session_factory)
                    if worked:
                        processed += 1
                    elif burst:
                        break
                    else:
                        self._stop.wait(self.poll_interval)
                except Exception:
                    log.exception("worker loop error")
                    if burst:
                        break
                    self._stop.wait(self.poll_interval)
        finally:
            maintenance_stop.set()
            if maintenance is not None:
                maintenance.join(timeout=5)
        log.info("worker stopped after %d job(s)", processed)
        return processed
