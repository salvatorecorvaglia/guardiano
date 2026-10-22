from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import admin_only
from app.models import AuditLog, Job, User
from app.schemas.admin import AuditOut, JobOut, JobStats
from app.schemas.common import Page
from app.services import audit, jobs

router = APIRouter(prefix="/admin", tags=["admin"])

_STATUS_PATTERN = f"^({'|'.join(jobs.JOB_STATUSES)})$"


@router.get("/jobs", response_model=Page[JobOut])
def list_jobs(
    status_: str | None = Query(None, alias="status", pattern=_STATUS_PATTERN),
    kind: str | None = Query(None, max_length=100),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    _: User = Depends(admin_only),
    db: Session = Depends(get_db),
):
    stmt = select(Job)
    if status_:
        stmt = stmt.where(Job.status == status_)
    if kind:
        stmt = stmt.where(Job.kind == kind)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    items = db.scalars(
        stmt.order_by(Job.created_at.desc(), Job.id.desc()).offset((page - 1) * page_size).limit(page_size)
    ).all()
    return Page(items=items, total=total, page=page, page_size=page_size)


@router.get("/jobs/stats", response_model=JobStats)
def job_stats(_: User = Depends(admin_only), db: Session = Depends(get_db)):
    counts = dict.fromkeys(jobs.JOB_STATUSES, 0)
    counts.update(db.execute(select(Job.status, func.count()).group_by(Job.status)).all())
    return JobStats(
        counts=counts,
        oldest_queued_at=db.scalar(select(func.min(Job.run_after)).where(Job.status == jobs.QUEUED)),
        last_finished_at=db.scalar(select(func.max(Job.finished_at)).where(Job.status == jobs.DONE)),
    )


@router.post("/jobs/{job_id}/retry", response_model=JobOut)
def retry_job(
    job_id: int, request: Request, admin: User = Depends(admin_only), db: Session = Depends(get_db)
):
    job = db.get(Job, job_id, with_for_update=True)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Job not found")
    if job.status not in (jobs.DEAD, jobs.QUEUED):
        raise HTTPException(status.HTTP_409_CONFLICT, f"A {job.status} job cannot be retried")
    audit.record(
        db,
        "job.retry",
        actor=admin,
        request=request,
        target_type="job",
        target_id=job.id,
        target_label=job.kind,
        changes={"status": {"from": job.status, "to": jobs.QUEUED}},
    )
    jobs.retry(job)
    db.commit()
    return job


@router.get("/audit", response_model=Page[AuditOut])
def list_audit(
    action: str | None = Query(None, max_length=50, description="Exact action, or a prefix ending in '.'"),
    actor_id: int | None = None,
    target_type: str | None = Query(None, max_length=30),
    target_id: int | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    _: User = Depends(admin_only),
    db: Session = Depends(get_db),
):
    stmt = select(AuditLog)
    if action:
        # "user." matches every user action; anything else is an exact match.
        stmt = stmt.where(
            AuditLog.action.startswith(action, autoescape=True)
            if action.endswith(".")
            else AuditLog.action == action
        )
    if actor_id:
        stmt = stmt.where(AuditLog.actor_id == actor_id)
    if target_type:
        stmt = stmt.where(AuditLog.target_type == target_type)
    if target_id:
        stmt = stmt.where(AuditLog.target_id == target_id)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    items = db.scalars(
        stmt.order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return Page(items=items, total=total, page=page, page_size=page_size)
