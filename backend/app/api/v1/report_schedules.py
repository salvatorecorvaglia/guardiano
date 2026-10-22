"""Scheduled reports: which users get the security report emailed, and how often (services/reports.py)."""

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import require
from app.models import Product, ReportSchedule, User
from app.models.enums import Role
from app.services import audit, email, jobs, reports

router = APIRouter(prefix="/report-schedules", tags=["reports"])
manager = require(Role.manager, None)


class ScheduleBody(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    frequency: Literal["weekly", "monthly"] = "weekly"
    product_id: int | None = Field(None, description="Only this product; null for everything the reader sees")
    recipient_ids: list[int] = Field(min_length=1, max_length=50, description="Guardiano users")
    enabled: bool = True


class ScheduleOut(BaseModel):
    id: int
    name: str
    frequency: str
    product_id: int | None
    recipient_ids: list[int]
    enabled: bool
    last_sent_at: datetime | None

    model_config = {"from_attributes": True}


def _check(db: Session, body: ScheduleBody) -> None:
    if body.product_id is not None and db.get(Product, body.product_id) is None:
        raise HTTPException(422, "Product not found")
    ids = set(body.recipient_ids)
    found = set(db.scalars(select(User.id).where(User.id.in_(ids), User.is_active.is_(True))))
    if found != ids:
        raise HTTPException(422, f"Not active users: {sorted(ids - found)}")


def _load(db: Session, schedule_id: int) -> ReportSchedule:
    schedule = db.get(ReportSchedule, schedule_id)
    if schedule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Schedule not found")
    return schedule


@router.get("", response_model=list[ScheduleOut])
def list_schedules(_: User = Depends(manager), db: Session = Depends(get_db)):
    return db.scalars(select(ReportSchedule).order_by(ReportSchedule.name)).all()


@router.post("", response_model=ScheduleOut, status_code=status.HTTP_201_CREATED)
def create_schedule(
    body: ScheduleBody, request: Request, user: User = Depends(manager), db: Session = Depends(get_db)
):
    _check(db, body)
    schedule = ReportSchedule(
        **body.model_dump(exclude={"recipient_ids"}),
        recipient_ids=sorted(set(body.recipient_ids)),
        created_by_id=user.id,
    )
    db.add(schedule)
    db.flush()
    audit.record(db, "report_schedule.create", actor=user, request=request, target_type="report_schedule",
                 target_id=schedule.id, target_label=schedule.name,
                 changes={"frequency": schedule.frequency, "recipients": schedule.recipient_ids})  # fmt: skip
    db.commit()
    return schedule


@router.put("/{schedule_id}", response_model=ScheduleOut)
def replace_schedule(
    schedule_id: int,
    body: ScheduleBody,
    request: Request,
    user: User = Depends(manager),
    db: Session = Depends(get_db),
):
    schedule = _load(db, schedule_id)
    _check(db, body)
    before = audit.snapshot(schedule, ("name", "frequency", "product_id", "recipient_ids", "enabled"))
    for field, value in body.model_dump().items():
        setattr(schedule, field, sorted(set(value)) if field == "recipient_ids" else value)
    if changes := audit.diff(before, schedule):
        audit.record(db, "report_schedule.update", actor=user, request=request, target_type="report_schedule",
                     target_id=schedule.id, target_label=schedule.name, changes=changes)  # fmt: skip
    db.commit()
    return schedule


@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_schedule(
    schedule_id: int, request: Request, user: User = Depends(manager), db: Session = Depends(get_db)
):
    schedule = _load(db, schedule_id)
    audit.record(db, "report_schedule.delete", actor=user, request=request, target_type="report_schedule",
                 target_id=schedule.id, target_label=schedule.name)  # fmt: skip
    db.delete(schedule)
    db.commit()


@router.post("/{schedule_id}/send", status_code=status.HTTP_202_ACCEPTED)
def send_now(schedule_id: int, _: User = Depends(manager), db: Session = Depends(get_db)) -> dict:
    """Send it to its recipients now, to check what it looks like. The schedule itself is unchanged."""
    if not email.enabled():
        raise HTTPException(422, "Email is not configured (SMTP_HOST)")
    schedule = _load(db, schedule_id)
    people = reports.recipients(db, schedule)
    for person in people:
        jobs.enqueue(db, email.SEND_JOB, {
            "kind": "report", "recipient_id": person.id, "schedule_id": schedule.id,
        })
    db.commit()
    return {"queued": len(people)}
