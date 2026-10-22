from datetime import datetime
from typing import Any

from pydantic import BaseModel

from app.schemas.common import ORMModel


class JobOut(ORMModel):
    id: int
    kind: str
    payload: dict[str, Any]
    status: str
    attempts: int
    max_attempts: int
    run_after: datetime
    locked_at: datetime | None
    finished_at: datetime | None
    last_error: str | None
    created_at: datetime


class JobStats(BaseModel):
    counts: dict[str, int]  # per status
    oldest_queued_at: datetime | None  # a stale value means no worker is running
    last_finished_at: datetime | None


class AuditOut(ORMModel):
    id: int
    actor_id: int | None
    actor_email: str | None
    action: str
    target_type: str | None
    target_id: int | None
    target_label: str | None
    changes: dict[str, Any]
    ip: str | None
    created_at: datetime
