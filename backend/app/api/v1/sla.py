from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import get_db
from app.core.deps import require
from app.models import SlaPolicy, User
from app.models.enums import ANY_CRITICALITY, CRITICALITIES, Role
from app.schemas.sla import SlaMatrix, SlaUpdate
from app.services import audit, sla

router = APIRouter(prefix="/sla", tags=["sla"])
COLUMNS = [ANY_CRITICALITY, *CRITICALITIES]
MAX_DAYS = 3650


def _matrix(policy: sla.EffectivePolicy) -> SlaMatrix:
    return SlaMatrix(
        severities=list(sla.SLA_SEVERITIES),
        criticalities=COLUMNS,
        days={s: {c: policy.days.get((s, c)) for c in COLUMNS} for s in sla.SLA_SEVERITIES},
        env_defaults={s: settings.sla_days[s] for s in sla.SLA_SEVERITIES},
    )


@router.get("", response_model=SlaMatrix)
def get_sla(_: User = Depends(require(Role.viewer)), db: Session = Depends(get_db)):
    return _matrix(sla.load_policy(db))


@router.put("", response_model=SlaMatrix)
def put_sla(
    body: SlaUpdate,
    request: Request,
    admin: User = Depends(require(Role.admin, None)),
    db: Session = Depends(get_db),
):
    rows: list[tuple[str, str, int]] = []
    for severity, columns in body.days.items():
        if severity not in sla.SLA_SEVERITIES:
            raise HTTPException(422, f"Unknown severity '{severity}' (info findings have no SLA)")
        for criticality, days in columns.items():
            if criticality not in COLUMNS:
                raise HTTPException(422, f"Unknown criticality '{criticality}'")
            if days is None:
                continue
            if not 1 <= days <= MAX_DAYS:
                raise HTTPException(422, f"SLA days must be between 1 and {MAX_DAYS}")
            # A default equal to SLA_*_DAYS is not stored, so the environment stays authoritative for it.
            if criticality == ANY_CRITICALITY and days == settings.sla_days[severity]:
                continue
            rows.append((severity, criticality, days))

    before, after = sla.load_policy(db), sla.build_policy(rows)
    changes = {
        f"{s}/{c}": {"from": before.days.get((s, c)), "to": after.days.get((s, c))}
        for s in sla.SLA_SEVERITIES
        for c in COLUMNS
        if before.days.get((s, c)) != after.days.get((s, c))
    }
    db.execute(delete(SlaPolicy))
    db.add_all(SlaPolicy(severity=s, criticality=c, days=d) for s, c, d in rows)
    if changes:
        audit.record(db, "sla.update", actor=admin, request=request, target_type="sla", changes=changes)
    db.commit()
    sla.invalidate()
    return _matrix(after)
