from typing import Literal

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_scope, require
from app.models import User
from app.models.base import utcnow
from app.models.enums import Role
from app.schemas.analytics import (
    BreakdownRow,
    Compliance,
    Coverage,
    Summary,
    TopAsset,
    TopCwe,
    TopPackage,
    Trends,
)
from app.services import analytics
from app.services import compliance as compliance_tables
from app.services.scope import Scope

router = APIRouter(prefix="/analytics", tags=["analytics"])
viewer = require(Role.viewer)


@router.get("/summary", response_model=Summary)
def summary(
    asset_id: int | None = None,
    _: User = Depends(viewer),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    return analytics.summary(db, asset_id, scope=scope)


@router.get("/trends", response_model=Trends)
def trends(
    days: int = Query(90, ge=7, le=365),
    asset_id: int | None = None,
    _: User = Depends(viewer),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    return analytics.trends(db, days, asset_id, scope=scope)


@router.get("/top", response_model=list[TopAsset] | list[TopCwe] | list[TopPackage])
def top(
    by: Literal["assets", "cwes", "packages"] = "assets",
    limit: int = Query(10, ge=1, le=50),
    asset_id: int | None = None,
    _: User = Depends(viewer),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    if by == "assets":
        return analytics.top_assets(db, limit, scope=scope)
    if by == "cwes":
        return analytics.top_cwes(db, limit, asset_id, scope=scope)
    return analytics.top_packages(db, limit, asset_id, scope=scope)


@router.get("/compliance", response_model=Compliance)
def compliance(
    asset_id: int | None = None,
    days: int = Query(90, ge=7, le=365, description="Window for the 'resolved on time' figures"),
    _: User = Depends(viewer),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    """Open findings against the OWASP Top 10 and the CWE Top 25, plus SLA performance.

    Everything a printable report needs in one request, so the page cannot show two figures taken a few
    seconds apart and disagreeing with each other.
    """
    return {
        "generated_at": utcnow(),
        "asset_id": asset_id,
        "owasp": analytics.owasp_breakdown(db, asset_id, scope=scope),
        "cwe_top_25": analytics.cwe_top_25(db, asset_id, scope=scope),
        "cwe_top_25_edition": compliance_tables.CWE_TOP_25_EDITION,
        "sla": analytics.sla_performance(db, days, asset_id, scope=scope),
        "mttr_trend": analytics.mttr_trend(db, days, asset_id, scope=scope),
    }


@router.get("/coverage", response_model=Coverage)
def coverage(
    stale_days: int = Query(30, ge=1, le=365, description="An asset not scanned for this long is stale"),
    _: User = Depends(viewer),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    """Which assets are not being scanned, or not recently."""
    return analytics.coverage(db, stale_days, scope=scope)


@router.get("/breakdown", response_model=list[BreakdownRow])
def breakdown(
    by: Literal["product", "team", "environment", "tool"] = "product",
    days: int = Query(90, ge=7, le=365, description="Window for resolved, MTTR and time to triage"),
    _: User = Depends(viewer),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    """The estate by product, team, environment or scanner."""
    return analytics.breakdown(db, by, days, scope=scope)
