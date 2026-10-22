"""One search box over findings, assets, packages and vulnerabilities (the Ctrl/Cmd-K palette)."""

import re

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import get_scope, require
from app.models import Asset, Component, Finding, User
from app.models.enums import Role
from app.schemas.finding import FindingOut
from app.schemas.scan import AssetRef
from app.services.queries import FindingFilters, findings_query, like_pattern
from app.services.scope import Scope
from app.services.serializers import finding_out

router = APIRouter(prefix="/search", tags=["search"])
_VULN_ID = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA(-[a-z0-9]{4}){3}|[A-Z]+-\d{4}-[\w-]+)$", re.IGNORECASE)


class PackageHit(BaseModel):
    name: str
    ecosystem: str | None
    assets: int


class SearchResult(BaseModel):
    vulnerability: str | None  # the query is a vulnerability id with findings you can see
    findings: list[FindingOut]
    assets: list[AssetRef]
    packages: list[PackageHit]


@router.get("", response_model=SearchResult)
def search(
    q: str = Query(min_length=2, max_length=200),
    limit: int = Query(8, ge=1, le=20),
    _: User = Depends(require(Role.viewer)),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    text = q.strip()
    pattern = like_pattern(text)
    matching = findings_query(FindingFilters(q=text, scope=scope), "-severity").limit(limit)
    found = db.scalars(matching).unique().all()
    assets = db.scalars(
        select(Asset)
        .where(scope.assets(), Asset.name.ilike(pattern))
        .order_by(func.lower(Asset.name))
        .limit(limit)
    ).all()
    packages = db.execute(
        scope.narrow(
            select(Component.name, Component.ecosystem, func.count(func.distinct(Component.asset_id)))
            .where(or_(Component.name.ilike(pattern), Component.purl.ilike(pattern)))
            .group_by(Component.name, Component.ecosystem),
            Component.asset_id,
        )
        .order_by(func.count(func.distinct(Component.asset_id)).desc(), Component.name)
        .limit(limit)
    ).all()
    vulnerability = None
    if _VULN_ID.match(text):
        ident = text.upper()
        hit = db.scalar(
            scope.narrow(select(Finding.id), Finding.asset_id)
            .where(or_(func.upper(Finding.cve_id) == ident, func.upper(Finding.vuln_id) == ident))
            .limit(1)
        )
        vulnerability = ident if hit is not None else None
    return SearchResult(
        vulnerability=vulnerability,
        findings=[finding_out(f) for f in found],
        assets=[AssetRef(id=a.id, name=a.name) for a in assets],
        packages=[PackageHit(name=n, ecosystem=e, assets=c) for n, e, c in packages],
    )
