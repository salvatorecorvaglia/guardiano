"""One vulnerability (a CVE or an advisory id) across the estate."""

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.orm import Session, joinedload

from app.core.db import get_db
from app.core.deps import get_scope, require
from app.models import Component, Finding, User, VulnIntel
from app.models.enums import ACTIVE_STATUSES, Role
from app.schemas.vulnerability import AffectedFinding, ShippedComponent, Vulnerability
from app.services.dedup import _ECOSYSTEMS
from app.services.scope import Scope

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])
_ACTIVE = {s.value for s in ACTIVE_STATUSES}
_SHIPPED_LIMIT = 500


@router.get("/{vuln_id}", response_model=Vulnerability)
def get_vulnerability(
    vuln_id: str = Path(max_length=100, pattern=r"^[A-Za-z0-9._:-]+$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    _: User = Depends(require(Role.viewer)),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    """Every finding for it, and every other asset that ships an affected package without a finding.

    The second list is the one that matters during an incident: an asset whose SBOM lists the package
    but that was not scanned for vulnerabilities, or not recently, is exposed without anybody knowing.
    """
    ident = vuln_id.upper()
    matching = scope.narrow(select(Finding), Finding.asset_id).where(
        or_(func.upper(Finding.cve_id) == ident, func.upper(Finding.vuln_id) == ident)
    )
    match_ids = matching.with_only_columns(Finding.id).subquery()
    condition = Finding.id.in_(select(match_ids.c.id))
    by_status = dict(
        db.execute(select(Finding.status, func.count()).where(condition).group_by(Finding.status)).all()
    )
    total = sum(by_status.values())
    rows = db.scalars(
        matching.options(joinedload(Finding.asset), joinedload(Finding.assignee))
        .order_by(Finding.status, Finding.asset_id, Finding.id)
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    intel = db.get(VulnIntel, ident)
    if not total and intel is None:
        raise HTTPException(404, "No finding on the assets you can see names this vulnerability")

    def ecosystem(column):
        lowered = func.lower(func.trim(func.coalesce(column, "")))
        return case(_ECOSYSTEMS, value=lowered, else_=lowered)

    # Keep package matching in SQL: a large advisory must not expand into an
    # unbounded Python set or thousands of OR parameters in the inventory query.
    affected = (
        select(
            ecosystem(Finding.ecosystem).label("ecosystem"),
            func.lower(Finding.package_name).label("name"),
            Finding.package_version.label("version"),
        )
        .where(condition, Finding.package_name.is_not(None), Finding.package_name != "")
        .distinct()
        .cte("affected_packages")
    )
    package_match = and_(
        ecosystem(Component.ecosystem) == affected.c.ecosystem, func.lower(Component.name) == affected.c.name
    )
    ships_package = select(1).select_from(affected).where(package_match).exists()
    same_version = (
        select(1)
        .select_from(affected)
        .where(
            package_match,
            affected.c.version.is_not(None),
            affected.c.version != "",
            affected.c.version == func.coalesce(Component.version, ""),
        )
        .exists()
    )
    with_finding = select(Finding.asset_id).where(condition)
    active_assets = db.scalar(
        select(func.count(func.distinct(Finding.asset_id))).where(condition, Finding.status.in_(_ACTIVE))
    )
    candidates = db.execute(
        scope.narrow(select(Component, same_version), Component.asset_id)
        .where(ships_package, Component.asset_id.not_in(with_finding))
        .options(joinedload(Component.asset))
        .order_by(Component.asset_id, Component.name, Component.version)
        .limit(_SHIPPED_LIMIT + 1)
    ).all()
    truncated = len(candidates) > _SHIPPED_LIMIT
    shipped = [
        ShippedComponent(
            asset=c.asset,
            name=c.name,
            version=c.version,
            ecosystem=c.ecosystem,
            same_version=same,
            last_seen_at=c.last_seen_at,
        )
        for c, same in candidates[:_SHIPPED_LIMIT]
    ]

    return Vulnerability(
        id=ident,
        in_kev=bool(intel and intel.in_kev),
        kev_due_date=intel.kev_due_date if intel else None,
        kev_ransomware=bool(intel and intel.kev_ransomware),
        epss=intel.epss if intel else None,
        epss_percentile=intel.epss_percentile if intel else None,
        assets_affected=active_assets,
        open=sum(count for status, count in by_status.items() if status in _ACTIVE),
        by_status=by_status,
        findings_total=total,
        page=page,
        page_size=page_size,
        findings=[
            AffectedFinding(
                finding_id=f.id,
                asset=f.asset,
                type=f.type,
                title=f.title,
                severity=f.severity,
                status=f.status,
                package_name=f.package_name,
                package_version=f.package_version,
                fixed_version=f.fixed_version,
                url=f.url,
                assignee=f.assignee,
                first_seen_at=f.first_seen_at,
            )
            for f in rows
        ],
        also_ships=shipped,
        also_ships_truncated=truncated,
    )
