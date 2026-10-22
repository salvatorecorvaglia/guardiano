
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import String, any_, case, cast, delete, func, literal_column, or_, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import get_db
from app.core.deps import get_scope, require
from app.models import Asset, Component, LicensePolicy, User
from app.models.enums import Role
from app.schemas.common import Page
from app.schemas.component import (
    ComponentUse,
    InventoryStats,
    LicenceCount,
    LicenceRule,
    LicensePolicyOut,
    LicensePolicyUpdate,
)
from app.schemas.scan import AssetRef
from app.services import audit, inventory, licenses
from app.services.queries import like_pattern
from app.services.scope import Scope

router = APIRouter(prefix="/components", tags=["components"])
viewer = require(Role.viewer)


def _carries_licence(listed: list[str]):
    """Components carrying any of these licences, compared case-insensitively.

    EXISTS over the unnested array rather than a regex over the array cast: licence names are full of
    regex metacharacters ("Apache-2.0", "GPL-3.0+").
    """
    value = func.unnest(Component.licenses).alias("licence_value")
    return (
        select(literal_column("1"))
        .select_from(value)
        .where(func.lower(func.trim(literal_column("licence_value"))).in_(listed))
        .exists()
    )


def _filtered(
    q: str | None,
    ecosystem: str | None,
    licence: str | None,
    asset_id: int | None,
    with_license: bool,
    scope: Scope,
):
    stmt = scope.narrow(select(Component), Component.asset_id)
    if q and q.strip():
        pattern = like_pattern(q.strip())
        stmt = stmt.where(or_(Component.name.ilike(pattern), Component.purl.ilike(pattern)))
    if ecosystem:
        stmt = stmt.where(Component.ecosystem == ecosystem)
    if licence:
        stmt = stmt.where(licence == any_(Component.licenses))
    if asset_id:
        stmt = stmt.where(Component.asset_id == asset_id)
    if with_license is False:
        stmt = stmt.where(func.cardinality(Component.licenses) == 0)
    return stmt


@router.get("", response_model=Page[ComponentUse])
def list_components(
    q: str | None = Query(None, max_length=200, description="Name or purl"),
    ecosystem: str | None = Query(None, max_length=50),
    licence: str | None = Query(None, max_length=100, alias="license"),
    asset_id: int | None = None,
    unlicensed: bool = Query(False, description="Only components with no licence recorded"),
    licence_rule: str | None = Query(
        None,
        pattern="^(allowed|denied|review|unknown)$",
        alias="licence_rule",
        description="Filter by what the licence policy says",
    ),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    _: User = Depends(viewer),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    """One row per package version, with every asset that ships it.

    This is the "who uses log4j-core 2.14?" query, answered without opening a single scan.
    """
    policy = licenses.load(db)
    stmt = _filtered(q, ecosystem, licence, asset_id, not unlicensed, scope)
    listed = sorted(policy.rules)
    value = func.unnest(Component.licenses).alias("licence_value")
    unlisted = (
        select(literal_column("1"))
        .select_from(value)
        .where(func.lower(func.trim(literal_column("licence_value"))).not_in(listed))
        .exists()
    )
    denied = _carries_licence(policy.listed("denied"))
    review = _carries_licence(policy.listed("review"))
    if settings.license_default == "review":
        review = or_(review, unlisted)
    priority = case((denied, 3), (review, 2), (func.cardinality(Component.licenses) > 0, 1), else_=0)
    stmt = stmt.add_columns(priority.label("verdict_priority"))
    base = stmt.subquery()
    grouped = (
        select(
            base.c.name,
            base.c.version,
            base.c.ecosystem,
            func.min(base.c.purl).label("purl"),
            func.max(base.c.last_seen_at).label("last_seen_at"),
            func.array_agg(func.distinct(cast(base.c.asset_id, String))).label("asset_ids"),
            # Not array_agg over the array column: Postgres refuses to accumulate empty arrays, which a
            # component with no licence recorded has.
            func.max(base.c.verdict_priority).label("verdict_priority"),
        )
        .group_by(base.c.name, base.c.version, base.c.ecosystem)
        .subquery()
    )
    licence_rows = select(
        base.c.name, base.c.version, base.c.ecosystem, func.unnest(base.c.licenses).label("licence")
    ).subquery()
    licence_groups = (
        select(
            licence_rows.c.name,
            licence_rows.c.version,
            licence_rows.c.ecosystem,
            func.array_agg(func.distinct(licence_rows.c.licence)).label("licences"),
        )
        .group_by(licence_rows.c.name, licence_rows.c.version, licence_rows.c.ecosystem)
        .subquery()
    )
    grouped = (
        select(grouped, licence_groups.c.licences)
        .outerjoin(
            licence_groups,
            (grouped.c.name == licence_groups.c.name)
            & grouped.c.version.is_not_distinct_from(licence_groups.c.version)
            & grouped.c.ecosystem.is_not_distinct_from(licence_groups.c.ecosystem),
        )
        .subquery()
    )
    if licence_rule:
        grouped = (
            select(grouped)
            .where(
                grouped.c.verdict_priority
                == {"unknown": 0, "allowed": 1, "review": 2, "denied": 3}[licence_rule]
            )
            .subquery()
        )
    total = db.scalar(select(func.count()).select_from(grouped)) or 0
    rows = db.execute(
        select(grouped)
        .order_by(grouped.c.name, grouped.c.version)
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()

    ids = {int(i) for r in rows for i in (r.asset_ids or [])}
    names = dict(db.execute(select(Asset.id, Asset.name).where(Asset.id.in_(ids))).all()) if ids else {}
    items = [
        ComponentUse(
            licence_rule=policy.verdict(sorted({x for x in (r.licences or []) if x})),
            name=r.name,
            version=r.version,
            ecosystem=r.ecosystem,
            purl=r.purl,
            licenses=sorted({x for x in (r.licences or []) if x}),
            assets=[
                AssetRef(id=int(i), name=names.get(int(i), "?"))
                for i in sorted(r.asset_ids or [], key=int)
                if int(i) in names
            ],
            last_seen_at=r.last_seen_at,
        )
        for r in rows
    ]
    return Page(items=items, total=total, page=page, page_size=page_size)


@router.get("/licenses", response_model=list[LicenceCount])
def list_licenses(
    _: User = Depends(viewer), scope: Scope = Depends(get_scope), db: Session = Depends(get_db)
):
    """Every licence in the inventory, most common first, with what the policy says about it."""
    policy = licenses.load(db)
    return [
        LicenceCount(licence=name, components=n, rule=policy.verdict([name]))
        for name, n in inventory.licenses_in_use(db, scope)
    ]


@router.get("/license-policy", response_model=LicensePolicyOut)
def get_license_policy(_: User = Depends(viewer), db: Session = Depends(get_db)):
    rows = db.scalars(select(LicensePolicy).order_by(LicensePolicy.licence)).all()
    return LicensePolicyOut(
        rules=[LicenceRule(licence=r.licence, rule=r.rule, note=r.note) for r in rows],
        default=settings.license_default,
    )


@router.put("/license-policy", response_model=LicensePolicyOut)
def put_license_policy(
    body: LicensePolicyUpdate,
    request: Request,
    admin: User = Depends(require(Role.admin, None)),
    db: Session = Depends(get_db),
):
    """Replace the whole policy. Licences not listed follow LICENSE_DEFAULT."""
    before = {r.licence: r.rule for r in db.scalars(select(LicensePolicy))}
    db.execute(delete(LicensePolicy))
    seen: set[str] = set()
    for rule in body.rules:
        licence = rule.licence.strip().lower()
        if not licence or licence in seen:
            continue
        seen.add(licence)
        db.add(LicensePolicy(licence=licence, rule=rule.rule, note=rule.note))
    after = {r.licence.strip().lower(): r.rule for r in body.rules}
    if before != after:
        audit.record(
            db,
            "license_policy.update",
            actor=admin,
            request=request,
            target_type="license_policy",
            changes={"from": before, "to": after},
        )
    db.commit()
    return get_license_policy(admin, db)


@router.get("/stats", response_model=InventoryStats)
def stats(_: User = Depends(viewer), scope: Scope = Depends(get_scope), db: Session = Depends(get_db)):
    """Size and freshness of the inventory, for the empty state and the page header."""
    mine = scope.narrow(select(Component), Component.asset_id).subquery()
    return {
        "components": db.scalar(select(func.count()).select_from(mine)) or 0,
        "distinct": db.scalar(
            select(func.count()).select_from(select(mine.c.name, mine.c.version).distinct().subquery())
        )
        or 0,
        "assets": db.scalar(select(func.count(func.distinct(mine.c.asset_id)))) or 0,
        "last_seen_at": db.scalar(select(func.max(mine.c.last_seen_at))),
    }
