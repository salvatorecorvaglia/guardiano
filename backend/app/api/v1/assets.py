from typing import Literal

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import JSONResponse
from sqlalchemy import Select, any_, func, literal, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from app.api.uploads import read_limited as _read_limited
from app.core.db import get_db
from app.core.deps import get_scope, require
from app.models import Asset, Component, Finding, Product, Scan, Team, User
from app.models.enums import Role
from app.schemas.asset import AssetCreate, AssetOut, AssetSummary, AssetUpdate, SeverityCounts
from app.schemas.common import Page
from app.schemas.component import ComponentOut, VexImportResult
from app.schemas.scan import AssetRef
from app.services import audit, licenses, sbom, vex
from app.services.queries import ACTIVE, criticality_multiplier_expr, like_pattern, severity_weight_expr
from app.services.scope import Scope

router = APIRouter(prefix="/assets", tags=["assets"])
manager = require(Role.manager, None)


_SEVERITIES = list(SeverityCounts.model_fields)
_AUDITED = (
    "name",
    "type",
    "description",
    "repo_url",
    "team_id",
    "owner",
    "criticality",
    "tags",
    "default_assignee_id",
    "default_branch",
)


def _check_team(db: Session, team_id: int | None) -> None:
    if team_id is not None and db.get(Team, team_id) is None:
        raise HTTPException(422, "Team not found")


def _check_product(db: Session, product_id: int | None) -> None:
    if product_id is not None and db.get(Product, product_id) is None:
        raise HTTPException(422, "Product not found")


def _check_assignee(db: Session, user_id: int | None) -> None:
    if user_id is not None:
        user = db.get(User, user_id)
        if user is None or not user.is_active:
            raise HTTPException(422, "Default assignee not found")


def _summary_query(assets: Select | list[int] | None = None) -> tuple[Select, dict[str, ColumnElement]]:
    """Assets with open counts per severity, risk score and last scan, computed in SQL.

    ``assets`` -- asset ids, as a list or a select -- limits the aggregates to those assets. The
    filter has to be inside the grouped subqueries: Postgres does not push an outer
    ``Asset.id IN (...)`` through a GROUP BY, so without it every call aggregated every finding and
    scan in the installation, even to summarise one asset.
    """
    active = Finding.status.in_(ACTIVE)
    counts = select(
        Finding.asset_id,
        *[func.count().filter(active, Finding.severity == s).label(s) for s in _SEVERITIES],
        func.coalesce(func.sum(severity_weight_expr()).filter(active), 0.0).label("weight"),
    )
    # Previews change nothing, so they are not the asset's last scan.
    scans = select(Scan.asset_id, func.max(Scan.created_at).label("last_scan_at")).where(
        Scan.source != "preview"
    )
    if assets is not None:
        counts = counts.where(Finding.asset_id.in_(assets))
        scans = scans.where(Scan.asset_id.in_(assets))
    counts = counts.group_by(Finding.asset_id).subquery()
    scans = scans.group_by(Scan.asset_id).subquery()
    open_total = sum((func.coalesce(counts.c[s], 0) for s in _SEVERITIES), literal(0))
    risk = func.coalesce(counts.c.weight, 0.0) * criticality_multiplier_expr()
    return (
        select(
            Asset,
            *[func.coalesce(counts.c[s], 0).label(s) for s in _SEVERITIES],
            open_total.label("open_total"),
            risk.label("risk_score"),
            scans.c.last_scan_at,
        )
        .outerjoin(counts, counts.c.asset_id == Asset.id)
        .outerjoin(scans, scans.c.asset_id == Asset.id)
    ), {"risk": risk, "open": open_total, "last_scan": scans.c.last_scan_at, "name": func.lower(Asset.name)}


def _to_summary(row) -> AssetSummary:
    return AssetSummary(
        **AssetOut.model_validate(row.Asset).model_dump(),
        open_counts=SeverityCounts(**{s: row._mapping[s] for s in _SEVERITIES}),
        open_total=row.open_total,
        risk_score=round(float(row.risk_score), 1),
        last_scan_at=row.last_scan_at,
    )


def summarize(db: Session, assets: list[Asset]) -> list[AssetSummary]:
    ids = [a.id for a in assets]
    stmt, _ = _summary_query(ids)
    rows = {r.Asset.id: r for r in db.execute(stmt.where(Asset.id.in_(ids)))}
    return [_to_summary(rows[a.id]) for a in assets]


@router.get("/options", response_model=list[AssetRef])
def asset_options(
    _: User = Depends(require(Role.viewer)),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    """Every asset this person can see, by id and name only, for pickers and filters.

    Unpaginated on purpose: a picker that silently stops at page_size is wrong, and pickers used to
    read /assets?page_size=500, which stopped at 500 and computed the full risk summary of every
    asset just to fill a dropdown.
    """
    return db.execute(
        select(Asset.id, Asset.name).where(scope.assets()).order_by(func.lower(Asset.name), Asset.id)
    ).all()


@router.get("", response_model=Page[AssetSummary])
def list_assets(
    q: str | None = None,
    product_id: int | None = None,
    environment: str | None = Query(None, pattern="^(production|staging|development|test)$"),
    sort: str = Query("-risk", pattern=r"^-?(risk|name|last_scan|open)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    _: User = Depends(require(Role.viewer)),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    visible = select(Asset.id).where(scope.assets())
    if product_id is not None:
        visible = visible.where(Asset.product_id == product_id)
    if environment:
        visible = visible.where(Asset.environment == environment)
    if q and q.strip():
        term = q.strip()
        like = like_pattern(term)
        visible = visible.where(
            or_(Asset.name.ilike(like), Asset.owner.ilike(like), term == any_(Asset.tags))
        )
    # Aggregate only what this person can see and asked for, and count without aggregating at all:
    # the total used to wrap the whole aggregate query, computing every sum a second time.
    stmt, sort_cols = _summary_query(visible)
    stmt = stmt.where(Asset.id.in_(visible))
    total = db.scalar(select(func.count()).select_from(visible.subquery())) or 0
    col = sort_cols[sort.lstrip("-")]
    order = col.desc().nulls_last() if sort.startswith("-") else col.asc().nulls_first()
    rows = db.execute(
        stmt.order_by(order, Asset.name, Asset.id).offset((page - 1) * page_size).limit(page_size)
    )
    return Page(items=[_to_summary(r) for r in rows], total=total, page=page, page_size=page_size)


@router.post("", response_model=AssetSummary, status_code=status.HTTP_201_CREATED)
def create_asset(
    body: AssetCreate, request: Request, user: User = Depends(manager), db: Session = Depends(get_db)
):
    _check_assignee(db, body.default_assignee_id)
    _check_product(db, body.product_id)
    if body.team_id is not None:
        if user.role != Role.admin.value:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Only an administrator can put an asset in a team")
        _check_team(db, body.team_id)
    asset = Asset(**body.model_dump(mode="json"))
    db.add(asset)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "An asset with this name already exists")
    audit.record(
        db,
        "asset.create",
        actor=user,
        request=request,
        target_type="asset",
        target_id=asset.id,
        target_label=asset.name,
    )
    db.commit()
    return summarize(db, [asset])[0]


def _get(db: Session, asset_id: int, scope: Scope) -> Asset:
    """An asset, or 404 — including when it belongs to a team the reader is not in."""
    asset = db.get(Asset, asset_id)
    if asset is None or not scope.owns(asset):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")
    return asset


@router.get("/{asset_id}", response_model=AssetSummary)
def get_asset(
    asset_id: int,
    _: User = Depends(require(Role.viewer)),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    return summarize(db, [_get(db, asset_id, scope)])[0]


@router.patch("/{asset_id}", response_model=AssetSummary)
def update_asset(
    asset_id: int,
    body: AssetUpdate,
    request: Request,
    user: User = Depends(manager),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    asset = _get(db, asset_id, scope)
    changes = body.model_dump(exclude_unset=True, mode="json")
    _check_product(db, changes.get("product_id"))
    if "default_assignee_id" in changes:
        _check_assignee(db, changes["default_assignee_id"])
    if "team_id" in changes:
        # Only administrators move an asset between teams: otherwise anybody who can edit an asset could
        # hide it from its team, or help themselves to another team's.
        if user.role != Role.admin.value:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Only an administrator can change an asset's team")
        _check_team(db, changes["team_id"])
    before = audit.snapshot(asset, _AUDITED)
    for k, v in changes.items():
        setattr(asset, k, v)
    if diff := audit.diff(before, asset):
        audit.record(
            db,
            "asset.update",
            actor=user,
            request=request,
            target_type="asset",
            target_id=asset.id,
            target_label=asset.name,
            changes=diff,
        )
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "An asset with this name already exists")
    return summarize(db, [asset])[0]


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(
    asset_id: int,
    request: Request,
    user: User = Depends(manager),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    asset = _get(db, asset_id, scope)
    audit.record(
        db,
        "asset.delete",
        actor=user,
        request=request,
        target_type="asset",
        target_id=asset.id,
        target_label=asset.name,
    )
    db.delete(asset)
    db.commit()


@router.get("/{asset_id}/components", response_model=Page[ComponentOut])
def asset_components(
    asset_id: int,
    q: str | None = Query(None, max_length=200, description="Name or purl"),
    ecosystem: str | None = Query(None, max_length=50),
    sort: str = Query("name", pattern=r"^-?(name|last_seen)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    _: User = Depends(require(Role.viewer)),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    """Everything this asset ships, with what the licence policy makes of it.

    The inventory-wide `GET /components` answers "who uses package X"; this answers the other direction,
    "what is in this service", which is the question asked during an incident.
    """
    _get(db, asset_id, scope)  # 404 for an asset this person may not see
    policy = licenses.load(db)
    stmt = select(Component).where(Component.asset_id == asset_id)
    if q and q.strip():
        pattern = like_pattern(q.strip())
        stmt = stmt.where(or_(Component.name.ilike(pattern), Component.purl.ilike(pattern)))
    if ecosystem:
        stmt = stmt.where(Component.ecosystem == ecosystem)

    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    column = Component.last_seen_at if sort.lstrip("-") == "last_seen" else func.lower(Component.name)
    order = column.desc() if sort.startswith("-") else column.asc()
    rows = db.scalars(
        stmt.order_by(order, Component.id).offset((page - 1) * page_size).limit(page_size)
    ).all()
    items = [
        ComponentOut(
            **{c: getattr(row, c) for c in ComponentOut.model_fields if c != "licence_rule"},
            licence_rule=policy.verdict(row.licenses),
        )
        for row in rows
    ]
    return Page(items=items, total=total, page=page, page_size=page_size)


@router.get("/{asset_id}/sbom", response_class=JSONResponse)
def asset_sbom(
    asset_id: int,
    format: Literal["cyclonedx", "spdx"] = "cyclonedx",
    include: Literal["current", "all"] = Query(
        "current",
        description="current: what each tool's latest scan listed; all: every component ever seen",
    ),
    _: User = Depends(require(Role.viewer)),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    """The asset's components as a CycloneDX 1.5 or SPDX 2.3 JSON document, to hand to whoever asks."""
    asset = _get(db, asset_id, scope)
    rows = sbom.components(db, asset, include)
    document = sbom.cyclonedx(asset, rows) if format == "cyclonedx" else sbom.spdx(asset, rows)
    legacy = (
        db.scalar(
            select(Scan.id)
            .where(
                Scan.id.in_(sbom.latest_inventory_scans(asset.id)),
                Scan.inventory_complete.is_(None),
            )
            .limit(1)
        )
        is not None
    )
    if legacy:
        notice = "Best-effort legacy inventory; upload fresh SBOMs to establish complete scanner snapshots."
        if format == "cyclonedx":
            document["metadata"].setdefault("properties", []).append(
                {
                    "name": "guardiano:inventory:provenance",
                    "value": notice,
                }
            )
        else:
            document["comment"] = notice
    ext = "cdx.json" if format == "cyclonedx" else "spdx.json"
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "-" for ch in asset.name)
    media = "application/vnd.cyclonedx+json" if format == "cyclonedx" else "application/spdx+json"
    return JSONResponse(
        document,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{safe}.{ext}"'},
    )


@router.get("/{asset_id}/vex", response_class=JSONResponse)
def asset_vex(
    asset_id: int,
    format: Literal["openvex", "cyclonedx"] = "openvex",
    _: User = Depends(require(Role.viewer)),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    """What Guardiano knows about each vulnerable package on the asset, as OpenVEX or CycloneDX VEX."""
    asset = _get(db, asset_id, scope)
    rows = vex.exportable(db, asset)
    document = vex.openvex(asset, rows) if format == "openvex" else vex.cyclonedx(asset, rows)
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "-" for ch in asset.name)
    ext = "openvex.json" if format == "openvex" else "vex.cdx.json"
    media = "application/json" if format == "openvex" else "application/vnd.cyclonedx+json"
    return JSONResponse(
        document, media_type=media, headers={"Content-Disposition": f'attachment; filename="{safe}.{ext}"'}
    )


@router.post("/{asset_id}/vex", response_model=VexImportResult)
def import_vex(
    asset_id: int,
    request: Request,
    file: UploadFile = File(..., description="An OpenVEX or CycloneDX VEX document"),
    user: User = Depends(require(Role.manager, None)),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
) -> dict:
    """Apply a supplier's VEX statements to this asset's open findings.

    not_affected marks them false positive and fixed resolves them; other statuses change nothing.
    Manager or higher: one document can close many findings.
    """
    asset = _get(db, asset_id, scope)
    kind, statements = vex.parse(_read_limited(file))
    result = vex.apply(db, asset, statements, user)
    audit.record(
        db,
        "vex.import",
        actor=user,
        request=request,
        target_type="asset",
        target_id=asset.id,
        target_label=asset.name,
        changes={"format": kind, "statements": result.statements, "changed": result.changed},
    )
    db.commit()
    return {
        "format": kind,
        "statements": result.statements,
        "changed": result.changed,
        "already_closed": result.already_closed,
        "informational": result.informational,
        "unmatched": result.unmatched,
    }
