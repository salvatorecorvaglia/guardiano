from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile, status
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session, joinedload

from app.api.uploads import read_limited as _read_limited
from app.core.config import settings
from app.core.db import get_db
from app.core.deps import get_scope, require
from app.core.ratelimit import credential_key, limiter
from app.models import Asset, FindingScan, Scan, User
from app.models.enums import Role, TokenScope
from app.parsers.base import ParseError
from app.parsers.detect import SUPPORTED_FORMATS
from app.schemas.common import Page
from app.schemas.scan import ScanDiff, ScanOut
from app.services.ingestion import IngestOptions, get_or_create_asset, ingest_report
from app.services.scope import Scope

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanOut, status_code=status.HTTP_201_CREATED)
@limiter.limit(
    lambda: settings.ingest_rate_limit or "1/second",
    key_func=credential_key,
    exempt_when=lambda: not settings.ingest_rate_limit,
)
def upload_scan(
    request: Request,
    file: UploadFile = File(
        ..., description="SARIF, CycloneDX JSON, Trivy JSON, Semgrep JSON or Guardiano JSON"
    ),
    asset_id: int | None = Form(None),
    asset_name: str | None = Form(
        None, max_length=200, description="Created automatically if it does not exist"
    ),
    format: str | None = Form(None, description=f"Override auto-detection: {', '.join(SUPPORTED_FORMATS)}"),
    scan_type: str | None = Form(None, pattern="^(sast|sca|iac|dast)$"),
    # Both reach issue-tracker API URLs (services/trackers/*). commit_sha lands in a path segment, so it
    # is constrained to a git object name; branch is only ever a query value and is URL-encoded at use.
    branch: str | None = Form(None, max_length=255, pattern=r"^[^\x00-\x1f\x7f]+$"),
    commit_sha: str | None = Form(None, max_length=64, pattern=r"^[0-9a-fA-F]{4,64}$"),
    close_missing: bool = Form(
        False, description="Resolve active findings from this tool not present in the report"
    ),
    preview: bool = Form(
        False,
        description="Evaluate the report (and its quality gate) without changing the inventory. "
        "Implied when the asset has a default_branch and 'branch' differs from it.",
    ),
    allow_empty: bool = Form(
        False, description="Let close_missing act on a report with no findings (skipped by default)"
    ),
    user: User = Depends(require(Role.analyst, TokenScope.ingest)),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    if asset_id is not None:
        asset = db.get(Asset, asset_id)
        if asset is None or not scope.owns(asset):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")
    elif asset_name and asset_name.strip():
        asset = get_or_create_asset(db, asset_name, scope)
    else:
        raise HTTPException(422, "Provide asset_id or asset_name")

    raw = _read_limited(file)
    is_api = getattr(request.state, "via_token", False)
    try:
        scan = ingest_report(
            db,
            raw,
            asset,
            user,
            IngestOptions(
                fmt=format,
                scan_type=scan_type,
                branch=branch,
                commit_sha=commit_sha,
                source="api" if is_api else "upload",
                file_name=(file.filename or "")[:255] or None,
                close_missing=close_missing,
                allow_empty=allow_empty,
                preview=preview,
            ),
        )
    except ParseError as exc:
        db.rollback()
        raise HTTPException(422, str(exc))
    return db.scalar(
        select(Scan).options(joinedload(Scan.asset), joinedload(Scan.uploaded_by)).where(Scan.id == scan.id)
    )


@router.get("", response_model=Page[ScanOut])
def list_scans(
    asset_id: int | None = None,
    scan_type: str | None = Query(None, pattern="^(sast|sca|iac|dast)$"),
    source: str | None = Query(None, pattern="^(upload|api|preview)$"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    _: User = Depends(require(Role.viewer)),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    stmt = scope.narrow(select(Scan), Scan.asset_id)
    if asset_id:
        stmt = stmt.where(Scan.asset_id == asset_id)
    if scan_type:
        stmt = stmt.where(Scan.scan_type == scan_type)
    if source:
        stmt = stmt.where(Scan.source == source)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    items = db.scalars(
        stmt.options(joinedload(Scan.asset), joinedload(Scan.uploaded_by))
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return Page(items=items, total=total, page=page, page_size=page_size)


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: int,
    _: User = Depends(require(Role.viewer)),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    return _scan(db, scan_id, scope)


def _scan(db: Session, scan_id: int, scope: Scope) -> Scan:
    """A scan, or 404 — including when its asset belongs to a team the reader is not in."""
    scan = db.scalar(
        scope.narrow(
            select(Scan).options(joinedload(Scan.asset), joinedload(Scan.uploaded_by)), Scan.asset_id
        ).where(Scan.id == scan_id)
    )
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    return scan


def previous_scan(db: Session, scan: Scan) -> Scan | None:
    """The latest earlier scan of the same asset by the same tool and scan type."""
    earlier = or_(
        Scan.created_at < scan.created_at, and_(Scan.created_at == scan.created_at, Scan.id < scan.id)
    )
    return db.scalar(
        select(Scan)
        .options(joinedload(Scan.asset), joinedload(Scan.uploaded_by))
        .where(
            Scan.source != "preview",  # a preview reported nothing, so it is not a baseline
            Scan.asset_id == scan.asset_id,
            Scan.tool_name == scan.tool_name,
            Scan.scan_type == scan.scan_type,
            Scan.id != scan.id,
            earlier,
        )
        .order_by(Scan.created_at.desc(), Scan.id.desc())
        .limit(1)
    )


@router.get("/{scan_id}/diff", response_model=ScanDiff)
def scan_diff(
    scan_id: int,
    against: int | None = Query(None, description="Scan to compare with; defaults to the previous scan"),
    _: User = Depends(require(Role.viewer)),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    scan = _scan(db, scan_id, scope)
    if scan.source == "preview":
        raise HTTPException(422, "A preview scan reports no stored findings; read its 'preview' instead")
    base = _scan(db, against, scope) if against is not None else previous_scan(db, scan)
    if base is not None and base.asset_id != scan.asset_id:
        raise HTTPException(422, "Both scans must belong to the same asset")

    def ids(s: Scan | None):
        return select(FindingScan.finding_id).where(FindingScan.scan_id == (s.id if s else -1))

    current, previous = ids(scan).subquery(), ids(base).subquery()
    total = db.scalar(select(func.count()).select_from(current)) or 0
    both = (
        db.scalar(
            select(func.count())
            .select_from(current)
            .join(previous, previous.c.finding_id == current.c.finding_id)
        )
        or 0
    )
    before = db.scalar(select(func.count()).select_from(previous)) or 0
    return ScanDiff(
        scan=ScanOut.model_validate(scan),
        against=ScanOut.model_validate(base) if base else None,
        new=total - both,
        no_longer_reported=before - both,
        unchanged=both,
    )
