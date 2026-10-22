import csv
import io
from collections.abc import Callable, Iterable, Iterator
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session, joinedload, selectinload
from sqlalchemy.orm.attributes import set_committed_value

from app.core.db import SessionLocal, get_db
from app.core.deps import get_scope, require
from app.models import Finding, FindingEvent, FindingLink, Integration, User
from app.models.enums import Role, Severity, Status, TokenScope
from app.schemas.common import Page
from app.schemas.finding import (
    BulkChange,
    BulkResult,
    BulkUpdate,
    CommentCreate,
    FindingDetail,
    FindingEventOut,
    FindingOut,
    FindingUpdate,
    TagCount,
)
from app.schemas.integration import FindingLinkOut, IntegrationOut, TicketCreate
from app.services import export, lifecycle, notifications, tickets
from app.services.errors import ValidationFailed
from app.services.finding_changes import apply_change as _apply
from app.services.finding_changes import check_overrides as _check_due
from app.services.queries import ACTIVE, FindingFilters, apply_filters, findings_query
from app.services.scope import Scope, ScopeCache
from app.services.serializers import finding_detail, finding_out
from app.services.trackers.base import TrackerError

router = APIRouter(prefix="/findings", tags=["findings"])
analyst = require(Role.analyst, None)
# Triage (status, assignee, tags, dates, severity, comments) is also open to API tokens given the
# "triage" scope; everything else here stays with people.
triager = require(Role.analyst, TokenScope.triage)


def filters(
    q: str | None = Query(
        None, max_length=200, description="Full-text search (title, CVE, package, path, rule)"
    ),
    severity: list[Severity] = Query([]),
    status_: list[Status] = Query([], alias="status"),
    type: str | None = Query(None, pattern="^(sast|sca|iac|dast)$"),
    asset_id: list[int] = Query([]),
    product_id: int | None = None,
    environment: str | None = Query(None, pattern="^(production|staging|development|test)$"),
    tool: str | None = None,
    cwe: str | None = None,
    cve: str | None = None,
    package: str | None = None,
    assignee_id: int | None = None,
    unassigned: bool = False,
    overdue: bool | None = None,
    first_seen_from: datetime | None = None,
    first_seen_to: datetime | None = None,
    tag: list[str] = Query([], description="Repeatable; findings must carry every tag"),
    kev: bool | None = Query(None, description="In CISA's Known Exploited Vulnerabilities catalogue"),
    epss_min: float | None = Query(None, ge=0, le=1, description="Minimum EPSS probability (0-1)"),
    ticket_done: bool | None = Query(
        None, description="Findings whose linked ticket the tracker now reports as finished"
    ),
    scan_id: int | None = Query(None, description="Only findings reported by this scan"),
    not_in_scan_id: int | None = Query(
        None, description="Only findings not reported by this scan (with scan_id: a scan diff)"
    ),
    scope: Scope = Depends(get_scope),
) -> FindingFilters:
    return FindingFilters(
        q=q,
        severity=[s.value for s in severity],
        status=[s.value for s in status_],
        type=type,
        asset_id=asset_id,
        product_id=product_id,
        environment=environment,
        tool=tool,
        cwe=cwe,
        cve=cve,
        package=package,
        assignee_id=assignee_id,
        unassigned=unassigned,
        overdue=overdue,
        first_seen_from=first_seen_from,
        first_seen_to=first_seen_to,
        tag=tag,
        kev=kev,
        epss_min=epss_min,
        ticket_done=ticket_done,
        scan_id=scan_id,
        not_in_scan_id=not_in_scan_id,
        scope=scope,
    )


SORT_PATTERN = r"^-?(severity|first_seen|last_seen|title|status|cvss|due|epss|priority)$"


@router.get("", response_model=Page[FindingOut])
def list_findings(
    f: FindingFilters = Depends(filters),
    sort: str = Query("-severity", pattern=SORT_PATTERN),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    _: User = Depends(require(Role.viewer)),
    db: Session = Depends(get_db),
):
    stmt = findings_query(f, sort)
    total = db.scalar(apply_filters(select(func.count(Finding.id)), f)) or 0
    rows = db.scalars(stmt.offset((page - 1) * page_size).limit(page_size)).unique().all()
    return Page(items=[finding_out(r) for r in rows], total=total, page=page, page_size=page_size)


EXPORT_COLUMNS = [
    "id",
    "asset",
    "type",
    "severity",
    "cvss_score",
    "status",
    "title",
    "cwe",
    "rule_id",
    "tools",
    "file_path",
    "line_start",
    "package_name",
    "package_version",
    "cve_id",
    "fixed_version",
    "first_seen_at",
    "last_seen_at",
    "closed_at",
    "assignee",
    "tags",  # appended last so existing column positions stay stable
    "epss",
    "in_kev",
]


def _csv_safe(v: object) -> object:
    # Neutralise spreadsheet formula injection.
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


def _csv_row(r: Finding) -> list[object]:
    return [
        _csv_safe(x)
        for x in (
            r.id,
            r.asset.name,
            r.type,
            r.severity,
            r.cvss_score,
            r.status,
            r.title,
            ";".join(r.cwe or []),
            r.rule_id,
            ";".join(r.tools or []),
            r.file_path,
            r.line_start,
            r.package_name,
            r.package_version,
            r.cve_id,
            r.fixed_version,
            r.first_seen_at.isoformat(),
            r.last_seen_at.isoformat(),
            r.closed_at.isoformat() if r.closed_at else "",
            r.assignee.email if r.assignee else "",
            ";".join(r.tags or []),
            r.intel.epss if r.intel else "",
            "yes" if (r.intel and r.intel.in_kev) else "",
        )
    ]


def _csv_stream(rows: Iterable[Finding]) -> Iterator[str]:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(EXPORT_COLUMNS)
    yield buf.getvalue()
    for r in rows:
        buf.seek(0)
        buf.truncate()
        w.writerow(_csv_row(r))
        yield buf.getvalue()


def _export(
    f: FindingFilters, sort: str, render: Callable[[Iterable[Finding]], Iterator[str]], media: str, ext: str
) -> StreamingResponse:
    def body() -> Iterator[str]:
        # The stream outlives the request-scoped session, so use a dedicated one.
        with SessionLocal() as db:
            # yield_per streams from a server-side cursor instead of buffering every row; the eager
            # loads are many-to-one, so no unique() pass (which would also hold every row) is needed.
            stmt = findings_query(f, sort).execution_options(yield_per=500)
            yield from render(db.scalars(stmt))

    return StreamingResponse(
        body(),
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="guardiano-findings.{ext}"'},
    )


@router.get("/export.csv", response_class=StreamingResponse)
def export_csv(
    f: FindingFilters = Depends(filters),
    sort: str = Query("-severity", pattern=SORT_PATTERN),
    _: User = Depends(require(Role.viewer)),
):
    return _export(f, sort, _csv_stream, "text/csv", "csv")


@router.get("/export.json", response_class=StreamingResponse)
def export_json(
    f: FindingFilters = Depends(filters),
    sort: str = Query("-severity", pattern=SORT_PATTERN),
    _: User = Depends(require(Role.viewer)),
):
    """A JSON array of findings in the same shape as `GET /findings` items."""
    return _export(f, sort, export.json_stream, "application/json", "json")


@router.get("/export.sarif", response_class=StreamingResponse)
def export_sarif(
    f: FindingFilters = Depends(filters),
    sort: str = Query("-severity", pattern=SORT_PATTERN),
    _: User = Depends(require(Role.viewer)),
):
    """SARIF 2.1.0, for code-scanning dashboards and other SARIF consumers."""
    return _export(f, sort, export.sarif_stream, "application/sarif+json", "sarif")


@router.get("/tags", response_model=list[TagCount])
def list_tags(
    q: str | None = Query(None, max_length=64),
    limit: int = Query(50, ge=1, le=200),
    _: User = Depends(require(Role.viewer)),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    """Tags in use, most used first, with how many of their findings are active (for pickers)."""
    tag = func.unnest(Finding.tags).label("tag")
    inner = scope.narrow(select(tag, Finding.status), Finding.asset_id).subquery()
    stmt = select(
        inner.c.tag,
        func.count().label("count"),
        func.count().filter(inner.c.status.in_(ACTIVE)).label("active"),
    ).group_by(inner.c.tag)
    if q and q.strip():
        stmt = stmt.where(inner.c.tag.startswith(q.strip().lower(), autoescape=True))
    rows = db.execute(stmt.order_by(func.count().desc(), inner.c.tag).limit(limit))
    return [TagCount(tag=r.tag, count=r.count, active=r.active) for r in rows]


def _load(
    db: Session, finding_id: int, scope: Scope, *, history: bool = False, lock: bool = False
) -> Finding:
    """A finding, or 404 -- including when it belongs to a team the reader is not in.

    ``history`` loads the latest 200 events and their actors for detail responses.
    It is off by default because a long-lived finding carries hundreds of events, and
    the endpoints that only check access or read the asset were loading all of them each time.
    """
    options = [
        joinedload(Finding.asset),
        joinedload(Finding.assignee),
        selectinload(Finding.links).joinedload(FindingLink.created_by),
        joinedload(Finding.intel),
    ]
    stmt = scope.narrow(select(Finding), Finding.asset_id).options(*options).where(Finding.id == finding_id)
    if lock:
        stmt = stmt.with_for_update(of=Finding).execution_options(populate_existing=True)
    f = db.scalar(stmt)
    if f is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    if history:
        history_rows = db.execute(
            select(FindingEvent, func.count().over())
            .where(FindingEvent.finding_id == f.id)
            .options(joinedload(FindingEvent.actor))
            .order_by(FindingEvent.created_at.desc(), FindingEvent.id.desc())
            .limit(200)
        ).all()
        set_committed_value(f, "events", [row[0] for row in history_rows])
        f.events_total = history_rows[0][1] if history_rows else 0
    return f


@router.get("/{finding_id}/events", response_model=Page[FindingEventOut])
def finding_events(
    finding_id: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(200, ge=1, le=200),
    _: User = Depends(require(Role.viewer)),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    _load(db, finding_id, scope)
    query = select(FindingEvent).where(FindingEvent.finding_id == finding_id)
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.scalars(
        query.options(joinedload(FindingEvent.actor))
        .order_by(FindingEvent.created_at.desc(), FindingEvent.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return Page(
        items=[FindingEventOut.model_validate(row) for row in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{finding_id}", response_model=FindingDetail)
def get_finding(
    finding_id: int,
    _: User = Depends(require(Role.viewer)),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    return finding_detail(_load(db, finding_id, scope, history=True))


@router.patch("/{finding_id}", response_model=FindingDetail)
def update_finding(
    finding_id: int,
    body: FindingUpdate,
    user: User = Depends(triager),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    _check_due(body, user)
    f = _load(db, finding_id, scope, lock=True)  # serialize lifecycle changes
    if _apply(db, f, body, user):
        db.commit()
    db.expire_all()
    return finding_detail(_load(db, finding_id, scope, history=True))


@router.post("/bulk", response_model=BulkResult)
def bulk_update(
    body: BulkUpdate,
    user: User = Depends(triager),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    chosen = scope.narrow(select(Finding).where(Finding.id.in_(body.ids)), Finding.asset_id)
    return _bulk(db, chosen, body, user)


# The most findings one "apply to everything that matches" may change. Beyond it the request is refused
# with the count, so the person narrows the filter rather than waiting on one enormous transaction.
MAX_BULK_MATCHING = 2000


@router.post("/bulk/matching", response_model=BulkResult)
def bulk_update_matching(
    body: BulkChange,
    f: FindingFilters = Depends(filters),
    user: User = Depends(triager),
    db: Session = Depends(get_db),
):
    """Apply one change to every finding the filters match: the same query parameters as `GET /findings`.

    Refused, with the count, when more than MAX_BULK_MATCHING findings match.
    """
    matching = apply_filters(select(Finding.id), f)  # narrowed to the caller's teams by the filters
    total = db.scalar(select(func.count()).select_from(matching.subquery())) or 0
    if total > MAX_BULK_MATCHING:
        raise ValidationFailed(
            f"{total} findings match; narrow the filters to at most {MAX_BULK_MATCHING} "
            "to change them at once"
        )
    return _bulk(db, select(Finding).where(Finding.id.in_(matching)), body, user)


def _bulk(db: Session, stmt: Select, body: BulkChange, user: User) -> BulkResult:
    if body.is_empty():
        raise HTTPException(422, "Nothing to update")
    _check_due(body, user)
    findings = db.scalars(
        stmt.order_by(Finding.id)
        .with_for_update(of=Finding)
        .execution_options(populate_existing=True)
        .options(
            # Everything _apply reads per finding, loaded once for the batch rather than once per row.
            selectinload(Finding.asset),
            selectinload(Finding.links),
        )
    ).all()
    hooks: dict = {}  # webhook subscribers, looked up once per asset for the whole batch
    scopes = ScopeCache(db)
    updated = sum(1 for f in findings if _apply(db, f, body, user, hooks, scopes))
    db.commit()
    return BulkResult(updated=updated)


@router.post("/{finding_id}/comments", response_model=FindingEventOut, status_code=status.HTTP_201_CREATED)
def add_comment(
    finding_id: int,
    body: CommentCreate,
    user: User = Depends(triager),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    f = _load(db, finding_id, scope)
    ev = lifecycle.add_comment(db, f, body.text, actor=user)
    excerpt = " ".join(body.text.split())[:200]
    notifications.notify(
        db,
        notifications.mentioned(db, body.text),
        "mentioned",
        f,
        f'{user.full_name or user.email} mentioned you: "{excerpt}"',
        actor=user,
    )
    db.commit()
    db.refresh(ev)
    return ev


# ---- issue tracker tickets ----------------------------------------------------------------------


@router.get("/{finding_id}/trackers", response_model=list[IntegrationOut])
def list_trackers(
    finding_id: int,
    _: User = Depends(analyst),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    """Trackers a ticket can be opened in for this finding."""
    return tickets.available(db, _load(db, finding_id, scope).asset_id)


@router.post("/{finding_id}/ticket", response_model=FindingLinkOut, status_code=status.HTTP_201_CREATED)
def create_ticket(
    finding_id: int,
    body: TicketCreate,
    user: User = Depends(analyst),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    """Open a ticket for this finding and link it.

    Done in the request, not the worker, because whoever pressed the button is waiting for the link and
    needs to see the reason if the tracker refuses.
    """
    f = _load(db, finding_id, scope)
    options = tickets.available(db, f.asset_id)
    if not options:
        raise HTTPException(422, "No issue tracker is configured for this asset")
    if body.integration_id is not None:
        integration = next((i for i in options if i.id == body.integration_id), None)
        if integration is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Tracker not found for this asset")
    elif len(options) > 1:
        raise HTTPException(422, "Several trackers are available: choose one with integration_id")
    else:
        integration = options[0]

    existing = db.scalar(
        select(FindingLink).where(
            FindingLink.finding_id == f.id, FindingLink.integration_id == integration.id
        )
    )
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"Already linked to {existing.external_key}")

    # Hand the database connection back before calling the tracker, which may take up to
    # TRACKER_TIMEOUT. Holding it meant a few slow trackers could drain a worker's small pool and stall
    # every other request that worker served. Everything the ticket is built from is already loaded.
    db.commit()
    try:
        link = tickets.create_ticket(db, f, integration, user)
    except (TrackerError, ValueError) as exc:
        db.rollback()
        integration = db.get(Integration, integration.id)
        integration.last_error = str(exc)[:500]
        db.commit()
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc))

    lifecycle.add_comment(db, f, f"Ticket {link.external_key} opened: {link.url}", actor=user)
    db.commit()
    db.refresh(link)
    return link


@router.delete("/{finding_id}/ticket/{link_id}", status_code=status.HTTP_204_NO_CONTENT)
def unlink_ticket(
    finding_id: int,
    link_id: int,
    user: User = Depends(analyst),
    scope: Scope = Depends(get_scope),
    db: Session = Depends(get_db),
):
    """Forget a ticket. The ticket itself is left untouched in the tracker."""
    _load(db, finding_id, scope)  # 404 for a finding this person cannot see
    link = db.get(FindingLink, link_id)
    if link is None or link.finding_id != finding_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Link not found")
    db.delete(link)
    db.commit()
