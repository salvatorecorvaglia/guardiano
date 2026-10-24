"""Reusable query builders for findings (list, export, analytics)."""

from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import Select, and_, case, exists, false, func, literal, or_, select
from sqlalchemy.orm import Session, joinedload
from sqlalchemy.sql.elements import ColumnElement

from app.core.config import settings
from app.models import Asset, Finding, FindingLink, FindingScan, VulnIntel
from app.models.base import utcnow
from app.models.enums import ACTIVE_STATUSES, CRITICALITY_MULTIPLIER, SEVERITY_WEIGHT
from app.services import sla
from app.services.priority import priority_expr
from app.services.scope import Scope

ACTIVE = [s.value for s in ACTIVE_STATUSES]


def sla_due_expr(db: Session | None = None) -> ColumnElement:
    return sla.sla_due_expr(db=db)


def overdue_expr(now: datetime | None = None, *, db: Session | None = None) -> ColumnElement:
    # coalesce: severities without an SLA (info) are never overdue, rather than NULL (which NOT can't negate).
    return and_(Finding.status.in_(ACTIVE), func.coalesce(sla_due_expr(db) < (now or utcnow()), false()))


def severity_weight_expr() -> ColumnElement:
    weight = case(
        *[(Finding.severity == s, literal(w)) for s, w in SEVERITY_WEIGHT.items()], else_=literal(0.0)
    )
    return weight * exploitability_factor() if settings.risk_use_exploitability else weight


def kev_expr() -> ColumnElement:
    """True for a finding whose CVE is in CISA's Known Exploited Vulnerabilities catalogue."""
    return exists().where(VulnIntel.cve_id == Finding.cve_id, VulnIntel.in_kev.is_(True))


def _intel(column: ColumnElement) -> ColumnElement:
    """A finding's exploitability column, as a correlated subquery so no query grows a join."""
    return select(column).where(VulnIntel.cve_id == Finding.cve_id).correlate(Finding).scalar_subquery()


def exploitability_factor() -> ColumnElement:
    """Multiplies a finding's weight when the world says it is actually being exploited."""
    return case(
        (_intel(VulnIntel.in_kev).is_(True), literal(settings.kev_risk_multiplier)),
        (
            _intel(VulnIntel.epss) >= literal(settings.epss_risk_threshold),
            literal(settings.epss_risk_multiplier),
        ),
        else_=literal(1.0),
    )


def criticality_multiplier_expr() -> ColumnElement:
    return case(
        *[(Asset.criticality == c, literal(m)) for c, m in CRITICALITY_MULTIPLIER.items()], else_=literal(1.0)
    )


@dataclass
class FindingFilters:
    q: str | None = None
    severity: list[str] = field(default_factory=list)
    status: list[str] = field(default_factory=list)
    type: str | None = None
    asset_id: list[int] = field(default_factory=list)
    product_id: int | None = None
    environment: str | None = None
    tool: str | None = None
    tool_case_insensitive: bool = False  # triage matcher semantics; public list filters stay exact
    cwe: str | None = None
    cve: str | None = None
    package: str | None = None
    assignee_id: int | None = None
    unassigned: bool = False
    overdue: bool | None = None
    first_seen_from: datetime | None = None
    first_seen_to: datetime | None = None
    tag: list[str] = field(default_factory=list)
    kev: bool | None = None  # in CISA's Known Exploited Vulnerabilities catalogue
    epss_min: float | None = None
    ticket_done: bool | None = None  # a linked ticket the tracker now calls finished
    scan_id: int | None = None  # reported by this scan
    not_in_scan_id: int | None = None  # not reported by this scan (with scan_id: a scan diff)
    # Who is asking. Not a filter the caller chooses: it narrows every selection to the assets that
    # person may see (services/scope.py). Required, and keyword-only so it can be: a default here
    # would be the unsafe one, and omitting it leaks other teams' rows with nothing to notice.
    scope: Scope = field(kw_only=True)


def like_pattern(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped}%"


def apply_filters(stmt: Select, f: FindingFilters, db: Session | None = None) -> Select:
    stmt = f.scope.narrow(stmt, Finding.asset_id)
    if f.q and f.q.strip():
        q = f.q.strip()
        ts = func.websearch_to_tsquery("simple", q)
        pattern = like_pattern(q)
        stmt = stmt.where(
            or_(
                Finding.search_vector.op("@@")(ts),
                Finding.title.ilike(pattern),
                Finding.cve_id.ilike(pattern),
                Finding.vuln_id.ilike(pattern),
                Finding.package_name.ilike(pattern),
                Finding.file_path.ilike(pattern),
                Finding.rule_id.ilike(pattern),
            )
        )
    if f.severity:
        stmt = stmt.where(Finding.severity.in_(f.severity))
    if f.status:
        stmt = stmt.where(Finding.status.in_(f.status))
    if f.type:
        stmt = stmt.where(Finding.type == f.type)
    if f.asset_id:
        stmt = stmt.where(Finding.asset_id.in_(f.asset_id))
    if f.product_id is not None:
        stmt = stmt.where(Finding.asset_id.in_(select(Asset.id).where(Asset.product_id == f.product_id)))
    if f.environment:
        stmt = stmt.where(Finding.asset_id.in_(select(Asset.id).where(Asset.environment == f.environment)))
    if f.tool:
        if f.tool_case_insensitive:
            tools = func.unnest(Finding.tools).table_valued("name").render_derived()
            stmt = stmt.where(
                select(1).select_from(tools).where(func.lower(tools.c.name) == f.tool.lower()).exists()
            )
        else:
            stmt = stmt.where(Finding.tools.contains([f.tool]))
    if f.cwe:
        cwe = f.cwe.upper() if f.cwe.upper().startswith("CWE-") else f"CWE-{f.cwe}"
        stmt = stmt.where(Finding.cwe.contains([cwe]))
    if f.cve:
        stmt = stmt.where(Finding.cve_id.ilike(like_pattern(f.cve)))
    if f.package:
        stmt = stmt.where(Finding.package_name.ilike(like_pattern(f.package)))
    if f.unassigned:
        stmt = stmt.where(Finding.assignee_id.is_(None))
    elif f.assignee_id:
        stmt = stmt.where(Finding.assignee_id == f.assignee_id)
    if f.overdue is True:
        stmt = stmt.where(overdue_expr(db=db))
    elif f.overdue is False:
        stmt = stmt.where(~overdue_expr(db=db))
    if f.first_seen_from:
        stmt = stmt.where(Finding.first_seen_at >= f.first_seen_from)
    if f.first_seen_to:
        stmt = stmt.where(Finding.first_seen_at <= f.first_seen_to)
    if f.tag:
        stmt = stmt.where(Finding.tags.contains([t.strip().lower() for t in f.tag]))
    if f.kev is not None:
        known = kev_expr()
        stmt = stmt.where(known if f.kev else ~known)
    if f.epss_min is not None:
        stmt = stmt.where(exists().where(VulnIntel.cve_id == Finding.cve_id, VulnIntel.epss >= f.epss_min))
    if f.ticket_done is not None:
        finished = exists().where(
            FindingLink.finding_id == Finding.id, FindingLink.remote_done_at.is_not(None)
        )
        stmt = stmt.where(finished if f.ticket_done else ~finished)
    if f.scan_id is not None:
        stmt = stmt.where(_in_scan(f.scan_id))
    if f.not_in_scan_id is not None:
        stmt = stmt.where(~_in_scan(f.not_in_scan_id))
    return stmt


def _in_scan(scan_id: int) -> ColumnElement:
    return exists().where(FindingScan.finding_id == Finding.id, FindingScan.scan_id == scan_id)


SEVERITY_SORT = case(
    (Finding.severity == "critical", 4),
    (Finding.severity == "high", 3),
    (Finding.severity == "medium", 2),
    (Finding.severity == "low", 1),
    else_=0,
)

SORTS: dict[str, ColumnElement] = {
    "severity": SEVERITY_SORT,
    "first_seen": Finding.first_seen_at,
    "last_seen": Finding.last_seen_at,
    "title": Finding.title,
    "status": Finding.status,
    "cvss": Finding.cvss_score,
}


def findings_query(f: FindingFilters, sort: str = "-severity", db: Session | None = None) -> Select:
    stmt = select(Finding).options(
        joinedload(Finding.asset), joinedload(Finding.assignee), joinedload(Finding.intel)
    )
    stmt = apply_filters(stmt, f, db)
    desc = sort.startswith("-")
    key = sort.lstrip("-")
    # The due date depends on the current SLA policy, so it is built per query rather than in SORTS.
    if key == "due":
        col = sla_due_expr(db)
    elif key == "epss":
        col = _intel(VulnIntel.epss)
    elif key == "priority":
        col = priority_expr()  # built per query: it reads the exploitability settings
    else:
        col = SORTS.get(key, SEVERITY_SORT)
    order = col.desc().nulls_last() if desc else col.asc().nulls_last()
    return stmt.order_by(order, Finding.first_seen_at.desc(), Finding.id.desc())
