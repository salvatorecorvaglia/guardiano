from datetime import UTC, date, datetime, timedelta
from typing import Any

from sqlalchemy import Integer, and_, cast, func, literal_column, or_, select, text
from sqlalchemy.orm import Session, aliased

from app.models import Asset, Component, Finding, FindingEvent, Product, Scan, Team
from app.models.base import utcnow
from app.models.enums import SCAN_TYPES, SEVERITY_ORDER, Status
from app.services import compliance, sla
from app.services.queries import (
    ACTIVE,
    criticality_multiplier_expr,
    kev_expr,
    overdue_expr,
    severity_weight_expr,
)
from app.services.scope import Scope

SEVERITIES = [s.value for s in SEVERITY_ORDER]


def _kev_expr():
    """Active findings whose CVE is in CISA's exploited catalogue."""
    return kev_expr()


def _scoped(stmt, asset_id: int | None, scope: Scope):
    """Narrow to one asset if asked, and always to the assets the viewer may see."""
    if asset_id:
        stmt = stmt.where(Finding.asset_id == asset_id)
    return scope.narrow(stmt, Finding.asset_id)


def summary(db: Session, asset_id: int | None = None, *, scope: Scope) -> dict[str, Any]:
    now = utcnow()
    since = now - timedelta(days=30)
    active = Finding.status.in_(ACTIVE)
    resolved = and_(Finding.status == Status.resolved.value, Finding.closed_at.is_not(None))
    days_expr = func.extract("epoch", Finding.closed_at - Finding.first_seen_at) / 86400.0
    statuses = [s.value for s in Status]

    # One pass over findings: every figure is a filtered aggregate.
    cols = {
        **{f"open_{sev}": func.count().filter(active, Finding.severity == sev) for sev in SEVERITIES},
        **{f"status_{st}": func.count().filter(Finding.status == st) for st in statuses},
        **{f"type_{t}": func.count().filter(active, Finding.type == t) for t in SCAN_TYPES},
        **{
            f"mttr_{sev}": func.avg(days_expr).filter(resolved, Finding.severity == sev) for sev in SEVERITIES
        },
        "mttr": func.avg(days_expr).filter(resolved),
        "overdue": func.count().filter(overdue_expr(now, db=db)),
        "kev": func.count().filter(active, _kev_expr()),
        "new_30d": func.count().filter(Finding.first_seen_at >= since),
        "resolved_30d": func.count().filter(
            Finding.status == Status.resolved.value, Finding.closed_at >= since
        ),
    }
    r = db.execute(_scoped(select(*[c.label(k) for k, c in cols.items()]), asset_id, scope)).mappings().one()

    def days(v: Any) -> float | None:
        return round(float(v), 1) if v is not None else None

    open_by_sev = {sev: r[f"open_{sev}"] for sev in SEVERITIES}
    # Previews are excluded: they report what a branch would add without ingesting anything.
    scan_q = select(func.count()).select_from(Scan).where(Scan.created_at >= since, Scan.source != "preview")
    if asset_id:
        scan_q = scan_q.where(Scan.asset_id == asset_id)
    scan_q = scope.narrow(scan_q, Scan.asset_id)

    return {
        "open_total": sum(open_by_sev.values()),
        "open_by_severity": open_by_sev,
        "by_status": {st: r[f"status_{st}"] for st in statuses},
        "open_by_type": {t: r[f"type_{t}"] for t in SCAN_TYPES},
        "overdue": r["overdue"],
        "known_exploited": r["kev"],
        "mttr_days": {sev: days(r[f"mttr_{sev}"]) for sev in SEVERITIES},
        "mttr_days_overall": days(r["mttr"]),
        "new_last_30d": r["new_30d"],
        "resolved_last_30d": r["resolved_30d"],
        "scans_last_30d": db.scalar(scan_q) or 0,
        "assets_total": db.scalar(select(func.count()).select_from(Asset).where(scope.assets())) or 0,
    }


# Status and severity intervals keep past closures intact when a finding later reopens.
# Intersect status and severity intervals: two ordered streams avoid re-sorting carried window groups.
_OPEN_DELTAS_SQL = text(
    """
    WITH scoped AS MATERIALIZED (
        SELECT id, severity, first_seen_at, closed_at FROM findings
        WHERE (CAST(:asset_id AS integer) IS NULL OR asset_id = CAST(:asset_id AS integer))
          AND (CAST(:unscoped AS boolean) OR asset_id IN (
            SELECT id FROM assets WHERE team_id IS NULL OR team_id = ANY(CAST(:team_ids AS integer[]))))
          AND first_seen_at::date <= CAST(:end AS date)
    ), history AS MATERIALIZED (
        SELECT e.finding_id, e.id, e.created_at, e.from_status, e.to_status,
               e.from_severity, e.to_severity
        FROM finding_events e JOIN scoped f ON f.id = e.finding_id
        WHERE e.to_status IS NOT NULL OR e.to_severity IS NOT NULL OR e.from_severity IS NOT NULL
    ), first_status AS (
        SELECT DISTINCT ON (finding_id) finding_id, from_status FROM history
        WHERE to_status IS NOT NULL ORDER BY finding_id, created_at, id
    ), first_severity AS (
        SELECT DISTINCT ON (finding_id) finding_id, from_severity FROM history
        WHERE from_severity IS NOT NULL ORDER BY finding_id, created_at, id
    ), f AS MATERIALIZED (
        SELECT scoped.*, COALESCE(s.from_status, 'open') AS initial_status,
          COALESCE(v.from_severity, scoped.severity) AS initial_severity,
          s.finding_id IS NOT NULL AS has_status_history
        FROM scoped LEFT JOIN first_status s ON s.finding_id = scoped.id
          LEFT JOIN first_severity v ON v.finding_id = scoped.id
    ), status_timeline AS (
        SELECT id AS finding_id, first_seen_at AS at, -1 AS seq, initial_status AS status FROM f
        UNION ALL
        SELECT finding_id, created_at, id, to_status FROM history WHERE to_status IS NOT NULL
        UNION ALL
        SELECT id, closed_at, 2147483647, 'resolved' FROM f
        WHERE closed_at IS NOT NULL AND NOT has_status_history
    ), severity_timeline AS (
        SELECT id AS finding_id, first_seen_at AS at, -1 AS seq, initial_severity AS severity FROM f
        UNION ALL
        SELECT finding_id, created_at, id, to_severity FROM history WHERE to_severity IS NOT NULL
    ), status_intervals AS (
        SELECT *, LEAD(at) OVER (PARTITION BY finding_id ORDER BY at, seq) AS until FROM status_timeline
    ), severity_intervals AS (
        SELECT *, LEAD(at) OVER (PARTITION BY finding_id ORDER BY at, seq) AS until FROM severity_timeline
    ), intervals AS (
        SELECT v.severity, GREATEST(s.at, v.at) AS at, LEAST(s.until, v.until) AS until
        FROM status_intervals s JOIN severity_intervals v USING (finding_id)
        WHERE s.status IN ('open', 'in_progress')
          AND (s.until IS NULL OR v.at < s.until)
          AND (v.until IS NULL OR s.at < v.until)
    ), ev AS (
        SELECT severity, at::date AS day, 1 AS delta FROM intervals
        WHERE at::date <= CAST(:end AS date)
        UNION ALL
        SELECT severity, until::date, -1 FROM intervals
        WHERE until::date <= CAST(:end AS date)
    )
    SELECT GREATEST(day, CAST(:start AS date)) AS day, severity, SUM(delta) AS n
    FROM ev GROUP BY 1, 2
    """
)


def open_series(
    db: Session, start: date, end: date, asset_id: int | None = None, *, scope: Scope
) -> list[dict[str, Any]]:
    """Daily count of open findings per severity for every day in [start, end]."""
    deltas: dict[date, dict[str, int]] = {}
    params = {
        "start": start,
        "end": end,
        "asset_id": asset_id,
        "unscoped": scope.unrestricted,
        "team_ids": list(scope.team_ids or ()),
    }
    for day, sev, n in db.execute(_OPEN_DELTAS_SQL, params):
        if sev in SEVERITIES:
            deltas.setdefault(day, dict.fromkeys(SEVERITIES, 0))[sev] += int(n)
    running = dict.fromkeys(SEVERITIES, 0)
    out = []
    for i in range((end - start).days + 1):
        day = start + timedelta(days=i)
        for sev, n in deltas.get(day, {}).items():
            running[sev] += n
        out.append({"date": day.isoformat(), **running})
    return out


def trends(db: Session, days: int = 90, asset_id: int | None = None, *, scope: Scope) -> dict[str, Any]:
    today = utcnow().date()
    start = today - timedelta(days=days - 1)
    series = open_series(db, start, today, asset_id, scope=scope)

    bucket = "day" if days <= 31 else "week"
    start_dt = datetime.combine(start, datetime.min.time(), tzinfo=UTC)

    def bucketed(col) -> Any:
        return func.date_trunc(bucket, col).label("b")

    flow: dict[str, dict[str, Any]] = {}

    def add(rows, key: str) -> None:
        for b, n in rows:
            k = b.date().isoformat()
            flow.setdefault(k, {"period": k, "new": 0, "closed": 0})[key] += n

    new_q = _scoped(
        select(bucketed(Finding.first_seen_at), func.count()).where(Finding.first_seen_at >= start_dt),
        asset_id,
        scope,
    ).group_by(literal_column("b"))
    closed_q = _scoped(
        select(bucketed(FindingEvent.created_at), func.count())
        .join(Finding, Finding.id == FindingEvent.finding_id)
        .where(
            FindingEvent.created_at >= start_dt,
            FindingEvent.to_status.in_(["resolved", "false_positive", "risk_accepted"]),
            or_(FindingEvent.from_status.is_(None), FindingEvent.from_status.in_(ACTIVE)),
        ),
        asset_id,
        scope,
    ).group_by(literal_column("b"))
    legacy_closed_q = _scoped(
        select(bucketed(Finding.closed_at), func.count()).where(
            Finding.closed_at >= start_dt,
            ~select(FindingEvent.id)
            .where(
                FindingEvent.finding_id == Finding.id,
                FindingEvent.to_status.in_(["resolved", "false_positive", "risk_accepted"]),
            )
            .exists(),
        ),
        asset_id,
        scope,
    ).group_by(literal_column("b"))
    # Zero-fill every bucket in the range so periods without activity still appear on the time axis.
    period = timedelta(days=1 if bucket == "day" else 7)
    b = start if bucket == "day" else start - timedelta(days=start.weekday())  # date_trunc('week') = Monday
    while b <= today:
        flow[b.isoformat()] = {"period": b.isoformat(), "new": 0, "closed": 0}
        b += period
    add(db.execute(new_q), "new")
    add(db.execute(closed_q), "closed")
    add(db.execute(legacy_closed_q), "closed")

    structured = aliased(FindingEvent)
    same_time_structured = (
        select(structured.id)
        .where(
            structured.finding_id == FindingEvent.finding_id,
            structured.created_at == FindingEvent.created_at,
            structured.from_severity.is_not(None),
        )
        .exists()
    )
    history_complete = not db.scalar(
        _scoped(
            select(FindingEvent.id)
            .join(Finding, Finding.id == FindingEvent.finding_id)
            .where(
                or_(
                    (FindingEvent.event == "severity_changed") & FindingEvent.from_severity.is_(None),
                    (FindingEvent.event == "rule_applied")
                    & FindingEvent.comment.contains("severity ")
                    & ~same_time_structured,
                )
            )
            .limit(1),
            asset_id,
            scope,
        )
    )
    return {
        "severity_history_complete": history_complete,
        "days": days,
        "bucket": bucket,
        "open_by_severity": series,
        "new_vs_closed": sorted(flow.values(), key=lambda r: r["period"]),
    }


def top_assets(
    db: Session, limit: int = 10, *, scope: Scope, product_id: int | None = None
) -> list[dict[str, Any]]:
    score = (func.sum(severity_weight_expr()) * criticality_multiplier_expr()).label("score")
    stmt = (
        select(
            Asset.id,
            Asset.name,
            Asset.criticality,
            score,
            func.count(Finding.id).label("open"),
            *[
                func.sum(cast(Finding.severity == s, Integer)).label(s)
                for s in ("critical", "high", "medium", "low")
            ],
        )
        .join(Finding, Finding.asset_id == Asset.id)
        .where(Finding.status.in_(ACTIVE), scope.assets())
        .group_by(Asset.id)
        .order_by(score.desc())
        .limit(limit)
    )
    if product_id is not None:
        stmt = stmt.where(Asset.product_id == product_id)
    return [
        {
            "id": r.id,
            "name": r.name,
            "criticality": r.criticality,
            "risk_score": round(float(r.score or 0), 1),
            "open": r.open,
            "critical": r.critical or 0,
            "high": r.high or 0,
            "medium": r.medium or 0,
            "low": r.low or 0,
        }
        for r in db.execute(stmt)
    ]


def top_cwes(
    db: Session, limit: int = 10, asset_id: int | None = None, *, scope: Scope
) -> list[dict[str, Any]]:
    cwe = func.unnest(Finding.cwe).label("cwe")
    inner = _scoped(select(cwe).where(Finding.status.in_(ACTIVE)), asset_id, scope).subquery()
    stmt = (
        select(inner.c.cwe, func.count().label("n"))
        .group_by(inner.c.cwe)
        .order_by(func.count().desc())
        .limit(limit)
    )
    return [{"cwe": r.cwe, "count": r.n} for r in db.execute(stmt)]


def top_packages(
    db: Session, limit: int = 10, asset_id: int | None = None, *, scope: Scope
) -> list[dict[str, Any]]:
    stmt = _scoped(
        select(
            Finding.package_name,
            Finding.ecosystem,
            func.count().label("n"),
            func.count(func.distinct(Finding.asset_id)).label("assets"),
            func.sum(cast(Finding.severity.in_(["critical", "high"]), Integer)).label("crit_high"),
        ).where(Finding.type == "sca", Finding.status.in_(ACTIVE), Finding.package_name.is_not(None)),
        asset_id,
        scope,
    )
    stmt = (
        stmt.group_by(Finding.package_name, Finding.ecosystem)
        .order_by(literal_column("crit_high").desc(), literal_column("n").desc())
        .limit(limit)
    )
    return [
        {
            "package": r.package_name,
            "ecosystem": r.ecosystem,
            "count": r.n,
            "assets": r.assets,
            "critical_high": r.crit_high or 0,
        }
        for r in db.execute(stmt)
    ]


def _overlaps(cwes: frozenset[str] | set[str]):
    """True when a finding carries any of these CWEs.

    Postgres array overlap (``&&``), so this is one indexable predicate rather than a join or an unnest.
    The comparator comes from the column itself, which types the parameter as ``varchar[]`` to match.
    """
    return Finding.cwe.overlap(sorted(cwes))


def owasp_breakdown(db: Session, asset_id: int | None = None, *, scope: Scope) -> dict[str, Any]:
    """Open findings per OWASP Top 10 category, in one pass over the findings."""
    active = Finding.status.in_(ACTIVE)
    cols: dict[str, Any] = {}
    for category in compliance.OWASP_TOP_10:
        hit = _overlaps(category.cwes)
        cols[f"{category.id}_n"] = func.count().filter(active, hit)
        cols[f"{category.id}_s"] = func.count().filter(
            active, hit, Finding.severity.in_(("critical", "high"))
        )
    cols["mapped"] = func.count().filter(active, _overlaps(compliance.ALL_MAPPED_CWES))
    cols["total"] = func.count().filter(active)
    r = db.execute(_scoped(select(*[c.label(k) for k, c in cols.items()]), asset_id, scope)).mappings().one()

    return {
        "edition": compliance.OWASP_EDITION,
        "categories": [
            {
                "id": c.id,
                "title": c.title,
                "open": r[f"{c.id}_n"],
                "critical_high": r[f"{c.id}_s"],
            }
            for c in compliance.OWASP_TOP_10
        ],
        "open_total": r["total"],
        "mapped": r["mapped"],
        "unmapped": r["total"] - r["mapped"],
    }


def cwe_top_25(db: Session, asset_id: int | None = None, *, scope: Scope) -> list[dict[str, Any]]:
    """The weaknesses from the CWE Top 25 that are actually open here, worst rank first."""
    listed = sorted(compliance.TOP_25_RANK)
    cwe = func.unnest(Finding.cwe).label("cwe")
    inner = _scoped(
        select(cwe, Finding.severity.label("severity")).where(
            Finding.status.in_(ACTIVE), _overlaps(set(listed))
        ),
        asset_id,
        scope,
    ).subquery()
    rows = db.execute(
        select(
            inner.c.cwe,
            func.count().label("n"),
            func.count().filter(inner.c.severity.in_(("critical", "high"))).label("s"),
        )
        .where(inner.c.cwe.in_(listed))  # a finding may also carry CWEs that are not on the list
        .group_by(inner.c.cwe)
    )
    found = {r.cwe: (r.n, r.s) for r in rows}
    return [
        {
            "rank": rank,
            "cwe": cwe_id,
            "name": name,
            "open": found.get(cwe_id, (0, 0))[0],
            "critical_high": found.get(cwe_id, (0, 0))[1],
        }
        for rank, cwe_id, name in compliance.CWE_TOP_25
    ]


def sla_performance(
    db: Session, days: int = 90, asset_id: int | None = None, *, scope: Scope
) -> dict[str, Any]:
    """Two honest SLA numbers, per severity and overall.

    *Open within SLA* is where the estate stands right now. *Resolved on time* is how it was actually
    worked over the window: a finding closed after its due date is late, however green the first number
    looks today. Findings with no SLA (``info``, or a severity with no policy) are excluded from both
    rather than counted as compliant.
    """
    now = utcnow()
    since = now - timedelta(days=days)
    due = sla.sla_due_expr(db=db)
    has_sla = due.is_not(None)
    active = and_(Finding.status.in_(ACTIVE), has_sla)
    closed = and_(
        Finding.status == Status.resolved.value, Finding.closed_at >= since, Finding.closed_at.is_not(None)
    )

    def pct(ok: int, total: int) -> float | None:
        return round(100.0 * ok / total, 1) if total else None

    cols: dict[str, Any] = {}
    for sev in SEVERITIES:
        at = Finding.severity == sev
        cols[f"open_{sev}"] = func.count().filter(active, at)
        cols[f"ontrack_{sev}"] = func.count().filter(active, at, due >= now)
        cols[f"closed_{sev}"] = func.count().filter(closed, has_sla, at)
        cols[f"intime_{sev}"] = func.count().filter(closed, has_sla, at, Finding.closed_at <= due)
    r = db.execute(_scoped(select(*[c.label(k) for k, c in cols.items()]), asset_id, scope)).mappings().one()

    rows = []
    for sev in SEVERITIES:
        if r[f"open_{sev}"] or r[f"closed_{sev}"]:
            rows.append(
                {
                    "severity": sev,
                    "open": r[f"open_{sev}"],
                    "within_sla": r[f"ontrack_{sev}"],
                    "within_sla_pct": pct(r[f"ontrack_{sev}"], r[f"open_{sev}"]),
                    "resolved": r[f"closed_{sev}"],
                    "resolved_on_time": r[f"intime_{sev}"],
                    "resolved_on_time_pct": pct(r[f"intime_{sev}"], r[f"closed_{sev}"]),
                }
            )
    open_total = sum(r[f"open_{s}"] for s in SEVERITIES)
    within = sum(r[f"ontrack_{s}"] for s in SEVERITIES)
    resolved = sum(r[f"closed_{s}"] for s in SEVERITIES)
    in_time = sum(r[f"intime_{s}"] for s in SEVERITIES)
    return {
        "days": days,
        "by_severity": rows,
        "open": open_total,
        "within_sla": within,
        "within_sla_pct": pct(within, open_total),
        "resolved": resolved,
        "resolved_on_time": in_time,
        "resolved_on_time_pct": pct(in_time, resolved),
    }


def mttr_trend(
    db: Session, days: int = 90, asset_id: int | None = None, *, scope: Scope
) -> list[dict[str, Any]]:
    """Mean time to remediate, per period, for findings closed in that period.

    The count travels with each point: a two-day average over one finding is noise, and a reader who
    cannot see that is being misled by a flattering line.
    """
    today = utcnow().date()
    start = today - timedelta(days=days - 1)
    start_dt = datetime.combine(start, datetime.min.time(), tzinfo=UTC)
    bucket = "day" if days <= 31 else "week"
    elapsed = func.extract("epoch", Finding.closed_at - Finding.first_seen_at) / 86400.0

    rows = db.execute(
        _scoped(
            select(
                func.date_trunc(bucket, Finding.closed_at).label("b"),
                func.avg(elapsed).label("mttr"),
                func.count().label("n"),
            ).where(Finding.status == Status.resolved.value, Finding.closed_at >= start_dt),
            asset_id,
            scope,
        )
        .group_by(literal_column("b"))
        .order_by(literal_column("b"))
    )
    return [
        {"period": r.b.date().isoformat(), "days": round(float(r.mttr), 1), "resolved": r.n} for r in rows
    ]


# How many uncovered assets coverage() lists; the counts always cover every asset.
COVERAGE_LIST_LIMIT = 200


def coverage(db: Session, stale_days: int, *, scope: Scope) -> dict[str, Any]:
    """Which assets are scanned, and how recently. A finding count of zero means nothing on an asset
    nobody scans, so this is the other half of every figure on the dashboard.

    Preview scans do not count: they leave the inventory as it was. An asset is *stale* when its newest
    real scan is older than ``stale_days``, and *never scanned* when it has none.
    """
    scanned = (
        select(
            Scan.asset_id,
            func.max(Scan.created_at).label("last_scan_at"),
            func.max(Scan.created_at).filter(Scan.scan_type == "sast").label("last_sast_at"),
            func.max(Scan.created_at).filter(Scan.scan_type == "sca").label("last_sca_at"),
        )
        .where(Scan.source != "preview", scope.where(Scan.asset_id))
        .group_by(Scan.asset_id)
        .subquery()
    )
    has_sbom = select(Component.id).where(Component.asset_id == Asset.id).correlate(Asset).exists()
    rows = db.execute(
        select(
            Asset.id,
            Asset.name,
            Asset.criticality,
            scanned.c.last_scan_at,
            scanned.c.last_sast_at,
            scanned.c.last_sca_at,
            has_sbom.label("has_sbom"),
        )
        .outerjoin(scanned, scanned.c.asset_id == Asset.id)
        .where(scope.assets())
    ).all()

    cutoff = utcnow() - timedelta(days=stale_days)
    never = [r for r in rows if r.last_scan_at is None]
    stale = [r for r in rows if r.last_scan_at is not None and r.last_scan_at < cutoff]
    # Never-scanned first, then the longest-unscanned; the most critical first within each.
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    uncovered = sorted(never, key=lambda r: (rank.get(r.criticality, 4), r.name.lower())) + sorted(
        stale, key=lambda r: (r.last_scan_at, rank.get(r.criticality, 4))
    )
    return {
        "stale_days": stale_days,
        "assets": len(rows),
        "covered": len(rows) - len(never) - len(stale),
        "stale": len(stale),
        "never_scanned": len(never),
        "without_sast": sum(1 for r in rows if r.last_sast_at is None),
        "without_sca": sum(1 for r in rows if r.last_sca_at is None),
        "uncovered": [
            {
                "id": r.id,
                "name": r.name,
                "criticality": r.criticality,
                "last_scan_at": r.last_scan_at,
                "last_sast_at": r.last_sast_at,
                "last_sca_at": r.last_sca_at,
                "has_sbom": bool(r.has_sbom),
            }
            for r in uncovered[:COVERAGE_LIST_LIMIT]
        ],
    }


BREAKDOWNS = ("product", "team", "environment", "tool")


def breakdown(db: Session, by: str, days: int = 90, *, scope: Scope) -> list[dict[str, Any]]:
    """The estate split by product, team, environment or scanner, one row per group.

    Per group: what is open (and how much of it critical/high or past its SLA), active risk
    acceptances, what was resolved in the last ``days`` and how long that took (MTTR), and the median
    time from a finding appearing to a person first acting on it (a status change, an assignment or a
    comment): how quickly new findings get looked at. By tool, open findings are also split into those
    only that tool reports and those another tool reports too.
    """
    now = utcnow()
    since = now - timedelta(days=days)
    active = Finding.status.in_(ACTIVE)
    resolved = and_(Finding.status == Status.resolved.value, Finding.closed_at >= since)
    first_touch = (
        select(FindingEvent.finding_id, func.min(FindingEvent.created_at).label("at"))
        .where(
            FindingEvent.actor_id.is_not(None),
            FindingEvent.finding_id.in_(
                scope.narrow(select(Finding.id).where(Finding.first_seen_at >= since), Finding.asset_id)
            ),
        )
        .group_by(FindingEvent.finding_id)
        .subquery()
    )
    triage_hours = func.extract("epoch", first_touch.c.at - Finding.first_seen_at) / 3600.0
    metrics = [
        func.count().filter(active).label("open"),
        func.count().filter(active, Finding.severity.in_(("critical", "high"))).label("critical_high"),
        func.count().filter(overdue_expr(now, db=db)).label("overdue"),
        func.count().filter(Finding.status == Status.risk_accepted.value).label("accepted"),
        func.count().filter(resolved).label("resolved"),
        (
            func.avg(func.extract("epoch", Finding.closed_at - Finding.first_seen_at)).filter(resolved)
            / 86400.0
        ).label("mttr_days"),
        func.percentile_cont(0.5)
        .within_group(triage_hours)
        .filter(Finding.first_seen_at >= since, first_touch.c.at.is_not(None))
        .label("triage_hours"),
    ]
    if by == "tool":
        tool = func.unnest(Finding.tools).table_valued("name").render_derived()
        key = tool.c.name
        many = func.cardinality(Finding.tools) > 1
        stmt = (
            select(
                key.label("key"),
                *metrics,
                func.count().filter(active, ~many).label("unique_open"),
                func.count().filter(active, many).label("shared_open"),
            )  # fmt: skip
            .select_from(Finding)
            .join(tool, literal_column("true"))
        )
        labels: dict[Any, str] = {}
    else:
        column = {"product": Asset.product_id, "team": Asset.team_id, "environment": Asset.environment}[by]
        key = column
        stmt = select(key.label("key"), *metrics).select_from(Finding)
        stmt = stmt.join(Asset, Asset.id == Finding.asset_id)
        model = {"product": Product, "team": Team}.get(by)
        labels = dict(db.execute(select(model.id, model.name)).all()) if model is not None else {}
    stmt = scope.narrow(stmt.outerjoin(first_touch, first_touch.c.finding_id == Finding.id), Finding.asset_id)
    rows = db.execute(stmt.group_by(key).order_by(literal_column("open").desc())).mappings().all()
    none_label = {"product": "No product", "team": "No team", "environment": "Not set", "tool": "?"}[by]
    out = []
    for r in rows:
        out.append(
            {
                "key": None if r["key"] is None else str(r["key"]),
                "label": labels.get(r["key"], r["key"]) if r["key"] is not None else none_label,
                "open": r["open"],
                "critical_high": r["critical_high"],
                "overdue": r["overdue"],
                "accepted": r["accepted"],
                "resolved": r["resolved"],
                "mttr_days": round(float(r["mttr_days"]), 1) if r["mttr_days"] is not None else None,
                "median_triage_hours": (
                    round(float(r["triage_hours"]), 1) if r["triage_hours"] is not None else None
                ),
                "unique_open": r.get("unique_open"),
                "shared_open": r.get("shared_open"),
            }
        )
    return out
