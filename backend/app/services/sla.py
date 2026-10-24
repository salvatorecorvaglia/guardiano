"""Remediation SLA resolution.

The number of days a finding has to be fixed is resolved in this order:

1. ``findings.due_at_override`` (a manager-set deadline) replaces the computed due date entirely.
2. An ``sla_policies`` row for the finding's severity and its asset's criticality.
3. An ``sla_policies`` row for the severity with ``criticality = "any"``.
4. The ``SLA_*_DAYS`` environment settings.

Policies are few (at most severities x criticalities), so the effective policy is cached per process for
only ``_TTL`` seconds and invalidated by the process that edits it. Other workers (gunicorn processes,
replicas) pick up a change within the TTL; reloading a handful of rows that often costs next to nothing.

Without policy rows the SQL built here is the same severity CASE as before policies existed, and the asset
criticality lookup (a correlated subquery, so it is safe in queries that select only from ``findings``) is
only added when a criticality-specific policy exists.
"""

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import and_, case, func, literal, select
from sqlalchemy.orm import Session, object_session
from sqlalchemy.sql.elements import ColumnElement

from app.core.config import settings
from app.core.db import SessionLocal
from app.models import Asset, Finding, SlaPolicy
from app.models.enums import ANY_CRITICALITY

SLA_SEVERITIES = ("critical", "high", "medium", "low")  # info findings never have an SLA
_TTL = 5.0


@dataclass(frozen=True)
class EffectivePolicy:
    # (severity, criticality or "any") -> days; "any" rows always exist for every SLA severity.
    days: dict[tuple[str, str], int] = field(default_factory=dict)

    @property
    def by_criticality(self) -> bool:
        return any(c != ANY_CRITICALITY for _, c in self.days)

    def default_days(self) -> dict[str, int]:
        return {s: self.days[(s, ANY_CRITICALITY)] for s in SLA_SEVERITIES}

    def days_for(self, severity: str, criticality: str | None) -> int | None:
        return self.days.get((severity, criticality or "")) or self.days.get((severity, ANY_CRITICALITY))


def build_policy(rows: list[tuple[str, str, int]]) -> EffectivePolicy:
    days = {(s, ANY_CRITICALITY): d for s, d in settings.sla_days.items() if s in SLA_SEVERITIES}
    days.update({(s, c): d for s, c, d in rows if s in SLA_SEVERITIES})
    return EffectivePolicy(days)


def load_policy(db: Session) -> EffectivePolicy:
    rows = db.execute(select(SlaPolicy.severity, SlaPolicy.criticality, SlaPolicy.days)).all()
    return build_policy(list(rows))


_lock = threading.Lock()
_cached: tuple[float, EffectivePolicy] | None = None


def get_policy(db: Session | None = None) -> EffectivePolicy:
    global _cached
    with _lock:
        if _cached is not None and time.monotonic() - _cached[0] < _TTL:
            return _cached[1]
        # Single flight, using the caller's connection when it already holds one.
        # Opening a second connection per cache miss can exhaust the request pool.
        if db is not None:
            policy = load_policy(db)
        else:
            with SessionLocal() as session:
                policy = load_policy(session)
        _cached = (time.monotonic(), policy)
        return policy


def invalidate() -> None:
    global _cached
    with _lock:
        _cached = None


def sla_days_expr(policy: EffectivePolicy | None = None, db: Session | None = None) -> ColumnElement:
    """SLA length in days for each finding row, NULL for severities without an SLA."""
    p = policy or get_policy(db)
    whens = []
    if p.by_criticality:
        criticality = (
            select(Asset.criticality).where(Asset.id == Finding.asset_id).correlate(Finding).scalar_subquery()
        )
        whens += [
            (and_(Finding.severity == s, criticality == c), literal(d))
            for (s, c), d in sorted(p.days.items())
            if c != ANY_CRITICALITY
        ]
    whens += [(Finding.severity == s, literal(d)) for s, d in p.default_days().items()]
    return case(*whens, else_=literal(None))


def sla_due_expr(policy: EffectivePolicy | None = None, db: Session | None = None) -> ColumnElement:
    computed = Finding.first_seen_at + func.make_interval(0, 0, 0, sla_days_expr(policy, db))
    return func.coalesce(Finding.due_at_override, computed)


def due_at(f: Finding, policy: EffectivePolicy | None = None) -> datetime | None:
    """Python twin of ``sla_due_expr`` for serialisation; must agree with it (tests/test_sla.py)."""
    if f.due_at_override is not None:
        return f.due_at_override
    p = policy or get_policy(object_session(f))
    # Only touch the asset relationship when it matters, so serialising stays free of extra loads.
    days = p.days_for(f.severity, f.asset.criticality if p.by_criticality else None)
    return f.first_seen_at + timedelta(days=days) if days is not None else None
