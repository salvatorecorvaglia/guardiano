"""The cumulative open-series must match the original day x finding join exactly."""

import random
from datetime import timedelta

import pytest
from sqlalchemy import text

from app.models import Asset, Finding
from app.models.base import utcnow
from app.services.analytics import SEVERITIES, open_series
from app.services.scope import GLOBAL

_REFERENCE_SQL = text(
    """
    WITH days AS (
        SELECT generate_series(CAST(:start AS date), CAST(:end AS date), interval '1 day')::date AS d
    )
    SELECT days.d AS day, f.severity AS severity, count(f.id) AS n
    FROM days
    LEFT JOIN findings f
      ON f.first_seen_at < (days.d + 1)
     AND (f.closed_at IS NULL OR f.closed_at >= (days.d + 1))
     AND (CAST(:asset_id AS integer) IS NULL OR f.asset_id = CAST(:asset_id AS integer))
    GROUP BY days.d, f.severity
    """
)


def _reference(db, start, end, asset_id):
    out = {start + timedelta(days=i): dict.fromkeys(SEVERITIES, 0) for i in range((end - start).days + 1)}
    for day, sev, n in db.execute(_REFERENCE_SQL, {"start": start, "end": end, "asset_id": asset_id}):
        if sev:
            out[day][sev] = n
    return [{"date": d.isoformat(), **c} for d, c in out.items()]


@pytest.fixture
def random_findings(db):
    rng = random.Random(42)
    assets = [Asset(name=f"a{i}", tags=[]) for i in range(3)]
    db.add_all(assets)
    db.flush()
    now = utcnow()
    for i in range(600):
        first = now - timedelta(days=rng.randint(0, 200), hours=rng.randint(0, 23))
        closed = None
        roll = rng.random()
        if roll < 0.5:
            closed = first + timedelta(days=rng.randint(0, 120), hours=rng.randint(0, 23))
            closed = min(closed, now)
        elif roll < 0.55:
            closed = first  # closed the same instant it was found
        db.add(
            Finding(
                asset_id=rng.choice(assets).id,
                type="sast",
                dedup_key=f"k{i}",
                title="t",
                severity=rng.choice(SEVERITIES),
                status="resolved" if closed else "open",
                cwe=[],
                tools=["x"],
                references=[],
                first_seen_at=first,
                last_seen_at=first,
                closed_at=closed,
            )
        )
    db.commit()
    return assets


@pytest.mark.parametrize("days", [7, 30, 90, 365])
def test_open_series_matches_reference(db, random_findings, days):
    end = utcnow().date()
    start = end - timedelta(days=days - 1)
    for asset_id in (None, random_findings[1].id):
        assert open_series(db, start, end, asset_id, scope=GLOBAL) == _reference(db, start, end, asset_id)


def test_summary_counts(db, random_findings):
    """Exact expectations computed in Python from the same rows."""
    from sqlalchemy import select

    from app.models.enums import Status
    from app.services.analytics import summary
    from app.services.queries import overdue_expr

    rows = db.scalars(select(Finding)).all()
    now = utcnow()
    # Mix in other statuses so every bucket is exercised.
    for f, st in zip(
        rows[:40], ["in_progress", "false_positive", "risk_accepted", "resolved"] * 10, strict=True
    ):
        f.status = st
        f.closed_at = f.closed_at or (now if st != "in_progress" else None)
    db.commit()

    for asset_id in (None, random_findings[0].id):
        scoped = [f for f in rows if asset_id is None or f.asset_id == asset_id]
        active = [f for f in scoped if f.status in ("open", "in_progress")]
        s = summary(db, asset_id, scope=GLOBAL)
        assert s["open_total"] == len(active)
        assert s["open_by_severity"] == {sev: sum(f.severity == sev for f in active) for sev in SEVERITIES}
        assert s["by_status"] == {st.value: sum(f.status == st.value for f in scoped) for st in Status}
        assert s["open_by_type"] == {"sast": len(active), "sca": 0, "iac": 0, "dast": 0}
        resolved = [f for f in scoped if f.status == "resolved" and f.closed_at]
        mttr = sum((f.closed_at - f.first_seen_at).total_seconds() / 86400 for f in resolved) / len(resolved)
        assert s["mttr_days_overall"] == round(mttr, 1)
        since = now - timedelta(days=30)
        assert s["new_last_30d"] == sum(f.first_seen_at >= since for f in scoped)
        assert s["resolved_last_30d"] == sum(f.status == "resolved" and f.closed_at >= since for f in scoped)
        q = select(Finding.id).where(overdue_expr(now))
        if asset_id:
            q = q.where(Finding.asset_id == asset_id)
        assert s["overdue"] == len(db.scalars(q).all())


def test_sparse_status_and_severity_timeline_matches_daily_snapshots(db):
    """Independent replay covers reopenings, same-time events, and carried-forward severity."""
    from datetime import UTC, datetime

    from app.models import FindingEvent

    rng = random.Random(51)
    start = datetime(2026, 1, 1, tzinfo=UTC)
    asset = Asset(name="timeline-snapshots")
    db.add(asset)
    db.flush()
    histories = []
    for index in range(30):
        status, severity = "open", "medium"
        history = [(start, status, severity)]
        row = Finding(
            asset_id=asset.id,
            dedup_key=f"history-{index}",
            title="History",
            type="sast",
            severity=severity,
            status=status,
            tools=["test"],
            first_seen_at=start,
        )
        db.add(row)
        db.flush()
        for step in range(20):
            at = start + timedelta(hours=6 * step)
            if rng.choice([True, False]):
                target = rng.choice(["open", "in_progress", "resolved", "false_positive", "risk_accepted"])
                db.add(
                    FindingEvent(
                        finding_id=row.id,
                        event="status_changed",
                        from_status=status,
                        to_status=target,
                        created_at=at,
                    )
                )
                status = target
            else:
                target = rng.choice(SEVERITIES)
                db.add(
                    FindingEvent(
                        finding_id=row.id,
                        event="severity_changed",
                        from_severity=severity,
                        to_severity=target,
                        created_at=at,
                    )
                )
                severity = target
            history.append((at, status, severity))
        row.status, row.severity = status, severity
        histories.append(history)
    db.commit()
    expected = []
    for day in range(7):
        current = start.date() + timedelta(days=day)
        counts = dict.fromkeys(SEVERITIES, 0)
        for history in histories:
            _, status, severity = [event for event in history if event[0].date() <= current][-1]
            if status in ("open", "in_progress"):
                counts[severity] += 1
        expected.append({"date": current.isoformat(), **counts})
    assert open_series(db, start.date(), start.date() + timedelta(days=6), asset.id, scope=GLOBAL) == expected
