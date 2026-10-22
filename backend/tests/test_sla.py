"""SLA policies: SQL/Python parity, criticality overrides, due-date overrides and the /sla API."""

import random
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from app.models import Asset, AuditLog, Finding, SlaPolicy
from app.models.base import utcnow
from app.services import sla
from app.services.analytics import summary
from app.services.queries import overdue_expr
from app.services.scope import GLOBAL

SEVERITIES = ["critical", "high", "medium", "low", "info"]


@pytest.fixture
def findings(db):
    rng = random.Random(7)
    assets = [Asset(name=f"a-{c}", criticality=c, tags=[]) for c in ("low", "medium", "high", "critical")]
    db.add_all(assets)
    db.flush()
    now = utcnow()
    for i in range(300):
        first = now - timedelta(days=rng.randint(0, 200))
        db.add(
            Finding(
                asset_id=rng.choice(assets).id,
                type="sast",
                dedup_key=f"k{i}",
                title="t",
                severity=rng.choice(SEVERITIES),
                status=rng.choice(["open", "in_progress", "resolved"]),
                cwe=[],
                tools=["x"],
                references=[],
                first_seen_at=first,
                last_seen_at=first,
                # A handful of manual deadlines, some past and some future.
                due_at_override=now + timedelta(days=rng.randint(-30, 30)) if i % 17 == 0 else None,
            )
        )
    db.commit()
    return assets


def _set_policies(db, rows):
    db.query(SlaPolicy).delete()
    db.add_all(SlaPolicy(severity=s, criticality=c, days=d) for s, c, d in rows)
    db.commit()
    sla.invalidate()


def _assert_parity(db):
    rows = db.scalars(select(Finding)).all()
    due_sql = dict(db.execute(select(Finding.id, sla.sla_due_expr())).all())
    for f in rows:
        assert due_sql[f.id] == sla.due_at(f), (f.id, f.severity, f.asset.criticality)
    # The overdue aggregate must count each finding once: the criticality lookup is a correlated subquery,
    # not a join, so selecting only from findings cannot turn into a cross join with assets.
    now = utcnow()
    active = [f for f in rows if f.status in ("open", "in_progress")]
    expected = sum(1 for f in active if (d := sla.due_at(f)) is not None and d < now)
    assert summary(db, scope=GLOBAL)["overdue"] == expected
    assert db.scalar(select(func.count(Finding.id)).where(overdue_expr(now))) == expected


POLICY_CASES = {
    "env defaults only": [],
    "default overrides": [("critical", "any", 3), ("low", "any", 365)],
    "criticality overrides": [("critical", "critical", 1), ("high", "critical", 7), ("high", "low", 60)],
    "mixed": [("medium", "any", 45), ("medium", "high", 20), ("critical", "low", 14)],
}


@pytest.mark.parametrize("case", POLICY_CASES)
def test_sql_and_python_due_dates_agree(db, findings, case):
    _set_policies(db, POLICY_CASES[case])
    _assert_parity(db)


def test_without_policies_the_sql_is_unchanged(db):
    """No criticality lookup and no extra severity branches when nothing is configured."""
    sql = str(sla.sla_days_expr(sla.build_policy([])).compile())
    assert "assets" not in sql and sql.count("WHEN") == 4
    with_crit = str(sla.sla_days_expr(sla.build_policy([("high", "critical", 7)])).compile())
    assert "assets" in with_crit


def test_resolution_order(db):
    p = sla.build_policy([("high", "any", 20), ("high", "critical", 5)])
    assert p.days_for("high", "critical") == 5
    assert p.days_for("high", "low") == 20
    assert p.days_for("critical", "low") == 7  # SLA_CRITICAL_DAYS
    assert p.days_for("info", "critical") is None


def test_sla_api(client, auth, db):
    r = client.get("/api/v1/sla", headers=auth["viewer"])
    assert r.status_code == 200
    m = r.json()
    assert m["days"]["critical"] == {"any": 7, "low": None, "medium": None, "high": None, "critical": None}
    assert m["env_defaults"] == {"critical": 7, "high": 30, "medium": 90, "low": 180}

    body = {"days": {"critical": {"any": 7, "critical": 2}, "high": {"any": 21}}}
    for role in ("viewer", "analyst", "manager"):
        assert client.put("/api/v1/sla", json=body, headers=auth[role]).status_code == 403
    r = client.put("/api/v1/sla", json=body, headers=auth["admin"])
    assert r.status_code == 200
    assert r.json()["days"]["critical"]["critical"] == 2 and r.json()["days"]["high"]["any"] == 21
    # critical/any equals SLA_CRITICAL_DAYS, so it is not stored.
    stored = {(p.severity, p.criticality, p.days) for p in db.scalars(select(SlaPolicy))}
    assert stored == {("critical", "critical", 2), ("high", "any", 21)}

    meta = client.get("/api/v1/meta").json()
    assert meta["sla_days"]["high"] == 21

    entry = db.scalar(select(AuditLog).where(AuditLog.action == "sla.update"))
    assert entry.changes == {
        "critical/critical": {"from": None, "to": 2},
        "high/any": {"from": 30, "to": 21},
    }

    for bad in (
        {"days": {"info": {"any": 5}}},
        {"days": {"high": {"huge": 5}}},
        {"days": {"high": {"any": 0}}},
    ):
        assert client.put("/api/v1/sla", json=bad, headers=auth["admin"]).status_code == 422

    # Clearing everything returns to the environment defaults.
    assert (
        client.put("/api/v1/sla", json={"days": {}}, headers=auth["admin"]).json()["days"]["high"]["any"]
        == 30
    )
    assert db.scalar(select(SlaPolicy)) is None
