"""Compliance reporting: the OWASP Top 10 and CWE Top 25 views, and the two SLA figures."""

from datetime import timedelta

import pytest

from app.models import Asset, Finding
from app.models.base import utcnow
from app.services import compliance
from app.services.analytics import cwe_top_25, owasp_breakdown, sla_performance
from app.services.scope import GLOBAL

# ---- the mapping tables --------------------------------------------------------------------------


def test_the_tables_are_the_published_ones():
    assert len(compliance.OWASP_TOP_10) == 10
    assert [c.id for c in compliance.OWASP_TOP_10] == [f"A{i:02d}" for i in range(1, 11)]
    assert len(compliance.CWE_TOP_25) == 25
    assert [rank for rank, _, _ in compliance.CWE_TOP_25] == list(range(1, 26))
    # The editions are stated, so a printed report says what it was measured against.
    assert compliance.OWASP_EDITION == "2021" and compliance.CWE_TOP_25_EDITION == "2024"


def test_no_weakness_lands_in_two_categories():
    """OWASP's mapping is disjoint; if that ever stops being true the counts need rethinking."""
    for i, a in enumerate(compliance.OWASP_TOP_10):
        for b in compliance.OWASP_TOP_10[i + 1 :]:
            assert not a.cwes & b.cwes, f"{a.id} and {b.id} share {sorted(a.cwes & b.cwes)}"


@pytest.mark.parametrize(
    "cwes,expected",
    [
        (["CWE-89"], ["A03"]),  # SQL injection
        (["89"], ["A03"]),  # bare number
        (["cwe-89"], ["A03"]),  # lower case
        (["CWE-798"], ["A07"]),  # hard-coded credentials, where Gitleaks findings land
        (["CWE-918"], ["A10"]),
        (["CWE-79", "CWE-918"], ["A03", "A10"]),  # one finding, two categories
        (["CWE-99999"], []),  # unknown
        ([], []),
        (None, []),
    ],
)
def test_categorising_a_finding(cwes, expected):
    assert compliance.categories_for(cwes) == expected


# ---- the queries ---------------------------------------------------------------------------------


@pytest.fixture
def estate(db):
    """Findings whose categories are known by hand, so the counts can be asserted exactly."""
    asset = Asset(name="svc", tags=[])
    other = Asset(name="other", tags=[])
    db.add_all([asset, other])
    db.flush()
    now = utcnow()
    rows = [
        # (cwe, severity, status, asset)
        (["CWE-89"], "critical", "open", asset),
        (["CWE-79"], "high", "open", asset),
        (["CWE-79"], "medium", "open", asset),
        (["CWE-798"], "critical", "open", asset),
        (["CWE-79", "CWE-918"], "high", "open", asset),  # counted under A03 and A10
        ([], "medium", "open", asset),  # unmapped: no CWE at all
        (["CWE-99999"], "low", "open", asset),  # unmapped: not in OWASP's table
        (["CWE-89"], "critical", "resolved", asset),  # closed: never counted as open
        (["CWE-89"], "high", "open", other),  # another asset
    ]
    for i, (cwe, severity, status, on) in enumerate(rows):
        db.add(
            Finding(
                asset_id=on.id,
                type="sast",
                dedup_key=f"k{i}",
                title="t",
                severity=severity,
                status=status,
                cwe=cwe,
                tools=["x"],
                references=[],
                first_seen_at=now - timedelta(days=10),
                last_seen_at=now,
                closed_at=now if status == "resolved" else None,
            )
        )
    db.commit()
    return {"asset": asset, "other": other}


def by_id(breakdown):
    return {c["id"]: c["open"] for c in breakdown["categories"]}


def test_owasp_breakdown_counts_open_findings_once_per_category(db, estate):
    b = owasp_breakdown(db, scope=GLOBAL)
    counts = by_id(b)
    assert counts["A03"] == 5, "3 XSS + 1 SQLi (open) + the two-CWE finding, from both assets"
    assert counts["A07"] == 1  # hard-coded credentials
    assert counts["A10"] == 1  # the SSRF half of the two-CWE finding
    assert counts["A01"] == 0 and counts["A06"] == 0

    assert b["open_total"] == 8  # everything except the resolved one
    assert b["mapped"] == 6 and b["unmapped"] == 2
    # A finding with two CWEs is in two categories, so the categories need not sum to 'mapped'.
    assert sum(counts.values()) == 7


def test_the_breakdown_carries_critical_and_high(db, estate):
    high = {c["id"]: c["critical_high"] for c in owasp_breakdown(db, scope=GLOBAL)["categories"]}
    assert high["A03"] == 4 and high["A07"] == 1  # the medium XSS is excluded


def test_the_breakdown_can_be_asked_about_one_asset(db, estate):
    assert by_id(owasp_breakdown(db, estate["other"].id, scope=GLOBAL))["A03"] == 1
    assert owasp_breakdown(db, estate["other"].id, scope=GLOBAL)["open_total"] == 1


def test_cwe_top_25_lists_every_rank_even_at_zero(db, estate):
    rows = cwe_top_25(db, scope=GLOBAL)
    assert [r["rank"] for r in rows] == list(range(1, 26)), "a report shows the whole list, gaps and all"
    found = {r["cwe"]: r["open"] for r in rows}
    assert found["CWE-79"] == 3 and found["CWE-918"] == 1
    assert found["CWE-89"] == 2, "open on both assets; the resolved one does not count"
    assert found["CWE-798"] == 1
    assert found["CWE-787"] == 0  # not present here
    assert all(r["name"] for r in rows)


def test_an_unlisted_cwe_on_a_listed_finding_is_not_counted(db):
    """A finding carrying CWE-79 and CWE-99999 must add nothing to the unlisted one."""
    asset = Asset(name="svc", tags=[])
    db.add(asset)
    db.flush()
    db.add(
        Finding(
            asset_id=asset.id,
            type="sast",
            dedup_key="k",
            title="t",
            severity="high",
            status="open",
            cwe=["CWE-79", "CWE-99999"],
            tools=["x"],
            references=[],
            first_seen_at=utcnow(),
            last_seen_at=utcnow(),
        )
    )
    db.commit()
    rows = {r["cwe"]: r["open"] for r in cwe_top_25(db, scope=GLOBAL)}
    assert rows["CWE-79"] == 1
    assert sum(rows.values()) == 1


# ---- SLA performance -----------------------------------------------------------------------------


@pytest.fixture
def sla_estate(db):
    """Findings placed either side of their SLA, with the default policy (critical 7 days, high 30)."""
    asset = Asset(name="svc", tags=[])
    db.add(asset)
    db.flush()
    now = utcnow()
    rows = [
        ("critical", "open", now - timedelta(days=2), None),  # on track
        ("critical", "open", now - timedelta(days=40), None),  # overdue
        ("high", "open", now - timedelta(days=1), None),  # on track
        ("critical", "resolved", now - timedelta(days=30), now - timedelta(days=28)),  # 2 days: on time
        ("critical", "resolved", now - timedelta(days=60), now - timedelta(days=10)),  # 50 days: late
        ("info", "open", now - timedelta(days=400), None),  # no SLA: excluded from both figures
    ]
    for i, (severity, status, first, closed) in enumerate(rows):
        db.add(
            Finding(
                asset_id=asset.id,
                type="sast",
                dedup_key=f"s{i}",
                title="t",
                severity=severity,
                status=status,
                cwe=[],
                tools=["x"],
                references=[],
                first_seen_at=first,
                last_seen_at=now,
                closed_at=closed,
            )
        )
    db.commit()
    return asset


def test_sla_performance_reports_both_now_and_over_the_window(db, sla_estate):
    p = sla_performance(db, days=90, scope=GLOBAL)
    assert (p["open"], p["within_sla"]) == (3, 2)
    assert p["within_sla_pct"] == 66.7
    assert (p["resolved"], p["resolved_on_time"]) == (2, 1)
    assert p["resolved_on_time_pct"] == 50.0

    critical = next(r for r in p["by_severity"] if r["severity"] == "critical")
    assert (critical["open"], critical["within_sla"], critical["resolved_on_time"]) == (2, 1, 1)
    assert [r["severity"] for r in p["by_severity"]] == ["critical", "high"], "info has no SLA"


def test_a_finding_resolved_outside_the_window_is_not_counted(db, sla_estate):
    assert sla_performance(db, days=5, scope=GLOBAL)["resolved"] == 0


# ---- the endpoint --------------------------------------------------------------------------------


def test_the_compliance_endpoint_answers_in_one_request(client, auth, db, estate):
    r = client.get("/api/v1/analytics/compliance", headers=auth["viewer"])
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["owasp"]["edition"] == "2021" and body["cwe_top_25_edition"] == "2024"
    assert len(body["owasp"]["categories"]) == 10 and len(body["cwe_top_25"]) == 25
    assert body["generated_at"] and body["sla"]["days"] == 90
    assert {c["id"]: c["open"] for c in body["owasp"]["categories"]}["A03"] == 5


def test_the_report_is_scoped_to_one_asset(client, auth, estate):
    r = client.get(
        "/api/v1/analytics/compliance",
        params={"asset_id": estate["other"].id, "days": 30},
        headers=auth["viewer"],
    )
    body = r.json()
    assert body["asset_id"] == estate["other"].id and body["owasp"]["open_total"] == 1
    assert body["sla"]["days"] == 30


# ---- MTTR trend ----------------------------------------------------------------------------------


def test_the_mttr_trend_carries_the_count_with_each_point(db, sla_estate):
    from app.services.analytics import mttr_trend

    points = mttr_trend(db, days=90, scope=GLOBAL)
    assert points, "two findings were resolved inside the window"
    assert all(p["resolved"] >= 1 for p in points), "an average with no count behind it misleads"
    assert all(p["days"] >= 0 for p in points)
    assert [p["period"] for p in points] == sorted(p["period"] for p in points)
    # 2 days and 50 days, in whichever weeks they were closed.
    assert round(sum(p["days"] * p["resolved"] for p in points) / sum(p["resolved"] for p in points)) == 26


def test_an_empty_window_gives_an_empty_trend(db, sla_estate):
    from app.services.analytics import mttr_trend

    assert mttr_trend(db, days=7, scope=GLOBAL) == []


def test_the_report_includes_the_trend(client, auth, sla_estate):
    body = client.get("/api/v1/analytics/compliance", headers=auth["viewer"]).json()
    assert "mttr_trend" in body and body["mttr_trend"]
    assert set(body["mttr_trend"][0]) == {"period", "days", "resolved"}
