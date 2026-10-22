"""The finding priority: one number from severity, exploitability and asset criticality."""

import random

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models import Asset, Finding, VulnIntel
from app.models.enums import CRITICALITIES, SEVERITY_ORDER
from app.services.priority import priority, priority_expr


def _finding(asset, key, severity="high", cve=None):
    return Finding(
        asset_id=asset.id,
        type="sca",
        dedup_key=key,
        title=key,
        severity=severity,
        status="open",
        cwe=[],
        tools=["x"],
        references=[],
        cve_id=cve,
    )


@pytest.fixture
def estate(db):
    """Assets of every criticality, and findings with every kind of exploitability."""
    rng = random.Random(7)
    assets = [Asset(name=f"asset-{c}", tags=[], criticality=c) for c in CRITICALITIES]
    db.add_all(assets)
    db.add_all(
        [
            VulnIntel(cve_id="CVE-KEV", in_kev=True, epss=0.01),
            VulnIntel(cve_id="CVE-HOT", in_kev=False, epss=0.9),
            VulnIntel(cve_id="CVE-EDGE", in_kev=False, epss=settings.epss_risk_threshold),
            VulnIntel(cve_id="CVE-COLD", in_kev=False, epss=0.01),
            VulnIntel(cve_id="CVE-NOSCORE", in_kev=False, epss=None),
        ]
    )
    db.flush()
    cves = [None, "CVE-KEV", "CVE-HOT", "CVE-EDGE", "CVE-COLD", "CVE-NOSCORE", "CVE-UNKNOWN"]
    for i in range(300):
        db.add(_finding(rng.choice(assets), f"k{i}", rng.choice(SEVERITY_ORDER).value, rng.choice(cves)))
    db.commit()
    return {a.criticality: a for a in assets}


def test_sql_and_python_agree_on_every_finding(db, estate):
    in_sql = dict(db.execute(select(Finding.id, priority_expr())).all())
    findings = db.scalars(select(Finding)).all()
    assert len(findings) == 300
    for f in findings:
        assert round(in_sql[f.id], 2) == priority(f), (f.severity, f.cve_id, f.asset.criticality)


def test_the_parts_multiply(db, estate):
    critical, low = estate["critical"], estate["low"]
    for f in (
        _finding(critical, "p1", "high", "CVE-KEV"),
        _finding(low, "p2", "high"),
        _finding(critical, "p3", "info", "CVE-KEV"),
    ):
        db.add(f)
    db.commit()
    rows = db.scalars(select(Finding).where(Finding.dedup_key.like("p%")))
    by_key = {f.dedup_key: priority(f) for f in rows}
    assert by_key["p1"] == 5.0 * settings.kev_risk_multiplier * 2.0
    assert by_key["p2"] == 5.0 * 0.5
    assert by_key["p3"] == 0.0  # informational stays at zero, whatever else is true


def test_the_list_sorts_by_priority_without_duplicating_rows(client, auth, db, estate):
    """Ordering reads the asset by subquery: joining it would repeat each finding per eager-loaded asset."""
    r = client.get("/api/v1/findings", params={"sort": "-priority", "page_size": 500}, headers=auth["admin"])
    assert r.status_code == 200, r.text
    items = r.json()["items"]
    assert r.json()["total"] == 300 and len({i["id"] for i in items}) == 300
    values = [i["priority"] for i in items]
    assert values == sorted(values, reverse=True)

    params = {"sort": "priority", "page_size": 500}
    ascending = client.get("/api/v1/findings", params=params, headers=auth["admin"])
    assert [i["priority"] for i in ascending.json()["items"]] == sorted(values)


def test_the_detail_and_event_payload_carry_it(client, auth, db, estate):
    f = _finding(estate["high"], "d1", "critical", "CVE-HOT")
    db.add(f)
    db.commit()
    detail = client.get(f"/api/v1/findings/{f.id}", headers=auth["viewer"]).json()
    assert detail["priority"] == 10.0 * settings.epss_risk_multiplier * 1.5

    from app.services.serializers import finding_payload

    assert finding_payload(f)["priority"] == detail["priority"]
