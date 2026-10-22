"""The estate by product, team, environment and tool."""

import json
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.models import Asset, Finding, FindingEvent, Product, Team
from app.models.base import utcnow
from app.services.ingestion import IngestOptions, ingest_report


def _report(tool, *titles, severity="high"):
    return json.dumps({"schema": "guardiano/v1", "tool": {"name": tool}, "scan_type": "sast", "findings": [
        {"title": t, "severity": severity, "cwe": ["CWE-89"], "file_path": f"{t}.py", "line_start": 1}
        for t in titles]}).encode()  # fmt: skip


@pytest.fixture
def estate(db, users):
    checkout = Product(name="Checkout", description="")
    team = Team(name="payments", description="")
    db.add_all([checkout, team])
    db.flush()
    api = Asset(name="api", tags=[], product_id=checkout.id, environment="production")
    web = Asset(name="web", tags=[], product_id=checkout.id, environment="staging", team_id=team.id)
    blog = Asset(name="blog", tags=[])
    db.add_all([api, web, blog])
    db.commit()
    ingest_report(db, _report("Semgrep", "a", "b"), api, None, IngestOptions())
    ingest_report(db, _report("CodeQL", "b", "c"), api, None, IngestOptions())  # b is reported by both
    ingest_report(db, _report("Semgrep", "d"), web, None, IngestOptions())
    ingest_report(db, _report("Semgrep", "e", severity="low"), blog, None, IngestOptions())

    now = utcnow()
    by_title = {f.title: f for f in db.scalars(select(Finding))}
    # Triaged by a person 4 hours and 10 hours after appearing; "a" resolved after 2 days.
    for title, hours in (("a", 4), ("c", 10)):
        f = by_title[title]
        f.first_seen_at = now - timedelta(days=3)
        db.add(FindingEvent(finding_id=f.id, actor_id=users["analyst"].id, event="assigned",
                            created_at=f.first_seen_at + timedelta(hours=hours)))  # fmt: skip
    by_title["a"].status, by_title["a"].closed_at = "resolved", now - timedelta(days=1)
    db.commit()
    return {"checkout": checkout, "team": team}


def get(client, auth, by, role="admin"):
    r = client.get("/api/v1/analytics/breakdown", params={"by": by}, headers=auth[role])
    assert r.status_code == 200, r.text
    return {row["label"]: row for row in r.json()}


def test_by_product(client, auth, estate):
    rows = get(client, auth, "product")
    assert rows["Checkout"]["key"] == str(estate["checkout"].id)
    checkout = rows["Checkout"]
    assert (checkout["open"], checkout["critical_high"], checkout["resolved"]) == (3, 3, 1)
    assert rows["Checkout"]["mttr_days"] == 2.0
    assert rows["Checkout"]["median_triage_hours"] == 7.0  # between 4 and 10
    assert rows["No product"]["open"] == 1


def test_by_tool_splits_unique_from_shared(client, auth, estate):
    rows = get(client, auth, "tool")
    # b is reported by both tools: it counts for each, as shared.
    assert (rows["CodeQL"]["open"], rows["CodeQL"]["unique_open"], rows["CodeQL"]["shared_open"]) == (2, 1, 1)
    semgrep = rows["Semgrep"]
    assert (semgrep["open"], semgrep["unique_open"], semgrep["shared_open"]) == (3, 2, 1)


def test_by_environment_and_team_within_scope(client, auth, estate):
    assert get(client, auth, "environment")["production"]["open"] == 2
    rows = get(client, auth, "team", role="viewer")  # the viewer is in no team
    assert set(rows) == {"No team"} and rows["No team"]["open"] == 3
    assert get(client, auth, "team")["payments"]["open"] == 1


def test_an_unknown_grouping_is_refused(client, auth):
    r = client.get("/api/v1/analytics/breakdown", params={"by": "colour"}, headers=auth["viewer"])
    assert r.status_code == 422
