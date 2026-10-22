"""Global search: findings, assets, packages and vulnerabilities, within the reader's scope."""

import pytest

from app.models import Asset, Team
from app.services.ingestion import IngestOptions, ingest_report
from tests.conftest import sample


@pytest.fixture
def estate(db):
    shared, hidden = Asset(name="payments-api", tags=[]), Asset(name="payroll-secret", tags=[])
    team = Team(name="hr", description="")
    db.add_all([shared, hidden, team])
    db.flush()
    hidden.team_id = team.id
    db.commit()
    for a in (shared, hidden):
        ingest_report(db, sample("osv.json"), a, None, IngestOptions())
        ingest_report(db, sample("cyclonedx.json"), a, None, IngestOptions())
    return shared, hidden


def search(client, auth, q, role="viewer"):
    r = client.get("/api/v1/search", params={"q": q}, headers=auth[role])
    assert r.status_code == 200, r.text
    return r.json()


def test_one_box_for_everything(client, auth, estate):
    r = search(client, auth, "pay")
    assert [a["name"] for a in r["assets"]] == ["payments-api"], "another team's asset stays hidden"
    lodash = search(client, auth, "lodash")
    assert lodash["packages"] and lodash["packages"][0]["name"] == "lodash"
    assert lodash["packages"][0]["assets"] == 1  # only the asset the viewer can see is counted
    assert all(f["asset"]["name"] == "payments-api" for f in lodash["findings"])


def test_a_vulnerability_id_goes_straight_to_it(client, auth, db, estate):
    from sqlalchemy import select

    from app.models import Finding

    cve = db.scalar(select(Finding.cve_id).where(Finding.cve_id.is_not(None)))
    assert search(client, auth, cve.lower())["vulnerability"] == cve
    assert search(client, auth, "CVE-1999-0001")["vulnerability"] is None


def test_the_query_needs_two_characters(client, auth):
    assert client.get("/api/v1/search", params={"q": "a"}, headers=auth["viewer"]).status_code == 422
