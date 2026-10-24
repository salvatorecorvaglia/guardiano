"""Endpoints whose query count must not grow with the rows they touch.

Measured with count_queries: an N+1 is invisible on a test database with a handful of rows, and only
shows as time once there are thousands. Pinning the count per row catches it at any size.
"""

import json

from app.models import Asset, Finding, Team, Webhook
from app.services.ingestion import IngestOptions, ingest_report


def _findings(db, n: int, name: str) -> list[int]:
    asset = Asset(name=name, tags=[])
    db.add(asset)
    db.flush()
    report = {
        "schema": "guardiano/v1",
        "scan_type": "sast",
        "findings": [
            {"title": f"f{i}", "severity": "high", "cwe": ["CWE-89"], "file_path": "x.py", "line_start": i}
            for i in range(1, n + 1)
        ],
    }
    ingest_report(db, json.dumps(report).encode(), asset, None, IngestOptions())
    db.commit()
    return [f.id for f in db.query(Finding).filter(Finding.asset_id == asset.id)]


def test_a_bulk_update_reads_nothing_more_per_finding(client, auth, db, count_queries):
    """Each finding still costs its own writes -- the status, a history event, and a webhook delivery
    with its job -- but the reads (linked tickets, webhook subscribers, the asset) are one per batch.
    They used to be one per finding."""
    db.add(Webhook(name="h", url="https://example.test/h", secret="s", events=["finding.status_changed"]))
    db.commit()
    cost = {}
    for n in (2, 22):
        ids = _findings(db, n, f"asset-{n}")
        with count_queries(reads_only=True) as queries:
            r = client.post(
                "/api/v1/findings/bulk", json={"ids": ids, "status": "in_progress"}, headers=auth["analyst"]
            )
        assert r.status_code == 200 and r.json()["updated"] == n
        cost[n] = queries()
    assert cost[22] <= cost[2] + 1, f"Read queries grew with the batch: {cost}"


def test_listing_your_teams_is_not_one_query_per_team(client, auth, db, users, count_queries):
    def teams_listed():
        with count_queries() as queries:
            assert client.get("/api/v1/teams", headers=auth["analyst"]).status_code == 200
        return queries()

    def join(n, prefix):
        for i in range(n):
            team = Team(name=f"{prefix}-{i}", description="")
            team.members.append(users["analyst"])
            db.add(team)
        db.commit()

    join(2, "a")
    few = teams_listed()
    join(10, "b")
    assert teams_listed() == few


def test_an_api_token_request_loads_its_user_with_the_token(client, auth, count_queries):
    body = {"name": "ci", "scopes": ["read"]}
    token = client.post("/api/v1/tokens", json=body, headers=auth["admin"]).json()
    headers = {"Authorization": f"Bearer {token['token']}"}
    client.get("/api/v1/sla", headers=headers)  # first use writes last_used_at; measure a normal request
    with count_queries() as queries:
        assert client.get("/api/v1/sla", headers=headers).status_code == 200
    assert queries() <= 2  # the token with its user, then the endpoint; the user was a third


def test_changing_a_finding_does_not_load_its_history_twice(client, auth, db, count_queries):
    (fid,) = _findings(db, 1, "history")
    for i in range(30):  # a long-lived finding
        client.post(f"/api/v1/findings/{fid}/comments", json={"text": f"note {i}"}, headers=auth["analyst"])
    with count_queries() as queries:
        r = client.patch(f"/api/v1/findings/{fid}", json={"tags": ["x"]}, headers=auth["analyst"])
    assert r.status_code == 200 and len(r.json()["events"]) >= 31  # the response still has it all
    assert queries() <= 9
