"""In-app notifications: who hears about what, and only about findings they can see."""

import json
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.models import Asset, Finding, Notification, Team
from app.models.base import utcnow
from app.services import notifications
from app.services.ingestion import IngestOptions, ingest_report


@pytest.fixture
def fid(db):
    asset = Asset(name="svc", tags=[])
    db.add(asset)
    db.commit()
    found = {"title": "SQL injection", "severity": "high", "cwe": ["CWE-89"], "file_path": "a.py"}
    report = {"schema": "guardiano/v1", "tool": {"name": "t"}, "scan_type": "sast", "findings": [found]}
    ingest_report(db, json.dumps(report).encode(), asset, None, IngestOptions())
    return db.scalar(select(Finding.id))


def assign(client, auth, fid, user):
    r = client.patch(f"/api/v1/findings/{fid}", json={"assignee_id": user.id}, headers=auth["analyst"])
    assert r.status_code == 200, r.text


def bell(client, auth, role):
    r = client.get("/api/v1/notifications", headers=auth[role])
    assert r.status_code == 200, r.text
    return r.json()


def test_being_assigned_by_somebody_else(client, auth, users, fid):
    assign(client, auth, fid, users["manager"])
    body = bell(client, auth, "manager")
    assert body["unread"] == 1
    (n,) = body["items"]
    assert n["kind"] == "assigned" and n["finding_id"] == fid and "SQL injection" in n["text"]
    assert n["actor"]["email"] == users["analyst"].email

    assign(client, auth, fid, users["analyst"])
    assert bell(client, auth, "analyst")["unread"] == 0  # nobody is told about their own action


def test_a_mention_in_a_comment(client, auth, users, fid):
    text = "@manager@test.io can you look? cc @nobody@test.io and mail me at analyst@test.io"
    r = client.post(f"/api/v1/findings/{fid}/comments", json={"text": text}, headers=auth["analyst"])
    assert r.status_code == 201
    (n,) = bell(client, auth, "manager")["items"]
    assert n["kind"] == "mentioned" and "can you look?" in n["text"]
    assert bell(client, auth, "analyst")["unread"] == 0  # a bare address is not a mention


def test_a_mention_does_not_reach_across_a_team_boundary(client, auth, db, users, fid):
    team = Team(name="payments", description="")
    db.add(team)
    db.flush()
    team.members.append(users["analyst"])
    db.get(Finding, fid).asset.team_id = team.id
    db.commit()
    body = {"text": "@manager@test.io have a look"}
    client.post(f"/api/v1/findings/{fid}/comments", json=body, headers=auth["analyst"])
    # The manager is outside the team, so not even the finding's title may reach them.
    assert db.scalar(select(Notification)) is None


def test_marking_read(client, auth, users, fid):
    for who in ("admin", "viewer"):
        body = {"text": f"@manager@test.io from {who}"}
        client.post(f"/api/v1/findings/{fid}/comments", json=body, headers=auth["analyst"])
    first, second = (n["id"] for n in bell(client, auth, "manager")["items"])
    r = client.post("/api/v1/notifications/read", json={"ids": [first]}, headers=auth["manager"])
    assert r.json()["unread"] == 1
    # Somebody else's ids are not yours to mark.
    client.post("/api/v1/notifications/read", json={"ids": [second]}, headers=auth["admin"])
    assert bell(client, auth, "manager")["unread"] == 1
    client.post("/api/v1/notifications/read", json={}, headers=auth["manager"])
    assert bell(client, auth, "manager")["unread"] == 0
    assert bell(client, auth, "admin")["items"] == []


def test_acceptance_requests_and_decisions(client, auth, users, fid):
    until = (utcnow() + timedelta(days=30)).isoformat()
    body = {"justification": "behind the WAF", "until": until}
    r = client.post(f"/api/v1/findings/{fid}/acceptance-requests", json=body, headers=auth["analyst"])
    rid = r.json()["id"]
    assert [n["kind"] for n in bell(client, auth, "manager")["items"]] == ["acceptance_requested"]
    assert [n["kind"] for n in bell(client, auth, "admin")["items"]] == ["acceptance_requested"]
    assert bell(client, auth, "analyst")["items"] == []

    note = {"note": "fix it"}
    client.post(f"/api/v1/acceptance-requests/{rid}/reject", json=note, headers=auth["manager"])
    (n,) = bell(client, auth, "analyst")["items"]
    assert n["kind"] == "acceptance_decided" and "rejected" in n["text"] and "fix it" in n["text"]


def test_leaving_a_team_hides_what_was_about_its_assets(client, auth, db, users, fid):
    assign(client, auth, fid, users["manager"])
    team = Team(name="elsewhere", description="")
    db.add(team)
    db.flush()
    db.get(Finding, fid).asset.team_id = team.id
    db.commit()
    assert bell(client, auth, "manager") == {"items": [], "unread": 0}


def test_an_sla_breach_on_your_finding(client, auth, db, users, fid):
    from app.services.tasks import sla_breaches

    f = db.get(Finding, fid)
    f.assignee_id = users["analyst"].id
    f.due_at_override = utcnow() - timedelta(hours=1)
    db.commit()
    sla_breaches(db, {})
    db.commit()
    assert [n["kind"] for n in bell(client, auth, "analyst")["items"]] == ["sla_breached"]


def test_read_notifications_are_pruned_after_a_while(db, users, fid):
    old, fresh = utcnow() - timedelta(days=100), utcnow()
    for read_at in (old, fresh, None):
        who = users["viewer"].id
        db.add(Notification(user_id=who, kind="assigned", finding_id=fid, text="x", read_at=read_at))
    db.commit()
    assert notifications.prune(db) == 1
    db.commit()
    assert sorted(n.read_at is None for n in db.scalars(select(Notification))) == [False, True]
