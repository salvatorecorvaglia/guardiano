"""Risk-acceptance requests: asked for by one person, decided by a manager who is someone else."""

import json
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models import AcceptanceRequest, Asset, Finding, Team
from app.models.base import utcnow
from app.services.ingestion import IngestOptions, ingest_report


def native(*titles):
    return json.dumps({"schema": "guardiano/v1", "tool": {"name": "t"}, "scan_type": "sast", "findings": [
        {"title": t, "severity": "high", "cwe": ["CWE-1"], "file_path": f"{t}.py", "line_start": 1}
        for t in titles]}).encode()  # fmt: skip


@pytest.fixture
def fid(db):
    asset = Asset(name="svc", tags=[])
    db.add(asset)
    db.commit()
    ingest_report(db, native("a", "b"), asset, None, IngestOptions())
    return db.scalar(select(Finding.id).where(Finding.title == "a"))


def _until(days=30):
    return (utcnow() + timedelta(days=days)).isoformat()


def ask(client, headers, fid, **body):
    body = {"justification": "compensating WAF rule", "until": _until(), **body}
    return client.post(f"/api/v1/findings/{fid}/acceptance-requests", json=body, headers=headers)


def decide(client, headers, rid, verb, note=None):
    return client.post(f"/api/v1/acceptance-requests/{rid}/{verb}", json={"note": note}, headers=headers)


def test_a_request_is_approved_by_a_manager(client, auth, db, fid):
    r = ask(client, auth["analyst"], fid)
    assert r.status_code == 201, r.text
    req = r.json()
    assert req["state"] == "pending" and req["finding_title"] == "a"
    pending = client.get("/api/v1/acceptance-requests", headers=auth["viewer"]).json()
    assert [p["id"] for p in pending] == [req["id"]]

    r = decide(client, auth["manager"], req["id"], "approve", "reviewed with the team")
    assert r.status_code == 200, r.text
    assert r.json()["state"] == "approved" and r.json()["decided_by"]["email"] == "manager@test.io"
    db.expire_all()
    f = db.get(Finding, fid)
    assert f.status == "risk_accepted" and f.risk_accepted_until is not None
    assert "requested by" in f.status_justification and "approved by" in f.status_justification
    assert client.get("/api/v1/acceptance-requests", headers=auth["viewer"]).json() == []


def test_a_rejection_leaves_the_finding_open(client, auth, db, fid):
    rid = ask(client, auth["analyst"], fid).json()["id"]
    r = decide(client, auth["manager"], rid, "reject", "fix it instead")
    assert r.json()["state"] == "rejected"
    detail = client.get(f"/api/v1/findings/{fid}", headers=auth["viewer"]).json()
    assert detail["status"] == "open"
    assert [e["event"] for e in detail["events"]][:2] == ["acceptance_rejected", "acceptance_requested"]
    assert decide(client, auth["admin"], rid, "approve").status_code == 422  # already decided


def test_nobody_decides_their_own_request(client, auth, db, fid):
    rid = ask(client, auth["manager"], fid).json()["id"]
    assert decide(client, auth["manager"], rid, "approve").status_code == 403
    assert decide(client, auth["admin"], rid, "approve").status_code == 200


def test_one_pending_request_per_open_finding(client, auth, db, fid):
    assert ask(client, auth["analyst"], fid).status_code == 201
    assert ask(client, auth["manager"], fid).status_code == 422
    closed = db.scalar(select(Finding).where(Finding.title == "b"))
    closed.status = "resolved"
    db.commit()
    assert ask(client, auth["analyst"], closed.id).status_code == 422


def test_roles(client, auth, fid):
    assert ask(client, auth["viewer"], fid).status_code == 403
    rid = ask(client, auth["analyst"], fid).json()["id"]
    assert decide(client, auth["analyst"], rid, "approve").status_code == 403


def test_four_eyes_turns_direct_acceptance_off(client, auth, db, fid, monkeypatch):
    monkeypatch.setattr(settings, "risk_acceptance_four_eyes", True)
    direct = {"status": "risk_accepted", "justification": "x", "risk_accepted_until": _until()}
    assert client.patch(f"/api/v1/findings/{fid}", json=direct, headers=auth["manager"]).status_code == 403
    bulk = {"ids": [fid], **direct}
    assert client.post("/api/v1/findings/bulk", json=bulk, headers=auth["admin"]).status_code == 403

    rid = ask(client, auth["manager"], fid).json()["id"]
    assert decide(client, auth["admin"], rid, "approve").status_code == 200


def test_the_bounds_apply_to_every_way_in(client, auth, db, fid, monkeypatch):
    monkeypatch.setattr(settings, "risk_acceptance_max_days", 90)
    direct = {"status": "risk_accepted", "justification": "x"}
    for body in ({**direct}, {**direct, "risk_accepted_until": _until(120)}):
        assert client.patch(f"/api/v1/findings/{fid}", json=body, headers=auth["manager"]).status_code == 422
    assert ask(client, auth["analyst"], fid, until=None).status_code == 422
    assert ask(client, auth["analyst"], fid, until=_until(120)).status_code == 422
    assert ask(client, auth["analyst"], fid, until=_until(60)).status_code == 201


def test_requests_stay_inside_the_team_boundary(client, auth, db, fid):
    team = Team(name="elsewhere", description="")
    db.add(team)
    db.flush()
    db.get(Finding, fid).asset.team_id = team.id
    db.commit()
    assert ask(client, auth["analyst"], fid).status_code == 404
    rid = ask(client, auth["admin"], fid).json()["id"]
    assert client.get("/api/v1/acceptance-requests", headers=auth["manager"]).json() == []
    assert decide(client, auth["manager"], rid, "approve").status_code == 404
    assert db.scalar(select(AcceptanceRequest.state)) == "pending"
