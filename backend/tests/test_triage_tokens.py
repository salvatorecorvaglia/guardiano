"""API tokens with the "triage" scope, and the per-credential upload limit."""

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.core.ratelimit import limiter
from app.models import Finding
from tests.conftest import sample


def token(client, auth, role, *scopes):
    r = client.post("/api/v1/tokens", headers=auth[role], json={"name": "bot", "scopes": list(scopes)})
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def upload(client, headers, name="osv.json", asset="svc"):
    files = {"file": (name, sample(name), "application/json")}
    return client.post("/api/v1/scans", headers=headers, files=files, data={"asset_name": asset})


@pytest.fixture
def fid(client, auth, db):
    assert upload(client, auth["analyst"]).status_code == 201
    return db.scalar(select(Finding.id).order_by(Finding.id))


def test_a_triage_token_can_triage(client, auth, db, fid):
    bot = token(client, auth, "analyst", "triage")
    r = client.patch(f"/api/v1/findings/{fid}", json={"status": "in_progress", "tags": ["bot"]}, headers=bot)
    assert r.status_code == 200, r.text
    bulk = {"ids": [fid], "add_tags": ["x"]}
    assert client.post("/api/v1/findings/bulk", json=bulk, headers=bot).status_code == 200
    comment = {"text": "seen"}
    assert client.post(f"/api/v1/findings/{fid}/comments", json=comment, headers=bot).status_code == 201
    db.expire_all()
    assert db.get(Finding, fid).status == "in_progress"


def test_other_tokens_cannot(client, auth, fid):
    for scopes in (["read"], ["ingest"], ["read", "ingest"]):
        bot = token(client, auth, "analyst", *scopes)
        r = client.patch(f"/api/v1/findings/{fid}", json={"status": "in_progress"}, headers=bot)
        assert r.status_code == 403, scopes


def test_a_token_carries_its_owners_role(client, auth, fid):
    """The scope opens the endpoint; what the owner may do there still applies."""
    bot = token(client, auth, "analyst", "triage")
    due = {"due_at": "2030-01-01T00:00:00Z"}
    assert client.patch(f"/api/v1/findings/{fid}", json=due, headers=bot).status_code == 403
    accept = {"status": "risk_accepted", "justification": "x"}
    assert client.patch(f"/api/v1/findings/{fid}", json=accept, headers=bot).status_code == 403


def test_only_analysts_may_mint_one(client, auth):
    r = client.post("/api/v1/tokens", headers=auth["viewer"], json={"name": "x", "scopes": ["triage"]})
    assert r.status_code == 403 and "'triage'" in r.text


def test_a_triage_token_still_cannot_configure(client, auth):
    bot = token(client, auth, "admin", "triage", "read")
    assert client.post("/api/v1/triage-rules", json={}, headers=bot).status_code == 403
    assert client.get("/api/v1/webhooks", headers=bot).status_code == 403


@pytest.fixture
def limited(monkeypatch):
    monkeypatch.setattr(settings, "ingest_rate_limit", "2/minute")
    limiter.reset()
    yield
    limiter.reset()


def test_uploads_are_limited_per_credential(client, auth, limited):
    first, second = token(client, auth, "analyst", "ingest"), token(client, auth, "analyst", "ingest")
    assert [upload(client, first).status_code for _ in range(3)] == [201, 201, 429]
    assert upload(client, second).status_code == 201, "another credential has its own allowance"


def test_uploads_are_unlimited_by_default(client, auth):
    limiter.reset()
    bot = token(client, auth, "analyst", "ingest")
    assert {upload(client, bot).status_code for _ in range(4)} == {201}
