import csv
import io

import pytest
from sqlalchemy import select

from app.models import Finding
from tests.conftest import PASSWORD, sample


def upload(client, headers, name, asset="payments-api", **form):
    return client.post(
        "/api/v1/scans",
        headers=headers,
        files={"file": (name, sample(name), "application/json")},
        data={"asset_name": asset, **form},
    )


def test_health(client):
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/readyz").status_code == 200


def test_login_and_refresh(client, users):
    assert (
        client.post("/api/v1/auth/login", json={"email": "admin@test.io", "password": "wrong"}).status_code
        == 401
    )
    r = client.post("/api/v1/auth/login", json={"email": "ADMIN@test.io", "password": PASSWORD})
    assert r.status_code == 200 and "guardiano_refresh" in r.cookies
    r2 = client.post("/api/v1/auth/refresh")
    assert r2.status_code == 200 and r2.json()["user"]["role"] == "admin"
    assert client.get("/api/v1/findings").status_code == 401


def test_upload_and_list(client, auth):
    r = upload(client, auth["analyst"], "codeql.sarif")
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["new_count"] == 6 and body["asset"]["name"] == "payments-api" and body["source"] == "upload"

    r = client.get("/api/v1/findings", headers=auth["viewer"], params={"severity": ["critical"]})
    assert r.json()["total"] == 1
    r = client.get("/api/v1/findings", headers=auth["viewer"], params={"q": "orders"})
    assert r.json()["total"] == 1
    r = client.get("/api/v1/findings", headers=auth["viewer"], params={"cwe": "79"})
    assert r.json()["items"][0]["rule_id"] == "js/reflected-xss"

    assets = client.get("/api/v1/assets", headers=auth["viewer"]).json()
    assert assets["items"][0]["open_total"] == 6 and assets["items"][0]["risk_score"] > 0

    r = client.get("/api/v1/findings/export.csv", headers=auth["viewer"])
    assert r.status_code == 200 and len(list(csv.DictReader(io.StringIO(r.text)))) == 6


def test_upload_rejects_garbage(client, auth):
    r = client.post(
        "/api/v1/scans",
        headers=auth["analyst"],
        files={"file": ("x.json", b'{"a": 1}')},
        data={"asset_name": "x"},
    )
    assert r.status_code == 422


def test_rbac_status_changes(client, auth, db):
    upload(client, auth["analyst"], "semgrep.json", asset="inv")
    fid = db.scalar(select(Finding.id))

    r = client.patch(f"/api/v1/findings/{fid}", headers=auth["viewer"], json={"status": "in_progress"})
    assert r.status_code == 403
    r = client.patch(f"/api/v1/findings/{fid}", headers=auth["analyst"], json={"status": "false_positive"})
    assert r.status_code == 422  # justification required
    r = client.patch(
        f"/api/v1/findings/{fid}",
        headers=auth["analyst"],
        json={"status": "risk_accepted", "justification": "x"},
    )
    assert r.status_code == 403
    r = client.patch(
        f"/api/v1/findings/{fid}",
        headers=auth["manager"],
        json={
            "status": "risk_accepted",
            "justification": "WAF",
            "risk_accepted_until": "2099-01-01T00:00:00Z",
        },
    )
    assert r.status_code == 200
    d = r.json()
    assert (
        d["status"] == "risk_accepted" and d["closed_at"] and d["events"][0]["to_status"] == "risk_accepted"
    )

    r = client.post("/api/v1/findings/bulk", headers=auth["analyst"], json={"ids": [fid], "status": "open"})
    assert r.json() == {"updated": 1}


def test_viewer_cannot_upload_or_manage(client, auth):
    assert upload(client, auth["viewer"], "semgrep.json").status_code == 403
    assert client.get("/api/v1/users", headers=auth["manager"]).status_code == 403
    assert client.post("/api/v1/assets", headers=auth["analyst"], json={"name": "a"}).status_code == 403
    assert client.post("/api/v1/assets", headers=auth["manager"], json={"name": "a"}).status_code == 201


def test_api_token_scopes(client, auth):
    r = client.post("/api/v1/tokens", headers=auth["analyst"], json={"name": "ci", "scopes": ["ingest"]})
    assert r.status_code == 201
    token = {"Authorization": f"Bearer {r.json()['token']}"}

    r = upload(client, token, "trivy.json", asset="inv")
    assert r.status_code == 201 and r.json()["source"] == "api"
    # ingest-only token cannot read findings, manage users or change status
    assert client.get("/api/v1/findings", headers=token).status_code == 403
    assert client.get("/api/v1/users", headers=token).status_code == 403
    assert client.patch("/api/v1/findings/1", headers=token, json={"status": "resolved"}).status_code == 403

    # viewers cannot mint ingest tokens
    r = client.post("/api/v1/tokens", headers=auth["viewer"], json={"name": "x", "scopes": ["ingest"]})
    assert r.status_code == 403

    tid = client.get("/api/v1/tokens", headers=auth["analyst"]).json()[0]["id"]
    client.delete(f"/api/v1/tokens/{tid}", headers=auth["analyst"])
    assert upload(client, token, "trivy.json", asset="inv").status_code == 401


def test_last_admin_protected(client, auth, users):
    admin_id = users["admin"].id
    r = client.patch(f"/api/v1/users/{admin_id}", headers=auth["admin"], json={"role": "viewer"})
    assert r.status_code == 409


def test_analytics(client, auth):
    upload(client, auth["analyst"], "codeql.sarif")
    upload(client, auth["analyst"], "cyclonedx.json")
    s = client.get("/api/v1/analytics/summary", headers=auth["viewer"]).json()
    assert s["open_total"] == 14 and s["open_by_type"] == {"sast": 6, "sca": 8, "iac": 0, "dast": 0}
    t = client.get("/api/v1/analytics/trends", headers=auth["viewer"], params={"days": 30}).json()
    assert len(t["open_by_severity"]) == 30
    last = t["open_by_severity"][-1]
    assert sum(last[s] for s in ("critical", "high", "medium", "low", "info")) == 14
    assert client.get("/api/v1/analytics/top", headers=auth["viewer"], params={"by": "cwes"}).json()
    pk = client.get("/api/v1/analytics/top", headers=auth["viewer"], params={"by": "packages"}).json()
    assert pk[0]["critical_high"] >= 1


def test_a_role_map_typo_warns_instead_of_failing_silently(monkeypatch):
    """A group mapped to a role that does not exist is ignored at sign-in, which looks like the
    mapping simply not working. Say so at startup instead."""
    import warnings

    from app.core.config import Settings

    monkeypatch.setenv("OIDC_ROLE_MAP", "idp-admins:superuser")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        Settings()
    assert any("superuser" in str(w.message) for w in caught), [str(w.message) for w in caught]


def test_a_valid_role_map_is_quiet(monkeypatch):
    import warnings

    from app.core.config import Settings

    monkeypatch.setenv("OIDC_ROLE_MAP", "idp-admins:admin,appsec:manager")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        Settings()
    assert not [w for w in caught if "OIDC_ROLE_MAP" in str(w.message)]


def test_the_asset_picker_is_not_capped_at_a_page(client, auth, db):
    """Pickers read /assets?page_size=500 and silently stopped there."""
    from app.models import Asset

    db.add_all(Asset(name=f"svc-{i:04d}", tags=[]) for i in range(620))
    db.commit()
    options = client.get("/api/v1/assets/options", headers=auth["viewer"]).json()
    assert len(options) == 620 and set(options[0]) == {"id", "name"}


@pytest.mark.parametrize(
    "path,body,role",
    [
        (
            "/api/v1/webhooks",
            {"name": "h", "url": "https://hooks.example.test/x", "events": ["scan.completed"]},
            "admin",
        ),
        (
            "/api/v1/integrations",
            {
                "kind": "github",
                "name": "g",
                "base_url": "https://api.github.com",
                "project": "a/b",
                "token": "t",
            },
            "admin",
        ),
        (
            "/api/v1/triage-rules",
            {
                "name": "r",
                "match": {"path_glob": "*/vendor/*"},
                "action": {"status": "false_positive", "justification": "Third-party code"},
            },
            "manager",
        ),
    ],
)
def test_a_body_naming_a_missing_asset_is_invalid_not_missing(client, auth, path, body, role):
    """A missing *referenced* row makes the request invalid (422), as the asset form already answers
    for a missing team; 404 is for the resource in the URL. These three answered 404."""
    r = client.post(path, json={**body, "asset_id": 999_999}, headers=auth[role])
    assert r.status_code == 422, r.text
    assert r.json()["detail"] == "Asset not found"


def test_a_rate_limited_request_answers_in_the_shape_of_every_other_error():
    """slowapi's stock handler answered {"error": ...}; everything else is {"detail": ...}. Called
    directly rather than through a probe route, which would stay registered on the shared app."""
    import asyncio
    import json as jsonlib

    from limits import parse
    from slowapi.errors import RateLimitExceeded
    from slowapi.wrappers import Limit
    from starlette.requests import Request

    from app.main import app

    limit = Limit(parse("10/minute"), lambda: "k", None, False, None, None, None, 1, False)
    request = Request({"type": "http", "app": app, "method": "POST", "path": "/", "headers": [], "state": {}})
    handler = app.exception_handlers[RateLimitExceeded]
    response = asyncio.run(handler(request, RateLimitExceeded(limit)))
    body = jsonlib.loads(response.body)
    assert response.status_code == 429
    assert set(body) == {"detail"} and body["detail"].startswith("Too many requests")


def test_readiness_fails_when_the_database_does_not_answer(client):
    """The one thing a readiness probe is for. Only the healthy case was ever checked."""
    from app.core.db import get_db
    from app.main import app

    class Unreachable:
        def execute(self, *args, **kwargs):
            raise ConnectionError("database is down")

    app.dependency_overrides[get_db] = lambda: Unreachable()
    try:
        assert client.get("/readyz").status_code == 503
        assert client.get("/healthz").status_code == 200  # liveness does not depend on the database
    finally:
        app.dependency_overrides.pop(get_db)
