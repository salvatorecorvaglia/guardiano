"""System audit log: user, asset, token and auth actions, and the admin audit API."""

from sqlalchemy import select

from app.models import AuditLog
from tests.conftest import PASSWORD


def entries(db, prefix: str = "") -> list[AuditLog]:
    db.expire_all()
    return db.scalars(select(AuditLog).where(AuditLog.action.startswith(prefix)).order_by(AuditLog.id)).all()


def test_user_management_is_audited_without_secrets(client, auth, db, users):
    admin = users["admin"]
    r = client.post(
        "/api/v1/users",
        json={"email": "new@test.io", "full_name": "New", "password": PASSWORD, "role": "viewer"},
        headers=auth["admin"],
    )
    uid = r.json()["id"]
    client.patch(
        f"/api/v1/users/{uid}",
        json={"role": "analyst", "password": "An0ther-Passw0rd!"},
        headers=auth["admin"],
    )
    client.patch(f"/api/v1/users/{uid}", json={"role": "analyst"}, headers=auth["admin"])  # no-op
    client.delete(f"/api/v1/users/{uid}", headers=auth["admin"])

    create, update, delete = entries(db, "user.")
    assert (create.action, create.target_id, create.target_label) == ("user.create", uid, "new@test.io")
    assert create.actor_id == admin.id and create.actor_email == admin.email and create.ip
    assert update.changes == {"role": {"from": "viewer", "to": "analyst"}, "password": "changed"}
    assert create.changes == {"role": "viewer"}
    assert delete.action == "user.delete" and delete.changes == {"role": "analyst"}
    assert "argon2" not in str([e.changes for e in entries(db)])


def test_conflicting_create_leaves_no_audit_entry(client, auth, db):
    body = {"name": "svc", "criticality": "high"}
    assert client.post("/api/v1/assets", json=body, headers=auth["manager"]).status_code == 201
    assert client.post("/api/v1/assets", json=body, headers=auth["manager"]).status_code == 409
    assert [e.action for e in entries(db, "asset.")] == ["asset.create"]


def test_asset_changes_are_audited(client, auth, db, users):
    aid = client.post("/api/v1/assets", json={"name": "svc"}, headers=auth["manager"]).json()["id"]
    client.patch(
        f"/api/v1/assets/{aid}", json={"criticality": "critical", "tags": ["pci"]}, headers=auth["manager"]
    )
    client.patch(f"/api/v1/assets/{aid}", json={"criticality": "critical"}, headers=auth["manager"])  # no-op
    client.delete(f"/api/v1/assets/{aid}", headers=auth["manager"])

    create, update, delete = entries(db, "asset.")
    assert create.actor_id == users["manager"].id and create.target_label == "svc"
    assert update.changes == {
        "criticality": {"from": "medium", "to": "critical"},
        "tags": {"from": [], "to": ["pci"]},
    }
    assert delete.action == "asset.delete" and delete.target_id == aid


def test_token_lifecycle_is_audited(client, auth, db):
    r = client.post("/api/v1/tokens", json={"name": "ci", "scopes": ["ingest"]}, headers=auth["analyst"])
    token = r.json()
    client.delete(f"/api/v1/tokens/{token['id']}", headers=auth["analyst"])
    client.delete(f"/api/v1/tokens/{token['id']}", headers=auth["analyst"])  # already revoked: no entry

    create, revoke = entries(db, "token.")
    assert create.changes["scopes"] == ["ingest"] and create.changes["expires_at"]
    assert create.changes["expires_at"][:19] == token["expires_at"][:19]
    assert token["token"] not in str(create.changes) and create.target_label.startswith("ci (")
    assert revoke.action == "token.revoke" and revoke.target_id == token["id"]


def test_sign_in_events_are_audited(client, users, db):
    client.post("/api/v1/auth/login", json={"email": "nobody@test.io", "password": "x"})
    client.post("/api/v1/auth/login", json={"email": "viewer@test.io", "password": "wrong"})
    r = client.post("/api/v1/auth/login", json={"email": "Viewer@test.io", "password": PASSWORD})
    headers = {"Authorization": f"Bearer {r.json()['access_token']}"}
    client.post(
        "/api/v1/auth/change-password",
        json={"current_password": PASSWORD, "new_password": "Brand-New-Passw0rd"},
        headers=headers,
    )

    unknown, wrong, ok, pw = entries(db, "auth.")
    assert (unknown.action, unknown.target_id, unknown.target_label) == (
        "auth.login_failed",
        None,
        "nobody@test.io",
    )
    assert wrong.action == "auth.login_failed" and wrong.target_id == users["viewer"].id
    assert wrong.actor_id is None
    assert ok.action == "auth.login" and ok.actor_id == users["viewer"].id
    assert pw.action == "auth.password_change" and pw.changes == {"password": "changed"}


def test_audit_api_is_admin_only_and_filterable(client, auth, db):
    client.post("/api/v1/assets", json={"name": "svc"}, headers=auth["manager"])
    client.post("/api/v1/tokens", json={"name": "ci", "scopes": ["read"]}, headers=auth["viewer"])

    for role in ("viewer", "analyst", "manager"):
        assert client.get("/api/v1/admin/audit", headers=auth[role]).status_code == 403

    def actions(**params):
        r = client.get("/api/v1/admin/audit", params=params, headers=auth["admin"])
        assert r.status_code == 200
        return [e["action"] for e in r.json()["items"]]

    assert actions(action="asset.create") == ["asset.create"]
    assert actions(action="token.") == ["token.create"]
    assert actions(action="auth.") == ["auth.login"] * 4  # the auth fixture signs every role in
    assert actions(target_type="asset") == ["asset.create"]
    # Newest first.
    assert actions()[:2] == ["token.create", "asset.create"]
