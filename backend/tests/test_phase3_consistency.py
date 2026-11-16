"""Asset identity, configuration atomicity, and expiry regression coverage."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select

from app.core.db import SessionLocal
from app.models import Asset, AuditLog, PasswordReset, SlaPolicy
from app.models.base import utcnow
from app.schemas.asset import AssetCreate, AssetUpdate, ProductBody, ProductUpdate
from app.schemas.team import TeamCreate, TeamUpdate
from app.services import retention
from app.services.asset_names import NameConflict
from app.services.ingestion import get_or_create_asset
from app.services.scope import GLOBAL


@pytest.mark.no_database
@pytest.mark.parametrize(
    "schema", [AssetCreate, AssetUpdate, TeamCreate, TeamUpdate, ProductBody, ProductUpdate]
)
def test_names_are_trimmed_before_validation(schema):
    assert schema(name="  service  ").name == "service"
    with pytest.raises(ValidationError):
        schema(name="   ")


def test_asset_creation_rename_and_ingestion_share_identity(client, auth, db):
    headers = auth["manager"]
    created = client.post("/api/v1/assets", headers=headers, json={"name": " Payments "})
    assert created.status_code == 201
    ident = created.json()["id"]
    assert created.json()["name"] == "Payments"
    assert client.post("/api/v1/assets", headers=headers, json={"name": "payments"}).status_code == 409
    other = client.post("/api/v1/assets", headers=headers, json={"name": "other"}).json()["id"]
    assert (
        client.patch(f"/api/v1/assets/{other}", headers=headers, json={"name": "PAYMENTS"}).status_code == 409
    )
    assert (
        client.patch(f"/api/v1/assets/{ident}", headers=headers, json={"name": "PAYMENTS"}).status_code == 200
    )
    assert get_or_create_asset(db, "payments", GLOBAL).id == ident
    db.rollback()
    assert (
        client.patch(f"/api/v1/assets/{other}", headers=headers, json={"name": "renamed"}).status_code == 200
    )


def test_legacy_collisions_are_not_silently_selected_or_merged(db):
    db.add_all([Asset(name="Legacy"), Asset(name="legacy")])
    db.commit()
    with pytest.raises(NameConflict, match="ambiguous"):
        get_or_create_asset(db, "LEGACY", GLOBAL)
    db.rollback()
    assert db.scalar(select(func.count()).select_from(Asset)) == 2


def test_concurrent_manual_creation_and_ingestion_cannot_split_asset(client, auth, db):
    barrier = Barrier(2)

    def ingest():
        with SessionLocal() as session:
            barrier.wait(timeout=5)
            asset = get_or_create_asset(session, "race", GLOBAL)
            ident = asset.id
            session.commit()
            return ident

    def create():
        barrier.wait(timeout=5)
        return client.post("/api/v1/assets", headers=auth["manager"], json={"name": "RACE"})

    with ThreadPoolExecutor(max_workers=2) as pool:
        a, b = pool.submit(ingest), pool.submit(create)
        ident, response = a.result(timeout=10), b.result(timeout=10)
    assert response.status_code in {201, 409}
    rows = list(db.scalars(select(Asset).where(func.lower(Asset.name) == "race")))
    assert len(rows) == 1 and rows[0].id == ident


def test_concurrent_sla_replacements_are_atomic_and_audited(client, auth, db):
    barrier = Barrier(2)

    def replace(days):
        barrier.wait(timeout=5)
        return client.put(
            "/api/v1/sla",
            headers=auth["admin"],
            json={
                "days": {
                    "high": {"any": days},
                    "low": {"any": days + 1},
                }
            },
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(replace, days) for days in (11, 22)]
        assert [f.result(timeout=10).status_code for f in futures] == [200, 200]
    rows = {r.severity: r.days for r in db.scalars(select(SlaPolicy))}
    assert rows in ({"high": 11, "low": 12}, {"high": 22, "low": 23})
    logs = list(db.scalars(select(AuditLog).where(AuditLog.action == "sla.update").order_by(AuditLog.id)))
    assert len(logs) == 2
    assert logs[1].changes["high/any"]["from"] == logs[0].changes["high/any"]["to"]
    before = rows.copy()
    assert (
        client.put(
            "/api/v1/sla",
            headers=auth["admin"],
            json={
                "days": {
                    "high": {"any": 9},
                    "invalid": {"any": 10},
                }
            },
        ).status_code
        == 422
    )
    assert {r.severity: r.days for r in db.scalars(select(SlaPolicy))} == before


def test_reset_cleanup_is_bounded_transactional_and_preserves_live_tokens(db, users):
    now = utcnow()
    rows = [
        PasswordReset(user_id=users["admin"].id, token_hash=f"token-{i}", expires_at=expiry)
        for i, expiry in enumerate([now - timedelta(seconds=1), now, now + timedelta(seconds=1)])
    ]
    db.add_all(rows)
    db.commit()
    assert retention.prune_password_resets(db, now, batch_size=1) == 1
    db.rollback()
    assert db.scalar(select(func.count()).select_from(PasswordReset)) == 3
    assert retention.prune_password_resets(db, now, batch_size=1) == 1
    db.commit()
    assert retention.prune_password_resets(db, now, batch_size=1) == 1
    db.commit()
    assert retention.prune_password_resets(db, now, batch_size=1) == 0
    assert db.get(PasswordReset, rows[2].id) is not None


def test_collision_check_reports_ids_without_changing_assets(db, capsys):
    import argparse

    from app.cli import cmd_check_asset_names

    rows = [Asset(name="Legacy"), Asset(name="legacy")]
    db.add_all(rows)
    db.commit()
    with pytest.raises(SystemExit, match="no assets were merged"):
        cmd_check_asset_names(argparse.Namespace())
    assert str(sorted(row.id for row in rows)) in capsys.readouterr().out
    db.expire_all()
    assert [row.name for row in rows] == ["Legacy", "legacy"]


def test_worker_drains_reset_backlog_in_committed_batches(db, users, monkeypatch):
    from app.services import jobs, tasks

    monkeypatch.setattr(retention, "RESET_BATCH_SIZE", 2)
    original = retention.prune_password_resets
    monkeypatch.setattr(
        retention,
        "prune_password_resets",
        lambda session, now=None: original(
            session,
            now,
            batch_size=2,
        ),
    )
    commits = []
    commit = jobs.commit_owned
    monkeypatch.setattr(jobs, "commit_owned", lambda session: (commits.append(True), commit(session)))
    db.add_all(
        PasswordReset(
            user_id=users["admin"].id, token_hash=f"old-{i}", expires_at=utcnow() - timedelta(seconds=1)
        )
        for i in range(5)
    )
    db.commit()
    tasks.retention_sweep(db, {})
    db.commit()
    assert len(commits) == 2
    assert db.scalar(select(func.count()).select_from(PasswordReset)) == 0
