"""Migrate isolated schemas: fresh install, verified legacy adoption and refusal of drift."""

import uuid

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.orm import Session

from app.core.db import Base, engine
from app.core.schema import check_schema, initialize_schema, migration_config
from app.models import Asset, Component, ComponentScan, Scan, User
from app.parsers.base import NormalizedComponent
from app.services.inventory import component_key


@pytest.fixture
def isolated_schema():
    name = f"migration_{uuid.uuid4().hex}"
    with engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{name}"'))
    target = create_engine(engine.url, connect_args={"options": f"-csearch_path={name},public"})
    try:
        yield target
    finally:
        target.dispose()
        with engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{name}" CASCADE'))


def test_fresh_migration_matches_models_and_repeated_startup(isolated_schema):
    initialize_schema(isolated_schema)
    check_schema(isolated_schema)
    with isolated_schema.begin() as connection:
        assert not compare_metadata(MigrationContext.configure(connection), Base.metadata)
    with Session(isolated_schema) as db:
        user = User(email="preserved@test.io", password_hash="unused", role="admin")
        db.add(user)
        db.commit()
    initialize_schema(isolated_schema)
    with Session(isolated_schema) as db:
        assert db.scalar(select(User.email)) == "preserved@test.io"


def test_legacy_adoption_preserves_component_ids_and_membership(isolated_schema):
    with isolated_schema.begin() as connection:
        command.upgrade(migration_config(connection), "0001")
        connection.execute(text("DROP TABLE alembic_version"))
    with Session(isolated_schema) as db:
        asset = Asset(name="legacy")
        db.add(asset)
        db.flush()
        scan = Scan(asset_id=asset.id, tool_name="legacy", scan_type="sca", format="cyclonedx")
        db.add(scan)
        db.flush()
        component = Component(asset_id=asset.id, key="npm:lib@1", name="lib", ecosystem="npm", version="1")
        db.add(component)
        db.flush()
        cid, sid = component.id, scan.id
        db.add(ComponentScan(component_id=cid, scan_id=sid))
        db.commit()
    initialize_schema(isolated_schema)
    with Session(isolated_schema) as db:
        assert db.get(Component, cid).key == component_key(NormalizedComponent("lib", "1", "npm"))
        assert db.get(ComponentScan, (cid, sid)) is not None
    check_schema(isolated_schema)
    check_schema(engine)  # adopting another schema must never stamp or drop public


def test_unversioned_schema_drift_is_refused_without_stamping(isolated_schema):
    with isolated_schema.begin() as connection:
        command.upgrade(migration_config(connection), "0001")
        connection.execute(text("DROP TABLE alembic_version"))
        connection.execute(text("DROP INDEX ix_findings_search"))
    with pytest.raises(RuntimeError, match="refusing adoption"):
        initialize_schema(isolated_schema)
    with isolated_schema.connect() as connection:
        assert "alembic_version" not in inspect(connection).get_table_names(
            schema=connection.scalar(text("SELECT current_schema()"))
        )
        assert "findings" in inspect(connection).get_table_names(
            schema=connection.scalar(text("SELECT current_schema()"))
        )


def test_readiness_rejects_older_revision(isolated_schema):
    with isolated_schema.begin() as connection:
        command.upgrade(migration_config(connection), "0001")
    with pytest.raises(RuntimeError, match="incompatible"):
        check_schema(isolated_schema)


def test_concurrent_startup_serializes_upgrades(isolated_schema):
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: initialize_schema(isolated_schema), range(2)))
    check_schema(isolated_schema)
    with isolated_schema.connect() as connection:
        assert not compare_metadata(MigrationContext.configure(connection), Base.metadata)


def test_http_readiness_rejects_wrong_revision_but_liveness_survives(client):
    with engine.begin() as connection:
        revision = connection.scalar(text("SELECT version_num FROM alembic_version"))
        connection.execute(text("UPDATE alembic_version SET version_num = '0001'"))
    try:
        assert client.get("/readyz").status_code == 503
        assert client.get("/healthz").status_code == 200
    finally:
        with engine.begin() as connection:
            connection.execute(
                text("UPDATE alembic_version SET version_num = :revision"), {"revision": revision}
            )
    assert client.get("/readyz").status_code == 200
