"""Rehearse legacy backup, restore, upgrade and rollback on a local disposable PostgreSQL container.

REHEARSAL_DATABASE_URL=.../guardiano_test python ops/rehearse_upgrade.py \
  --postgres-container guardiano-completion-postgres --keep-databases
Only newly generated *_test databases are written. No existing database is migrated or dropped.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ["ENV"] = "test"

from alembic import command  # noqa: E402
from sqlalchemy import create_engine, func, inspect, select, table, text  # noqa: E402
from sqlalchemy.engine import make_url  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.core.schema import check_schema, initialize_schema, migration_config  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.core.testdb import validate_test_database  # noqa: E402
from app.models import (  # noqa: E402
    Asset,
    Component,
    ComponentScan,
    Finding,
    FindingEvent,
    FindingScan,
    Scan,
    User,
)
from app.parsers.base import NormalizedComponent  # noqa: E402
from app.services.inventory import component_key  # noqa: E402


def verify(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--postgres-container", required=True)
    parser.add_argument("--keep-databases", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if os.environ.get("DOCKER_HOST") and not os.environ["DOCKER_HOST"].startswith("unix://"):
        raise SystemExit("Remote DOCKER_HOST endpoints are not allowed for a local rehearsal")
    raw_url = os.environ["REHEARSAL_DATABASE_URL"]
    validate_test_database(raw_url)
    url = make_url(raw_url)
    if url.host not in {"localhost", "127.0.0.1", "::1"}:
        raise SystemExit("Rehearsal only supports a local PostgreSQL endpoint")
    executable = shutil.which("docker")
    if not executable:
        raise SystemExit("Docker CLI is required")
    context = json.loads(subprocess.check_output([executable, "context", "inspect"]))[0]  # noqa: S603,S607
    if not context["Endpoints"]["docker"]["Host"].startswith("unix://"):
        raise SystemExit("Rehearsal requires the local Docker socket")
    tag = uuid.uuid4().hex[:10]
    names = {kind: f"guardiano_rehearsal_{tag}_{kind}_test" for kind in ("legacy", "restored", "rollback")}
    engines = {kind: create_engine(url.set(database=name)) for kind, name in names.items()}
    artifact_dir = Path(tempfile.mkdtemp(prefix="guardiano-restore-rehearsal-"))
    dump = artifact_dir / "legacy.dump"
    created = []

    def docker(*arguments, **kwargs):
        return subprocess.run(  # noqa: S603,S607 -- argument arrays; only local, owned test databases
            [executable, "exec", "-i", args.postgres_container, *arguments],
            check=True,
            **kwargs,
        )

    def psql(sql):
        return docker(
            "psql",
            "-U",
            url.username,
            "-d",
            "postgres",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            sql,
            stdout=subprocess.DEVNULL,
        )

    def counts(target):
        with target.connect() as connection:
            return {
                name: connection.scalar(select(func.count()).select_from(table(name)))
                for name in sorted(inspect(connection).get_table_names())
                if name != "alembic_version"
            }

    def ids(target):
        with Session(target) as db:
            return {
                "user": db.scalar(select(User.id)),
                "asset": db.scalar(select(Asset.id)),
                "scan": db.scalar(select(Scan.id)),
                "finding": db.scalar(select(Finding.id)),
                "component": db.scalar(select(Component.id)),
            }

    try:
        for name in names.values():
            psql(f'CREATE DATABASE "{name}"')
            created.append(name)
        with engines["legacy"].begin() as connection:
            command.upgrade(migration_config(connection), "0001")
            connection.execute(text("DROP TABLE alembic_version"))
        with Session(engines["legacy"]) as db:
            user = User(
                email="browser@example.test",
                role="admin",
                full_name="Rehearsal admin",
                password_hash=hash_password("Browser-Smoke-Password-2026!"),
            )
            asset = Asset(name="restored-service")
            db.add_all([user, asset])
            db.flush()
            scan = Scan(asset_id=asset.id, tool_name="rehearsal", scan_type="sca", format="cyclonedx")
            db.add(scan)
            db.flush()
            finding = Finding(
                asset_id=asset.id,
                dedup_key="restored-finding",
                title="Restored advisory",
                type="sca",
                severity="high",
                status="open",
                tools=["rehearsal"],
                cve_id="CVE-2099-1000",
                package_name="library",
                package_version="v1",
                ecosystem="npm",
            )
            component = Component(
                asset_id=asset.id, key="npm:library@v1", name="library", version="v1", ecosystem="npm"
            )
            db.add_all([finding, component])
            db.flush()
            db.add_all(
                [
                    FindingScan(finding_id=finding.id, scan_id=scan.id),
                    ComponentScan(component_id=component.id, scan_id=scan.id),
                    FindingEvent(finding_id=finding.id, event="created", to_status="open", scan_id=scan.id),
                ]
            )
            db.commit()
        before, original_ids = counts(engines["legacy"]), ids(engines["legacy"])
        with dump.open("wb") as stream:
            dump.chmod(0o600)
            docker("pg_dump", "-U", url.username, "-Fc", "-d", names["legacy"], stdout=stream)
        for kind in ("restored", "rollback"):
            with dump.open("rb") as stream:
                docker(
                    "pg_restore",
                    "-U",
                    url.username,
                    "--exit-on-error",
                    "--no-owner",
                    "--no-acl",
                    "-d",
                    names[kind],
                    stdin=stream,
                )
        initialize_schema(engines["restored"])
        initialize_schema(engines["restored"])
        check_schema(engines["restored"])
        verify(
            before == counts(engines["restored"]) == counts(engines["rollback"]), "Restored row counts differ"
        )
        verify(
            original_ids == ids(engines["restored"]) == ids(engines["rollback"]),
            "Restored identifiers differ",
        )
        with Session(engines["restored"]) as db:
            verify(
                db.get(Component, original_ids["component"]).key
                == component_key(NormalizedComponent("library", "v1", "npm")),
                "Component identity was not upgraded",
            )
            verify(
                db.get(ComponentScan, (original_ids["component"], original_ids["scan"])) is not None,
                "Component scan membership missing",
            )
            verify(
                db.get(FindingScan, (original_ids["finding"], original_ids["scan"])) is not None,
                "Finding scan membership missing",
            )
        with Session(engines["rollback"]) as db:
            verify(
                db.get(Component, original_ids["component"]).key == "npm:library@v1",
                "Legacy rollback identity differs",
            )
        with engines["rollback"].connect() as connection:
            verify(
                "alembic_version" not in inspect(connection).get_table_names(),
                "Rollback schema was unexpectedly upgraded",
            )
        result = {
            "status": "passed",
            "backup_bytes": dump.stat().st_size,
            "backup": str(dump),
            "counts_preserved": before,
            "identifiers_preserved": original_ids,
            "component_identity_upgraded": True,
            "scan_memberships_preserved": True,
            "repeated_upgrade_passed": True,
            "legacy_backup_restored_for_rollback": True,
            "restored_database": names["restored"],
            "databases_kept": args.keep_databases,
        }
        rendered = json.dumps(result, indent=2) + "\n"
        if args.output:
            args.output.write_text(rendered)
        print(rendered, end="")
    finally:
        for target in engines.values():
            target.dispose()
        if not args.keep_databases:
            for name in created:
                psql(f'DROP DATABASE "{name}" WITH (FORCE)')


if __name__ == "__main__":
    main()
