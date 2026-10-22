"""Serialized, versioned upgrades and strict adoption of the legacy 1.0 schema."""

import json
from contextlib import nullcontext
from importlib.resources import files

from alembic import command
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Connection, Engine, inspect, text

from app.core.db import engine


def migration_config(connection: Connection) -> Config:
    config = Config()
    config.set_main_option("script_location", str(files("app.migrations")))
    config.attributes["connection"] = connection
    return config


def schema_contract(connection: Connection) -> dict:
    """Reflection contract; includes columns, indexes, and relational constraints."""
    inspector = inspect(connection)
    schema = connection.scalar(text("SELECT current_schema()"))
    contract = {}
    for name in sorted(set(inspector.get_table_names(schema=schema)) - {"alembic_version"}):
        contract[name] = {
            "columns": [
                {
                    "name": c["name"],
                    "type": str(c["type"]),
                    "nullable": c["nullable"],
                    "default": c.get("default"),
                    "computed": c.get("computed"),
                }
                for c in inspector.get_columns(name, schema=schema)
            ],
            "primary_key": inspector.get_pk_constraint(name, schema=schema),
            "foreign_keys": sorted(inspector.get_foreign_keys(name, schema=schema), key=lambda x: x["name"]),
            "unique_constraints": sorted(
                inspector.get_unique_constraints(name, schema=schema), key=lambda x: x["name"]
            ),
            "indexes": sorted(inspector.get_indexes(name, schema=schema), key=lambda x: x["name"]),
        }
    for table in contract.values():
        for fk in table["foreign_keys"]:
            if fk.get("referred_schema") == schema:
                fk["referred_schema"] = None
        for column in table["columns"]:
            default = column["default"]
            if default and default.startswith("nextval('"):
                column["default"] = default.replace(f'"{schema}".', "").replace(
                    f"nextval('{schema}.", "nextval('"
                )
    return json.loads(json.dumps(contract, default=str))


def initialize_schema(target: Engine | None = None) -> None:
    with (target or engine).begin() as connection:
        connection.execute(text("SELECT pg_advisory_xact_lock(734829105)"))
        config = migration_config(connection)
        schema = connection.scalar(text("SELECT current_schema()"))
        tables = set(inspect(connection).get_table_names(schema=schema))
        if tables and "alembic_version" not in tables:
            expected = json.loads(files("app.migrations").joinpath("baseline_contract.json").read_text())
            if schema_contract(connection) != expected:
                raise RuntimeError(
                    "Unversioned schema differs from Guardiano 1.0; refusing adoption. "
                    "Restore the matching schema or apply a reviewed upgrade first."
                )
            command.stamp(config, "0001")
        command.upgrade(config, "head")


def check_schema(target: Engine | Connection | None = None) -> None:
    with (
        nullcontext(target) if isinstance(target, Connection) else (target or engine).connect()
    ) as connection:
        config = migration_config(connection)
        expected = ScriptDirectory.from_config(config).get_heads()
        actual = MigrationContext.configure(
            connection, opts={"version_table_schema": connection.scalar(text("SELECT current_schema()"))}
        ).get_current_heads()
        if set(actual) != set(expected):
            raise RuntimeError("Database revision is incompatible; run python -m app.cli init-db")
