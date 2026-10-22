"""Frozen Guardiano 1.0 schema; never import mutable application models here."""

import json
from importlib.resources import files

from alembic import op

revision = "0001"
down_revision = None


def upgrade():
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")
    statements = json.loads(files("app.migrations").joinpath("baseline_ddl.json").read_text())
    for statement in statements:
        op.execute(statement)


def downgrade():
    raise RuntimeError("Baseline removal is destructive; restore a verified backup instead")
