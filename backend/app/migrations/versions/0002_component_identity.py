"""Hash complete component identities without losing IDs or scan memberships."""

import hashlib
import json

from alembic import op
from sqlalchemy import text

revision = "0002"
down_revision = "0001"


def upgrade():
    connection = op.get_bind()
    last_id = 0
    while True:
        rows = (
            connection.execute(
                text(
                    "SELECT id, ecosystem, name, version FROM components "
                    "WHERE id > :last_id ORDER BY id LIMIT 500"
                ),
                {"last_id": last_id},
            )
            .mappings()
            .all()
        )
        if not rows:
            break
        for row in rows:
            identity = [(row["ecosystem"] or "").lower(), row["name"].lower(), row["version"] or ""]
            key = hashlib.sha256(json.dumps(identity, ensure_ascii=True).encode()).hexdigest()
            connection.execute(
                text("UPDATE components SET key = :key WHERE id = :id"), {"key": key, "id": row["id"]}
            )
        last_id = rows[-1]["id"]


def downgrade():
    raise RuntimeError("Legacy component keys can collide; restore a verified backup instead")
