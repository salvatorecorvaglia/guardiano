"""Namespace SSO subjects by issuer; legacy bindings require explicit operator input."""

from alembic import op
from sqlalchemy import Column, Text

revision = "0003"
down_revision = "0002"


def upgrade():
    op.add_column("users", Column("oidc_issuer", Text(), nullable=True))
    op.drop_index("ix_users_oidc_subject", table_name="users")
    op.create_index("ix_users_oidc_subject", "users", ["oidc_subject"])
    op.execute("UPDATE users SET token_version = token_version + 1 WHERE oidc_subject IS NOT NULL")
    op.create_unique_constraint("uq_users_oidc_identity", "users", ["oidc_issuer", "oidc_subject"])


def downgrade():
    raise RuntimeError("Issuer removal can conflate identities; restore a verified backup instead")
