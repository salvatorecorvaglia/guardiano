"""Index bounded expiry sweeps without changing authentication records."""

from alembic import op

revision = "0004"
down_revision = "0003"


def upgrade():
    op.create_index("ix_password_resets_expires_at", "password_resets", ["expires_at"])


def downgrade():
    op.drop_index("ix_password_resets_expires_at", table_name="password_resets")
