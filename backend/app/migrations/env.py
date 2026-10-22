from alembic import context
from sqlalchemy import text

from app.core.db import Base

connection = context.config.attributes["connection"]
context.configure(
    connection=connection,
    target_metadata=Base.metadata,
    compare_type=True,
    version_table_schema=connection.scalar(text("SELECT current_schema()")),
)
with context.begin_transaction():
    context.run_migrations()
