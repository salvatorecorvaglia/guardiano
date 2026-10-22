"""Schema initialization creates the application schema and preserves existing rows."""

from sqlalchemy import inspect, select, text

from app.core.db import Base, engine
from app.core.schema import initialize_schema
from app.models import User
from tests.conftest import make_user


def test_schema_has_all_tables_and_search_support():
    with engine.connect() as connection:
        inspector = inspect(connection)
        assert set(inspector.get_table_names()) == set(Base.metadata.tables) | {"alembic_version"}
        assert connection.scalar(text("SELECT extname FROM pg_extension WHERE extname = 'pg_trgm'"))
        indexes = {index["name"] for index in inspector.get_indexes("findings")}
        assert {"ix_findings_search", "ix_findings_title_trgm"} <= indexes


def test_repeated_initialization_preserves_data(db):
    user = make_user(db, "preserved@example.test", "admin")
    initialize_schema()
    initialize_schema()
    db.expire_all()
    assert db.scalar(select(User).where(User.id == user.id)).email == "preserved@example.test"
