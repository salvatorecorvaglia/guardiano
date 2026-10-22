import os
import re

# Configure before the app (and its settings) are imported.
_base = os.environ.get("DATABASE_URL", "postgresql+psycopg://guardiano:guardiano@localhost:5432/guardiano")
TEST_DB_URL = os.environ.get("TEST_DATABASE_URL") or re.sub(
    r"/[^/?]+(\?|$)", r"/guardiano_test\1", _base, count=1
)
os.environ["DATABASE_URL"] = TEST_DB_URL
os.environ["ENV"] = "test"
os.environ["LOGIN_RATE_LIMIT"] = "1000/minute"
os.environ["LOG_JSON"] = "false"
os.environ["LOG_LEVEL"] = "WARNING"
os.environ.pop("GUARDIANO_ADMIN_EMAIL", None)
# Email and single sign-on off by default, whatever the developer's .env says; the suites that care turn
# them on with monkeypatch. Tests must not depend on the machine they run on.
os.environ["SMTP_HOST"] = ""
for name in [k for k in os.environ if k.startswith(("OIDC_", "MFA_"))]:
    del os.environ[name]
os.environ["LOCAL_LOGIN"] = "true"

from pathlib import Path  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402
from sqlalchemy.engine import make_url  # noqa: E402

# Fixtures shared by the issue-tracker modules (tests/trackers_support.py).
pytest_plugins = ["tests.trackers_support"]

BACKEND = Path(__file__).resolve().parents[1]
REPORT_FIXTURES = BACKEND / "tests" / "fixtures" / "reports"
PASSWORD = "Sup3r-Secret-Passw0rd"


def _ensure_database() -> None:
    from app.core.testdb import validate_test_database

    validate_test_database(TEST_DB_URL)
    url = make_url(TEST_DB_URL)
    admin = create_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as c:
        if not c.scalar(text("SELECT 1 FROM pg_database WHERE datname = :n"), {"n": url.database}):
            c.execute(text(f'CREATE DATABASE "{url.database}"'))
    admin.dispose()


@pytest.fixture(scope="session", autouse=True)
def _schema():
    from app.core.schema import initialize_schema

    _ensure_database()
    with create_engine(TEST_DB_URL).begin() as c:
        c.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public"))
    initialize_schema()
    yield


@pytest.fixture(autouse=True)
def _clean(_schema):
    # Derived from the models rather than listed by hand: a table added later is emptied between
    # tests automatically, instead of quietly leaking rows into whichever test runs next.
    import app.models  # noqa: F401  -- importing registers every table on Base.metadata
    from app.core.db import Base, engine

    tables = ", ".join(f'"{name}"' for name in Base.metadata.tables)
    with engine.begin() as c:
        c.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))
    from app.services import sla

    sla.invalidate()  # the cached SLA policy would otherwise survive the truncation
    yield


@pytest.fixture
def db():
    from app.core.db import SessionLocal

    with SessionLocal() as s:
        yield s


@pytest.fixture
def client():
    from app.main import app

    with TestClient(app) as c:
        yield c


def make_user(db, email: str, role: str):
    from app.core.security import hash_password
    from app.models import User

    u = User(
        email=email, full_name=email.split("@")[0].title(), role=role, password_hash=hash_password(PASSWORD)
    )
    db.add(u)
    db.commit()
    return u


def login(client, email: str) -> dict[str, str]:
    r = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture
def users(db):
    return {
        role: make_user(db, f"{role}@test.io", role) for role in ("admin", "manager", "analyst", "viewer")
    }


@pytest.fixture
def auth(client, users):
    return {role: login(client, f"{role}@test.io") for role in users}


def sample(name: str) -> bytes:
    return (REPORT_FIXTURES / name).read_bytes()


@pytest.fixture
def count_queries():
    """Counts SQL statements run inside the block: `with count_queries() as n: ...; n()`.

    For pinning N+1 fixes: an endpoint whose query count grows with the number of rows it touches is
    the bug, whatever its wall-clock time on a test database looks like."""
    from contextlib import contextmanager

    from sqlalchemy import event

    from app.core.db import engine

    @contextmanager
    def counting():
        seen: list[str] = []

        def record(conn, cursor, statement, *args):
            if not statement.lstrip().upper().startswith(("SAVEPOINT", "RELEASE")):
                seen.append(statement)

        event.listen(engine, "before_cursor_execute", record)
        try:
            yield lambda: len(seen)
        finally:
            event.remove(engine, "before_cursor_execute", record)

    return counting
