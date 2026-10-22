"""Start a real API for Playwright against a separate, disposable database."""

import os

os.environ["DATABASE_URL"] = os.environ.get(
    "BROWSER_DATABASE_URL", "postgresql+psycopg://guardiano:guardiano@localhost:5432/guardiano_browser_test"
)
os.environ["ENV"] = "test"
os.environ["MFA_ENFORCED_ROLES"] = "manager"
os.environ["SMTP_HOST"] = ""
os.environ["GUARDIANO_ADMIN_EMAIL"] = "browser@example.test"
os.environ["GUARDIANO_ADMIN_PASSWORD"] = "Browser-Smoke-Password-2026!"

if __name__ == "__main__":
    import uvicorn
    from sqlalchemy import create_engine, text
    from sqlalchemy.engine import make_url

    from app.core.db import SessionLocal
    from app.core.schema import initialize_schema
    from app.core.testdb import validate_test_database
    from app.services.bootstrap import ensure_admin

    url = os.environ["DATABASE_URL"]
    validate_test_database(url)
    parsed = make_url(url)
    admin = create_engine(parsed.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        if not connection.scalar(
            text("SELECT 1 FROM pg_database WHERE datname=:name"), {"name": parsed.database}
        ):
            connection.execute(text(f'CREATE DATABASE "{parsed.database}"'))
    admin.dispose()
    initialize_schema()
    with SessionLocal() as db:
        ensure_admin(db)
    uvicorn.run("app.main:app", host="127.0.0.1", port=8009)
