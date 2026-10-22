import logging

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import hash_password
from app.models import User
from app.models.enums import Role

log = logging.getLogger(__name__)

# The value shipped in .env.example; never acceptable for a production deployment.
EXAMPLE_ADMIN_PASSWORD = "ChangeMe-Admin-2026!"


def ensure_admin(db: Session) -> None:
    """Create the first administrator from env vars when the users table is empty."""
    if db.scalar(select(func.count()).select_from(User)):
        return
    email, password = settings.guardiano_admin_email, settings.guardiano_admin_password
    if not email or not password:
        log.warning(
            "No users exist. Set GUARDIANO_ADMIN_EMAIL/GUARDIANO_ADMIN_PASSWORD or run "
            "`python -m app.cli create-admin` to create the first administrator."
        )
        return
    if len(password) < 12:
        raise SystemExit("GUARDIANO_ADMIN_PASSWORD must be at least 12 characters")
    if settings.env == "production" and password == EXAMPLE_ADMIN_PASSWORD:
        raise SystemExit("GUARDIANO_ADMIN_PASSWORD is still the example value; set a unique password")
    db.add(
        User(
            email=email.lower(),
            full_name="Administrator",
            password_hash=hash_password(password),
            role=Role.admin.value,
        )
    )
    db.commit()
    log.info("bootstrap administrator %s created", email)
