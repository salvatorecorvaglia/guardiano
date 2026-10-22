"""Per-account lockout after repeated failed sign-ins.

The rate limit in ``core/ratelimit.py`` is keyed on the client address and held in the memory of one
gunicorn worker, so with ``WEB_CONCURRENCY`` workers the configured limit is really that many times
looser, it resets on every restart, and it does nothing at all about an attack spread across many
addresses. This counter is per account and lives in the database, which is the shape the threat
actually has: many addresses, one password.

The lock is deliberately short and doubles with each further failure, up to a cap. A fixed long lock
would hand anyone who knows an address a way to keep its owner out; a doubling one costs an attacker
progressively more while a real person who mistyped their password waits seconds, not hours.
"""

from datetime import timedelta

from app.core.config import settings
from app.models import User
from app.models.base import utcnow


def is_locked(user: User | None) -> bool:
    return bool(user and user.locked_until and user.locked_until > utcnow())


def _lock_for(failures: int) -> timedelta:
    over = failures - settings.login_max_failures
    seconds = settings.login_lockout_seconds * (2 ** max(over, 0))
    return timedelta(seconds=min(seconds, settings.login_lockout_max_seconds))


def record_failure(user: User | None) -> None:
    """Count a wrong password. Does nothing while already locked, so an attacker cannot keep
    extending a lock on somebody else's account by carrying on guessing."""
    if user is None or is_locked(user):
        return
    user.failed_logins = (user.failed_logins or 0) + 1
    if user.failed_logins >= settings.login_max_failures:
        user.locked_until = utcnow() + _lock_for(user.failed_logins)


def record_success(user: User) -> None:
    user.failed_logins = 0
    user.locked_until = None
