"""In-app notifications: the bell in the header.

A notification is written in the same transaction as the change it is about, and only to somebody who can
see that finding's asset (services/scope.py); the list is narrowed by scope again when read, so leaving a
team hides what was about its assets. Nobody is notified of their own action.
"""

import re
from collections.abc import Iterable
from datetime import timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.models import Finding, Notification, User
from app.models.base import utcnow
from app.models.enums import ROLE_RANK, Role
from app.services.scope import ScopeCache

# "@someone@example.com": the directory is small and emails are unique, so an address is the handle.
MENTION = re.compile(r"(?<![\w.+-])@([\w.+-]+@[\w-]+(?:\.[\w-]+)+)")
READ_RETENTION = timedelta(days=90)


def _title(finding: Finding) -> str:
    return finding.title if len(finding.title) <= 120 else finding.title[:119] + "…"


def notify(
    db: Session,
    users: Iterable[User],
    kind: str,
    finding: Finding,
    text: str,
    *,
    actor: User | None = None,
    scopes: ScopeCache | None = None,
) -> int:
    """Notify each active user who can see the finding, except the actor. Returns how many."""
    scopes = scopes or ScopeCache(db)
    sent = 0
    seen: set[int] = set()
    for user in users:
        if user is None or user.id in seen or not user.is_active:
            continue
        if actor is not None and user.id == actor.id:
            continue
        seen.add(user.id)
        if not scopes.scope(user).owns(finding.asset):
            continue
        db.add(
            Notification(
                user_id=user.id,
                kind=kind,
                finding_id=finding.id,
                actor_id=actor.id if actor else None,
                text=f"{text[:360]} — {_title(finding)}",
            )
        )
        sent += 1
    return sent


def mentioned(db: Session, text: str) -> list[User]:
    emails = {m.lower() for m in MENTION.findall(text or "")}
    if not emails:
        return []
    return list(db.scalars(select(User).where(User.email.in_(sorted(emails)), User.is_active.is_(True))))


def managers(db: Session) -> list[User]:
    """Everybody who can decide a risk-acceptance request."""
    ranked = [r.value for r in Role if ROLE_RANK[r] >= ROLE_RANK[Role.manager]]
    return list(db.scalars(select(User).where(User.role.in_(ranked), User.is_active.is_(True))))


def prune(db: Session) -> int:
    """Read notifications are kept for READ_RETENTION; unread ones until they are read."""
    cutoff = utcnow() - READ_RETENTION
    return db.execute(delete(Notification).where(Notification.read_at < cutoff)).rowcount or 0
