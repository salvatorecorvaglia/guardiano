"""System audit log: who changed users, assets, tokens and configuration, and when.

Entries are added to the caller's transaction, so an action and its audit record commit (or roll back)
together. Secrets are never recorded: password changes appear as ``"password": "changed"``.
"""

from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from app.models import AuditLog, User
from app.models.base import utcnow


def client_ip(request: Request | None) -> str | None:
    # nginx forwards one verified client address and gunicorn trusts it.
    return request.client.host if request is not None and request.client else None


def snapshot(obj: object, fields: tuple[str, ...]) -> dict[str, Any]:
    return {f: getattr(obj, f) for f in fields}


def diff(before: dict[str, Any], obj: object) -> dict[str, Any]:
    """``{field: {"from": old, "to": new}}`` for every field in ``before`` whose value changed on ``obj``."""
    out = {}
    for f, old in before.items():
        new = getattr(obj, f)
        if new != old:
            out[f] = {"from": _jsonable(old), "to": _jsonable(new)}
    return out


def _jsonable(v: Any) -> Any:
    if isinstance(v, str | int | float | bool) or v is None:
        return v
    if isinstance(v, list | tuple):
        return [_jsonable(x) for x in v]
    return str(v)


def record(
    db: Session,
    action: str,
    *,
    actor: User | None,
    request: Request | None = None,
    target_type: str | None = None,
    target_id: int | None = None,
    target_label: str | None = None,
    changes: dict[str, Any] | None = None,
) -> AuditLog:
    entry = AuditLog(
        actor_id=actor.id if actor else None,
        actor_email=actor.email if actor else None,
        action=action,
        target_type=target_type,
        target_id=target_id,
        target_label=(target_label or "")[:320] or None,
        changes=changes or {},
        ip=client_ip(request),
        created_at=utcnow(),
    )
    db.add(entry)
    return entry
