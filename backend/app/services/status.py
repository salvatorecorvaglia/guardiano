"""A status change people make, with everything that follows it.

``lifecycle.set_status`` changes the finding and records the event. A change a person makes also tells the
linked tickets and the webhooks; that is here, so the findings API and risk-acceptance approval
(services/acceptance.py) cannot drift apart. Changes scans and rules make do not announce themselves.
"""

from datetime import datetime

from sqlalchemy.orm import Session

from app.models import Finding, User
from app.models.enums import Status
from app.services import events, lifecycle, tickets
from app.services.serializers import finding_payload


def change(
    db: Session,
    finding: Finding,
    target: Status,
    *,
    actor: User,
    justification: str | None,
    risk_accepted_until: datetime | None = None,
    hooks: dict | None = None,
) -> bool:
    """Apply the change and announce it. Permissions and validation are the caller's. False if unchanged."""
    previous = finding.status
    if not lifecycle.set_status(
        db, finding, target, actor=actor, justification=justification, risk_accepted_until=risk_accepted_until
    ):
        return False
    who = actor.full_name or actor.email
    tickets.queue_status_sync(db, finding, previous, who)
    events.emit(
        db,
        events.FINDING_STATUS_CHANGED,
        finding_payload(finding, previous_status=previous, actor=who, justification=justification),
        asset_id=finding.asset_id,
        severity=finding.severity,
        cache=hooks,
    )
    return True
