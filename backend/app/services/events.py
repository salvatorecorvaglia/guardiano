"""Event fan-out to webhooks.

``emit`` records one delivery row per interested webhook and enqueues a job for each, inside the caller's
transaction. So an event is queued exactly when the change that caused it is committed, and a slow or broken
endpoint can never delay or fail an upload: the worker does the sending (services/webhooks.py).

Events, and what carries them:

| event                    | emitted when                                              |
|--------------------------|-----------------------------------------------------------|
| ``scan.completed``       | a report finished ingesting (previews included)            |
| ``gate.failed``          | that scan's quality gate failed                            |
| ``finding.reopened``     | a resolved finding was reported again                      |
| ``finding.status_changed`` | somebody changed a finding's status                      |
| ``finding.assigned``     | somebody assigned or unassigned a finding                  |
| ``finding.risk_acceptance_expiring`` | a risk acceptance ends within RISK_ACCEPTANCE_WARNING_DAYS |
| ``finding.kev_added``    | CISA added an active finding's CVE to its KEV catalogue    |
| ``sla.breached``         | a finding passed its remediation deadline (daily task)     |
| ``test``                 | the "Send test event" button                               |

New findings are reported inside ``scan.completed`` rather than one event each, so a first scan of a large
codebase cannot flood a chat channel. For the same reason ``finding.assigned`` is only sent for assignments
people make, not for the asset's default assignee taking every new finding.
"""

import logging
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models import Webhook, WebhookDelivery
from app.models.enums import SEVERITY_RANK
from app.services import jobs

log = logging.getLogger(__name__)

SCAN_COMPLETED = "scan.completed"
GATE_FAILED = "gate.failed"
FINDING_REOPENED = "finding.reopened"
FINDING_STATUS_CHANGED = "finding.status_changed"
FINDING_ASSIGNED = "finding.assigned"
RISK_ACCEPTANCE_EXPIRING = "finding.risk_acceptance_expiring"
KEV_ADDED = "finding.kev_added"
SLA_BREACHED = "sla.breached"
TEST = "test"

EVENTS = (
    SCAN_COMPLETED,
    GATE_FAILED,
    FINDING_REOPENED,
    FINDING_STATUS_CHANGED,
    FINDING_ASSIGNED,
    RISK_ACCEPTANCE_EXPIRING,
    KEV_ADDED,
    SLA_BREACHED,
    TEST,
)
DELIVER_JOB = "webhook.deliver"

# Some events are about the whole scan rather than one finding, so a severity filter must not drop them.
_UNFILTERED = {SCAN_COMPLETED, GATE_FAILED, TEST}


def subscribers(
    db: Session,
    event: str,
    *,
    asset_id: int | None = None,
    severity: str | None = None,
    cache: dict[tuple[str, int | None], list[Webhook]] | None = None,
) -> list[Webhook]:
    """``cache`` lets one operation over many findings look the webhooks up once per event and asset
    instead of once per finding. It is the caller's, so it lives exactly as long as that operation."""
    key = (event, asset_id)
    if cache is not None and key in cache:
        hooks = cache[key]
    else:
        hooks = db.scalars(
            select(Webhook).where(
                Webhook.enabled.is_(True),
                Webhook.events.contains([event]),
                or_(Webhook.asset_id.is_(None), Webhook.asset_id == asset_id),
            )
        ).all()
        if cache is not None:
            cache[key] = list(hooks)
    if severity is None or event in _UNFILTERED:
        return list(hooks)
    rank = SEVERITY_RANK.get(severity, 0)
    return [h for h in hooks if rank >= SEVERITY_RANK.get(h.min_severity, 0)]


def emit(
    db: Session,
    event: str,
    data: dict[str, Any],
    *,
    asset_id: int | None = None,
    severity: str | None = None,
    cache: dict[tuple[str, int | None], list[Webhook]] | None = None,
) -> list[WebhookDelivery]:
    """Queue ``event`` for every webhook that wants it. The caller commits."""
    deliveries = []
    for hook in subscribers(db, event, asset_id=asset_id, severity=severity, cache=cache):
        delivery = WebhookDelivery(webhook_id=hook.id, event=event, payload=data, attempts=0)
        db.add(delivery)
        db.flush()  # the job needs the delivery id
        jobs.enqueue(db, DELIVER_JOB, {"delivery_id": delivery.id})
        deliveries.append(delivery)
    if deliveries:
        log.info("event %s queued for %d webhook(s)", event, len(deliveries))
    return deliveries
