"""Housekeeping: forgetting what is no longer worth keeping.

Every retention setting is **off by default** (``0`` days), because deleting history is not a decision a
tool should make on an operator's behalf. Switch on what your policy requires.

What is safe to prune, and why:

- **Scans** are the record of an upload. Deleting one leaves its findings untouched — ``findings`` keeps
  its own ``first_seen_at``/``last_seen_at``, and the foreign keys to the scan are ``ON DELETE SET NULL``
  (``first_scan_id``, ``last_scan_id``, ``finding_events.scan_id``), so only the link is lost, never the
  finding or its history. Each asset's most recent real scan is **always kept**, however old, so "last
  scanned" never goes blank and the next ``close_missing`` still has its baseline. Previews are not
  baselines, so they are prunable to the last one.
- **Webhook deliveries** are a debugging trail for something already delivered.
- **The audit log** is the one an auditor asks for. It is prunable because some policies require it, but
  it is the last thing to switch on.

Finding events are never pruned: they are the finding's own history, and a finding without its history is
worse than no record at all.
"""

import logging
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import AuditLog, Scan, WebhookDelivery
from app.models.base import utcnow
from app.services import sessions
from app.services.sbom import latest_inventory_scans

log = logging.getLogger(__name__)


def _cutoff(days: int, now: datetime | None = None) -> datetime:
    return (now or utcnow()) - timedelta(days=days)


def prune_scans(db: Session, days: int, now: datetime | None = None) -> int:
    """Delete scans older than ``days``, never the newest real scan of an asset."""
    if days <= 0:
        return 0
    # Keep a baseline per scanner/type, including the explicit empty inventories.
    keep = select(func.max(Scan.id)).where(Scan.source != "preview").group_by(
        Scan.asset_id, Scan.tool_name, Scan.scan_type
    )
    return db.execute(delete(Scan).where(
        Scan.created_at < _cutoff(days, now), Scan.id.not_in(keep),
        Scan.id.not_in(latest_inventory_scans()),
    )).rowcount


def prune_deliveries(db: Session, days: int, now: datetime | None = None) -> int:
    if days <= 0:
        return 0
    return db.execute(delete(WebhookDelivery).where(WebhookDelivery.created_at < _cutoff(days, now))).rowcount


def prune_audit_log(db: Session, days: int, now: datetime | None = None) -> int:
    if days <= 0:
        return 0
    return db.execute(delete(AuditLog).where(AuditLog.created_at < _cutoff(days, now))).rowcount


def run(db: Session, now: datetime | None = None) -> dict[str, int]:
    """Apply every configured retention rule. Returns what was removed, for logging and the CLI."""
    removed = {
        "scans": prune_scans(db, settings.retention_scan_days, now),
        "webhook_deliveries": prune_deliveries(db, settings.retention_delivery_days, now),
        "audit_log": prune_audit_log(db, settings.retention_audit_days, now),
        # Not configurable: once a revoked token has expired on its own, the record of it is dead
        # weight, and keeping it changes nothing about who can sign in.
        "revoked_tokens": sessions.prune(db),
    }
    if any(removed.values()):
        log.info("retention removed %s", ", ".join(f"{n} {k}" for k, n in removed.items() if n))
    return removed
