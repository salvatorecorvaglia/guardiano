"""Webhook delivery: payload shapes, signing and the HTTP call.

Every request carries two signatures, so a receiver can verify it came from this Guardiano unmodified:

- ``X-Guardiano-Signature-256: t=<unix time>,v1=<hmac>``, an HMAC over ``"<t>." + body``. Binding the time
  lets a receiver refuse a captured request replayed later. Prefer this one.
- ``X-Guardiano-Signature: sha256=<hmac>`` over the body alone, kept for receivers written against it.

The Slack and Teams formats send what those services expect instead of the generic envelope; the
signatures are still present.

Delivery runs in the worker and is retried by the job queue, so a receiver that is briefly down does not lose
an event.
"""

import hashlib
import hmac
import json
import logging
import time
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.urlguard import BlockedURL, check_url, guarded_stream
from app.models import Webhook, WebhookDelivery
from app.models.base import utcnow
from app.parsers.base import truncate

log = logging.getLogger(__name__)

FORMATS = ("guardiano", "slack", "teams")
TIMEOUT = 10.0
_ERROR_LIMIT = 500
_SEVERITY_EMOJI = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜"}


def sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def sign_timestamped(secret: str, timestamp: int, body: bytes) -> str:
    digest = hmac.new(secret.encode(), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={digest}"


def envelope(delivery: WebhookDelivery) -> dict[str, Any]:
    from app import __version__

    return {
        "event": delivery.event,
        "delivery_id": delivery.id,
        "sent_at": utcnow().isoformat(),
        "guardiano_version": __version__,
        "data": delivery.payload or {},
    }


def _summary(event: str, data: dict[str, Any]) -> tuple[str, list[tuple[str, str]]]:
    """A title and label/value pairs, shared by the Slack and Teams renderings."""
    asset = data.get("asset") or "—"
    if event == "scan.completed":
        counts = data.get("counts") or {}
        preview = " (preview)" if data.get("preview") else ""
        return (
            f"Scan #{data.get('scan_id')} of {asset}{preview}",
            [
                ("Tool", str(data.get("tool") or "—")),
                ("New", str(counts.get("new", 0))),
                ("Reopened", str(counts.get("reopened", 0))),
                ("Resolved", str(counts.get("auto_resolved", 0))),
                ("Branch", str(data.get("branch") or "—")),
            ],
        )
    if event == "gate.failed":
        violations = data.get("violations") or []
        return (
            f"Quality gate failed on {asset}",
            [("Scan", f"#{data.get('scan_id')}"), *[("•", str(v)) for v in violations[:5]]],
        )
    titles = {
        "finding.reopened": "Finding reopened",
        "finding.status_changed": "Finding status changed",
        "finding.assigned": "Finding assigned",
        "finding.risk_acceptance_expiring": "Risk acceptance ending soon",
        "finding.kev_added": "Now known to be exploited",
        "sla.breached": "Finding past its SLA",
    }
    if event in titles:
        rows = [
            ("Asset", str(asset)),
            ("Severity", str(data.get("severity") or "—")),
            ("Status", str(data.get("status") or "—")),
        ]
        if event == "finding.assigned":
            rows.append(("Assigned to", str(data.get("assignee") or "nobody")))
        if event == "finding.risk_acceptance_expiring":
            rows.append(("Accepted until", str(data.get("risk_accepted_until") or "—")))
        if event == "finding.kev_added":
            rows.append(("CVE", str(data.get("cve") or "—")))
        if data.get("actor"):
            rows.append(("By", str(data["actor"])))
        if data.get("due_at"):
            rows.append(("Due", str(data["due_at"])))
        return f"{titles[event]}: {data.get('title') or ''}", rows
    return f"Guardiano {event}", [(k, str(v)) for k, v in list(data.items())[:5]]


def render(webhook: Webhook, delivery: WebhookDelivery) -> dict[str, Any]:
    data = delivery.payload or {}
    body = envelope(delivery)
    if webhook.format == "guardiano":
        return body

    title, rows = _summary(delivery.event, data)
    emoji = _SEVERITY_EMOJI.get(str(data.get("severity")), "🔔")
    if webhook.format == "slack":
        lines = "\n".join(f"*{k}*: {v}" for k, v in rows)
        block_text = f"{emoji} *{title}*\n{lines}"
        blocks: list[dict[str, Any]] = [{"type": "section", "text": {"type": "mrkdwn", "text": block_text}}]
        if url := data.get("url"):
            blocks.append(
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Open in Guardiano"},
                            "url": url,
                        }
                    ],
                }
            )
        return {"text": f"{emoji} {title}", "blocks": blocks}

    # Microsoft Teams: an Adaptive Card inside the connector envelope.
    card: dict[str, Any] = {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.4",
        "body": [
            {"type": "TextBlock", "text": f"{emoji} {title}", "weight": "Bolder", "wrap": True},
            {"type": "FactSet", "facts": [{"title": k, "value": v} for k, v in rows]},
        ],
    }
    if url := data.get("url"):
        card["actions"] = [{"type": "Action.OpenUrl", "title": "Open in Guardiano", "url": url}]
    return {
        "type": "message",
        "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}],
    }


def _post(url: str, body: bytes, headers: dict[str, str]) -> tuple[int, str | None]:
    """Perform the request. Separated so tests can drive delivery without a network."""
    try:
        check_url(url)  # re-checked here: the name may resolve elsewhere than when it was stored
    except BlockedURL as exc:
        return 0, str(exc)
    try:
        # Streamed and never read: only the status matters, and a receiver answering with an endless
        # or enormous body would otherwise be buffered into the worker's memory in full.
        with guarded_stream(
            "POST", url, content=body, headers=headers, timeout=TIMEOUT, follow_redirects=False
        ) as response:
            return response.status_code, None
    except (httpx.HTTPError, BlockedURL) as exc:
        return 0, f"{type(exc).__name__}: {exc}"


def deliver(delivery: WebhookDelivery, webhook: Webhook) -> tuple[int, str | None]:
    """Send one delivery. Returns (status_code, error); a non-2xx status is an error for the caller."""
    try:
        secret = webhook.secret
    except ValueError:  # encrypted under a SECRET_KEY/INTEGRATIONS_KEY that has since changed
        return 0, "The signing secret cannot be decrypted with the current SECRET_KEY; rotate it"
    body = json.dumps(render(webhook, delivery), default=str).encode()
    # Taken per attempt, so a retry is signed for the moment it is sent.
    timestamp = int(time.time())
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Guardiano-Webhook/1",
        "X-Guardiano-Event": delivery.event,
        "X-Guardiano-Delivery": str(delivery.id),
        "X-Guardiano-Timestamp": str(timestamp),
        "X-Guardiano-Signature-256": sign_timestamped(secret, timestamp, body),
        "X-Guardiano-Signature": sign(secret, body),
    }
    status, error = _post(webhook.url, body, headers)
    if error is None and not 200 <= status < 300:
        error = f"HTTP {status}"
    return status, truncate(error, _ERROR_LIMIT)


def encrypt_legacy_secrets(db: Session) -> int:
    """Encrypt legacy plaintext secrets. Idempotent; run at startup.

    Runs in the application with exactly the key that will decrypt the result.
    """
    hooks = db.scalars(select(Webhook).where(Webhook.secret_plaintext.is_not(None))).all()
    for hook in hooks:
        hook.secret = hook.secret_plaintext or ""
    if hooks:
        db.commit()
        log.info("encrypted the signing secret of %d webhook(s)", len(hooks))
    return len(hooks)
