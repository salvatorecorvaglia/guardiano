"""Email delivery and the messages Guardiano sends.

Nothing is sent unless ``SMTP_HOST`` is configured: on a stock install every email feature is simply
inactive, and the UI hides it. Sending happens in the worker through the ``email.send`` job, so a slow or
unreachable mail server never blocks a request, and a failure is retried like any other job.

Messages are plain text with an HTML twin. They carry no secrets beyond the password-reset link itself.
"""

import html
import logging
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any

from app.core.config import settings

log = logging.getLogger(__name__)

SEND_JOB = "email.send"


@dataclass(frozen=True)
class Message:
    subject: str
    text: str
    html: str

    def as_payload(self, to: str) -> dict[str, Any]:
        return {"to": to, "subject": self.subject, "text": self.text, "html": self.html}


def enabled() -> bool:
    return settings.email_enabled


def send(to: str, subject: str, text: str, html_body: str | None = None) -> None:
    """Send one message synchronously. Raises on failure so the job queue retries."""
    if not enabled():
        log.warning("email not sent (SMTP_HOST is not configured): %s", subject)
        return
    message = EmailMessage()
    message["From"] = settings.smtp_from
    message["To"] = to
    message["Subject"] = subject
    message.set_content(text)
    if html_body:
        message.add_alternative(html_body, subtype="html")

    timeout = settings.smtp_timeout
    if settings.smtp_security == "ssl":
        client: smtplib.SMTP = smtplib.SMTP_SSL(
            settings.smtp_host, settings.smtp_port, timeout=timeout, context=ssl.create_default_context()
        )
    else:
        client = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=timeout)
    with client:
        if settings.smtp_security == "starttls":
            client.starttls(context=ssl.create_default_context())
        if settings.smtp_user:
            client.login(settings.smtp_user, settings.smtp_password)
        client.send_message(message)
    log.info("email sent to %s: %s", to, subject)


# ---- messages -----------------------------------------------------------------------------------


def _link(path: str) -> str | None:
    base = (settings.public_url or "").rstrip("/")
    return f"{base}{path}" if base else None


def _wrap(title: str, body_html: str) -> str:
    return (
        '<div style="font-family:system-ui,sans-serif;font-size:14px;color:#111">'
        f"<h2 style='font-size:16px'>{html.escape(title)}</h2>{body_html}"
        '<p style="color:#666;font-size:12px">Sent by Guardiano.</p></div>'
    )


def password_reset(token: str, ttl_minutes: int) -> Message:
    link = _link(f"/reset-password?token={token}")
    where = link or f"the reset page, using this code: {token}"
    text = (
        "Someone asked to reset your Guardiano password.\n\n"
        f"{'Open this link to choose a new one:' if link else 'Use this to choose a new one:'}\n{where}\n\n"
        f"The link stops working in {ttl_minutes} minutes and can be used once.\n"
        "If this was not you, you can ignore this email: nothing has changed."
    )
    body = (
        "<p>Someone asked to reset your Guardiano password.</p>"
        + (
            f'<p><a href="{html.escape(link)}">Choose a new password</a></p>'
            if link
            else f"<p>Reset code: <code>{html.escape(token)}</code></p>"
        )
        + f"<p>The link stops working in {ttl_minutes} minutes and can be used once. "
        "If this was not you, ignore this email: nothing has changed.</p>"
    )
    return Message("Reset your Guardiano password", text, _wrap("Reset your password", body))


def assignment(finding: dict[str, Any], actor: str) -> Message:
    title = finding.get("title") or "A finding"
    severity = str(finding.get("severity", "")).upper()
    asset = finding.get("asset") or "an asset"
    url = finding.get("url")
    due = f"\nDue: {finding['due_at'][:10]}" if finding.get("due_at") else ""
    text = f"{actor} assigned a finding to you.\n\n{severity}: {title}\nAsset: {asset}{due}\n" + (
        f"\n{url}\n" if url else ""
    )
    due_html = f"<br>Due: {finding['due_at'][:10]}" if finding.get("due_at") else ""
    body = (
        f"<p><strong>{html.escape(actor)}</strong> assigned a finding to you.</p>"
        f"<p><strong>{html.escape(severity)}</strong>: {html.escape(str(title))}<br>"
        f"Asset: {html.escape(str(asset))}{due_html}</p>"
        + (f'<p><a href="{html.escape(url)}">Open in Guardiano</a></p>' if url else "")
    )
    return Message(
        f"[Guardiano] {severity}: {title}"[:200], text, _wrap("A finding was assigned to you", body)
    )


def digest(period: str, rows: dict[str, list[dict[str, Any]]], assignee_id: int) -> Message:
    """`rows` holds the sections: assigned, overdue and due_soon findings."""
    sections = [
        ("Assigned to you", rows.get("assigned", [])),
        ("Past their deadline", rows.get("overdue", [])),
        ("Due within a week", rows.get("due_soon", [])),
    ]
    lines, body = [], []
    for heading, items in sections:
        if not items:
            continue
        lines.append(f"{heading} ({len(items)})")
        body.append(f"<h3 style='font-size:14px'>{heading} ({len(items)})</h3><ul>")
        for f in items[:10]:
            label = f"{str(f.get('severity', '')).upper()}: {f.get('title')} — {f.get('asset')}"
            lines.append(f"  - {label}")
            link = f.get("url")
            escaped = html.escape(label)
            body.append(f"<li>{f'<a href="{html.escape(link)}">{escaped}</a>' if link else escaped}</li>")
        if len(items) > 10:
            lines.append(f"  … and {len(items) - 10} more")
            body.append(f"<li>… and {len(items) - 10} more</li>")
        lines.append("")
        body.append("</ul>")

    # Straight to this person's own open findings.
    link = _link(f"/findings?assignee_id={assignee_id}&status=open&status=in_progress")
    text = f"Your {period} Guardiano summary.\n\n" + "\n".join(lines)
    if link:
        text += f"\nOpen Guardiano: {link}\n"
    title = f"Your {period} security summary"
    return Message(f"[Guardiano] {title}", text, _wrap(title, "".join(body)))
