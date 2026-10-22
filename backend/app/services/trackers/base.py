"""Shared pieces of the issue-tracker providers.

Every HTTP call goes through ``request`` so that timeouts, error handling and tests have one place to work
with. Providers translate a finding into whatever their API wants and return a :class:`Ticket`.
"""

import json
import logging
import re
from dataclasses import dataclass
from typing import Any

import httpx

from app.core.config import settings
from app.core.crypto import decrypt
from app.core.urlguard import BlockedURL, TooLarge, check_url, guarded_stream, read_capped
from app.models import Finding, Integration
from app.models.enums import TRACKER_KINDS

log = logging.getLogger(__name__)

KINDS = TRACKER_KINDS
# A single issue or a page of pull requests is kilobytes; anything near this is not a tracker answering.
_MAX_RESPONSE = 5 * 1024 * 1024


@dataclass(frozen=True)
class RemoteState:
    """What a tracker says about a ticket now.

    ``name`` is the tracker's own word for it, shown to people as-is. ``done`` is the only thing code
    decides on, because "finished" is spelled differently in every tracker — and in Jira, differently in
    every project, which is why its status *category* is read rather than the status name.
    """

    name: str | None = None
    done: bool = False


class TrackerError(RuntimeError):
    """The tracker refused the request, or could not be reached."""

    def __init__(self, message: str, *, definitely_not_created: bool = False):
        super().__init__(message)
        self.definitely_not_created = definitely_not_created


@dataclass(frozen=True)
class Ticket:
    key: str
    url: str
    status: str | None = None


def token(integration: Integration) -> str:
    return decrypt(integration.secret_encrypted)


def request(method: str, url: str, **kwargs: Any) -> dict[str, Any]:
    """One call to a tracker API. Raises TrackerError with a readable message on any failure."""
    try:
        check_url(url)
    except BlockedURL as exc:
        raise TrackerError(str(exc), definitely_not_created=True)
    try:
        with guarded_stream(method, url, timeout=settings.tracker_timeout, **kwargs) as response:
            status = response.status_code
            raw = read_capped(response, _MAX_RESPONSE)
    except TooLarge:
        raise TrackerError(f"Tracker response was larger than {_MAX_RESPONSE // (1024 * 1024)} MB")
    except (httpx.HTTPError, BlockedURL) as exc:
        safe = isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout, BlockedURL))
        raise TrackerError(
            f"Could not reach the tracker: {type(exc).__name__}",
            definitely_not_created=safe,
        ) from exc
    if status >= 400:
        # Upstream bodies can contain credentials or private diagnostics; retain only the status.
        log.warning(
            "tracker returned an error",
            extra={"status": status},
        )
        raise TrackerError(
            f"Tracker returned HTTP {status}",
            definitely_not_created=status
            in {
                400,
                401,
                403,
                404,
                405,
                413,
                415,
                422,
                429,
            },
        )
    if not raw:
        return {}
    try:
        body = json.loads(raw)
    except ValueError:
        raise TrackerError("Tracker returned a response that is not JSON")
    return body if isinstance(body, dict) else {"items": body}


@dataclass(frozen=True)
class TicketContent:
    id: int
    title: str
    body: str


def describe(finding: Finding | TicketContent) -> tuple[str, str]:
    """The ticket's summary and body, in Markdown that Jira, GitHub and GitLab all render acceptably."""
    if isinstance(finding, TicketContent):
        return finding.title, finding.body
    # Imported here: serializers reads the finding schemas, which describe tracker links.
    from app.services.serializers import finding_payload

    payload = finding_payload(finding)
    title = f"[{finding.severity.upper()}] {finding.title}"[:250]
    where = (
        f"`{finding.file_path}`" + (f" line {finding.line_start}" if finding.line_start else "")
        if finding.file_path
        else f"`{finding.package_name}@{finding.package_version}`"
        if finding.package_name
        else "—"
    )
    rows = [
        ("Asset", finding.asset.name if finding.asset else "—"),
        ("Severity", finding.severity),
        ("Location", where),
        ("CWE", ", ".join(finding.cwe or []) or "—"),
        ("CVE", finding.cve_id or "—"),
        ("Fixed in", finding.fixed_version or "—"),
        ("Detected by", ", ".join(finding.tools or []) or "—"),
        ("Due", (payload.get("due_at") or "—")[:10]),
    ]
    body = [f"**{k}**: {v}" for k, v in rows if v != "—"]
    if finding.description:
        body.append(f"\n**Description**\n\n{finding.description[:4000]}")
    if finding.remediation:
        body.append(f"\n**Remediation**\n\n{finding.remediation[:4000]}")
    if url := payload.get("url"):
        body.append(f"\n[Open finding #{finding.id} in Guardiano]({url})")
    else:
        body.append(f"\nGuardiano finding #{finding.id}")
    body.append(
        f"\nGuardiano operation: guardiano-f{finding.id}-i{getattr(finding, '_ticket_integration_id', 0)}"
    )
    return title, "\n".join(body)


def has_operation_marker(text: str, marker: str) -> bool:
    """Search results may match prefixes; only accept the complete operation identifier."""
    return re.search(r"(?<![\w-])" + re.escape(marker) + r"(?![\w-])", text) is not None
