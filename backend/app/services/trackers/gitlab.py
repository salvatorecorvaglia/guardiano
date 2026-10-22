"""GitLab Issues (gitlab.com and self-managed)."""

from urllib.parse import quote

from app.models import Finding, Integration
from app.services.trackers.base import (
    RemoteState,
    Ticket,
    TrackerError,
    describe,
    has_operation_marker,
    request,
    token,
)


def _headers(integration: Integration) -> dict[str, str]:
    return {"PRIVATE-TOKEN": token(integration)}


def _segment(value: str) -> str:
    """One path segment. Nothing interpolated into a URL path may introduce '/' or dot segments:
    httpx normalises '..' per RFC 3986, which would otherwise walk out of /projects/<project>."""
    return quote(str(value), safe="")


def _api(integration: Integration, path: str = "") -> str:
    base = (integration.base_url or "https://gitlab.com").rstrip("/")
    # A project path has to be URL-encoded; a numeric id passes through unchanged.
    project = integration.project if integration.project.isdigit() else quote(integration.project, safe="")
    return f"{base}/api/v4/projects/{project}{path}"


def check(integration: Integration) -> str:
    project = request("GET", _api(integration), headers=_headers(integration))
    return f"{project.get('path_with_namespace', integration.project)}"


def create_issue(integration: Integration, finding: Finding) -> Ticket:
    title, body = describe(finding)
    payload = {"title": title, "description": body}
    if integration.labels:
        payload["labels"] = ",".join(integration.labels)
    issue = request("POST", _api(integration, "/issues"), headers=_headers(integration), json=payload)
    iid = issue.get("iid")
    if not iid:
        raise TrackerError("GitLab did not return an issue id")
    return Ticket(key=f"#{iid}", url=issue.get("web_url", ""), status=issue.get("state"))


def comment(integration: Integration, key: str, text: str) -> None:
    request(
        "POST",
        _api(integration, f"/issues/{_segment(key.lstrip('#'))}/notes"),
        headers=_headers(integration),
        json={"body": text},
    )


def fetch_status(integration: Integration, key: str) -> RemoteState:
    issue = request(
        "GET", _api(integration, f"/issues/{_segment(key.lstrip('#'))}"), headers=_headers(integration)
    )
    state = issue.get("state")
    return RemoteState(name=state, done=state == "closed")


def close(integration: Integration, key: str) -> bool:
    request(
        "PUT",
        _api(integration, f"/issues/{_segment(key.lstrip('#'))}"),
        headers=_headers(integration),
        json={"state_event": "close"},
    )
    return True


def reopen(integration: Integration, key: str) -> bool:
    request(
        "PUT",
        _api(integration, f"/issues/{_segment(key.lstrip('#'))}"),
        headers=_headers(integration),
        json={"state_event": "reopen"},
    )
    return True


# ---- commit and merge-request feedback -----------------------------------------------------------

STATES = {"success": "success", "failure": "failed", "pending": "running"}


def commit_status(
    integration: Integration, sha: str, state: str, description: str, target_url: str | None, context: str
) -> None:
    payload = {
        "state": STATES.get(state, "success"),
        "description": description[:255],
        "name": context,
    }
    if target_url:
        payload["target_url"] = target_url
    request(
        "POST", _api(integration, f"/statuses/{_segment(sha)}"), headers=_headers(integration), json=payload
    )


def find_open_pr(integration: Integration, branch: str) -> str | None:
    """The open merge request from this source branch, when there is exactly one."""
    found = request(
        "GET",
        _api(integration, f"/merge_requests?state=opened&source_branch={quote(branch, safe='')}"),
        headers=_headers(integration),
    )
    items = found.get("items", found if isinstance(found, list) else [])
    return str(items[0]["iid"]) if len(items) == 1 else None


def comment_on_pr(integration: Integration, number: str, text: str) -> str | None:
    """Post a note on a merge request; returns its id, for update_pr_comment."""
    created = request(
        "POST",
        _api(integration, f"/merge_requests/{_segment(number)}/notes"),
        headers=_headers(integration),
        json={"body": text},
    )
    return str(created["id"]) if created.get("id") else None


def update_pr_comment(integration: Integration, number: str, comment_id: str, text: str) -> None:
    request(
        "PUT",
        _api(integration, f"/merge_requests/{_segment(number)}/notes/{_segment(comment_id)}"),
        headers=_headers(integration),
        json={"body": text},
    )


def find_issue(integration: Integration, marker: str) -> Ticket | None:
    found = request(
        "GET",
        _api(integration, "/issues"),
        headers=_headers(integration),
        params={"search": marker, "in": "description", "scope": "all"},
    )
    matches = [
        item for item in found.get("items", []) if has_operation_marker(item.get("description") or "", marker)
    ]
    if len(matches) > 1:
        raise TrackerError("Several issues match the ticket operation; reconcile manually")
    if matches:
        item = matches[0]
        return Ticket(key=f"#{item['iid']}", url=item.get("web_url", ""), status=item.get("state"))
    return None
