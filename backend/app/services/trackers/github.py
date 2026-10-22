"""GitHub Issues (github.com and GitHub Enterprise)."""

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
    return {
        "Authorization": f"Bearer {token(integration)}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _segment(value: str) -> str:
    """One path segment. Nothing interpolated into a URL path may introduce '/' or dot segments:
    httpx normalises '..' per RFC 3986, which would otherwise walk out of /repos/<project>."""
    return quote(str(value), safe="")


def _api(integration: Integration, path: str = "") -> str:
    base = (integration.base_url or "https://api.github.com").rstrip("/")
    # The project is "owner/repo", so its separator is kept while everything else is encoded.
    project = "/".join(_segment(p) for p in integration.project.split("/"))
    return f"{base}/repos/{project}{path}"


def check(integration: Integration) -> str:
    repo = request("GET", _api(integration), headers=_headers(integration))
    if not repo.get("has_issues", True):
        raise TrackerError(f"Issues are disabled on {integration.project}")
    return f"{repo.get('full_name', integration.project)} (issues enabled)"


def create_issue(integration: Integration, finding: Finding) -> Ticket:
    title, body = describe(finding)
    payload = {"title": title, "body": body}
    if integration.labels:
        payload["labels"] = list(integration.labels)
    issue = request("POST", _api(integration, "/issues"), headers=_headers(integration), json=payload)
    number = issue.get("number")
    if not number:
        raise TrackerError("GitHub did not return an issue number")
    return Ticket(key=f"#{number}", url=issue.get("html_url", ""), status=issue.get("state"))


def comment(integration: Integration, key: str, text: str) -> None:
    number = key.lstrip("#")
    request(
        "POST",
        _api(integration, f"/issues/{_segment(number)}/comments"),
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
        "PATCH",
        _api(integration, f"/issues/{_segment(key.lstrip('#'))}"),
        headers=_headers(integration),
        json={"state": "closed"},
    )
    return True


def reopen(integration: Integration, key: str) -> bool:
    request(
        "PATCH",
        _api(integration, f"/issues/{_segment(key.lstrip('#'))}"),
        headers=_headers(integration),
        json={"state": "open"},
    )
    return True


# ---- commit and pull-request feedback ------------------------------------------------------------

STATES = {"success": "success", "failure": "failure", "pending": "pending"}


def commit_status(
    integration: Integration, sha: str, state: str, description: str, target_url: str | None, context: str
) -> None:
    """A commit status, which is what branch protection reads."""
    payload = {
        "state": STATES.get(state, "success"),
        "description": description[:140],  # GitHub truncates at 140 characters
        "context": context,
    }
    if target_url:
        payload["target_url"] = target_url
    request(
        "POST", _api(integration, f"/statuses/{_segment(sha)}"), headers=_headers(integration), json=payload
    )


def find_open_pr(integration: Integration, branch: str) -> str | None:
    """The open pull request whose head is this branch, when there is exactly one."""
    owner = integration.project.split("/")[0]
    found = request(
        "GET",
        _api(integration, f"/pulls?state=open&head={quote(owner, safe='')}:{quote(branch, safe='')}"),
        headers=_headers(integration),
    )
    items = found.get("items", found if isinstance(found, list) else [])
    return str(items[0]["number"]) if len(items) == 1 else None


def comment_on_pr(integration: Integration, number: str, text: str) -> str | None:
    """Post a comment on a pull request; returns its id, for update_pr_comment."""
    created = request(
        "POST",
        _api(integration, f"/issues/{_segment(number)}/comments"),
        headers=_headers(integration),
        json={"body": text},
    )
    return str(created["id"]) if created.get("id") else None


def update_pr_comment(integration: Integration, number: str, comment_id: str, text: str) -> None:
    # Issue and pull-request comments share one id space on GitHub; the number is not part of the path.
    request(
        "PATCH",
        _api(integration, f"/issues/comments/{_segment(comment_id)}"),
        headers=_headers(integration),
        json={"body": text},
    )


def find_issue(integration: Integration, marker: str) -> Ticket | None:
    found = request(
        "GET",
        (integration.base_url or "https://api.github.com").rstrip("/") + "/search/issues",
        headers=_headers(integration),
        params={"q": f"repo:{integration.project} {marker} in:body"},
    )
    matches = [
        item for item in found.get("items", []) if has_operation_marker(item.get("body") or "", marker)
    ]
    if len(matches) > 1:
        raise TrackerError("Several issues match the ticket operation; reconcile manually")
    if matches:
        item = matches[0]
        return Ticket(key=f"#{item['number']}", url=item.get("html_url", ""), status=item.get("state"))
    return None
