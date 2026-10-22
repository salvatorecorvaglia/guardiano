"""Jira Cloud and Data Center (REST v2: the same call works on both)."""

import base64
from typing import Any

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

# Jira renders its own wiki markup, not Markdown; bold and code spans survive, so keep it simple.
_DONE_CATEGORIES = {"done", "complete", "completed"}


def _auth(integration: Integration) -> dict[str, str]:
    if not integration.username:
        # Data Center personal access tokens authenticate as a bearer.
        return {"Authorization": f"Bearer {token(integration)}"}
    pair = f"{integration.username}:{token(integration)}".encode()
    return {"Authorization": "Basic " + base64.b64encode(pair).decode()}


def _api(integration: Integration, path: str) -> str:
    return f"{integration.base_url.rstrip('/')}/rest/api/2/{path.lstrip('/')}"


def check(integration: Integration) -> str:
    me = request("GET", _api(integration, "myself"), headers=_auth(integration))
    project = request("GET", _api(integration, f"project/{integration.project}"), headers=_auth(integration))
    who = me.get("displayName") or me.get("name") or "connected"
    return f"{who} → {project.get('name', integration.project)}"


def create_issue(integration: Integration, finding: Finding) -> Ticket:
    title, body = describe(finding)
    fields: dict[str, Any] = {
        "project": {"key": integration.project},
        "summary": title,
        "description": body,
        "issuetype": {"name": integration.issue_type or "Bug"},
    }
    if integration.labels:
        fields["labels"] = list(integration.labels)
    created = request("POST", _api(integration, "issue"), headers=_auth(integration), json={"fields": fields})
    key = created.get("key")
    if not key:
        raise TrackerError("Jira did not return an issue key")
    return Ticket(key=key, url=f"{integration.base_url.rstrip('/')}/browse/{key}")


def comment(integration: Integration, key: str, text: str) -> None:
    request(
        "POST", _api(integration, f"issue/{key}/comment"), headers=_auth(integration), json={"body": text}
    )


def fetch_status(integration: Integration, key: str) -> RemoteState:
    """Jira projects name their statuses freely, so done-ness comes from the status *category*."""
    issue = request("GET", _api(integration, f"issue/{key}?fields=status"), headers=_auth(integration))
    status = ((issue.get("fields") or {}).get("status") or {}) or {}
    category = (status.get("statusCategory") or {}).get("key")
    return RemoteState(name=status.get("name"), done=str(category).lower() == "done")


def _transition(integration: Integration, key: str, name: str) -> None:
    """Move the issue through the transition called ``name``, or the one leading to a status of that name."""
    found = request("GET", _api(integration, f"issue/{key}/transitions"), headers=_auth(integration))
    wanted = name.strip().lower()
    for t in found.get("transitions") or []:
        target = str((t.get("to") or {}).get("name", "")).lower()
        if str(t.get("name", "")).lower() == wanted or target == wanted:
            request(
                "POST",
                _api(integration, f"issue/{key}/transitions"),
                headers=_auth(integration),
                json={"transition": {"id": t["id"]}},
            )
            return
    # Worth an error on the integration: the name in its settings no longer fits this project's workflow.
    raise TrackerError(f"{key} has no transition named '{name}' from its current status")


def close(integration: Integration, key: str) -> bool:
    """Jira workflows differ per project: without a configured done_transition, only comment."""
    if not integration.done_transition:
        return False
    _transition(integration, key, integration.done_transition)
    return True


def reopen(integration: Integration, key: str) -> bool:
    if not integration.reopen_transition:
        return False
    _transition(integration, key, integration.reopen_transition)
    return True


def find_issue(integration: Integration, marker: str) -> Ticket | None:
    project = integration.project.replace("\\", "\\\\").replace('"', '\\"')
    found = request(
        "GET",
        _api(integration, "search"),
        headers=_auth(integration),
        params={
            "jql": f'project = "{project}" AND text ~ "{marker}"',
            "fields": "summary,description,status",
            "maxResults": 100,
        },
    )
    matches = [
        item
        for item in found.get("issues", [])
        if has_operation_marker(str(item.get("fields", {}).get("description", "")), marker)
    ]
    if len(matches) > 1:
        raise TrackerError("Several issues match the ticket operation; reconcile manually")
    if matches:
        item = matches[0]
        return Ticket(
            key=item["key"],
            url=f"{integration.base_url.rstrip('/')}/browse/{item['key']}",
            status=item.get("fields", {}).get("status", {}).get("name"),
        )
    return None
