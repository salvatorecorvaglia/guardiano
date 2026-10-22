"""Issue trackers: credential storage, ticket creation, linking and status sync."""

import json

import httpx
import pytest
from sqlalchemy import select

from app.core import crypto
from app.models import Asset, AuditLog, Finding, FindingLink, Integration
from app.services import jobs
from app.services.ingestion import IngestOptions, ingest_report
from app.services.trackers import base as trackers_base
from tests.conftest import sample
from tests.trackers_support import CALLS, RESPONSES, integration

pytestmark = pytest.mark.usefixtures("fake_http")  # every provider stubbed

# ---- credentials --------------------------------------------------------------------------------


def test_tokens_are_encrypted_at_rest(db):
    i = integration(db)
    assert "s3cret-token" not in i.secret_encrypted
    assert crypto.decrypt(i.secret_encrypted) == "s3cret-token"


def test_a_changed_key_is_reported_clearly(db, monkeypatch):
    i = integration(db)
    crypto._cipher.cache_clear()
    monkeypatch.setattr(crypto.settings, "integrations_key", "a-completely-different-key")
    with pytest.raises(ValueError, match="different SECRET_KEY"):
        crypto.decrypt(i.secret_encrypted)
    crypto._cipher.cache_clear()


# ---- ticket creation ----------------------------------------------------------------------------


def test_github_ticket_carries_the_finding(client, auth, db, finding):
    integration(db, "github")
    RESPONSES.append(
        {"number": 17, "html_url": "https://github.com/acme/payments/issues/17", "state": "open"}
    )

    r = client.post(f"/api/v1/findings/{finding.id}/ticket", json={}, headers=auth["analyst"])
    assert r.status_code == 201
    link = r.json()
    assert (link["system"], link["external_key"]) == ("github", "#17")
    assert link["url"].endswith("/issues/17") and link["created_by"]["email"] == "analyst@test.io"

    (call,) = CALLS
    assert call["method"] == "POST" and call["url"] == "https://api.github.com/repos/acme/payments/issues"
    assert call["headers"]["Authorization"] == "Bearer s3cret-token"
    body = call["json"]
    assert body["title"] == "[CRITICAL] SQL injection" and body["labels"] == ["security"]
    assert "`app/db.py` line 42" in body["body"] and "CWE-89" in body["body"]
    assert "Use a parameterised query." in body["body"]

    # The link shows up on the finding, with a comment in its history.
    detail = client.get(f"/api/v1/findings/{finding.id}", headers=auth["viewer"]).json()
    assert [x["external_key"] for x in detail["links"]] == ["#17"]
    assert "Ticket #17 opened" in detail["events"][0]["comment"]


def test_jira_and_gitlab_shapes(client, auth, db, finding):
    jira = integration(db, "jira", issue_type="Bug")
    RESPONSES.append({"key": "SEC-42"})
    r = client.post(
        f"/api/v1/findings/{finding.id}/ticket", json={"integration_id": jira.id}, headers=auth["analyst"]
    )
    assert r.status_code == 201 and r.json()["url"] == "https://acme.atlassian.net/browse/SEC-42"
    fields = CALLS[0]["json"]["fields"]
    assert fields["project"] == {"key": "SEC"} and fields["issuetype"] == {"name": "Bug"}
    assert CALLS[0]["headers"]["Authorization"].startswith("Bearer ")  # no username: PAT

    lab = integration(db, "gitlab")
    RESPONSES.append({"iid": 8, "web_url": "https://gitlab.com/acme/payments/-/issues/8", "state": "opened"})
    r = client.post(
        f"/api/v1/findings/{finding.id}/ticket", json={"integration_id": lab.id}, headers=auth["analyst"]
    )
    assert r.status_code == 201 and r.json()["external_key"] == "#8"
    assert CALLS[1]["headers"]["PRIVATE-TOKEN"] == "s3cret-token"
    assert CALLS[1]["json"]["labels"] == "security"


def test_jira_with_an_account_email_uses_basic_auth(db, finding):
    import base64

    from app.services.trackers import jira

    i = integration(db, "jira", username="bot@acme.test")
    RESPONSES.append({"key": "SEC-1"})
    jira.create_issue(i, finding)
    expected = "Basic " + base64.b64encode(b"bot@acme.test:s3cret-token").decode()
    assert CALLS[0]["headers"]["Authorization"] == expected


def test_a_tracker_failure_is_reported_not_swallowed(client, auth, db, finding):
    i = integration(db, "github")
    RESPONSES.append(trackers_base.TrackerError("Tracker returned HTTP 403: forbidden"))

    r = client.post(f"/api/v1/findings/{finding.id}/ticket", json={}, headers=auth["analyst"])
    assert r.status_code == 502 and "403" in r.json()["detail"]

    db.expire_all()
    assert db.scalar(select(FindingLink)) is None  # nothing half-linked
    assert "403" in db.get(Integration, i.id).last_error


def test_ticket_rules(client, auth, db, finding, asset):
    # Nothing configured.
    assert (
        client.post(f"/api/v1/findings/{finding.id}/ticket", json={}, headers=auth["analyst"]).status_code
        == 422
    )

    other = Asset(name="other", tags=[])
    db.add(other)
    db.commit()
    integration(db, "github", asset_id=other.id)  # bound to a different asset
    assert (
        client.post(f"/api/v1/findings/{finding.id}/ticket", json={}, headers=auth["analyst"]).status_code
        == 422
    )

    first = integration(db, "github", name="repo A")
    integration(db, "gitlab", name="repo B")
    # Two options and no choice made.
    assert (
        client.post(f"/api/v1/findings/{finding.id}/ticket", json={}, headers=auth["analyst"]).status_code
        == 422
    )

    RESPONSES.append({"number": 1, "html_url": "https://example.test/1", "state": "open"})
    assert (
        client.post(
            f"/api/v1/findings/{finding.id}/ticket",
            json={"integration_id": first.id},
            headers=auth["analyst"],
        ).status_code
        == 201
    )
    # The same tracker twice is a conflict, not a second ticket.
    r = client.post(
        f"/api/v1/findings/{finding.id}/ticket", json={"integration_id": first.id}, headers=auth["analyst"]
    )
    assert r.status_code == 409 and "#1" in r.json()["detail"]

    assert (
        client.post(f"/api/v1/findings/{finding.id}/ticket", json={}, headers=auth["viewer"]).status_code
        == 403
    )
    listed = client.get(f"/api/v1/findings/{finding.id}/trackers", headers=auth["analyst"]).json()
    assert {x["name"] for x in listed} == {"repo A", "repo B"}


def test_unlinking_keeps_the_ticket(client, auth, db, finding):
    integration(db, "github")
    RESPONSES.append({"number": 5, "html_url": "https://example.test/5", "state": "open"})
    link = client.post(f"/api/v1/findings/{finding.id}/ticket", json={}, headers=auth["analyst"]).json()

    before = len(CALLS)
    assert (
        client.delete(
            f"/api/v1/findings/{finding.id}/ticket/{link['id']}", headers=auth["analyst"]
        ).status_code
        == 204
    )
    assert len(CALLS) == before  # nothing was called on the tracker
    db.expire_all()
    assert db.scalar(select(FindingLink)) is None


# ---- status sync --------------------------------------------------------------------------------


def test_status_change_comments_and_closes_the_ticket(client, auth, db, finding):
    integration(db, "github")
    RESPONSES.append({"number": 9, "html_url": "https://example.test/9", "state": "open"})
    client.post(f"/api/v1/findings/{finding.id}/ticket", json={}, headers=auth["analyst"])
    CALLS.clear()

    r = client.patch(
        f"/api/v1/findings/{finding.id}",
        json={"status": "false_positive", "justification": "Test-only code path"},
        headers=auth["analyst"],
    )
    assert r.status_code == 200
    jobs.Worker(poll_interval=0).run(burst=True)

    comment, close = CALLS
    assert comment["url"].endswith("/issues/9/comments")
    assert "from **open** to **false_positive**" in comment["json"]["body"]
    assert "Test-only code path" in comment["json"]["body"]
    assert close["method"] == "PATCH" and close["json"] == {"state": "closed"}

    db.expire_all()
    assert db.scalar(select(FindingLink)).remote_status == "closed"


def test_jira_is_commented_but_not_transitioned(client, auth, db, finding):
    integration(db, "jira")
    RESPONSES.append({"key": "SEC-7"})
    client.post(f"/api/v1/findings/{finding.id}/ticket", json={}, headers=auth["analyst"])
    CALLS.clear()

    client.patch(f"/api/v1/findings/{finding.id}", json={"status": "resolved"}, headers=auth["analyst"])
    jobs.Worker(poll_interval=0).run(burst=True)
    # One call only: a comment. Jira workflows vary too much to force a transition.
    (comment,) = CALLS
    assert comment["url"].endswith("/issue/SEC-7/comment")


def _ticket(client, auth, finding, reply):
    RESPONSES.append(reply)
    r = client.post(f"/api/v1/findings/{finding.id}/ticket", json={}, headers=auth["analyst"])
    assert r.status_code == 201, r.text
    CALLS.clear()


def test_jira_follows_a_configured_transition(client, auth, db, finding):
    integration(db, "jira", done_transition="Done")
    _ticket(client, auth, finding, {"key": "SEC-7"})
    transitions = {"transitions": [{"id": "11", "name": "Start", "to": {"name": "In Progress"}},
                                   {"id": "31", "name": "Close issue", "to": {"name": "Done"}}]}  # fmt: skip
    RESPONSES.extend([{}, transitions, {}])  # comment, list transitions, transition

    client.patch(f"/api/v1/findings/{finding.id}", json={"status": "resolved"}, headers=auth["analyst"])
    jobs.Worker(poll_interval=0).run(burst=True)
    comment, listing, move = CALLS
    assert listing["method"] == "GET" and listing["url"].endswith("/issue/SEC-7/transitions")
    # "Done" is not a transition name here, but the status "Close issue" leads to.
    assert move["method"] == "POST" and move["json"] == {"transition": {"id": "31"}}


def test_a_transition_the_workflow_does_not_offer_is_reported(client, auth, db, finding):
    i = integration(db, "jira", done_transition="Shipped")
    _ticket(client, auth, finding, {"key": "SEC-7"})
    RESPONSES.extend([{}, {"transitions": [{"id": "11", "name": "Start", "to": {"name": "In Progress"}}]}])
    client.patch(f"/api/v1/findings/{finding.id}", json={"status": "resolved"}, headers=auth["analyst"])
    jobs.Worker(poll_interval=0).run(burst=True)
    db.expire_all()
    assert "no transition named 'Shipped'" in db.get(Integration, i.id).last_error
    assert db.get(Finding, finding.id).status == "resolved", "the finding is not held back by its ticket"


def test_reopening_a_finding_reopens_its_github_issue(client, auth, db, finding):
    integration(db, "github")
    _ticket(client, auth, finding, {"number": 9, "html_url": "https://example.test/9", "state": "open"})
    client.patch(f"/api/v1/findings/{finding.id}", json={"status": "resolved"}, headers=auth["analyst"])
    jobs.Worker(poll_interval=0).run(burst=True)
    CALLS.clear()

    client.patch(f"/api/v1/findings/{finding.id}", json={"status": "open"}, headers=auth["analyst"])
    RESPONSES.extend([{}, {}, {"state": "open"}])  # comment, reopen, re-read
    jobs.Worker(poll_interval=0).run(burst=True)
    assert [c["method"] for c in CALLS] == ["POST", "PATCH", "GET"]
    assert CALLS[1]["json"] == {"state": "open"}


def test_a_scan_that_reopens_a_finding_tells_its_ticket(client, auth, db, asset, finding):
    integration(db, "gitlab")
    _ticket(client, auth, finding, {"iid": 4, "web_url": "https://example.test/4", "state": "opened"})
    finding.status = "resolved"
    db.commit()
    report = {"schema": "guardiano/v1", "tool": {"name": "Semgrep"}, "scan_type": "sast", "findings": [
        {"title": "SQL injection", "severity": "critical", "cwe": ["CWE-89"], "file_path": "app/db.py",
         "line_start": 42}]}  # fmt: skip
    scan = ingest_report(db, json.dumps(report).encode(), asset, None, IngestOptions())
    assert scan.reopened_count == 1
    jobs.Worker(poll_interval=0).run(burst=True)
    comment, reopen = CALLS[:2]
    assert f"scan #{scan.id}" in comment["json"]["body"]
    assert reopen["method"] == "PUT" and reopen["json"] == {"state_event": "reopen"}


def _scan(db, asset, *items):
    report = {"schema": "guardiano/v1", "tool": {"name": "Semgrep"}, "scan_type": "sast", "findings": [
        {"title": t, "severity": sev, "cwe": ["CWE-89"], "file_path": f"{t}.py", "line_start": 1, **extra}
        for t, sev, extra in items]}  # fmt: skip
    return ingest_report(db, json.dumps(report).encode(), asset, None, IngestOptions())


def test_new_findings_at_the_severity_floor_get_a_ticket(db, asset):
    from app.models import TriageRule

    integration(db, "github", auto_ticket_min_severity="high")
    db.add(TriageRule(name="t", enabled=True, priority=1, match={"path_glob": "tests/*"},
                      action={"status": "false_positive", "justification": "fixture"}))  # fmt: skip
    db.commit()
    RESPONSES.extend([{"number": 1, "html_url": "https://example.test/1", "state": "open"}])
    _scan(db, asset, ("crit", "critical", {}), ("low", "low", {}),
          ("fixture", "critical", {"file_path": "tests/x.py"}))  # fmt: skip
    jobs.Worker(poll_interval=0).run(burst=True)

    created = [c for c in CALLS if c["method"] == "POST" and c["url"].endswith("/issues")]
    assert len(created) == 1, "only the critical one: low is under the floor, the fixture was suppressed"
    db.expire_all()
    (link,) = db.scalars(select(FindingLink)).all()
    assert link.created_by_id is None and link.external_key == "#1"
    f = db.get(Finding, link.finding_id)
    assert f.title == "crit" and any("opened automatically" in (e.comment or "") for e in f.events)

    CALLS.clear()
    _scan(db, asset, ("crit", "critical", {}))  # seen again: not new, no second ticket
    jobs.Worker(poll_interval=0).run(burst=True)
    assert not [c for c in CALLS if c["url"].endswith("/issues")]


def test_known_exploited_findings_get_a_ticket_whatever_their_severity(db, asset):
    from app.models import VulnIntel

    db.add(VulnIntel(cve_id="CVE-2021-44228", in_kev=True))
    integration(db, "gitlab", auto_ticket_kev=True)
    RESPONSES.append({"iid": 5, "web_url": "https://example.test/5", "state": "opened"})
    _scan(db, asset, ("log4j", "low", {"cve_id": "CVE-2021-44228"}), ("other", "critical", {}))
    jobs.Worker(poll_interval=0).run(burst=True)
    (link,) = db.scalars(select(FindingLink)).all()
    assert db.get(Finding, link.finding_id).title == "log4j"


def test_a_first_scan_cannot_flood_the_tracker(db, asset, monkeypatch):
    from app.core.config import settings
    from app.services import jobs as job_queue
    from app.services import tickets

    monkeypatch.setattr(settings, "auto_ticket_per_scan", 3)
    integration(db, "github", auto_ticket_min_severity="high")
    _scan(db, asset, *[(f"f{i}", "high", {}) for i in range(10)])
    queued = db.scalars(select(job_queue.Job).where(job_queue.Job.kind == tickets.AUTO_JOB)).all()
    assert len(queued) == 3


def test_nothing_is_opened_automatically_unless_asked(db, asset):
    from app.services import jobs as job_queue

    integration(db, "github")
    _scan(db, asset, ("crit", "critical", {}))
    assert db.scalar(select(job_queue.Job).where(job_queue.Job.kind == "tracker.create")) is None


def test_sync_failure_retries_without_touching_the_finding(client, auth, db, finding):
    i = integration(db, "github")
    RESPONSES.append({"number": 3, "html_url": "https://example.test/3", "state": "open"})
    client.post(f"/api/v1/findings/{finding.id}/ticket", json={}, headers=auth["analyst"])
    RESPONSES.append(trackers_base.TrackerError("Tracker returned HTTP 500: boom"))

    r = client.patch(
        f"/api/v1/findings/{finding.id}", json={"status": "in_progress"}, headers=auth["analyst"]
    )
    assert r.status_code == 200  # triage succeeds even though the tracker will fail
    jobs.Worker(poll_interval=0).run(burst=True)

    db.expire_all()
    assert db.get(Finding, finding.id).status == "in_progress"
    job = db.scalars(select(jobs.Job).where(jobs.Job.kind == "tracker.sync")).one()
    assert job.status == "queued" and "500" in job.last_error
    assert "500" in db.get(Integration, i.id).last_error


def test_sync_skips_links_whose_integration_is_gone(client, auth, db, finding):
    i = integration(db, "github")
    RESPONSES.append({"number": 4, "html_url": "https://example.test/4", "state": "open"})
    client.post(f"/api/v1/findings/{finding.id}/ticket", json={}, headers=auth["analyst"])
    client.patch(f"/api/v1/findings/{finding.id}", json={"status": "resolved"}, headers=auth["analyst"])

    db.delete(db.get(Integration, i.id))
    db.commit()
    CALLS.clear()
    jobs.Worker(poll_interval=0).run(burst=True)
    assert CALLS == []  # nothing to talk to, and no dead job
    assert db.scalars(select(jobs.Job).where(jobs.Job.kind == "tracker.sync")).one().status == "done"
    assert db.scalar(select(FindingLink)) is not None  # the link survives for its history


# ---- integrations API ---------------------------------------------------------------------------


def test_integration_api(client, auth, db, asset):
    body = {
        "kind": "github",
        "name": "payments repo",
        "base_url": "https://api.github.com",
        "project": "acme/payments",
        "token": "ghp_secret_value",
        "labels": ["security"],
    }
    for role in ("viewer", "analyst", "manager"):
        assert client.post("/api/v1/integrations", json=body, headers=auth[role]).status_code == 403
    r = client.post("/api/v1/integrations", json=body, headers=auth["admin"])
    assert r.status_code == 201
    created = r.json()
    assert "token" not in created and "secret_encrypted" not in created

    for bad in ({**body, "kind": "bugzilla"}, {**body, "base_url": "ftp://x"}, {**body, "token": ""}):
        assert client.post("/api/v1/integrations", json=bad, headers=auth["admin"]).status_code == 422

    iid = created["id"]
    RESPONSES.append({"full_name": "acme/payments", "has_issues": True})
    check = client.post(f"/api/v1/integrations/{iid}/check", headers=auth["admin"]).json()
    assert check == {"ok": True, "detail": "acme/payments (issues enabled)"}

    RESPONSES.append(trackers_base.TrackerError("Tracker returned HTTP 401: bad credentials"))
    check = client.post(f"/api/v1/integrations/{iid}/check", headers=auth["admin"]).json()
    assert check["ok"] is False and "401" in check["detail"]

    # Copy the string: the ORM object itself is refreshed in place by the patch below.
    stored = str(db.scalar(select(Integration)).secret_encrypted)
    client.patch(f"/api/v1/integrations/{iid}", json={"token": "ghp_rotated"}, headers=auth["admin"])
    db.expire_all()
    assert crypto.decrypt(db.get(Integration, iid).secret_encrypted) == "ghp_rotated"
    assert db.get(Integration, iid).secret_encrypted != stored

    assert client.delete(f"/api/v1/integrations/{iid}", headers=auth["admin"]).status_code == 204
    entries = db.scalars(select(AuditLog).where(AuditLog.action.startswith("integration."))).all()
    assert [e.action for e in entries] == ["integration.create", "integration.update", "integration.delete"]
    # No token, in any form, in the audit log.
    assert "ghp_" not in json.dumps([e.changes for e in entries])
    assert entries[1].changes == {"token": "replaced"}


# ---- commit and pull-request feedback ------------------------------------------------------------


def scan_with_commit(db, asset, *, branch="main", preview=False, sha="abc123"):

    report = json.dumps(
        {
            "schema": "guardiano/v1",
            "tool": {"name": "Semgrep"},
            "scan_type": "sast",
            "findings": [
                {
                    "title": "Hard-coded secret",
                    "severity": "high",
                    "cwe": ["CWE-798"],
                    "file_path": "a.py",
                    "line_start": 3,
                }
            ],
        }
    ).encode()
    return ingest_report(
        db, report, asset, None, IngestOptions(branch=branch, commit_sha=sha, preview=preview)
    )


def test_commit_status_reports_a_passing_scan(db, asset):
    integration(db, "github", scm_feedback=True)
    scan_with_commit(db, asset)
    jobs.Worker(poll_interval=0).run(burst=True)

    (status,) = [c for c in CALLS if c["url"].endswith("/statuses/abc123")]
    assert status["method"] == "POST"
    assert status["json"]["state"] == "success"
    assert status["json"]["context"] == "guardiano/security"
    assert "1 new finding(s)" in status["json"]["description"]


def test_commit_status_fails_when_the_gate_fails(db, asset):
    from app.models import GatePolicy

    db.add(GatePolicy(asset_id=None, enabled=True, conditions={"max_new": {"high": 0}}))
    db.commit()
    integration(db, "github", scm_feedback=True)
    scan_with_commit(db, asset)
    jobs.Worker(poll_interval=0).run(burst=True)

    (status,) = [c for c in CALLS if "/statuses/" in c["url"]]
    assert status["json"]["state"] == "failure"
    assert status["json"]["description"] == "1 new high finding(s), limit 0"


def test_a_preview_comments_on_its_pull_request(db, asset, monkeypatch):
    monkeypatch.setattr("app.services.scm.settings.public_url", "https://guardiano.test")
    asset.default_branch = "main"
    db.commit()
    integration(db, "github", scm_feedback=True)
    RESPONSES.extend([{}, {"items": [{"number": 7}]}, {}])  # status, PR lookup, comment

    scan_with_commit(db, asset, branch="feature/x")
    jobs.Worker(poll_interval=0).run(burst=True)

    lookup = [c for c in CALLS if "/pulls?" in c["url"]]
    # The branch is URL-encoded (as GitLab's twin already did), so it cannot add query parameters;
    # GitHub decodes "feature%2Fx" back to "feature/x".
    assert lookup and httpx.URL(lookup[0]["url"]).params["head"] == "acme:feature/x"
    (comment,) = [c for c in CALLS if c["url"].endswith("/issues/7/comments")]
    body = comment["json"]["body"]
    assert "**1 new finding(s)** this branch would add (1 high)" in body
    assert "- **high** Hard-coded secret — `a.py:3`" in body
    assert "https://guardiano.test/scans/" in body


def _preview_on_pr(db, asset, *responses, sha="abc123"):
    CALLS.clear()
    RESPONSES.extend(responses)
    scan_with_commit(db, asset, branch="feature/x", sha=sha)
    jobs.Worker(poll_interval=0).run(burst=True)


def test_later_scans_edit_the_comment_instead_of_adding_one(db, asset):
    from app.models import PrComment

    asset.default_branch = "main"
    db.commit()
    integration(db, "github", scm_feedback=True)

    _preview_on_pr(db, asset, {}, {"items": [{"number": 7}]}, {"id": 555})  # status, PR lookup, new comment
    assert [c["method"] for c in CALLS if "/comments" in c["url"]] == ["POST"]
    assert db.scalar(select(PrComment.comment_id)) == "555"

    _preview_on_pr(db, asset, {}, {"items": [{"number": 7}]}, {}, sha="def456")  # ... then the edit
    (edit,) = [c for c in CALLS if "/comments" in c["url"]]
    assert edit["method"] == "PATCH" and edit["url"].endswith("/issues/comments/555")
    assert "Hard-coded secret" in edit["json"]["body"]


def test_a_comment_that_cannot_be_edited_is_replaced(db, asset):
    from app.models import PrComment
    from app.services.trackers.base import TrackerError

    asset.default_branch = "main"
    db.commit()
    integration(db, "github", scm_feedback=True)
    _preview_on_pr(db, asset, {}, {"items": [{"number": 7}]}, {"id": 555})

    # Somebody deleted it: the edit fails, and a new comment takes its place.
    gone = TrackerError("Tracker returned HTTP 404")
    _preview_on_pr(db, asset, {}, {"items": [{"number": 7}]}, gone, {"id": 777}, sha="def456")
    assert [c["method"] for c in CALLS if "/comments" in c["url"]] == ["PATCH", "POST"]
    db.expire_all()
    assert db.scalar(select(PrComment.comment_id)) == "777"


def test_gitlab_edits_its_merge_request_note(db, asset):
    asset.default_branch = "main"
    db.commit()
    integration(db, "gitlab", scm_feedback=True)
    _preview_on_pr(db, asset, {}, {"items": [{"iid": 3}]}, {"id": 41})
    _preview_on_pr(db, asset, {}, {"items": [{"iid": 3}]}, {}, sha="def456")
    (edit,) = [c for c in CALLS if "/notes" in c["url"]]
    assert edit["method"] == "PUT" and edit["url"].endswith("/merge_requests/3/notes/41")


def test_each_asset_keeps_its_own_comment_on_a_shared_pull_request(db, asset):
    """A monorepo: two assets report to one pull request, and neither overwrites the other's summary."""
    from app.models import Asset, PrComment

    other = Asset(name="billing-api", tags=[], default_branch="main")
    asset.default_branch = "main"
    db.add(other)
    db.commit()
    integration(db, "github", scm_feedback=True)
    _preview_on_pr(db, asset, {}, {"items": [{"number": 7}]}, {"id": 1})
    _preview_on_pr(db, other, {}, {"items": [{"number": 7}]}, {"id": 2})
    assert [c["method"] for c in CALLS if "/comments" in c["url"]] == ["POST"]
    assert sorted(db.scalars(select(PrComment.comment_id))) == ["1", "2"]


def test_gitlab_uses_its_own_state_names(db, asset):
    from app.models import GatePolicy

    db.add(GatePolicy(asset_id=None, enabled=True, conditions={"max_new": {"high": 0}}))
    db.commit()
    integration(db, "gitlab", scm_feedback=True)
    scan_with_commit(db, asset)
    jobs.Worker(poll_interval=0).run(burst=True)

    (status,) = [c for c in CALLS if "/statuses/" in c["url"]]
    assert status["json"]["state"] == "failed"  # GitLab calls it "failed", GitHub "failure"
    assert status["json"]["name"] == "guardiano/security"


def test_nothing_is_posted_without_a_commit_or_a_flag(db, asset):
    integration(db, "github", scm_feedback=True)
    scan_with_commit(db, asset, sha=None)
    jobs.Worker(poll_interval=0).run(burst=True)
    assert [c for c in CALLS if "/statuses/" in c["url"]] == []

    db.query(Integration).delete()
    db.commit()
    integration(db, "github", scm_feedback=False)  # a ticket tracker that does not report on commits
    scan_with_commit(db, asset, sha="def456")
    jobs.Worker(poll_interval=0).run(burst=True)
    assert [c for c in CALLS if "/statuses/" in c["url"]] == []


def test_scm_feedback_needs_a_forge(client, auth, db):
    body = {
        "kind": "jira",
        "name": "jira",
        "base_url": "https://acme.atlassian.net",
        "project": "SEC",
        "token": "t",
        "scm_feedback": True,
    }
    assert client.post("/api/v1/integrations", json=body, headers=auth["admin"]).status_code == 422
    created = client.post(
        "/api/v1/integrations", json={**body, "scm_feedback": False}, headers=auth["admin"]
    ).json()
    r = client.patch(
        f"/api/v1/integrations/{created['id']}", json={"scm_feedback": True}, headers=auth["admin"]
    )
    assert r.status_code == 422


def test_forge_failure_retries_without_affecting_the_scan(db, asset):
    i = integration(db, "github", scm_feedback=True)
    RESPONSES.append(trackers_base.TrackerError("Tracker returned HTTP 500: boom"))
    scan = scan_with_commit(db, asset)
    assert scan.new_count == 1  # ingestion is unaffected

    jobs.Worker(poll_interval=0).run(burst=True)
    db.expire_all()
    job = db.scalars(select(jobs.Job).where(jobs.Job.kind == "scm.feedback")).one()
    assert job.status == "queued" and "500" in job.last_error
    assert "500" in db.get(Integration, i.id).last_error


# ---- URL injection via commit_sha / branch -------------------------------------------------------


@pytest.mark.parametrize(
    "sha",
    ["../../../user/repos", "abc123/../../../user", "abc?x=y", "abc#frag", "abc 123", "../" * 8],
)
def test_upload_refuses_a_commit_sha_that_is_not_a_git_object_name(client, auth, asset, sha):
    """commit_sha lands in a URL *path* segment on the forge API, where '..' would be normalised
    away by RFC 3986 and walk out of /repos/<project>. Only a git object name is accepted."""
    r = client.post(
        "/api/v1/scans",
        headers=auth["analyst"],
        files={"file": ("osv.json", sample("osv.json"), "application/json")},
        data={"asset_name": asset.name, "commit_sha": sha},
    )
    assert r.status_code == 422, r.text


@pytest.mark.parametrize("branch", ["a\nb", "a\rb", "a\x00b"])
def test_upload_refuses_control_characters_in_branch(client, auth, asset, branch):
    r = client.post(
        "/api/v1/scans",
        headers=auth["analyst"],
        files={"file": ("osv.json", sample("osv.json"), "application/json")},
        data={"asset_name": asset.name, "branch": branch},
    )
    assert r.status_code == 422, r.text


def test_commit_status_url_stays_inside_the_configured_repository(db, asset):
    """Defence in depth: even a sha that slipped past validation must not escape the project path."""
    from app.services.trackers import github

    integration_row = integration(db, "github", scm_feedback=True)
    github.commit_status(integration_row, "../../../user/repos", "success", "ok", None, "guardiano")

    # httpx.URL.path decodes, so assert on the wire form: the separators must stay percent-encoded.
    sent = CALLS[-1]["url"]
    assert sent.startswith("https://api.github.com/repos/acme/payments/statuses/")
    assert "/../" not in sent and not sent.endswith("/..")
    assert httpx.URL(sent).host == "api.github.com"


def test_pull_request_lookup_does_not_let_a_branch_add_query_parameters(db, asset):
    from app.services.trackers import github

    integration_row = integration(db, "github", scm_feedback=True)
    RESPONSES.append({"items": []})  # base.request always hands providers a dict
    github.find_open_pr(integration_row, "x&per_page=100&sort=created")

    params = httpx.URL(CALLS[-1]["url"]).params
    assert set(params) == {"state", "head"}  # the branch did not become extra parameters
    assert params["head"] == "acme:x&per_page=100&sort=created"


def test_gitlab_commit_status_url_stays_inside_the_configured_project(db, asset):
    from app.services.trackers import gitlab

    integration_row = integration(db, "gitlab", scm_feedback=True)
    gitlab.commit_status(integration_row, "../../../users", "success", "ok", None, "guardiano")

    sent = CALLS[-1]["url"]
    assert sent.startswith("https://gitlab.com/api/v4/projects/acme%2Fpayments/statuses/")
    assert "/../" not in sent and not sent.endswith("/..")


def test_no_database_connection_is_held_while_the_tracker_is_called(client, auth, db, finding, monkeypatch):
    """The call can take up to TRACKER_TIMEOUT; a connection held for it is one a busy worker's small
    pool does not have for anybody else."""
    from app.core.db import engine
    from app.services.trackers import github

    integration(db, "github")
    fid = finding.id
    db.close()  # the test's own session holds nothing either
    held = []

    def watching(method, url, **kwargs):
        held.append(engine.pool.checkedout())
        return {"number": 1, "html_url": "https://github.com/acme/payments/issues/1", "state": "open"}

    monkeypatch.setattr(github, "request", watching)
    r = client.post(f"/api/v1/findings/{fid}/ticket", json={}, headers=auth["analyst"])
    assert r.status_code == 201, r.text
    assert held == [0], f"{held[0]} connection(s) checked out during the tracker call"


def test_ticket_retry_reconciles_ambiguous_remote_creation(db, finding, monkeypatch):
    from app.services import tickets
    from app.services.trackers import github
    from app.services.trackers.base import Ticket, TrackerError

    tracker = integration(db)
    created = []

    def remote_create(integration, finding):
        created.append(finding.id)
        raise TrackerError("connection closed after remote creation")

    monkeypatch.setattr(github, "create_issue", remote_create)
    with pytest.raises(TrackerError):
        tickets.create_ticket(db, finding, tracker, None)
    db.rollback()
    monkeypatch.setattr(
        github, "find_issue", lambda integration, marker: Ticket("#42", "https://example.test/42")
    )
    link = tickets.create_ticket(db, finding, tracker, None)
    db.commit()
    assert link.external_key == "#42" and created == [finding.id]
    assert tickets.create_ticket(db, finding, tracker, None).id == link.id


@pytest.mark.parametrize("kind", ["github", "gitlab", "jira"])
def test_ticket_reconciliation_checks_complete_operation_marker(db, kind):
    from app.services import tickets

    tracker = integration(db, kind)
    marker = "guardiano-f1-i1"

    def issue(text):
        if kind == "github":
            return {"number": 42, "html_url": "https://example.test/42", "body": text}
        if kind == "gitlab":
            return {"iid": 42, "web_url": "https://example.test/42", "description": text}
        return {"key": "SEC-42", "fields": {"description": text}}

    collection = "issues" if kind == "jira" else "items"
    RESPONSES.append({collection: [issue(marker + "0")]})
    assert tickets.provider(kind).find_issue(tracker, marker) is None
    RESPONSES.append({collection: [issue("Guardiano operation: " + marker)]})
    assert tickets.provider(kind).find_issue(tracker, marker) is not None


def test_definitely_rejected_ticket_creation_can_be_retried(db, finding, monkeypatch):
    from app.services import tickets
    from app.services.trackers import github
    from app.services.trackers.base import Ticket, TrackerError

    tracker = integration(db)
    calls = []

    def create(integration, finding):
        calls.append(finding.id)
        if len(calls) == 1:
            raise TrackerError("Tracker refused credentials", definitely_not_created=True)
        return Ticket("#43", "https://example.test/43")

    monkeypatch.setattr(github, "create_issue", create)
    monkeypatch.setattr(
        github, "find_issue", lambda *args: pytest.fail("Rejected writes need no reconciliation")
    )
    with pytest.raises(TrackerError):
        tickets.create_ticket(db, finding, tracker, None)
    db.rollback()
    assert tickets.create_ticket(db, finding, tracker, None).external_key == "#43"
    assert len(calls) == 2
