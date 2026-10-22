"""Inbound ticket polling: the tracker's answer becomes a suggestion, never an action."""

from datetime import timedelta

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models import Finding, FindingEvent, FindingLink, Integration
from app.models.base import utcnow
from app.services import tickets
from app.services.trackers.base import RemoteState
from tests.trackers_support import RESPONSES, integration

pytestmark = pytest.mark.usefixtures("fake_http")  # every provider stubbed

REPLIES: list[dict | Exception] = []


@pytest.fixture(autouse=True)
def polling_on(monkeypatch):
    monkeypatch.setattr(settings, "tracker_poll_hours", 6)
    REPLIES.clear()


@pytest.fixture
def tracker_says(monkeypatch):
    """Answer the next fetch_status call with a given state, per provider."""

    def setter(*states: RemoteState | Exception):
        queue = list(states)

        def _fetch(integration, key):
            reply = queue.pop(0) if queue else RemoteState(name="open", done=False)
            if isinstance(reply, Exception):
                raise reply
            return reply

        for module in ("jira", "github", "gitlab"):
            monkeypatch.setattr(f"app.services.trackers.{module}.fetch_status", _fetch)

    return setter


def another_finding(db, on_asset, key: str) -> Finding:
    """A second finding: a finding may hold only one ticket per tracker."""
    row = Finding(
        asset_id=on_asset.id,
        type="sast",
        dedup_key=key,
        title="t",
        severity="high",
        status="open",
        cwe=[],
        tools=["x"],
        references=[],
        first_seen_at=utcnow(),
        last_seen_at=utcnow(),
    )
    db.add(row)
    db.commit()
    return row


def link_for(db, f, i, external_key="#7", **kw):
    row = FindingLink(
        finding_id=f.id,
        integration_id=i.id,
        system=i.kind,
        external_key=external_key,
        url=f"https://example.test/{external_key.lstrip('#')}",
        **kw,
    )
    db.add(row)
    db.commit()
    return row


# ---- what the providers consider "done" -----------------------------------------------------------


def test_github_and_gitlab_read_the_issue_state(db, fake_http):
    from app.services.trackers import github, gitlab

    i = integration(db, "github")

    RESPONSES.append({"state": "closed"})
    assert github.fetch_status(i, "#7") == RemoteState(name="closed", done=True)
    RESPONSES.append({"state": "open"})
    assert github.fetch_status(i, "#7").done is False
    RESPONSES.append({"state": "closed"})
    assert gitlab.fetch_status(integration(db, "gitlab"), "#7").done is True


def test_jira_uses_the_status_category_not_its_name(db, fake_http):
    """Projects rename statuses freely; only the category is dependable."""
    from app.services.trackers import jira

    i = integration(db, "jira")
    RESPONSES.append({"fields": {"status": {"name": "Shipped to prod", "statusCategory": {"key": "done"}}}})
    state = jira.fetch_status(i, "SEC-1")
    assert state == RemoteState(name="Shipped to prod", done=True), "an unusual name is still done"

    RESPONSES.append({"fields": {"status": {"name": "Done-ish", "statusCategory": {"key": "indeterminate"}}}})
    assert jira.fetch_status(i, "SEC-1").done is False, "a name that reads done but is not, is not"


# ---- choosing what to poll -------------------------------------------------------------------------


def test_only_stale_links_of_active_findings_are_polled(db, asset, finding, tracker_says):
    i = integration(db)
    now = utcnow()
    fresh = link_for(db, finding, i, synced_at=now - timedelta(hours=1))
    assert tickets.due_for_poll(db, now, 6, 100) == [], "checked an hour ago, nothing to ask"

    fresh.synced_at = now - timedelta(hours=7)
    db.commit()
    assert [row.id for row in tickets.due_for_poll(db, now, 6, 100)] == [fresh.id]

    finding.status = "resolved"
    db.commit()
    assert tickets.due_for_poll(db, now, 6, 100) == [], "a closed finding has nothing to learn"


def test_a_disabled_tracker_is_left_alone(db, asset, finding):
    i = integration(db, enabled=False)
    link_for(db, finding, i)
    assert tickets.due_for_poll(db, utcnow(), 6, 100) == []


def test_never_polled_links_go_first(db, asset, finding, tracker_says):
    i = integration(db)
    now = utcnow()
    polled = link_for(db, finding, i, synced_at=now - timedelta(days=1))
    never = link_for(db, another_finding(db, asset, "second"), i, external_key="#8")
    assert [row.id for row in tickets.due_for_poll(db, now, 6, 100)] == [never.id, polled.id]


def test_the_batch_is_capped(db, asset, finding, monkeypatch):
    i = integration(db)
    for n in range(3):
        link_for(db, another_finding(db, asset, f"f{n}"), i, external_key=f"#{n}")
    assert len(tickets.due_for_poll(db, utcnow(), 6, 2)) == 2


# ---- what a finished ticket does, and does not, do --------------------------------------------------


def test_a_finished_ticket_suggests_but_never_resolves(db, asset, finding, tracker_says):
    i = integration(db)
    link = link_for(db, finding, i)
    tracker_says(RemoteState(name="closed", done=True))

    assert tickets.poll(db) == {"checked": 1, "changed": 1, "failed": 0}
    db.commit()
    db.expire_all()

    assert db.get(FindingLink, link.id).remote_done_at is not None
    assert db.get(FindingLink, link.id).remote_status == "closed"
    assert db.get(Finding, finding.id).status == "open", "the finding's status is a person's decision"
    assert db.get(Finding, finding.id).closed_at is None

    note = db.scalar(select(FindingEvent).where(FindingEvent.event == "comment"))
    assert note.actor_id is None, "Guardiano said it, not a person"
    assert "#7" in note.comment and "decide" in note.comment


def test_it_is_said_once_not_every_hour(db, asset, finding, tracker_says):
    i = integration(db)
    link_for(db, finding, i)
    tracker_says(RemoteState("closed", True), RemoteState("closed", True), RemoteState("closed", True))

    first = tickets.poll(db)
    db.commit()
    for _ in range(2):
        db.execute(FindingLink.__table__.update().values(synced_at=utcnow() - timedelta(days=1)))
        db.commit()
        again = tickets.poll(db)
        db.commit()
        assert again["changed"] == 0, "the same news is not news twice"
    assert first["changed"] == 1
    assert len(db.scalars(select(FindingEvent).where(FindingEvent.event == "comment")).all()) == 1


def test_reopening_the_ticket_withdraws_the_suggestion(db, asset, finding, tracker_says):
    i = integration(db)
    link = link_for(db, finding, i)
    tracker_says(RemoteState("closed", True))
    tickets.poll(db)
    db.commit()
    assert db.get(FindingLink, link.id).remote_done_at is not None

    db.execute(FindingLink.__table__.update().values(synced_at=utcnow() - timedelta(days=1)))
    db.commit()
    tracker_says(RemoteState("open", False))
    assert tickets.poll(db)["changed"] == 1
    db.commit()
    db.expire_all()
    assert db.get(FindingLink, link.id).remote_done_at is None


def test_one_unreachable_tracker_does_not_stop_the_others(db, asset, finding, tracker_says):
    from app.services.trackers.base import TrackerError

    broken, working = integration(db, "jira"), integration(db, "github")
    link_for(db, finding, broken)
    link_for(db, another_finding(db, asset, "second"), working)
    tracker_says(TrackerError("Jira is down"), RemoteState("closed", True))

    result = tickets.poll(db)
    db.commit()
    assert result == {"checked": 1, "changed": 1, "failed": 1}
    db.expire_all()
    assert "down" in db.get(Integration, broken.id).last_error
    assert db.get(Integration, working.id).last_error is None


def test_one_link_that_cannot_be_recorded_does_not_stop_the_others(
    db, asset, finding, tracker_says, monkeypatch
):
    """Recording a tracker's answer sat outside the try that protects the sweep, so a failure there
    failed the whole poll_tickets job and every link after it."""
    first, second = integration(db, "github", name="one"), integration(db, "github", name="two")
    link_for(db, finding, first)
    later = link_for(db, another_finding(db, asset, "second"), second)
    tracker_says(RemoteState("closed", True), RemoteState("closed", True))

    real = tickets.apply_remote_state
    calls = []

    def flaky(db_, link, state, now):
        calls.append(link.id)
        if len(calls) == 1:
            raise RuntimeError("the database said no")
        return real(db_, link, state, now)

    monkeypatch.setattr(tickets, "apply_remote_state", flaky)
    result = tickets.poll(db)
    db.commit()
    assert result == {"checked": 2, "changed": 1, "failed": 1}
    db.expire_all()
    assert db.get(FindingLink, later.id).remote_done_at is not None


def test_a_failed_check_is_not_retried_immediately(db, asset, finding, tracker_says):
    """Otherwise a tracker that is down gets hammered every sweep."""
    from app.services.trackers.base import TrackerError

    i = integration(db)
    link = link_for(db, finding, i)
    tracker_says(TrackerError("boom"))
    tickets.poll(db)
    db.commit()
    db.expire_all()
    assert db.get(FindingLink, link.id).synced_at is not None
    assert tickets.due_for_poll(db, utcnow(), 6, 100) == []


# ---- it is off until asked ---------------------------------------------------------------------------


def test_nothing_is_polled_until_it_is_switched_on(db, asset, finding, tracker_says, monkeypatch):
    monkeypatch.setattr(settings, "tracker_poll_hours", 0)
    link_for(db, finding, integration(db))
    tracker_says(RemoteState("closed", True))
    assert tickets.poll(db) == {"checked": 0, "changed": 0, "failed": 0}
    assert db.scalars(select(FindingEvent).where(FindingEvent.event == "comment")).all() == []


def test_the_hourly_task_runs_the_poll(db, asset, finding, tracker_says):
    from app.services.jobs import Worker, schedule_periodic

    link = link_for(db, finding, integration(db))
    tracker_says(RemoteState("closed", True))
    schedule_periodic(db)
    db.commit()
    Worker().run(burst=True)

    db.expire_all()
    assert db.get(FindingLink, link.id).remote_done_at is not None


# ---- finding it afterwards ----------------------------------------------------------------------------


def test_the_suggestion_is_visible_on_the_finding_and_filterable(client, auth, db, finding, tracker_says):
    i = integration(db)
    link_for(db, finding, i)
    tracker_says(RemoteState(name="closed", done=True))
    tickets.poll(db)
    db.commit()

    detail = client.get(f"/api/v1/findings/{finding.id}", headers=auth["analyst"]).json()
    assert detail["links"][0]["remote_done_at"] is not None

    done = client.get("/api/v1/findings", params={"ticket_done": True}, headers=auth["analyst"]).json()
    assert [row["id"] for row in done["items"]] == [finding.id]
    assert done["total"] == 1
    waiting = client.get("/api/v1/findings", params={"ticket_done": False}, headers=auth["analyst"]).json()
    assert waiting["total"] == 0


# ---- close_resolves_finding -------------------------------------------------------------------------


def test_a_closed_ticket_resolves_its_finding_when_the_tracker_is_trusted(db, asset, finding, tracker_says):
    from app.services import jobs

    i = integration(db, close_resolves_finding=True)
    link_for(db, finding, i)
    tracker_says(RemoteState(name="closed", done=True))
    assert tickets.poll(db)["changed"] == 1
    db.commit()

    db.expire_all()
    f = db.get(Finding, finding.id)
    assert f.status == "resolved" and f.closed_at is not None
    assert "#7 was closed" in f.status_justification
    # Nothing is sent back to the ticket that told us: it would only close what is closed.
    assert db.scalar(select(jobs.Job).where(jobs.Job.kind == tickets.SYNC_JOB)) is None


def test_a_closed_ticket_is_only_a_suggestion_by_default(db, asset, finding, tracker_says):
    link_for(db, finding, integration(db))
    tracker_says(RemoteState(name="closed", done=True))
    tickets.poll(db)
    db.commit()
    db.expire_all()
    assert db.get(Finding, finding.id).status == "open"
