"""Finding tags, due-date overrides and the asset default assignee."""

import json
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.models import Asset, Finding, User
from app.models.base import utcnow
from app.services.ingestion import IngestOptions, ingest_report


def native(*titles, tool="t"):
    return json.dumps(
        {
            "schema": "guardiano/v1",
            "tool": {"name": tool},
            "scan_type": "sast",
            "findings": [
                {"title": t, "severity": "high", "cwe": ["CWE-1"], "file_path": f"{t}.py", "line_start": 1}
                for t in titles
            ],
        }
    ).encode()


@pytest.fixture
def asset(db):
    a = Asset(name="svc", tags=[])
    db.add(a)
    db.commit()
    return a


@pytest.fixture
def fid(db, asset):
    ingest_report(db, native("a"), asset, None, IngestOptions())
    return db.scalar(select(Finding.id))


def patch(client, headers, fid, body):
    return client.patch(f"/api/v1/findings/{fid}", json=body, headers=headers)


# ---- tags ---------------------------------------------------------------------------------------


def test_tags_are_normalised_and_audited(client, auth, fid):
    r = patch(client, auth["analyst"], fid, {"tags": [" Needs-Review ", "team:payments", "needs-review"]})
    assert r.status_code == 200
    body = r.json()
    assert body["tags"] == ["needs-review", "team:payments"]
    assert body["events"][0]["event"] == "tags_changed"
    assert body["events"][0]["comment"] == "Tags added needs-review, team:payments"

    r = patch(client, auth["analyst"], fid, {"tags": ["team:payments"]})
    assert r.json()["events"][0]["comment"] == "Tags removed needs-review"
    # Same set again: no event.
    n = len(r.json()["events"])
    assert len(patch(client, auth["analyst"], fid, {"tags": ["TEAM:payments"]}).json()["events"]) == n


def test_tag_validation_and_permissions(client, auth, fid):
    assert patch(client, auth["viewer"], fid, {"tags": ["x"]}).status_code == 403
    assert patch(client, auth["analyst"], fid, {"tags": ["has space"]}).status_code == 422
    assert patch(client, auth["analyst"], fid, {"tags": [f"t{i}" for i in range(21)]}).status_code == 422


def test_tag_filter_bulk_and_tag_counts(client, auth, db, asset):
    ingest_report(db, native("a", "b", "c"), asset, None, IngestOptions())
    ids = db.scalars(select(Finding.id).order_by(Finding.id)).all()
    r = client.post(
        "/api/v1/findings/bulk", json={"ids": ids[:2], "add_tags": ["pci", "Q3"]}, headers=auth["analyst"]
    )
    assert r.status_code == 200 and r.json() == {"updated": 2}
    client.post(
        "/api/v1/findings/bulk", json={"ids": [ids[0]], "remove_tags": ["q3"]}, headers=auth["analyst"]
    )

    def listed(**params):
        return [
            f["id"]
            for f in client.get("/api/v1/findings", params=params, headers=auth["viewer"]).json()["items"]
        ]

    assert sorted(listed(tag="pci")) == ids[:2]
    assert listed(tag=["pci", "q3"]) == [ids[1]]
    tags = client.get("/api/v1/findings/tags", headers=auth["viewer"]).json()
    assert tags == [{"tag": "pci", "count": 2, "active": 2}, {"tag": "q3", "count": 1, "active": 1}]
    assert [t["tag"] for t in client.get("/api/v1/findings/tags?q=Q", headers=auth["viewer"]).json()] == [
        "q3"
    ]


def test_reingestion_keeps_tags(client, auth, db, asset, fid):
    patch(client, auth["analyst"], fid, {"tags": ["keep"]})
    ingest_report(db, native("a"), asset, None, IngestOptions())
    db.expire_all()
    assert db.get(Finding, fid).tags == ["keep"]


# ---- due-date override --------------------------------------------------------------------------


def test_due_date_override_requires_manager(client, auth, fid):
    due = (utcnow() + timedelta(days=90)).isoformat()
    assert patch(client, auth["analyst"], fid, {"due_at": due}).status_code == 403
    assert patch(client, auth["manager"], fid, {"due_at": due, "clear_due_at": True}).status_code == 422
    r = patch(client, auth["manager"], fid, {"due_at": due, "due_reason": "Vendor fix in Q4"})
    assert r.status_code == 200
    body = r.json()
    assert body["due_at_override"][:10] == due[:10] and body["sla_due_at"][:10] == due[:10]
    assert body["events"][0]["event"] == "due_date_changed"
    assert body["events"][0]["comment"].endswith(": Vendor fix in Q4")


def test_due_date_override_drives_overdue_and_sort(client, auth, db, asset):
    ingest_report(db, native("a", "b"), asset, None, IngestOptions())
    a, b = db.scalars(select(Finding.id).order_by(Finding.id)).all()
    past = (utcnow() - timedelta(days=1)).isoformat()
    assert patch(client, auth["manager"], a, {"due_at": past}).json()["overdue"] is True

    overdue = client.get("/api/v1/findings?overdue=true", headers=auth["viewer"]).json()["items"]
    assert [f["id"] for f in overdue] == [a]
    assert client.get("/api/v1/analytics/summary", headers=auth["viewer"]).json()["overdue"] == 1
    by_due = client.get("/api/v1/findings?sort=due", headers=auth["viewer"]).json()["items"]
    assert [f["id"] for f in by_due] == [a, b]

    r = patch(client, auth["manager"], a, {"clear_due_at": True})
    assert r.json()["due_at_override"] is None and r.json()["overdue"] is False
    assert r.json()["events"][0]["comment"] == "Due date reset to the SLA"


# ---- default assignee ---------------------------------------------------------------------------


def test_default_assignee_is_validated(client, auth, users, db):
    users["viewer"].is_active = False
    db.commit()
    for bad in (999, users["viewer"].id):
        r = client.post(
            "/api/v1/assets", json={"name": "x", "default_assignee_id": bad}, headers=auth["manager"]
        )
        assert r.status_code == 422
    r = client.post(
        "/api/v1/assets",
        json={"name": "x", "default_assignee_id": users["analyst"].id},
        headers=auth["manager"],
    )
    assert r.status_code == 201 and r.json()["default_assignee_id"] == users["analyst"].id


def test_new_findings_go_to_the_default_assignee(db, users, asset):
    analyst = users["analyst"]
    ingest_report(db, native("old"), asset, None, IngestOptions())
    asset.default_assignee_id = analyst.id
    db.commit()
    ingest_report(db, native("old", "new"), asset, None, IngestOptions())
    db.expire_all()  # reload events in their API order (newest first)

    old, new = db.scalars(select(Finding).order_by(Finding.id)).all()
    assert old.assignee_id is None  # existing findings are left alone
    assert new.assignee_id == analyst.id
    assert new.events[0].event == "assigned" and "default assignee of svc" in new.events[0].comment

    db.get(User, analyst.id).is_active = False
    db.commit()
    ingest_report(db, native("newer"), asset, None, IngestOptions())
    newer = db.scalar(select(Finding).where(Finding.title == "newer"))
    assert newer.assignee_id is None


def test_deleting_the_default_assignee_clears_it(client, auth, users, db, asset):
    asset.default_assignee_id = users["analyst"].id
    db.commit()
    assert client.delete(f"/api/v1/users/{users['analyst'].id}", headers=auth["admin"]).status_code == 204
    db.expire_all()
    assert db.get(Asset, asset.id).default_assignee_id is None


# ---- bulk due dates and bulk by filter -----------------------------------------------------------


def test_bulk_due_date_is_for_managers(client, auth, db, asset):
    ingest_report(db, native("a", "b"), asset, None, IngestOptions())
    ids = list(db.scalars(select(Finding.id)))
    due = (utcnow() + timedelta(days=3)).isoformat()
    body = {"ids": ids, "due_at": due, "due_reason": "release freeze"}

    assert client.post("/api/v1/findings/bulk", json=body, headers=auth["analyst"]).status_code == 403
    r = client.post("/api/v1/findings/bulk", json=body, headers=auth["manager"])
    assert r.status_code == 200 and r.json()["updated"] == 2
    db.expire_all()
    assert all(f.due_at_override is not None for f in db.scalars(select(Finding)))

    r = client.post("/api/v1/findings/bulk", json={"ids": ids, "clear_due_at": True}, headers=auth["manager"])
    assert r.json()["updated"] == 2
    db.expire_all()
    assert all(f.due_at_override is None for f in db.scalars(select(Finding)))

    both = {"ids": ids, "due_at": due, "clear_due_at": True}
    assert client.post("/api/v1/findings/bulk", json=both, headers=auth["manager"]).status_code == 422


def test_bulk_by_filter_changes_exactly_what_the_list_shows(client, auth, db, asset):
    ingest_report(db, native("keep", "tag-me", "tag-me-too"), asset, None, IngestOptions())
    params = {"q": "tag-me"}
    page = client.get("/api/v1/findings", params=params, headers=auth["analyst"]).json()
    listed = {i["id"] for i in page["items"]}
    assert len(listed) == 2

    r = client.post("/api/v1/findings/bulk/matching", params=params, json={"add_tags": ["batch"]},
                    headers=auth["analyst"])  # fmt: skip
    assert r.status_code == 200 and r.json()["updated"] == 2
    db.expire_all()
    assert {f.id for f in db.scalars(select(Finding)) if "batch" in f.tags} == listed

    assert client.post("/api/v1/findings/bulk/matching", json={}, headers=auth["analyst"]).status_code == 422
    assert client.post("/api/v1/findings/bulk/matching", json={"add_tags": ["x"]},
                       headers=auth["viewer"]).status_code == 403  # fmt: skip


def test_bulk_by_filter_refuses_more_than_the_cap(client, auth, db, asset, monkeypatch):
    from app.api.v1 import findings

    monkeypatch.setattr(findings, "MAX_BULK_MATCHING", 2)
    ingest_report(db, native("a", "b", "c"), asset, None, IngestOptions())
    r = client.post("/api/v1/findings/bulk/matching", json={"add_tags": ["x"]}, headers=auth["analyst"])
    assert r.status_code == 422 and "3 findings match" in r.text
    db.expire_all()
    assert not any(f.tags for f in db.scalars(select(Finding)))  # all or nothing


# ---- severity overrides ----------------------------------------------------------------------------


def _report(severity, tool="t"):
    found = {"title": "a", "severity": severity, "cwe": ["CWE-1"], "file_path": "a.py", "line_start": 1}
    return json.dumps(
        {"schema": "guardiano/v1", "tool": {"name": tool}, "scan_type": "sast", "findings": [found]}
    ).encode()


def test_a_rule_severity_survives_the_next_scan(db, asset):
    """It used to last until the reporting tool scanned again and put its own severity back."""
    from app.models import TriageRule

    db.add(TriageRule(name="r", enabled=True, priority=1, match={"cwe": "1"}, action={"severity": "low"}))
    db.commit()
    ingest_report(db, _report("high"), asset, None, IngestOptions())
    ingest_report(db, _report("high"), asset, None, IngestOptions())
    f = db.scalar(select(Finding))
    assert (f.severity, f.severity_override, f.scanner_severity) == ("low", "low", "high")


def test_a_manual_severity_holds_until_cleared(client, auth, db, asset):
    ingest_report(db, _report("high"), asset, None, IngestOptions())
    fid = db.scalar(select(Finding.id))
    assert patch(client, auth["analyst"], fid, {"severity": "low"}).status_code == 403
    r = patch(client, auth["manager"], fid, {"severity": "low", "severity_reason": "not reachable"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["severity"], body["severity_override"], body["scanner_severity"]) == ("low", "low", "high")
    assert body["events"][0]["event"] == "severity_changed"
    assert "not reachable" in body["events"][0]["comment"]

    ingest_report(db, _report("critical"), asset, None, IngestOptions())  # the scanner changes its mind
    db.expire_all()
    f = db.get(Finding, fid)
    assert (f.severity, f.scanner_severity) == ("low", "critical")

    r = patch(client, auth["manager"], fid, {"clear_severity_override": True})
    assert (r.json()["severity"], r.json()["severity_override"]) == ("critical", None)
    both = {"severity": "low", "clear_severity_override": True}
    assert patch(client, auth["manager"], fid, both).status_code == 422


def test_another_tool_raising_the_severity_is_recorded_but_does_not_beat_an_override(client, auth, db, asset):
    ingest_report(db, _report("medium", tool="first"), asset, None, IngestOptions())
    fid = db.scalar(select(Finding.id))
    patch(client, auth["manager"], fid, {"severity": "low"})
    ingest_report(db, _report("critical", tool="second"), asset, None, IngestOptions())
    db.expire_all()
    f = db.get(Finding, fid)
    assert (f.severity, f.scanner_severity) == ("low", "critical")


def test_without_an_override_scans_behave_as_before(db, asset):
    ingest_report(db, _report("medium", tool="first"), asset, None, IngestOptions())
    ingest_report(db, _report("high", tool="second"), asset, None, IngestOptions())  # another tool raises
    assert db.scalar(select(Finding.severity)) == "high"
    ingest_report(db, _report("low", tool="first"), asset, None, IngestOptions())  # the reporting tool lowers
    assert db.scalar(select(Finding.severity)) == "low"


def test_bulk_severity_is_for_managers(client, auth, db, asset):
    ingest_report(db, native("a", "b"), asset, None, IngestOptions())
    ids = list(db.scalars(select(Finding.id)))
    body = {"ids": ids, "severity": "critical"}
    assert client.post("/api/v1/findings/bulk", json=body, headers=auth["analyst"]).status_code == 403
    assert client.post("/api/v1/findings/bulk", json=body, headers=auth["manager"]).json()["updated"] == 2
    db.expire_all()
    assert {f.severity for f in db.scalars(select(Finding))} == {"critical"}
