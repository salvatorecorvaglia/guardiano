"""Team-scoped access: who can see which assets, across every way of reading them.

The rule under test, in one sentence: **an asset with no team is visible to everyone, an asset in a team is
visible to that team's members, and administrators see everything.** The breadth is the risk here, so this
suite walks the whole matrix — every list, detail, export, count and analytics figure — rather than trusting
that one filter covers them all.
"""

import csv
import io
import json

import pytest
from sqlalchemy import func, select

from app.models import Asset, Finding, Scan, Team
from app.services.ingestion import IngestOptions, ingest_report
from tests.conftest import sample

# Who belongs where. The viewer is in no team at all, which is the state every existing account starts in.
MEMBERSHIP = {"analyst": "payments", "manager": "platform"}
# The assets each role may see, once the teams below exist.
VISIBLE = {
    "admin": {"shared-lib", "payments-api", "platform-svc"},
    "analyst": {"shared-lib", "payments-api"},
    "manager": {"shared-lib", "platform-svc"},
    "viewer": {"shared-lib"},
}
ROLES = list(VISIBLE)


@pytest.fixture
def world(db, users):
    """Three assets — one shared, two owned by a team — each with a scan, findings and components."""
    teams = {name: Team(name=name, description="") for name in ("payments", "platform")}
    db.add_all(teams.values())
    db.flush()
    for role, team in MEMBERSHIP.items():
        teams[team].members.append(users[role])

    assets = {}
    for name, team in [("shared-lib", None), ("payments-api", "payments"), ("platform-svc", "platform")]:
        asset = Asset(name=name, tags=[], team_id=teams[team].id if team else None)
        db.add(asset)
        db.flush()
        ingest_report(db, sample("osv.json"), asset, None, IngestOptions())
        assets[name] = asset
    db.commit()
    return {"assets": assets, "teams": teams}


def ids_by_asset(db) -> dict[str, list[int]]:
    rows = db.execute(select(Asset.name, Finding.id).join(Finding, Finding.asset_id == Asset.id)).all()
    out: dict[str, list[int]] = {}
    for name, finding_id in rows:
        out.setdefault(name, []).append(finding_id)
    return out


def names_in(client, headers) -> set[str]:
    r = client.get("/api/v1/findings", params={"page_size": 500}, headers=headers)
    assert r.status_code == 200, r.text
    return {item["asset"]["name"] for item in r.json()["items"]}


def expected_findings(world, role) -> int:
    return 2 * len(VISIBLE[role])  # osv.json carries two vulnerabilities


# ---- the baseline: nothing changes until somebody makes a team ------------------------------------


@pytest.mark.parametrize("role", ROLES)
def test_without_teams_everybody_still_sees_everything(client, auth, db, users, role):
    for name in ("alpha", "beta"):
        asset = Asset(name=name, tags=[])
        db.add(asset)
        db.flush()
        ingest_report(db, sample("osv.json"), asset, None, IngestOptions())
    db.commit()

    assert names_in(client, auth[role]) == {"alpha", "beta"}
    assert client.get("/api/v1/findings", headers=auth[role]).json()["total"] == 4
    assert client.get("/api/v1/assets", headers=auth[role]).json()["total"] == 2
    assert client.get("/api/v1/analytics/summary", headers=auth[role]).json()["open_total"] == 4


# ---- findings -------------------------------------------------------------------------------------


@pytest.mark.parametrize("role", ROLES)
def test_findings_are_limited_to_the_teams_you_belong_to(client, auth, world, role):
    assert names_in(client, auth[role]) == VISIBLE[role]


@pytest.mark.parametrize("role", ROLES)
def test_the_count_agrees_with_the_rows(client, auth, world, role):
    """A total that counts what the page cannot show would leak the existence of other teams' work."""
    body = client.get("/api/v1/findings", params={"page_size": 500}, headers=auth[role]).json()
    assert body["total"] == len(body["items"]) == expected_findings(world, role)


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("fmt", ["csv", "json", "sarif"])
def test_exports_carry_exactly_what_the_list_shows(client, auth, world, role, fmt):
    r = client.get(f"/api/v1/findings/export.{fmt}", headers=auth[role])
    assert r.status_code == 200
    if fmt == "csv":
        rows = list(csv.DictReader(io.StringIO(r.text)))
        assert {row["asset"] for row in rows} == VISIBLE[role]
    elif fmt == "json":
        rows = json.loads(r.text)
        assert {row["asset"]["name"] for row in rows} == VISIBLE[role]
    else:
        results = json.loads(r.text)["runs"][0]["results"]
        assert len(results) == expected_findings(world, role)


def test_a_finding_in_another_team_is_simply_not_there(client, auth, db, world):
    hidden = ids_by_asset(db)["platform-svc"][0]
    mine = ids_by_asset(db)["payments-api"][0]
    assert client.get(f"/api/v1/findings/{hidden}", headers=auth["analyst"]).status_code == 404
    assert client.get(f"/api/v1/findings/{mine}", headers=auth["analyst"]).status_code == 200
    assert client.get(f"/api/v1/findings/{hidden}", headers=auth["admin"]).status_code == 200
    assert client.get(f"/api/v1/findings/{hidden}/events", headers=auth["analyst"]).status_code == 404
    assert client.get(f"/api/v1/findings/{mine}/events", headers=auth["analyst"]).status_code == 200
    assert client.get(f"/api/v1/findings/{hidden}/events", headers=auth["admin"]).status_code == 200


def test_you_cannot_change_a_finding_you_cannot_see(client, auth, db, world):
    hidden = ids_by_asset(db)["platform-svc"][0]
    body = {"status": "false_positive", "justification": "not reachable in our build"}
    assert client.patch(f"/api/v1/findings/{hidden}", json=body, headers=auth["analyst"]).status_code == 404
    assert (
        client.post(
            f"/api/v1/findings/{hidden}/comments", json={"text": "hi"}, headers=auth["analyst"]
        ).status_code
        == 404
    )


def test_a_bulk_action_stops_at_the_team_boundary(client, auth, db, world):
    by_asset = ids_by_asset(db)
    ids = by_asset["payments-api"] + by_asset["platform-svc"]
    r = client.post(
        "/api/v1/findings/bulk",
        json={"ids": ids, "status": "resolved", "justification": "fixed in the latest release"},
        headers=auth["analyst"],
    )
    assert r.status_code == 200
    assert r.json()["updated"] == len(by_asset["payments-api"])

    db.expire_all()
    untouched = db.scalars(select(Finding).where(Finding.id.in_(by_asset["platform-svc"]))).all()
    assert {f.status for f in untouched} == {"open"}, "another team's findings must not be reachable in bulk"


def test_filtering_by_another_teams_asset_returns_nothing(client, auth, world):
    """The filter narrows what you may see; it never widens it."""
    hidden = world["assets"]["platform-svc"].id
    r = client.get("/api/v1/findings", params={"asset_id": hidden}, headers=auth["analyst"])
    assert r.status_code == 200 and r.json()["total"] == 0


@pytest.mark.parametrize("role", ROLES)
def test_the_tag_list_is_scoped(client, auth, db, world, role):
    by_asset = ids_by_asset(db)
    for asset_name, tag in [("payments-api", "payments-only"), ("platform-svc", "platform-only")]:
        client.patch(
            f"/api/v1/findings/{by_asset[asset_name][0]}",
            json={"tags": [tag]},
            headers=auth["admin"],
        )
    tags = {row["tag"] for row in client.get("/api/v1/findings/tags", headers=auth[role]).json()}
    assert ("payments-only" in tags) is ("payments-api" in VISIBLE[role])
    assert ("platform-only" in tags) is ("platform-svc" in VISIBLE[role])


# ---- assets, scans and components -----------------------------------------------------------------


@pytest.mark.parametrize("role", ROLES)
def test_the_asset_picker_is_scoped(client, auth, world, role):
    names = [a["name"] for a in client.get("/api/v1/assets/options", headers=auth[role]).json()]
    assert set(names) == VISIBLE[role] and names == sorted(names)


@pytest.mark.parametrize("role", ROLES)
def test_the_asset_list_is_scoped(client, auth, world, role):
    body = client.get("/api/v1/assets", params={"page_size": 100}, headers=auth[role]).json()
    assert {item["name"] for item in body["items"]} == VISIBLE[role]
    assert body["total"] == len(VISIBLE[role])


def test_an_asset_in_another_team_is_not_found(client, auth, world):
    hidden = world["assets"]["platform-svc"].id
    assert client.get(f"/api/v1/assets/{hidden}", headers=auth["analyst"]).status_code == 404
    assert client.get(f"/api/v1/assets/{hidden}", headers=auth["admin"]).status_code == 200


@pytest.mark.parametrize("role", ROLES)
def test_scans_are_scoped(client, auth, db, world, role):
    body = client.get("/api/v1/scans", params={"page_size": 100}, headers=auth[role]).json()
    assert {item["asset"]["name"] for item in body["items"]} == VISIBLE[role]


def test_a_scan_of_another_teams_asset_is_not_found(client, auth, db, world):
    from app.models import Scan

    hidden = db.scalar(select(Scan).where(Scan.asset_id == world["assets"]["platform-svc"].id))
    assert client.get(f"/api/v1/scans/{hidden.id}", headers=auth["analyst"]).status_code == 404
    assert client.get(f"/api/v1/scans/{hidden.id}/diff", headers=auth["analyst"]).status_code == 404
    assert client.get(f"/api/v1/scans/{hidden.id}", headers=auth["admin"]).status_code == 200


@pytest.mark.parametrize("role", ROLES)
def test_the_component_inventory_is_scoped(client, auth, world, role):
    """ "Where is this package used?" must not answer for systems you cannot see."""
    body = client.get("/api/v1/components", params={"page_size": 100}, headers=auth[role]).json()
    used_by = {ref["name"] for item in body["items"] for ref in item["assets"]}
    assert used_by == VISIBLE[role]
    stats = client.get("/api/v1/components/stats", headers=auth[role]).json()
    assert stats["assets"] == len(VISIBLE[role])


def test_uploading_to_another_teams_asset_is_refused(client, auth, world):
    hidden = world["assets"]["platform-svc"].id
    r = client.post(
        "/api/v1/scans",
        headers=auth["analyst"],
        files={"file": ("osv.json", sample("osv.json"), "application/json")},
        data={"asset_id": str(hidden)},
    )
    assert r.status_code == 404, r.text


@pytest.mark.parametrize("name", ["platform-svc", "PLATFORM-SVC"])
def test_uploading_to_another_teams_asset_by_name_is_refused(client, auth, world, db, name):
    """Naming the asset must not sidestep the check the asset_id path performs. The lookup is
    case-insensitive, so a different casing must be refused too rather than creating a twin."""

    def counts() -> tuple[int, int]:
        return (
            db.scalar(select(func.count()).select_from(Asset)),
            db.scalar(select(func.count()).select_from(Scan)),
        )

    before = counts()
    r = client.post(
        "/api/v1/scans",
        headers=auth["analyst"],
        files={"file": ("osv.json", sample("osv.json"), "application/json")},
        data={"asset_name": name},
    )
    assert r.status_code == 404, r.text
    # Nothing was written: no twin asset under a different casing, and no scan on the hidden one.
    assert counts() == before


def test_uploading_by_name_still_creates_a_brand_new_asset(client, auth, world):
    """The CI workflow the asset_name branch exists for keeps working."""
    r = client.post(
        "/api/v1/scans",
        headers=auth["analyst"],
        files={"file": ("osv.json", sample("osv.json"), "application/json")},
        data={"asset_name": "a-brand-new-service"},
    )
    assert r.status_code == 201, r.text


# ---- analytics --------------------------------------------------------------------------------------


@pytest.mark.parametrize("role", ROLES)
def test_every_analytics_figure_agrees_with_the_findings_list(client, auth, world, role):
    expected = expected_findings(world, role)
    summary = client.get("/api/v1/analytics/summary", headers=auth[role]).json()
    assert summary["open_total"] == expected
    assert summary["assets_total"] == len(VISIBLE[role])
    assert summary["scans_last_30d"] == len(VISIBLE[role])

    trends = client.get("/api/v1/analytics/trends", headers=auth[role]).json()
    assert sum(point["new"] for point in trends["new_vs_closed"]) == expected

    top = client.get("/api/v1/analytics/top", params={"by": "assets"}, headers=auth[role]).json()
    assert {row["name"] for row in top} == VISIBLE[role]
    packages = client.get("/api/v1/analytics/top", params={"by": "packages"}, headers=auth[role]).json()
    assert sum(row["count"] for row in packages) == expected


def test_a_triage_preview_only_scans_what_you_can_see(client, auth, world):
    body = {"match": {"severity": ["high", "medium"]}, "limit": 50}
    mine = client.post("/api/v1/triage-rules/preview", json=body, headers=auth["manager"]).json()
    everything = client.post("/api/v1/triage-rules/preview", json=body, headers=auth["admin"]).json()
    assert mine["scanned"] == 4 and everything["scanned"] == 6
    assert {f["asset"]["name"] for f in mine["sample"]} == VISIBLE["manager"]


# ---- the boundary itself ------------------------------------------------------------------------


def test_an_api_token_inherits_the_scope_of_whoever_made_it(client, auth, world):
    token = client.post(
        "/api/v1/tokens", json={"name": "ci", "scopes": ["read", "ingest"]}, headers=auth["analyst"]
    ).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    assert names_in(client, headers) == VISIBLE["analyst"]


def test_taking_an_asset_out_of_its_team_makes_it_public_again(client, auth, db, world):
    platform = world["assets"]["platform-svc"]
    assert client.get(f"/api/v1/assets/{platform.id}", headers=auth["analyst"]).status_code == 404
    r = client.patch(f"/api/v1/assets/{platform.id}", json={"team_id": None}, headers=auth["admin"])
    assert r.status_code == 200
    assert client.get(f"/api/v1/assets/{platform.id}", headers=auth["analyst"]).status_code == 200
    assert names_in(client, auth["viewer"]) == {"shared-lib", "platform-svc"}


def test_joining_a_team_grants_access(client, auth, db, world, users):
    payments = world["teams"]["payments"]
    assert names_in(client, auth["viewer"]) == {"shared-lib"}
    r = client.put(
        f"/api/v1/teams/{payments.id}/members",
        json={"user_ids": [users["viewer"].id, users["analyst"].id]},
        headers=auth["admin"],
    )
    assert r.status_code == 200
    assert names_in(client, auth["viewer"]) == {"shared-lib", "payments-api"}


def test_deleting_a_team_releases_its_assets(client, auth, db, world):
    r = client.delete(f"/api/v1/teams/{world['teams']['platform'].id}", headers=auth["admin"])
    assert r.status_code == 204
    db.expire_all()
    assert db.get(Asset, world["assets"]["platform-svc"].id).team_id is None
    assert names_in(client, auth["viewer"]) == {"shared-lib", "platform-svc"}


@pytest.mark.parametrize("role", ["manager", "analyst", "viewer"])
def test_only_administrators_manage_teams(client, auth, world, role):
    assert client.post("/api/v1/teams", json={"name": "new"}, headers=auth[role]).status_code == 403
    team_id = world["teams"]["payments"].id
    assert client.patch(f"/api/v1/teams/{team_id}", json={"name": "x"}, headers=auth[role]).status_code == 403
    assert client.delete(f"/api/v1/teams/{team_id}", headers=auth[role]).status_code == 403
    assert (
        client.put(f"/api/v1/teams/{team_id}/members", json={"user_ids": []}, headers=auth[role]).status_code
        == 403
    )


def test_only_administrators_move_an_asset_between_teams(client, auth, world):
    """Otherwise anybody who can edit an asset could hide it, or help themselves to another team's."""
    shared = world["assets"]["shared-lib"].id
    team_id = world["teams"]["platform"].id
    r = client.patch(f"/api/v1/assets/{shared}", json={"team_id": team_id}, headers=auth["manager"])
    assert r.status_code == 403
    # Everything else about the asset is still a manager's to edit.
    assert (
        client.patch(f"/api/v1/assets/{shared}", json={"owner": "me"}, headers=auth["manager"]).status_code
        == 200
    )


def test_everybody_sees_the_teams_they_are_in(client, auth, world, users):
    mine = client.get("/api/v1/teams", headers=auth["analyst"]).json()
    assert [t["name"] for t in mine] == ["payments"]
    assert [t["name"] for t in client.get("/api/v1/teams", headers=auth["viewer"]).json()] == []
    everything = client.get("/api/v1/teams", headers=auth["admin"]).json()
    assert {t["name"] for t in everything} == {"payments", "platform"}
    payments = next(t for t in everything if t["name"] == "payments")
    assert payments["member_count"] == 1 and payments["asset_count"] == 1


def test_a_team_change_is_audited(client, auth, db, world, users):
    from app.models import AuditLog

    team_id = world["teams"]["payments"].id
    client.put(
        f"/api/v1/teams/{team_id}/members", json={"user_ids": [users["viewer"].id]}, headers=auth["admin"]
    )
    entry = db.scalar(select(AuditLog).where(AuditLog.action == "team.members"))
    assert entry.target_label == "payments"
    assert entry.changes["members"] == {"from": ["analyst@test.io"], "to": ["viewer@test.io"]}


def test_a_scoped_user_cannot_assign_work_across_the_boundary(client, auth, db, world, users):
    """Assignments must not disclose work to people outside the asset scope."""
    mine = ids_by_asset(db)["payments-api"][0]
    r = client.patch(
        f"/api/v1/findings/{mine}", json={"assignee_id": users["manager"].id}, headers=auth["analyst"]
    )
    assert r.status_code == 422
    db.expire_all()
    assert db.get(Finding, mine).assignee_id != users["manager"].id
    # Rejected assignment does not grant visibility.
    assert client.get(f"/api/v1/findings/{mine}", headers=auth["manager"]).status_code == 404


def test_a_gate_policy_does_not_leak_another_teams_asset(client, auth, db, world):
    """A gate names its asset, so listing one for an asset you cannot see would leak the name."""
    for name in ("payments-api", "platform-svc"):
        body = {"asset_id": world["assets"][name].id, "conditions": {"max_new": {"critical": 0}}}
        assert client.put("/api/v1/gate-policies", json=body, headers=auth["admin"]).status_code == 200

    def named(role):
        rows = client.get("/api/v1/gate-policies", headers=auth[role]).json()
        return {p["asset"]["name"] for p in rows if p["asset"]}

    assert named("admin") == {"payments-api", "platform-svc"}
    assert named("analyst") == {"payments-api"}  # their team only
    assert named("manager") == {"platform-svc"}
    assert named("viewer") == set()

    # Nor can a manager outside the team create or delete a gate for that asset.
    payments = world["assets"]["payments-api"].id
    body = {"asset_id": payments, "conditions": {"max_new": {"high": 1}}}
    assert client.put("/api/v1/gate-policies", json=body, headers=auth["manager"]).status_code == 404
    policy_id = next(
        p["id"]
        for p in client.get("/api/v1/gate-policies", headers=auth["admin"]).json()
        if p["asset"] and p["asset"]["name"] == "payments-api"
    )
    assert client.delete(f"/api/v1/gate-policies/{policy_id}", headers=auth["manager"]).status_code == 404
    assert client.delete(f"/api/v1/gate-policies/{policy_id}", headers=auth["admin"]).status_code == 204


def test_a_triage_rule_does_not_leak_or_reach_another_teams_asset(client, auth, db, world):
    """A rule names its asset and what it matches there, and can mark that asset's findings false positive.

    So a rule on an asset outside your teams is hidden from the list, cannot be created, edited or deleted,
    and an existing rule cannot be moved onto such an asset. Global rules stay visible to everybody.
    """
    match = {"severity": ["low"]}
    action = {"tags": ["triaged"]}

    def create(asset_id, headers):
        body = {"name": f"rule-{asset_id}", "asset_id": asset_id, "match": match, "action": action}
        return client.post("/api/v1/triage-rules", json=body, headers=headers)

    rule_ids = {}
    for name in ("payments-api", "platform-svc"):
        r = create(world["assets"][name].id, auth["admin"])
        assert r.status_code == 201, r.text
        rule_ids[name] = r.json()["id"]
    assert create(None, auth["manager"]).status_code == 403  # a global rule reaches every team: admins only
    assert create(None, auth["admin"]).status_code == 201

    def named(role):
        rows = client.get("/api/v1/triage-rules", headers=auth[role]).json()
        return {p["asset"]["name"] if p["asset"] else "global" for p in rows}

    assert named("admin") == {"payments-api", "platform-svc", "global"}
    assert named("analyst") == {"payments-api", "global"}  # their team only
    assert named("manager") == {"platform-svc", "global"}
    assert named("viewer") == {"global"}

    payments, platform = world["assets"]["payments-api"].id, world["assets"]["platform-svc"].id
    # The manager is in "platform": nothing they do may touch the payments team's asset.
    assert create(payments, auth["manager"]).status_code == 422
    assert (
        client.patch(
            f"/api/v1/triage-rules/{rule_ids['payments-api']}",
            json={"enabled": False},
            headers=auth["manager"],
        ).status_code
        == 404
    )
    moved = {"asset_id": payments}
    assert (
        client.patch(
            f"/api/v1/triage-rules/{rule_ids['platform-svc']}", json=moved, headers=auth["manager"]
        ).status_code
        == 422
    )
    assert (
        client.delete(f"/api/v1/triage-rules/{rule_ids['payments-api']}", headers=auth["manager"]).status_code
        == 404
    )

    # Their own team's rule is still theirs to manage.
    assert create(platform, auth["manager"]).status_code == 201
    r = client.patch(
        f"/api/v1/triage-rules/{rule_ids['platform-svc']}", json={"enabled": False}, headers=auth["manager"]
    )
    assert r.status_code == 200, r.text
    for rule, role in (("platform-svc", "manager"), ("payments-api", "admin")):
        assert client.delete(f"/api/v1/triage-rules/{rule_ids[rule]}", headers=auth[role]).status_code == 204


def test_a_bulk_action_by_filter_stops_at_the_team_boundary(client, auth, db, world):
    """No filter at all is "everything", and everything must still mean everything you can see."""
    r = client.post(
        "/api/v1/findings/bulk/matching",
        json={"status": "resolved", "justification": "fixed in the latest release"},
        headers=auth["analyst"],
    )
    assert r.status_code == 200
    visible = VISIBLE["analyst"]
    assert r.json()["updated"] == expected_findings(world, "analyst")

    db.expire_all()
    for name, ids in ids_by_asset(db).items():
        statuses = {f.status for f in db.scalars(select(Finding).where(Finding.id.in_(ids)))}
        assert statuses == ({"resolved"} if name in visible else {"open"}), name
