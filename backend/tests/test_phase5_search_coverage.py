"""Bounded search, authorization, selection retention, and coverage semantics."""

from datetime import timedelta

from sqlalchemy import select

from app.models import Asset, Scan, Team, User
from app.models.base import utcnow
from app.services import analytics
from app.services.scope import GLOBAL, Scope


def test_asset_picker_pages_are_scoped_and_retain_selected_item(client, auth, db):
    team = Team(name="restricted")
    db.add(team)
    db.flush()
    rows = [Asset(name=f"service-{i:03}") for i in range(125)]
    secret = Asset(name="secret", team_id=team.id)
    literal = Asset(name="literal%name")
    db.add_all([*rows, secret, literal])
    db.commit()
    response = client.get(
        "/api/v1/assets/options/search",
        headers=auth["viewer"],
        params={
            "page": 2,
            "selected_id": rows[0].id,
        },
    )
    assert response.status_code == 200
    page = response.json()
    assert page["total"] == 126 and len(page["items"]) == 50
    assert page["selected"]["id"] == rows[0].id
    assert rows[0].id not in {row["id"] for row in page["items"]}
    response = client.get(
        "/api/v1/assets/options/search",
        headers=auth["viewer"],
        params={
            "q": "SECRET",
            "selected_id": secret.id,
        },
    ).json()
    assert response["items"] == [] and response["selected"] is None
    literal_page = client.get(
        "/api/v1/assets/options/search", headers=auth["viewer"], params={"q": "%"}
    ).json()
    assert [row["id"] for row in literal_page["items"]] == [literal.id]
    legacy = client.get("/api/v1/assets/options", headers=auth["viewer"])
    assert isinstance(legacy.json(), list) and len(legacy.json()) == 126
    assert (
        client.get(
            "/api/v1/assets/options/search", headers=auth["viewer"], params={"page_size": 101}
        ).status_code
        == 422
    )


def test_user_picker_and_selected_lookup_are_bounded_and_active_only(client, auth, db):
    people = [
        User(email=f"person{i:03}@test.io", full_name=f"Person {i:03}", password_hash="unused")
        for i in range(110)
    ]
    disabled = User(email="disabled@test.io", password_hash="unused", is_active=False)
    db.add_all([*people, disabled])
    db.commit()
    result = client.get(
        "/api/v1/users/directory/search",
        headers=auth["viewer"],
        params={
            "q": "PERSON",
            "page": 3,
            "selected_id": people[0].id,
        },
    ).json()
    assert result["total"] == 110 and len(result["items"]) == 10
    assert result["selected"]["id"] == people[0].id
    result = client.get(
        "/api/v1/users/directory/search",
        headers=auth["viewer"],
        params={
            "q": "disabled",
            "selected_id": disabled.id,
        },
    ).json()
    assert result["items"] == [] and result["selected"] is None
    result = client.get(
        "/api/v1/users/directory/lookup",
        headers=auth["viewer"],
        params={
            "ids": [people[0].id, people[109].id, disabled.id],
        },
    ).json()
    assert {row["id"] for row in result} == {people[0].id, people[109].id}
    assert client.get("/api/v1/users/directory/lookup", headers=auth["viewer"]).json() == []
    assert (
        client.get(
            "/api/v1/users/directory/lookup", headers=auth["viewer"], params={"ids": list(range(501))}
        ).status_code
        == 422
    )


def test_coverage_counts_every_asset_but_only_returns_ordered_cap(db, monkeypatch, count_queries):
    now = utcnow()
    monkeypatch.setattr(analytics, "utcnow", lambda: now)
    team = Team(name="private")
    db.add(team)
    db.flush()
    assets = [Asset(name=f"asset-{i:03}", criticality="critical" if i % 2 else "low") for i in range(310)]
    hidden = Asset(name="private", team_id=team.id)
    db.add_all([*assets, hidden])
    db.flush()
    # 210 never scanned, 50 stale, 50 recent. Previews do not count as coverage.
    for i in range(210, 310):
        db.add(
            Scan(
                asset_id=assets[i].id,
                scan_type="sast",
                tool_name="t",
                format="guardiano",
                created_at=now - timedelta(days=60 if i < 260 else 1),
            )
        )
    db.add(
        Scan(
            asset_id=assets[0].id,
            scan_type="sca",
            tool_name="t",
            format="guardiano",
            source="preview",
            created_at=now,
        )
    )
    db.commit()
    with count_queries() as queries:
        result = analytics.coverage(db, 30, scope=Scope(()))
    assert queries() == 1
    assert (result["assets"], result["covered"], result["never_scanned"], result["stale"]) == (
        310,
        50,
        210,
        50,
    )
    assert result["without_sast"] == 210 and result["without_sca"] == 310
    expected = sorted(
        assets[:210],
        key=lambda asset: (0 if asset.criticality == "critical" else 3, asset.name.lower(), asset.id),
    )
    assert [row["id"] for row in result["uncovered"]] == [asset.id for asset in expected[:200]]
    assert not any(row["has_sbom"] for row in result["uncovered"])
    assert analytics.coverage(db, 30, scope=GLOBAL)["assets"] == 311
    assert len(list(db.scalars(select(Asset)))) == 311


def test_coverage_empty_and_fully_covered_estates(db):
    assert analytics.coverage(db, 30, scope=GLOBAL) == {
        "stale_days": 30,
        "assets": 0,
        "covered": 0,
        "stale": 0,
        "never_scanned": 0,
        "without_sast": 0,
        "without_sca": 0,
        "uncovered": [],
    }
    asset = Asset(name="fully-covered")
    db.add(asset)
    db.flush()
    db.add(Scan(asset_id=asset.id, scan_type="sast", tool_name="t", format="guardiano", created_at=utcnow()))
    db.commit()
    result = analytics.coverage(db, 30, scope=GLOBAL)
    assert result["assets"] == result["covered"] == 1 and result["uncovered"] == []
