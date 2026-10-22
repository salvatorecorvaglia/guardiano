"""Scan coverage: which assets are scanned, and how recently."""

from datetime import timedelta

import pytest

from app.models import Asset, Scan, Team
from app.models.base import utcnow
from app.services.ingestion import IngestOptions, ingest_report
from tests.conftest import sample


def _scan(db, asset, *, days_ago, scan_type="sast", source="upload"):
    db.add(Scan(asset_id=asset.id, scan_type=scan_type, tool_name="t", format="guardiano", source=source,
                created_at=utcnow() - timedelta(days=days_ago)))  # fmt: skip


@pytest.fixture
def estate(db):
    names = {
        "fresh": "low", "old": "medium", "never-crit": "critical", "never-low": "low", "preview-only": "high",
    }  # fmt: skip
    assets = {n: Asset(name=n, tags=[], criticality=c) for n, c in names.items()}
    db.add_all(assets.values())
    db.flush()
    _scan(db, assets["fresh"], days_ago=2)
    _scan(db, assets["fresh"], days_ago=40, scan_type="sca")
    _scan(db, assets["old"], days_ago=90)
    _scan(db, assets["preview-only"], days_ago=1, source="preview")
    db.commit()
    return assets


def get(client, auth, role="viewer", **params):
    r = client.get("/api/v1/analytics/coverage", params=params, headers=auth[role])
    assert r.status_code == 200, r.text
    return r.json()


def test_counts_and_the_order_of_what_needs_attention(client, auth, estate):
    body = get(client, auth)
    assert (body["assets"], body["covered"], body["stale"], body["never_scanned"]) == (5, 1, 1, 3)
    # Never scanned first (most critical first), then the longest-unscanned.
    assert [a["name"] for a in body["uncovered"]] == ["never-crit", "preview-only", "never-low", "old"]
    assert body["without_sast"] == 3 and body["without_sca"] == 4


def test_a_preview_is_not_coverage(client, auth, estate):
    preview_only = next(a for a in get(client, auth)["uncovered"] if a["name"] == "preview-only")
    assert preview_only["last_scan_at"] is None


def test_the_window_decides_what_is_stale(client, auth, estate):
    assert get(client, auth, stale_days=120)["stale"] == 0
    assert get(client, auth, stale_days=1)["stale"] == 2


def test_an_sbom_is_reported(client, auth, db, estate):
    scan = ingest_report(db, sample("cyclonedx.json"), estate["old"], None, IngestOptions())
    scan.created_at = utcnow() - timedelta(days=60)  # still stale: only the inventory is new
    db.commit()
    old = get(client, auth)
    assert next(a for a in old["uncovered"] if a["name"] == "old")["has_sbom"] is True


def test_it_only_counts_what_the_viewer_can_see(client, auth, db, users, estate):
    team = Team(name="other", description="")
    db.add(team)
    db.flush()
    estate["never-crit"].team_id = team.id
    db.commit()
    assert get(client, auth, "viewer")["assets"] == 4
    assert get(client, auth, "admin")["assets"] == 5


def test_out_of_range_windows_are_refused(client, auth):
    for days in (0, 366):
        r = client.get("/api/v1/analytics/coverage", params={"stale_days": days}, headers=auth["viewer"])
        assert r.status_code == 422
