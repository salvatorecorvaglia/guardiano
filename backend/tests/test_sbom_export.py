"""SBOM export: the component inventory as CycloneDX and SPDX documents."""

import json

import pytest
from sqlalchemy import select

from app.models import Asset, Component, Team
from app.services.ingestion import IngestOptions, ingest_report
from tests.conftest import sample


def _sbom(*components, tool="cdxgen"):
    return json.dumps({
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"tools": {"components": [{"type": "application", "name": tool}]}},
        "components": [
            {"type": "library", "name": n, "version": v, "purl": f"pkg:npm/{n}@{v}",
             "licenses": [{"license": {"id": lic}} for lic in lics]}
            for n, v, lics in components
        ],
    }).encode()  # fmt: skip


@pytest.fixture
def asset(db):
    a = Asset(name="payments api", tags=[])
    db.add(a)
    db.commit()
    return a


def export(client, auth, asset, **params):
    r = client.get(f"/api/v1/assets/{asset.id}/sbom", params=params, headers=auth["viewer"])
    assert r.status_code == 200, r.text
    return r


def keys(db, asset):
    return sorted(db.scalars(select(Component.key).where(Component.asset_id == asset.id)))


def test_a_cyclonedx_export_imports_back_as_the_same_inventory(client, auth, db, asset):
    ingest_report(db, sample("cyclonedx.json"), asset, None, IngestOptions())
    r = export(client, auth, asset)
    assert r.headers["content-type"].startswith("application/vnd.cyclonedx+json")
    assert 'filename="payments-api.cdx.json"' in r.headers["content-disposition"]
    doc = r.json()
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.5"
    assert len({c["bom-ref"] for c in doc["components"]}) == len(doc["components"])

    copy = Asset(name="copy", tags=[])
    db.add(copy)
    db.commit()
    ingest_report(db, json.dumps(doc).encode(), copy, None, IngestOptions())
    assert keys(db, copy) == keys(db, asset)


def test_current_is_what_the_latest_scan_lists(client, auth, db, asset):
    both = _sbom(("left-pad", "1.0.0", ["MIT"]), ("lodash", "4.17.21", ["MIT"]))
    ingest_report(db, both, asset, None, IngestOptions())
    ingest_report(db, _sbom(("lodash", "4.17.21", ["MIT"])), asset, None, IngestOptions())  # left-pad removed
    current = [c["name"] for c in export(client, auth, asset).json()["components"]]
    everything = [c["name"] for c in export(client, auth, asset, include="all").json()["components"]]
    assert current == ["lodash"] and sorted(everything) == ["left-pad", "lodash"]


def test_each_tool_keeps_its_own_latest_scan(client, auth, db, asset):
    """A newer image SBOM must not hide the repository's, or the other way round."""

    def scan(tool, *components):
        ingest_report(db, _sbom(*components, tool=tool), asset, None, IngestOptions())

    scan("cdxgen", ("express", "4.19.2", ["MIT"]), ("debug", "2.6.9", ["MIT"]))  # the repository
    scan("syft", ("openssl", "3.0.13", ["Apache-2.0"]))  # the container image, scanned later
    scan("cdxgen", ("express", "4.19.2", ["MIT"]))  # the repository again, without debug
    names = {c["name"] for c in export(client, auth, asset).json()["components"]}
    assert names == {"express", "openssl"}


def test_spdx_declares_only_what_it_can_say_for_certain(client, auth, db, asset):
    ingest_report(
        db,
        _sbom(
            ("one", "1.0.0", ["MIT"]),
            ("dual", "1.0.0", ["MIT", "Apache-2.0"]),
            ("odd", "1.0.0", ["Some Licence"]),
        ),
        asset, None, IngestOptions(),
    )  # fmt: skip
    r = export(client, auth, asset, format="spdx")
    assert r.headers["content-type"].startswith("application/spdx+json")
    doc = r.json()
    assert doc["spdxVersion"] == "SPDX-2.3" and doc["dataLicense"] == "CC0-1.0"
    by_name = {p["name"]: p for p in doc["packages"]}
    assert by_name["one"]["licenseDeclared"] == "MIT"
    # Two licences on one component: AND or OR is a legal question, so nothing is asserted.
    assert by_name["dual"]["licenseDeclared"] == "NOASSERTION"
    assert "MIT; Apache-2.0" in by_name["dual"]["comment"]
    assert by_name["odd"]["licenseDeclared"] == "NOASSERTION"
    assert by_name["one"]["externalRefs"][0]["referenceLocator"] == "pkg:npm/one@1.0.0"
    ids = [p["SPDXID"] for p in doc["packages"]]
    assert len(ids) == len(set(ids)) == 4
    contained = {r["relatedSpdxElement"] for r in doc["relationships"] if r["relationshipType"] == "CONTAINS"}
    assert contained == set(ids) - {"SPDXRef-Asset"}


def test_an_asset_you_cannot_see_has_no_sbom(client, auth, db, asset):
    team = Team(name="other", description="")
    db.add(team)
    db.flush()
    asset.team_id = team.id
    db.commit()
    assert client.get(f"/api/v1/assets/{asset.id}/sbom", headers=auth["viewer"]).status_code == 404
    assert client.get(f"/api/v1/assets/{asset.id}/sbom", headers=auth["admin"]).status_code == 200
