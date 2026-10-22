"""The component inventory: what an SBOM says each asset ships."""

import json

import pytest
from sqlalchemy import select

from app.models import Asset, Component
from app.parsers.detect import parse_report
from app.services.ingestion import IngestOptions, ingest_report
from tests.conftest import sample


def cyclonedx(*components, vulnerabilities=()):
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {"tools": [{"name": "Syft", "version": "1.0"}]},
            "components": list(components),
            "vulnerabilities": list(vulnerabilities),
        }
    ).encode()


def component(name, version, purl=None, licenses=None, group=None):
    out = {"type": "library", "bom-ref": purl or f"{name}@{version}", "name": name, "version": version}
    if purl:
        out["purl"] = purl
    if group:
        out["group"] = group
    if licenses:
        out["licenses"] = licenses
    return out


@pytest.fixture
def asset(db):
    a = Asset(name="payments-api", tags=[])
    db.add(a)
    db.commit()
    return a


def components(db, asset=None):
    stmt = select(Component).order_by(Component.name)
    if asset:
        stmt = stmt.where(Component.asset_id == asset.id)
    return db.scalars(stmt).all()


# ---- parsing ------------------------------------------------------------------------------------


def test_cyclonedx_components_are_parsed_with_licences(db):
    report = parse_report(
        json.loads(
            cyclonedx(
                component(
                    "log4j-core",
                    "2.14.1",
                    "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                    [{"license": {"id": "Apache-2.0"}}],
                    group="org.apache.logging.log4j",
                ),
                component(
                    "lodash", "4.17.20", "pkg:npm/lodash@4.17.20", [{"license": {"name": "MIT License"}}]
                ),
                component("custom", "1.0", licenses=[{"expression": "MIT OR Apache-2.0"}]),
            )
        )
    )
    by_name = {c.name: c for c in report.components}
    assert set(by_name) == {"org.apache.logging.log4j:log4j-core", "lodash", "custom"}
    assert by_name["org.apache.logging.log4j:log4j-core"].ecosystem == "maven"
    assert by_name["org.apache.logging.log4j:log4j-core"].licenses == ["Apache-2.0"]
    assert by_name["lodash"].licenses == ["MIT License"]
    assert by_name["custom"].licenses == ["MIT OR Apache-2.0"]  # an expression is kept verbatim


def test_trivy_packages_are_parsed_when_present(db):
    report = parse_report(
        {
            "SchemaVersion": 2,
            "Trivy": {"Version": "0.55.2"},
            "Results": [
                {
                    "Target": "package-lock.json",
                    "Type": "npm",
                    "Packages": [
                        {
                            "Name": "express",
                            "Version": "4.17.1",
                            "Licenses": ["MIT"],
                            "Identifier": {"PURL": "pkg:npm/express@4.17.1"},
                        }
                    ],
                    "Vulnerabilities": [],
                }
            ],
        }
    )
    (pkg,) = report.components
    assert (pkg.name, pkg.version, pkg.ecosystem, pkg.licenses) == ("express", "4.17.1", "npm", ["MIT"])


def test_reports_without_an_sbom_record_nothing(db, asset):
    ingest_report(db, sample("semgrep.sarif"), asset, None, IngestOptions())
    assert components(db) == []


# ---- recording ----------------------------------------------------------------------------------


def test_components_are_recorded_and_refreshed(db, asset):
    ingest_report(
        db,
        cyclonedx(component("lodash", "4.17.20", "pkg:npm/lodash@4.17.20", [{"license": {"id": "MIT"}}])),
        asset,
        None,
        IngestOptions(),
    )
    (lodash,) = components(db)
    assert (lodash.name, lodash.version, lodash.ecosystem) == ("lodash", "4.17.20", "npm")
    assert lodash.licenses == ["MIT"] and lodash.last_scan_id is not None
    first_seen = lodash.first_seen_at

    # The same package again: one row, refreshed, keeping when it first appeared.
    second = ingest_report(
        db,
        cyclonedx(component("lodash", "4.17.20", "pkg:npm/lodash@4.17.20", [{"license": {"id": "MIT"}}])),
        asset,
        None,
        IngestOptions(),
    )
    db.expire_all()
    (lodash,) = components(db)
    assert lodash.first_seen_at == first_seen and lodash.last_scan_id == second.id


def test_an_upgrade_is_a_new_row_and_the_old_one_stays(db, asset):
    ingest_report(db, cyclonedx(component("lodash", "4.17.20")), asset, None, IngestOptions())
    ingest_report(db, cyclonedx(component("lodash", "4.17.21")), asset, None, IngestOptions())
    rows = components(db)
    assert [c.version for c in rows] == ["4.17.20", "4.17.21"]
    # The version that is gone simply stops being seen; the fact it was there is not erased.
    assert rows[0].last_seen_at < rows[1].last_seen_at


def test_each_asset_keeps_its_own_inventory(db, asset):
    other = Asset(name="web-portal", tags=[])
    db.add(other)
    db.commit()
    ingest_report(db, cyclonedx(component("lodash", "4.17.20")), asset, None, IngestOptions())
    ingest_report(db, cyclonedx(component("lodash", "4.17.20")), other, None, IngestOptions())
    assert len(components(db)) == 2
    assert len(components(db, asset)) == 1


def test_previews_record_nothing(db, asset):
    asset.default_branch = "main"
    db.commit()
    ingest_report(db, cyclonedx(component("lodash", "4.17.20")), asset, None, IngestOptions(branch="pr-1"))
    assert components(db) == []


# ---- reading it back ----------------------------------------------------------------------------


@pytest.fixture
def inventory(db, asset):
    other = Asset(name="web-portal", tags=[])
    db.add(other)
    db.commit()
    log4j = component(
        "log4j-core",
        "2.14.1",
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
        [{"license": {"id": "Apache-2.0"}}],
        group="org.apache.logging.log4j",
    )
    ingest_report(
        db,
        cyclonedx(log4j, component("lodash", "4.17.20", "pkg:npm/lodash@4.17.20")),
        asset,
        None,
        IngestOptions(),
    )
    ingest_report(
        db,
        cyclonedx(
            log4j, component("express", "4.17.1", "pkg:npm/express@4.17.1", [{"license": {"id": "MIT"}}])
        ),
        other,
        None,
        IngestOptions(),
    )
    return asset, other


def test_who_uses_this_package(client, auth, inventory):
    payments, portal = inventory
    r = client.get("/api/v1/components?q=log4j", headers=auth["viewer"])
    assert r.status_code == 200
    (row,) = r.json()["items"]
    assert row["name"] == "org.apache.logging.log4j:log4j-core" and row["version"] == "2.14.1"
    assert {a["name"] for a in row["assets"]} == {payments.name, portal.name}
    assert row["licenses"] == ["Apache-2.0"] and row["ecosystem"] == "maven"

    # A purl search finds the same thing.
    assert (
        client.get("/api/v1/components?q=pkg:maven/org.apache", headers=auth["viewer"]).json()["total"] == 1
    )


def test_component_filters(client, auth, inventory):
    def names(query=""):
        return [
            c["name"]
            for c in client.get(f"/api/v1/components?{query}", headers=auth["viewer"]).json()["items"]
        ]

    assert names() == ["express", "lodash", "org.apache.logging.log4j:log4j-core"]
    assert names("ecosystem=npm") == ["express", "lodash"]
    assert names("license=MIT") == ["express"]
    assert names("unlicensed=true") == ["lodash"]  # no licence recorded
    assert names(f"asset_id={inventory[1].id}") == ["express", "org.apache.logging.log4j:log4j-core"]


def test_licence_and_stats_endpoints(client, auth, inventory):
    licences = client.get("/api/v1/components/licenses", headers=auth["viewer"]).json()
    assert {x["licence"]: x["components"] for x in licences} == {"Apache-2.0": 2, "MIT": 1}

    stats = client.get("/api/v1/components/stats", headers=auth["viewer"]).json()
    assert stats["components"] == 4 and stats["distinct"] == 3 and stats["assets"] == 2
    assert stats["last_seen_at"] is not None


def test_components_need_a_session(client, auth):
    token = client.post(
        "/api/v1/tokens", json={"name": "ci", "scopes": ["read"]}, headers=auth["viewer"]
    ).json()
    headers = {"Authorization": f"Bearer {token['token']}"}
    # Read-scoped API tokens may read the inventory, like any other read endpoint.
    assert client.get("/api/v1/components", headers=headers).status_code == 200


def test_the_sbom_subject_is_not_part_of_its_own_inventory(db, asset):
    """metadata.component describes the application; it is not something the application ships."""
    document = json.loads(cyclonedx(component("lodash", "4.17.20", "pkg:npm/lodash@4.17.20")))
    document["metadata"]["component"] = {
        "type": "application",
        "bom-ref": "payments-api",
        "name": "payments-api",
        "version": "3.1.0",
    }
    ingest_report(db, json.dumps(document).encode(), asset, None, IngestOptions())
    assert [c.name for c in components(db)] == ["lodash"]


# ---- licence policy -----------------------------------------------------------------------------


def set_policy(client, auth, *rules):
    r = client.put(
        "/api/v1/components/license-policy",
        json={"rules": [{"licence": lic, "rule": rule} for lic, rule in rules]},
        headers=auth["admin"],
    )
    assert r.status_code == 200, r.text
    return r.json()


@pytest.fixture
def licensed(db, asset):
    """One component per licence situation: denied, review, allowed and none recorded."""
    ingest_report(
        db,
        cyclonedx(
            component(
                "copyleft-lib", "1.0", "pkg:npm/copyleft-lib@1.0", [{"license": {"id": "GPL-3.0-only"}}]
            ),
            component("watched-lib", "2.0", "pkg:npm/watched-lib@2.0", [{"license": {"id": "LGPL-2.1"}}]),
            component("lodash", "4.17.20", "pkg:npm/lodash@4.17.20", [{"license": {"id": "MIT"}}]),
            component("mystery-lib", "0.1", "pkg:npm/mystery-lib@0.1"),
        ),
        asset,
        None,
        IngestOptions(),
    )
    return asset


def test_everything_is_allowed_until_a_policy_says_otherwise(client, auth, licensed):
    rows = client.get("/api/v1/components", headers=auth["viewer"]).json()["items"]
    verdicts = {c["name"]: c["licence_rule"] for c in rows}
    assert verdicts == {
        "copyleft-lib": "allowed",
        "watched-lib": "allowed",
        "lodash": "allowed",
        "mystery-lib": "unknown",  # no licence recorded is not the same as approved
    }
    policy = client.get("/api/v1/components/license-policy", headers=auth["viewer"]).json()
    assert policy == {"rules": [], "default": "allowed"}


def test_policy_verdicts_and_filters(client, auth, licensed):
    set_policy(client, auth, ("GPL-3.0-only", "denied"), ("LGPL-2.1", "review"), ("MIT", "allowed"))

    rows = client.get("/api/v1/components", headers=auth["viewer"]).json()["items"]
    assert {c["name"]: c["licence_rule"] for c in rows} == {
        "copyleft-lib": "denied",
        "watched-lib": "review",
        "lodash": "allowed",
        "mystery-lib": "unknown",
    }

    def names(rule):
        r = client.get(f"/api/v1/components?licence_rule={rule}", headers=auth["viewer"])
        return [c["name"] for c in r.json()["items"]]

    assert names("denied") == ["copyleft-lib"]
    assert names("review") == ["watched-lib"]
    assert names("unknown") == ["mystery-lib"]


def test_licence_matching_ignores_case(client, auth, licensed):
    set_policy(client, auth, ("gpl-3.0-ONLY", "denied"))
    rows = client.get("/api/v1/components?licence_rule=denied", headers=auth["viewer"]).json()["items"]
    assert [c["name"] for c in rows] == ["copyleft-lib"]


def test_the_strictest_licence_wins(db, client, auth, asset):
    ingest_report(
        db,
        cyclonedx(
            component(
                "dual",
                "1.0",
                "pkg:npm/dual@1.0",
                [{"license": {"id": "MIT"}}, {"license": {"id": "GPL-3.0-only"}}],
            )
        ),
        asset,
        None,
        IngestOptions(),
    )
    set_policy(client, auth, ("MIT", "allowed"), ("GPL-3.0-only", "denied"))
    (row,) = client.get("/api/v1/components", headers=auth["viewer"]).json()["items"]
    assert row["licence_rule"] == "denied"


def test_policy_api_rules(client, auth, db, licensed):
    from app.models import AuditLog

    for role in ("viewer", "analyst", "manager"):
        assert (
            client.put(
                "/api/v1/components/license-policy", json={"rules": []}, headers=auth[role]
            ).status_code
            == 403
        )
    assert (
        client.put(
            "/api/v1/components/license-policy",
            json={"rules": [{"licence": "MIT", "rule": "sometimes"}]},
            headers=auth["admin"],
        ).status_code
        == 422
    )

    # Duplicates collapse, and the whole policy is replaced each time.
    saved = set_policy(client, auth, ("MIT", "allowed"), ("mit", "denied"), ("GPL-3.0-only", "denied"))
    assert [r["licence"] for r in saved["rules"]] == ["gpl-3.0-only", "mit"]
    replaced = set_policy(client, auth, ("GPL-3.0-only", "review"))
    assert replaced["rules"] == [{"licence": "gpl-3.0-only", "rule": "review", "note": None}]

    entries = db.scalars(select(AuditLog).where(AuditLog.action == "license_policy.update")).all()
    assert len(entries) == 2 and entries[-1].changes["to"] == {"gpl-3.0-only": "review"}


def test_licence_rollup_carries_the_verdict(client, auth, licensed):
    set_policy(client, auth, ("GPL-3.0-only", "denied"))
    rollup = client.get("/api/v1/components/licenses", headers=auth["viewer"]).json()
    assert {x["licence"]: x["rule"] for x in rollup} == {
        "GPL-3.0-only": "denied",
        "LGPL-2.1": "allowed",
        "MIT": "allowed",
    }


# ---- what one asset ships --------------------------------------------------------------------------


def test_an_assets_own_components_are_listed_with_the_licence_verdict(client, auth, db):
    from app.models import LicensePolicy

    asset = Asset(name="svc", tags=[])
    db.add(asset)
    db.flush()
    ingest_report(db, sample("cyclonedx.json"), asset, None, IngestOptions())
    db.add(LicensePolicy(licence="gpl-3.0", rule="denied", note=None))
    db.commit()

    body = client.get(f"/api/v1/assets/{asset.id}/components", headers=auth["viewer"]).json()
    assert body["total"] > 0 and len(body["items"]) == body["total"]
    assert [c["name"] for c in body["items"]] == sorted(c["name"].lower() for c in body["items"])
    assert all(set(c) >= {"name", "version", "purl", "licenses", "licence_rule"} for c in body["items"])
    assert {c["licence_rule"] for c in body["items"]} <= {"allowed", "denied", "review", "unknown"}


def test_it_only_lists_that_asset(client, auth, db):
    one, two = Asset(name="one", tags=[]), Asset(name="two", tags=[])
    db.add_all([one, two])
    db.flush()
    ingest_report(db, sample("cyclonedx.json"), one, None, IngestOptions())
    ingest_report(db, sample("osv.json"), two, None, IngestOptions())
    db.commit()

    listed = client.get(f"/api/v1/assets/{two.id}/components", headers=auth["viewer"]).json()
    names = {c["name"] for c in listed["items"]}
    assert names == {"lodash", "requests"}, "the other asset's packages are somebody else's business"


def test_it_can_be_searched_and_is_404_for_an_unknown_asset(client, auth, db):
    asset = Asset(name="svc", tags=[])
    db.add(asset)
    db.flush()
    ingest_report(db, sample("osv.json"), asset, None, IngestOptions())
    db.commit()

    found = client.get(
        f"/api/v1/assets/{asset.id}/components", params={"q": "loda"}, headers=auth["viewer"]
    ).json()
    assert [c["name"] for c in found["items"]] == ["lodash"]
    assert client.get("/api/v1/assets/99999/components", headers=auth["viewer"]).status_code == 404


def test_empty_inventory_stats_are_nullable_and_typed(client, auth):
    response = client.get("/api/v1/components/stats", headers=auth["viewer"])
    assert response.status_code == 200, response.text
    assert response.json() == {"components": 0, "distinct": 0, "assets": 0, "last_seen_at": None}
