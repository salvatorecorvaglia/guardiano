"""VEX: triage decisions exported as OpenVEX / CycloneDX, and suppliers' statements imported."""

import json
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.models import Asset, Finding, Team
from app.models.base import utcnow
from app.services.ingestion import IngestOptions, ingest_report
from app.services.vex import parse_purl


def _sca(title, cve, package, version, ecosystem="npm", purl=True):
    return {"title": title, "severity": "high", "type": "sca", "cve_id": cve, "package_name": package,
            "package_version": version, "ecosystem": ecosystem,
            **({"purl": f"pkg:{ecosystem}/{package}@{version}"} if purl else {})}  # fmt: skip


def _report(*findings):
    return json.dumps({"schema": "guardiano/v1", "tool": {"name": "t"}, "scan_type": "sca",
                       "findings": list(findings)}).encode()  # fmt: skip


REPORT = _report(
    _sca("a", "CVE-2024-0001", "lodash", "4.17.20"),
    _sca("b", "CVE-2024-0002", "minimist", "1.2.5"),
    _sca("c", "CVE-2024-0003", "express", "4.17.1", purl=False),  # identified by name only
    _sca("d", "CVE-2024-0004", "qs", "6.5.2"),
)


@pytest.fixture
def asset(db):
    a = Asset(name="svc", tags=[])
    db.add(a)
    db.commit()
    ingest_report(db, REPORT, a, None, IngestOptions())
    return a


def by_cve(db, asset):
    return {f.cve_id: f for f in db.scalars(select(Finding).where(Finding.asset_id == asset.id))}


def import_vex(client, headers, asset, doc):
    files = {"file": ("vex.json", json.dumps(doc).encode(), "application/json")}
    return client.post(f"/api/v1/assets/{asset.id}/vex", files=files, headers=headers)


def test_purls_reduce_to_a_package():
    assert parse_purl("pkg:npm/%40babel/core@7.0.0?foo=bar#sub").name == "@babel/core"
    assert parse_purl("pkg:golang/github.com/x/y@v1.2.3").ecosystem == parse_purl("pkg:go/a@1").ecosystem
    assert parse_purl("pkg:pypi/django").version is None
    assert parse_purl("not-a-purl") is None and parse_purl("pkg:npm") is None


def test_openvex_export_states_each_decision(client, auth, db, asset):
    f = by_cve(db, asset)
    f["CVE-2024-0001"].status = "false_positive"
    f["CVE-2024-0001"].status_justification = "only in dev builds"
    f["CVE-2024-0002"].status = "resolved"
    f["CVE-2024-0003"].status, f["CVE-2024-0003"].status_justification = "risk_accepted", "behind the WAF"
    f["CVE-2024-0003"].risk_accepted_until = utcnow() + timedelta(days=30)
    db.commit()

    r = client.get(f"/api/v1/assets/{asset.id}/vex", headers=auth["viewer"])
    assert r.status_code == 200 and "openvex.json" in r.headers["content-disposition"]
    doc = r.json()
    assert doc["@context"].startswith("https://openvex.dev/ns/")
    st = {s["vulnerability"]["name"]: s for s in doc["statements"]}
    assert st["CVE-2024-0001"]["status"] == "not_affected"
    assert st["CVE-2024-0001"]["impact_statement"] == "only in dev builds"
    assert st["CVE-2024-0002"]["status"] == "fixed"
    accepted = st["CVE-2024-0003"]
    assert accepted["status"] == "affected" and "Risk accepted until" in accepted["action_statement"]
    assert accepted["products"] == [{"@id": "pkg:npm/express@4.17.1"}]  # built from name and version
    assert st["CVE-2024-0004"]["status"] == "under_investigation"


def test_cyclonedx_vex_export_references_its_components(client, auth, db, asset):
    params = {"format": "cyclonedx"}
    doc = client.get(f"/api/v1/assets/{asset.id}/vex", params=params, headers=auth["viewer"]).json()
    refs = {c["bom-ref"] for c in doc["components"]}
    assert all(a["ref"] in refs for v in doc["vulnerabilities"] for a in v["affects"])
    assert {v["analysis"]["state"] for v in doc["vulnerabilities"]} == {"in_triage"}


def test_an_export_imports_into_another_asset(client, auth, db, asset):
    """A decision made on one asset, handed over as VEX, applies to the same package elsewhere."""
    other = Asset(name="other", tags=[])
    db.add(other)
    db.commit()
    ingest_report(db, REPORT, other, None, IngestOptions())
    by_cve(db, asset)["CVE-2024-0001"].status = "false_positive"
    by_cve(db, asset)["CVE-2024-0001"].status_justification = "only in dev builds"
    db.commit()

    doc = client.get(f"/api/v1/assets/{asset.id}/vex", headers=auth["viewer"]).json()
    r = import_vex(client, auth["manager"], other, doc)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["format"] == "openvex" and body["changed"] == 1 and body["informational"] == 3
    db.expire_all()
    moved = by_cve(db, other)["CVE-2024-0001"]
    assert moved.status == "false_positive"
    assert "VEX from Guardiano: only in dev builds" in moved.status_justification


def test_a_cyclonedx_vex_from_a_supplier(client, auth, db, asset):
    doc = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "components": [{"bom-ref": "lib-1", "purl": "pkg:npm/lodash"},  # no version: every version
                       {"bom-ref": "lib-2", "purl": "pkg:npm/qs@6.5.2"},
                       {"bom-ref": "lib-3", "purl": "pkg:npm/minimist@9.9.9"}],  # a version we do not have
        "vulnerabilities": [
            {"id": "CVE-2024-0001", "affects": [{"ref": "lib-1"}],
             "analysis": {"state": "not_affected", "detail": "not reachable"}},
            {"id": "CVE-2024-0004", "affects": [{"ref": "lib-2"}], "analysis": {"state": "resolved"}},
            {"id": "CVE-2024-0002", "affects": [{"ref": "lib-3"}], "analysis": {"state": "not_affected"}},
            {"id": "CVE-2024-0003", "affects": [{"ref": "pkg:npm/express@4.17.1"}],
             "analysis": {"state": "exploitable"}},
        ],
    }  # fmt: skip
    body = import_vex(client, auth["manager"], asset, doc).json()
    assert (body["format"], body["changed"], body["informational"]) == ("cyclonedx", 2, 1)
    assert body["unmatched"] == ["CVE-2024-0002 on minimist@9.9.9"]
    db.expire_all()
    f = by_cve(db, asset)
    assert f["CVE-2024-0001"].status == "false_positive"
    assert "not reachable" in f["CVE-2024-0001"].status_justification
    assert f["CVE-2024-0004"].status == "resolved"
    assert f["CVE-2024-0002"].status == "open" and f["CVE-2024-0003"].status == "open"

    again = import_vex(client, auth["manager"], asset, doc).json()
    assert again["changed"] == 0 and again["already_closed"] == 2  # closed findings are not re-decided


def test_who_may_import_and_export(client, auth, db, asset):
    doc = {"@context": "https://openvex.dev/ns/v0.2.0", "statements": []}
    assert import_vex(client, auth["analyst"], asset, doc).status_code == 403
    assert import_vex(client, auth["manager"], asset, {"hello": "world"}).status_code == 422
    team = Team(name="elsewhere", description="")
    db.add(team)
    db.flush()
    asset.team_id = team.id
    db.commit()
    assert client.get(f"/api/v1/assets/{asset.id}/vex", headers=auth["viewer"]).status_code == 404
    assert import_vex(client, auth["manager"], asset, doc).status_code == 404
