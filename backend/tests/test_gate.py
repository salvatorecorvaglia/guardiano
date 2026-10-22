"""CI quality gates and branch-aware preview scans."""

import json
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.models import Asset, AuditLog, Finding, FindingScan, GatePolicy, Scan
from app.models.base import utcnow
from app.services.ingestion import IngestOptions, ingest_report


def native(*findings, tool="t"):
    return json.dumps(
        {"schema": "guardiano/v1", "tool": {"name": tool}, "scan_type": "sast", "findings": list(findings)}
    ).encode()


def finding(title, severity="high", line=1):
    return {
        "title": title,
        "severity": severity,
        "cwe": ["CWE-89"],
        "file_path": f"{title}.py",
        "line_start": line,
    }


@pytest.fixture
def asset(db):
    a = Asset(name="svc", tags=[])
    db.add(a)
    db.commit()
    return a


def policy(db, conditions, asset_id=None, enabled=True):
    db.add(GatePolicy(asset_id=asset_id, enabled=enabled, conditions=conditions))
    db.commit()


def upload(client, headers, body, **form):
    return client.post(
        "/api/v1/scans",
        headers=headers,
        files={"file": ("r.json", body, "application/json")},
        data={"asset_name": "svc", **form},
    )


# ---- gate evaluation ----------------------------------------------------------------------------


def test_no_policy_means_no_gate(db, asset):
    scan = ingest_report(db, native(finding("a")), asset, None, IngestOptions())
    assert scan.gate_result is None


def test_max_new_per_severity(db, asset):
    policy(db, {"max_new": {"critical": 0, "high": 2}})
    scan = ingest_report(db, native(finding("a"), finding("b"), finding("c")), asset, None, IngestOptions())
    result = scan.gate_result
    assert result["passed"] is False and result["policy_scope"] == "global"
    assert [(v["rule"], v["severity"], v["limit"], v["actual"]) for v in result["violations"]] == [
        ("max_new", "high", 2, 3)
    ]
    assert result["violations"][0]["message"] == "3 new high finding(s), limit 2"

    # Re-ingesting the same report introduces nothing new, so the gate passes.
    again = ingest_report(db, native(finding("a"), finding("b"), finding("c")), asset, None, IngestOptions())
    assert again.gate_result["passed"] is True


def test_max_open_counts_the_whole_asset(db, asset):
    ingest_report(db, native(finding("a"), finding("b")), asset, None, IngestOptions())
    policy(db, {"max_open": {"high": 1}})
    scan = ingest_report(db, native(finding("c")), asset, None, IngestOptions())
    v = scan.gate_result["violations"]
    assert [(x["rule"], x["actual"], x["limit"]) for x in v] == [("max_open", 3, 1)]
    assert "on svc" in v[0]["message"]


def test_fail_on_overdue_and_reopened(db, asset, client, auth):
    ingest_report(db, native(finding("a")), asset, None, IngestOptions(now=utcnow() - timedelta(days=400)))
    f = db.scalar(select(Finding))
    client.patch(f"/api/v1/findings/{f.id}", json={"status": "resolved"}, headers=auth["analyst"])
    db.expire_all()  # the API resolved it in its own session
    policy(db, {"fail_on_overdue": True, "fail_on_reopened": True})

    scan = ingest_report(db, native(finding("a")), asset, None, IngestOptions())
    rules = {v["rule"]: v for v in scan.gate_result["violations"]}
    assert rules["fail_on_reopened"]["actual"] == 1
    assert rules["fail_on_overdue"]["actual"] == 1  # reopened, first seen 400 days ago, SLA 30


def test_asset_policy_overrides_global(db, asset):
    policy(db, {"max_new": {"high": 0}})  # global
    policy(db, {"max_new": {"high": 5}}, asset_id=asset.id)
    scan = ingest_report(db, native(finding("a")), asset, None, IngestOptions())
    assert scan.gate_result["passed"] is True and scan.gate_result["policy_scope"] == "asset"


def test_disabled_asset_policy_does_not_fall_back_to_global(db, asset):
    policy(db, {"max_new": {"high": 0}})  # global would fail
    policy(db, {"max_new": {"high": 0}}, asset_id=asset.id, enabled=False)
    assert ingest_report(db, native(finding("a")), asset, None, IngestOptions()).gate_result is None


def test_gate_is_returned_by_the_upload_endpoint(client, auth, db, asset):
    policy(db, {"max_new": {"high": 0}})
    r = upload(client, auth["analyst"], native(finding("a")))
    assert r.status_code == 201  # the gate never changes the status code
    gate = r.json()["gate"]
    assert gate["passed"] is False and gate["violations"][0]["rule"] == "max_new"
    assert client.get(f"/api/v1/scans/{r.json()['id']}", headers=auth["viewer"]).json()["gate"] == gate


# ---- policy API ---------------------------------------------------------------------------------


def test_gate_policy_api(client, auth, db, asset):
    body = {"asset_id": asset.id, "conditions": {"max_new": {"critical": 0}, "fail_on_overdue": True}}
    assert client.put("/api/v1/gate-policies", json=body, headers=auth["viewer"]).status_code == 403
    assert client.put("/api/v1/gate-policies", json=body, headers=auth["analyst"]).status_code == 403
    r = client.put("/api/v1/gate-policies", json=body, headers=auth["manager"])
    assert r.status_code == 200 and r.json()["asset"]["name"] == "svc"
    assert r.json()["conditions"]["max_new"] == {"critical": 0}

    # Only admins may edit the global policy.
    glob = {"asset_id": None, "conditions": {"max_open": {"high": 10}}}
    assert client.put("/api/v1/gate-policies", json=glob, headers=auth["manager"]).status_code == 403
    assert client.put("/api/v1/gate-policies", json=glob, headers=auth["admin"]).status_code == 200

    # Upsert: one policy per asset, one global.
    client.put("/api/v1/gate-policies", json={**body, "enabled": False}, headers=auth["manager"])
    listed = client.get("/api/v1/gate-policies", headers=auth["viewer"]).json()
    assert [(p["asset"] and p["asset"]["name"], p["enabled"]) for p in listed] == [
        (None, True),
        ("svc", False),
    ]

    assert (
        client.put("/api/v1/gate-policies", json={"asset_id": 999}, headers=auth["manager"]).status_code
        == 404
    )
    bad = {"asset_id": asset.id, "conditions": {"max_new": {"high": -1}}}
    assert client.put("/api/v1/gate-policies", json=bad, headers=auth["manager"]).status_code == 422

    actions = [e.action for e in db.scalars(select(AuditLog).where(AuditLog.action.startswith("gate.")))]
    assert actions == ["gate.create", "gate.create", "gate.update"]

    pid = [p["id"] for p in listed if p["asset"]][0]
    assert client.delete(f"/api/v1/gate-policies/{pid}", headers=auth["analyst"]).status_code == 403
    assert client.delete(f"/api/v1/gate-policies/{pid}", headers=auth["manager"]).status_code == 204
    gid = [p["id"] for p in listed if not p["asset"]][0]
    assert client.delete(f"/api/v1/gate-policies/{gid}", headers=auth["manager"]).status_code == 403
    assert client.delete(f"/api/v1/gate-policies/{gid}", headers=auth["admin"]).status_code == 204


# ---- preview scans ------------------------------------------------------------------------------


def test_without_default_branch_every_branch_is_ingested(db, asset):
    scan = ingest_report(db, native(finding("a")), asset, None, IngestOptions(branch="feature/x"))
    assert scan.source == "upload" and scan.preview_result is None
    assert db.scalar(select(Finding).where(Finding.title == "a")) is not None


def test_preview_leaves_the_inventory_untouched(client, auth, db, asset):
    asset.default_branch = "main"
    db.commit()
    ingest_report(db, native(finding("a")), asset, None, IngestOptions(branch="main"))
    before = {(f.id, f.status, f.last_scan_id) for f in db.scalars(select(Finding))}

    r = upload(
        client,
        auth["analyst"],
        native(finding("a"), finding("new", "critical")),
        branch="pr-42",
        close_missing="true",
    )
    assert r.status_code == 201
    body = r.json()
    assert body["source"] == "preview"
    assert body["preview"]["counts"] == {"total": 2, "new": 1, "known": 1, "new_by_severity": {"critical": 1}}
    assert body["preview"]["branch"] == "pr-42" and body["preview"]["default_branch"] == "main"
    assert [f["title"] for f in body["preview"]["new"]] == ["new"]

    db.expire_all()
    assert {(f.id, f.status, f.last_scan_id) for f in db.scalars(select(Finding))} == before
    assert db.scalar(select(Finding).where(Finding.title == "new")) is None
    # No finding is linked to the preview scan, and close_missing resolved nothing.
    assert db.scalar(select(FindingScan).where(FindingScan.scan_id == body["id"])) is None


def test_preview_is_gated_like_a_normal_scan(client, auth, db, asset):
    asset.default_branch = "main"
    policy(db, {"max_new": {"critical": 0}})
    r = upload(client, auth["analyst"], native(finding("boom", "critical")), branch="pr-1")
    gate = r.json()["gate"]
    assert gate["passed"] is False and gate["violations"][0]["actual"] == 1
    assert db.scalar(select(Finding)) is None  # still nothing ingested


def test_preview_can_be_forced_on_the_default_branch(client, auth, db, asset):
    r = upload(client, auth["analyst"], native(finding("a")), branch="main", preview="true")
    assert r.json()["source"] == "preview" and db.scalar(select(Finding)) is None


def test_previews_stay_out_of_rollups(client, auth, db, asset):
    asset.default_branch = "main"
    db.commit()
    ingest_report(db, native(finding("a")), asset, None, IngestOptions(branch="main"))
    summary_before = client.get("/api/v1/analytics/summary", headers=auth["viewer"]).json()
    asset_before = client.get(f"/api/v1/assets/{asset.id}", headers=auth["viewer"]).json()

    upload(client, auth["analyst"], native(finding("x")), branch="pr-9")

    assert client.get("/api/v1/analytics/summary", headers=auth["viewer"]).json() == summary_before
    assert client.get(f"/api/v1/assets/{asset.id}", headers=auth["viewer"]).json() == asset_before
    # Previews are listed, and can be filtered out.
    assert client.get("/api/v1/scans", headers=auth["viewer"]).json()["total"] == 2
    assert client.get("/api/v1/scans?source=preview", headers=auth["viewer"]).json()["total"] == 1


def test_preview_is_not_a_diff_baseline(client, auth, db, asset):
    asset.default_branch = "main"
    db.commit()
    s1 = ingest_report(db, native(finding("a")), asset, None, IngestOptions(branch="main"))
    preview = upload(client, auth["analyst"], native(finding("z")), branch="pr-3").json()
    s2 = ingest_report(db, native(finding("a"), finding("b")), asset, None, IngestOptions(branch="main"))

    d = client.get(f"/api/v1/scans/{s2.id}/diff", headers=auth["viewer"]).json()
    assert d["against"]["id"] == s1.id and d["new"] == 1
    assert client.get(f"/api/v1/scans/{preview['id']}/diff", headers=auth["viewer"]).status_code == 422


def test_preview_scan_row_records_what_it_saw(client, auth, db, asset):
    asset.default_branch = "main"
    db.commit()
    r = upload(
        client, auth["analyst"], native(finding("a"), finding("b")), branch="pr-7", commit_sha="abc123"
    )
    scan = db.get(Scan, r.json()["id"])
    assert (scan.total_count, scan.new_count, scan.duplicate_count) == (2, 2, 0)
    assert scan.auto_resolved_count == 0 and scan.commit_sha == "abc123"


# ---- known-exploited vulnerabilities ---------------------------------------------------------------


def sca(title, cve, severity="high"):
    return {
        "title": title,
        "severity": severity,
        "type": "sca",
        "cve_id": cve,
        "package_name": "lodash",
        "package_version": "4.17.20",
        "ecosystem": "npm",
    }


def exploited(db, *cves):
    """Put these CVEs on CISA's list, as the intel sync would."""
    from app.models import VulnIntel

    for cve in cves:
        db.add(VulnIntel(cve_id=cve, in_kev=True, epss=0.9))
    db.commit()


def test_fail_on_kev_blocks_a_build_carrying_an_exploited_vulnerability(db, asset):
    exploited(db, "CVE-2021-44228")
    policy(db, {"fail_on_kev": True})

    scan = ingest_report(db, native(sca("log4shell", "CVE-2021-44228")), asset, None, IngestOptions())
    assert scan.gate_result["passed"] is False
    violation = scan.gate_result["violations"][0]
    assert violation["rule"] == "fail_on_kev" and violation["actual"] == 1
    assert "CVE-2021-44228" in violation["message"], "CI logs must name what to fix"


def test_a_vulnerability_nobody_is_exploiting_does_not_fail_the_gate(db, asset):
    policy(db, {"fail_on_kev": True})
    scan = ingest_report(db, native(sca("something", "CVE-2020-0001")), asset, None, IngestOptions())
    assert scan.gate_result["passed"] is True


def test_it_counts_the_whole_asset_not_just_this_scan(db, asset):
    """Something already being exploited does not stop mattering because this scan did not introduce it."""
    exploited(db, "CVE-2021-44228")
    ingest_report(db, native(sca("log4shell", "CVE-2021-44228")), asset, None, IngestOptions())
    policy(db, {"fail_on_kev": True})

    later = ingest_report(db, native(sca("log4shell", "CVE-2021-44228")), asset, None, IngestOptions())
    assert later.new_count == 0 and later.gate_result["passed"] is False


def test_a_closed_finding_no_longer_fails_the_gate(db, asset, client, auth):
    exploited(db, "CVE-2021-44228")
    policy(db, {"fail_on_kev": True})
    ingest_report(db, native(sca("log4shell", "CVE-2021-44228")), asset, None, IngestOptions())
    f = db.scalar(select(Finding).where(Finding.cve_id == "CVE-2021-44228"))
    client.patch(
        f"/api/v1/findings/{f.id}",
        json={"status": "risk_accepted", "justification": "not reachable from any entry point"},
        headers=auth["manager"],
    )
    db.expire_all()

    scan = ingest_report(db, native(sca("log4shell", "CVE-2021-44228")), asset, None, IngestOptions())
    assert scan.gate_result["passed"] is True, "an accepted risk is a decision, not a blocker"


def test_several_exploited_vulnerabilities_are_summarised(db, asset):
    cves = [f"CVE-2021-1000{n}" for n in range(5)]
    exploited(db, *cves)
    policy(db, {"fail_on_kev": True})
    scan = ingest_report(
        db, native(*[sca(f"v{n}", cve) for n, cve in enumerate(cves)]), asset, None, IngestOptions()
    )
    message = scan.gate_result["violations"][0]["message"]
    assert scan.gate_result["violations"][0]["actual"] == 5
    assert "and 2 more" in message, "the message names a few and counts the rest"


def test_the_condition_is_off_unless_asked_for(db, asset):
    exploited(db, "CVE-2021-44228")
    policy(db, {"max_new": {"critical": 10}})
    scan = ingest_report(db, native(sca("log4shell", "CVE-2021-44228")), asset, None, IngestOptions())
    assert scan.gate_result["passed"] is True


# ---- EPSS, CVSS, secrets and licences ----------------------------------------------------------


def test_max_open_epss_counts_open_findings_above_the_limit(db, asset):
    from app.models import VulnIntel

    db.add_all([VulnIntel(cve_id="CVE-2024-0001", epss=0.7), VulnIntel(cve_id="CVE-2024-0002", epss=0.2)])
    db.commit()
    policy(db, {"max_open_epss": 0.5})
    likely, unlikely = sca("likely", "CVE-2024-0001"), sca("unlikely", "CVE-2024-0002")

    scan = ingest_report(db, native(likely, unlikely), asset, None, IngestOptions())
    (v,) = scan.gate_result["violations"]
    assert (v["rule"], v["actual"], v["limit"]) == ("max_open_epss", 1, 0.5)
    assert "CVE-2024-0001" in v["message"] and "50%" in v["message"]

    policy_row = db.scalar(select(GatePolicy))
    policy_row.conditions = {"max_open_epss": 0.8}
    db.commit()
    assert ingest_report(db, native(likely, unlikely), asset, None, IngestOptions()).gate_result["passed"]


def test_max_new_cvss_looks_only_at_what_this_scan_introduces(db, asset):
    severe = {**finding("severe", "critical"), "cvss_score": 9.8}
    mild = {**finding("mild", "medium"), "cvss_score": 5.0}
    policy(db, {"max_new_cvss": 8.9})

    scan = ingest_report(db, native(severe, mild), asset, None, IngestOptions())
    (v,) = scan.gate_result["violations"]
    assert (v["rule"], v["actual"]) == ("max_new_cvss", 1)
    assert v["message"] == "1 new finding(s) with CVSS above 8.9 (highest 9.8)"

    # Seen before, so not new: the condition passes even though the finding is still there.
    assert ingest_report(db, native(severe, mild), asset, None, IngestOptions()).gate_result["passed"]


def test_fail_on_new_secrets(db, asset):
    policy(db, {"fail_on_new_secrets": True})
    secret = {**finding("aws-key"), "cwe": ["CWE-798"], "file_path": "config/prod.env"}
    scan = ingest_report(db, native(secret, finding("sqli")), asset, None, IngestOptions())
    (v,) = scan.gate_result["violations"]
    assert (v["rule"], v["actual"]) == ("fail_on_new_secrets", 1)
    assert "config/prod.env" in v["message"]
    assert ingest_report(db, native(finding("xss")), asset, None, IngestOptions()).gate_result["passed"]


def test_gitleaks_findings_count_as_secrets(db, asset):
    from tests.conftest import sample

    policy(db, {"fail_on_new_secrets": True})
    scan = ingest_report(db, sample("gitleaks.json"), asset, None, IngestOptions())
    assert scan.gate_result["violations"][0]["rule"] == "fail_on_new_secrets"


def _sbom(*components):
    return json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "components": [
                {"type": "library", "name": n, "version": v, "purl": f"pkg:npm/{n}@{v}",
                 "licenses": [{"license": {"id": lic}}]}
                for n, v, lic in components
            ],
        }
    ).encode()  # fmt: skip


def test_fail_on_denied_license_names_the_components(db, asset):
    from app.models import LicensePolicy

    db.add(LicensePolicy(licence="agpl-3.0", rule="denied"))
    db.commit()
    policy(db, {"fail_on_denied_license": True})

    sbom = _sbom(("left-pad", "1.0.0", "AGPL-3.0"), ("lodash", "4.17.21", "MIT"))
    scan = ingest_report(db, sbom, asset, None, IngestOptions())
    (v,) = scan.gate_result["violations"]
    assert (v["rule"], v["actual"]) == ("fail_on_denied_license", 1)
    assert "left-pad@1.0.0" in v["message"]

    # The component is gone from the next SBOM, so the gate passes, though the inventory still lists it.
    later = ingest_report(db, _sbom(("lodash", "4.17.21", "MIT")), asset, None, IngestOptions())
    assert later.gate_result["passed"] is True


def test_a_pull_request_preview_is_refused_for_a_denied_licence(client, auth, db, asset):
    from app.models import LicensePolicy

    asset.default_branch = "main"
    db.add(LicensePolicy(licence="agpl-3.0", rule="denied"))
    db.commit()
    policy(db, {"fail_on_denied_license": True})
    r = upload(client, auth["analyst"], _sbom(("left-pad", "1.0.0", "AGPL-3.0")), branch="feature/x")
    assert r.status_code == 201, r.text
    assert r.json()["gate"]["passed"] is False


def test_the_new_conditions_are_off_unless_asked_for(db, asset):
    from app.models import LicensePolicy, VulnIntel

    db.add_all(
        [LicensePolicy(licence="agpl-3.0", rule="denied"), VulnIntel(cve_id="CVE-2024-0001", epss=0.99)]
    )
    db.commit()
    policy(db, {"max_new": {"critical": 10}})
    secret = {**finding("aws-key", "critical"), "cwe": ["CWE-798"], "cvss_score": 10.0}
    for body in (native(secret, sca("likely", "CVE-2024-0001")), _sbom(("left-pad", "1.0.0", "AGPL-3.0"))):
        assert ingest_report(db, body, asset, None, IngestOptions()).gate_result["passed"] is True


@pytest.mark.parametrize(
    "conditions",
    [{"max_open_epss": 1.5}, {"max_open_epss": -0.1}, {"max_new_cvss": 11}, {"max_new_cvss": -1}],
)
def test_out_of_range_limits_are_refused(client, auth, conditions):
    body = {"asset_id": None, "conditions": conditions}
    r = client.put("/api/v1/gate-policies", json=body, headers=auth["admin"])
    assert r.status_code == 422
