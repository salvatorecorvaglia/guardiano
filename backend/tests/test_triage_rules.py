"""Auto-triage rules and fingerprint-assisted deduplication."""

import json
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models import Asset, AuditLog, Finding, TriageRule
from app.models.base import utcnow
from app.services import triage
from app.services.ingestion import IngestOptions, ingest_report


def native(*findings, tool="Semgrep"):
    return json.dumps(
        {"schema": "guardiano/v1", "tool": {"name": tool}, "scan_type": "sast", "findings": list(findings)}
    ).encode()


def finding(title="a", severity="high", path="app/main.py", line=1, cwe=("CWE-89",), rule="sql-injection"):
    return {
        "title": title,
        "severity": severity,
        "cwe": list(cwe),
        "file_path": path,
        "line_start": line,
        "rule_id": rule,
    }


@pytest.fixture
def asset(db):
    a = Asset(name="svc", tags=[])
    db.add(a)
    db.commit()
    return a


def rule(db, match, action, *, name="r", enabled=True, priority=100, asset_id=None, expires_at=None):
    r = TriageRule(
        name=name,
        enabled=enabled,
        priority=priority,
        asset_id=asset_id,
        match=match,
        action=action,
        expires_at=expires_at,
    )
    db.add(r)
    db.commit()
    return r


def findings(db):
    return db.scalars(select(Finding).order_by(Finding.id)).all()


# ---- matcher ------------------------------------------------------------------------------------


def test_matcher_conditions(db, asset):
    ingest_report(
        db, native(finding(path="tests/unit/test_x.py", severity="medium")), asset, None, IngestOptions()
    )
    f = db.scalar(select(Finding))

    assert triage.matches({"path_glob": "tests/*"}, f) is True
    assert triage.matches({"path_glob": "TESTS/*"}, f) is True  # case-insensitive, platform-independent
    assert triage.matches({"path_glob": "src/*"}, f) is False
    assert triage.matches({"cwe": "89"}, f) is True and triage.matches({"cwe": "CWE-89"}, f) is True
    assert triage.matches({"cwe": "79"}, f) is False
    assert triage.matches({"severity": ["medium", "low"]}, f) is True
    assert triage.matches({"severity": ["critical"]}, f) is False
    assert triage.matches({"tool": "semgrep"}, f) is True
    assert triage.matches({"rule_id": "SQL-Injection"}, f) is True
    assert triage.matches({"title_contains": "A"}, f) is True
    assert triage.matches({"type": "sca"}, f) is False
    # Every condition must hold.
    assert triage.matches({"path_glob": "tests/*", "severity": ["critical"]}, f) is False
    # An empty rule matches nothing, so a misconfigured rule cannot suppress everything.
    assert triage.matches({}, f) is False


# ---- application at ingestion -------------------------------------------------------------------


def test_rule_suppresses_new_findings_with_an_audit_trail(db, asset):
    rule(
        db,
        {"path_glob": "tests/*"},
        {"status": "false_positive", "justification": "Test fixtures are not shipped"},
        name="Ignore tests",
    )
    ingest_report(
        db, native(finding(path="tests/fixtures.py"), finding(path="app/db.py")), asset, None, IngestOptions()
    )

    db.expire_all()  # reload events in their API order (newest first)
    suppressed, kept = findings(db)
    assert suppressed.status == "false_positive"
    assert suppressed.status_justification == "Test fixtures are not shipped (rule 'Ignore tests')"
    assert suppressed.closed_at is not None
    assert suppressed.events[0].event == "rule_applied"
    assert kept.status == "open"


def test_rule_can_retag_reseverity_and_assign(db, asset, users):
    rule(
        db,
        {"cwe": "89", "severity": ["high"]},
        {"severity": "critical", "tags": ["Needs-Review"], "assignee_id": users["analyst"].id},
    )
    ingest_report(db, native(finding()), asset, None, IngestOptions())
    db.expire_all()
    f = db.scalar(select(Finding))
    assert (f.severity, f.tags, f.assignee_id) == ("critical", ["needs-review"], users["analyst"].id)
    assert "severity high -> critical" in f.events[0].comment
    assert f.status == "open"  # no status action, so it stays open


def test_rules_run_in_priority_order_and_stack(db, asset):
    rule(db, {"path_glob": "app/*"}, {"severity": "low", "tags": ["first"]}, name="first", priority=1)
    rule(db, {"cwe": "89"}, {"severity": "medium", "tags": ["second"]}, name="second", priority=2)
    ingest_report(db, native(finding()), asset, None, IngestOptions())
    f = db.scalar(select(Finding))
    assert f.severity == "medium"  # the later rule wins
    assert f.tags == ["first", "second"]  # tags accumulate


def test_rules_ignore_disabled_expired_and_other_assets(db, asset):
    other = Asset(name="other", tags=[])
    db.add(other)
    db.commit()
    rule(db, {"cwe": "89"}, {"tags": ["off"]}, name="disabled", enabled=False)
    rule(db, {"cwe": "89"}, {"tags": ["expired"]}, name="expired", expires_at=utcnow() - timedelta(days=1))
    rule(db, {"cwe": "89"}, {"tags": ["other-asset"]}, name="other", asset_id=other.id)
    rule(db, {"cwe": "89"}, {"tags": ["mine"]}, name="mine", asset_id=asset.id)
    ingest_report(db, native(finding()), asset, None, IngestOptions())
    assert db.scalar(select(Finding)).tags == ["mine"]


def test_rules_never_touch_findings_that_already_exist(db, asset, client, auth):
    ingest_report(db, native(finding()), asset, None, IngestOptions())
    f = db.scalar(select(Finding))
    client.patch(f"/api/v1/findings/{f.id}", json={"status": "in_progress"}, headers=auth["analyst"])
    db.expire_all()

    rule(db, {"cwe": "89"}, {"status": "false_positive", "justification": "x"})
    ingest_report(db, native(finding()), asset, None, IngestOptions())  # same finding again

    db.expire_all()
    f = db.scalar(select(Finding))
    assert f.status == "in_progress"  # a person's triage is not overridden
    assert db.scalar(select(TriageRule)).applied_count == 0


def test_applied_count_tracks_suppressions(db, asset):
    r = rule(db, {"path_glob": "tests/*"}, {"tags": ["test-code"]})
    ingest_report(
        db,
        native(finding(path="tests/a.py"), finding(path="tests/b.py"), finding(path="app/c.py")),
        asset,
        None,
        IngestOptions(),
    )
    db.expire_all()
    assert db.get(TriageRule, r.id).applied_count == 2


# ---- rule API -----------------------------------------------------------------------------------


def test_rule_api(client, auth, db, asset):
    body = {
        "name": "Ignore vendored code",
        "asset_id": asset.id,
        "match": {"path_glob": "*/vendor/*"},
        "action": {"status": "false_positive", "justification": "Third-party code"},
    }
    assert client.post("/api/v1/triage-rules", json=body, headers=auth["analyst"]).status_code == 403
    r = client.post("/api/v1/triage-rules", json=body, headers=auth["manager"])
    assert r.status_code == 201
    created = r.json()
    assert created["match"] == {
        "type": None,
        "severity": [],
        "tool": None,
        "rule_id": None,
        "cwe": None,
        "package": None,
        "path_glob": "*/vendor/*",
        "title_contains": None,
        "cve": None,
        "ecosystem": None,
        "kev": None,
        "epss_min": None,
        "asset_tags": [],
        "asset_criticality": [],
    }
    assert created["created_by"]["email"] == "manager@test.io" and created["applied_count"] == 0

    # A rule needs conditions, an action, and a justification to suppress.
    for bad in (
        {"name": "x", "match": {}, "action": {"tags": ["t"]}},
        {"name": "x", "match": {"cwe": "89"}, "action": {}},
        {"name": "x", "match": {"cwe": "89"}, "action": {"status": "false_positive"}},
        {"name": "x", "match": {"cwe": "89"}, "action": {"status": "resolved"}},
    ):
        bad["asset_id"] = asset.id
        assert client.post("/api/v1/triage-rules", json=bad, headers=auth["manager"]).status_code == 422

    rid = created["id"]
    assert (
        client.patch(f"/api/v1/triage-rules/{rid}", json={"enabled": False}, headers=auth["manager"]).json()[
            "enabled"
        ]
        is False
    )
    # A patch cannot strip a rule down to nothing.
    assert (
        client.patch(f"/api/v1/triage-rules/{rid}", json={"match": {}}, headers=auth["manager"]).status_code
        == 422
    )
    assert [x["name"] for x in client.get("/api/v1/triage-rules", headers=auth["viewer"]).json()] == [
        "Ignore vendored code"
    ]

    assert client.delete(f"/api/v1/triage-rules/{rid}", headers=auth["analyst"]).status_code == 403
    assert client.delete(f"/api/v1/triage-rules/{rid}", headers=auth["manager"]).status_code == 204
    actions = [
        e.action for e in db.scalars(select(AuditLog).where(AuditLog.action.startswith("triage_rule.")))
    ]
    assert actions == ["triage_rule.create", "triage_rule.update", "triage_rule.delete"]


def test_preview_is_a_dry_run(client, auth, db, asset):
    ingest_report(
        db,
        native(finding(title="in tests", path="tests/a.py"), finding(title="in app", path="app/b.py")),
        asset,
        None,
        IngestOptions(),
    )
    body = {"match": {"path_glob": "tests/*"}}
    assert client.post("/api/v1/triage-rules/preview", json=body, headers=auth["analyst"]).status_code == 403
    r = client.post("/api/v1/triage-rules/preview", json=body, headers=auth["manager"])
    assert r.status_code == 200
    out = r.json()
    assert (out["scanned"], out["matched"], out["truncated"]) == (2, 1, False)
    assert [f["title"] for f in out["sample"]] == ["in tests"]
    # Nothing changed.
    db.expire_all()
    assert {f.status for f in findings(db)} == {"open"}


# ---- fingerprint-assisted dedup -----------------------------------------------------------------


@pytest.fixture
def fingerprints_on(monkeypatch):
    # monkeypatch restores the value it found, whatever the test does; setting it by hand and writing
    # False back afterwards would not, if the setting ever defaulted to True or a test failed midway.
    monkeypatch.setattr(settings, "dedup_fingerprints", True)


def sarif(line, fingerprint="abc123", rule_id="py/sql-injection"):
    return json.dumps(
        {
            "$schema": "sarif-2.1.0",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "CodeQL", "rules": [{"id": rule_id}]}},
                    "results": [
                        {
                            "ruleId": rule_id,
                            "level": "error",
                            "message": {"text": "SQL injection"},
                            "partialFingerprints": {"primaryLocationLineHash": fingerprint},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "app/db.py"},
                                        "region": {"startLine": line},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    ).encode()


def test_fingerprints_are_parsed(db, asset):
    ingest_report(db, sarif(10), asset, None, IngestOptions())
    assert db.scalar(select(Finding)).fingerprint == "abc123"


def test_moved_line_creates_a_new_finding_by_default(db, asset):
    ingest_report(db, sarif(10), asset, None, IngestOptions())
    ingest_report(db, sarif(14), asset, None, IngestOptions())
    assert len(findings(db)) == 2  # unchanged behaviour without the flag


def test_moved_line_follows_the_fingerprint_when_enabled(db, asset, fingerprints_on):
    first = ingest_report(db, sarif(10), asset, None, IngestOptions())
    second = ingest_report(db, sarif(14), asset, None, IngestOptions())
    assert (second.new_count, second.duplicate_count) == (0, 1)

    db.expire_all()
    rows = findings(db)
    assert len(rows) == 1
    f = rows[0]
    assert f.line_start == 14 and f.first_scan_id == first.id and f.last_scan_id == second.id
    assert f.events[0].event == "seen_again"
    assert f.events[0].comment == "Moved from app/db.py:10 to app/db.py:14 (same CodeQL fingerprint)"
    # The stored key now matches the new location, so the next scan matches it directly.
    third = ingest_report(db, sarif(14), asset, None, IngestOptions())
    assert third.new_count == 0 and len(findings(db)) == 1


def test_fingerprint_match_requires_the_same_rule(db, asset, fingerprints_on):
    ingest_report(db, sarif(10, rule_id="py/sql-injection"), asset, None, IngestOptions())
    ingest_report(db, sarif(14, rule_id="py/xss"), asset, None, IngestOptions())
    assert len(findings(db)) == 2


def test_one_stored_finding_is_claimed_once(db, asset, fingerprints_on):
    """Two results sharing a fingerprint must not both collapse onto the same finding."""
    ingest_report(db, sarif(10), asset, None, IngestOptions())
    doc = json.loads(sarif(14))
    second = json.loads(sarif(20))["runs"][0]["results"][0]
    doc["runs"][0]["results"].append(second)
    scan = ingest_report(db, json.dumps(doc).encode(), asset, None, IngestOptions())
    rows = findings(db)
    assert len(rows) == 2 and scan.new_count == 1
    assert sorted(f.line_start for f in rows) == [14, 20]


def test_finding_matched_by_key_is_not_stolen_by_a_fingerprint(db, asset, fingerprints_on):
    """A report containing both the old and the new location keeps them apart."""
    ingest_report(db, sarif(10), asset, None, IngestOptions())
    doc = json.loads(sarif(10))
    doc["runs"][0]["results"].append(json.loads(sarif(14))["runs"][0]["results"][0])
    scan = ingest_report(db, json.dumps(doc).encode(), asset, None, IngestOptions())
    assert scan.new_count == 1 and len(findings(db)) == 2


# ---- CVE, ecosystem, exploitability and asset conditions ---------------------------------------


def _sca(title, cve, ecosystem="npm"):
    return {"title": title, "severity": "high", "type": "sca", "cve_id": cve, "package_name": title,
            "package_version": "1.0.0", "ecosystem": ecosystem}  # fmt: skip


def _sca_report(*findings):
    return json.dumps({"schema": "guardiano/v1", "tool": {"name": "t"}, "scan_type": "sca",
                       "findings": list(findings)}).encode()  # fmt: skip


def _tagged(db):
    return {f.title: f.tags for f in findings(db)}


def test_cve_and_ecosystem_conditions(db, asset):
    rule(db, {"cve": "cve-2021-44228"}, {"tags": ["log4shell"]}, name="cve")
    rule(db, {"ecosystem": "golang"}, {"tags": ["go"]}, name="eco")  # "golang" and "go" are one ecosystem
    ingest_report(
        db,
        _sca_report(_sca("log4j", "CVE-2021-44228", "maven"), _sca("gin", "CVE-2020-0001", "go"),
                    _sca("other", "CVE-2020-0002")),
        asset, None, IngestOptions(),
    )  # fmt: skip
    assert _tagged(db) == {"log4j": ["log4shell"], "gin": ["go"], "other": []}


def test_exploitability_conditions(db, asset):
    from app.models import VulnIntel

    db.add_all([VulnIntel(cve_id="CVE-1", in_kev=True, epss=0.2), VulnIntel(cve_id="CVE-2", epss=0.8)])
    db.commit()
    rule(db, {"kev": True}, {"tags": ["kev"]}, name="kev")
    rule(db, {"kev": False, "type": "sca"}, {"tags": ["not-kev"]}, name="not kev")
    rule(db, {"epss_min": 0.5}, {"tags": ["likely"]}, name="epss")
    ingest_report(
        db,
        _sca_report(_sca("a", "CVE-1"), _sca("b", "CVE-2"), _sca("c", "CVE-3")),
        asset,
        None,
        IngestOptions(),
    )
    assert _tagged(db) == {"a": ["kev"], "b": ["likely", "not-kev"], "c": ["not-kev"]}


def test_asset_conditions(db, asset):
    asset.tags, asset.criticality = ["pci", "internet-facing"], "critical"
    other = Asset(name="internal", tags=["pci"], criticality="low")
    db.add(other)
    db.commit()
    rule(db, {"asset_tags": ["PCI", "internet-facing"]}, {"tags": ["exposed-pci"]}, name="tags")
    rule(db, {"asset_criticality": ["high", "critical"]}, {"severity": "critical"}, name="crit")
    for a in (asset, other):
        ingest_report(db, native(finding("x")), a, None, IngestOptions())
    by_asset = {f.asset.name: f for f in findings(db)}
    assert by_asset["svc"].tags == ["exposed-pci"] and by_asset["svc"].severity == "critical"
    assert by_asset["internal"].tags == [] and by_asset["internal"].severity == "high"


def test_exploitability_is_looked_up_once_per_scan(db, asset, count_queries):
    """Rules see unflushed findings, whose f.intel is never loaded, so intel is read up front: once."""
    rule(db, {"kev": True}, {"tags": ["kev"]})
    report = _sca_report(*[_sca(f"p{i}", f"CVE-2026-{i:04d}") for i in range(40)])
    with count_queries() as small:
        ingest_report(db, _sca_report(_sca("p", "CVE-2026-9999")), asset, None, IngestOptions())
    with count_queries() as large:
        ingest_report(db, report, asset, None, IngestOptions())
    assert large() - small() < 20, "the lookup must not cost a query per finding"


def test_the_preview_uses_the_new_conditions(client, auth, db, asset):
    from app.models import VulnIntel

    db.add(VulnIntel(cve_id="CVE-1", in_kev=True))
    db.commit()
    ingest_report(db, _sca_report(_sca("a", "CVE-1"), _sca("b", "CVE-2")), asset, None, IngestOptions())
    r = client.post("/api/v1/triage-rules/preview", json={"match": {"kev": True}}, headers=auth["manager"])
    assert r.status_code == 200, r.text
    assert r.json()["matched"] == 1 and r.json()["sample"][0]["title"] == "a"


# ---- applying a rule to existing findings --------------------------------------------------------


def _apply(client, auth, rule_id, role="manager"):
    from app.services import jobs

    r = client.post(f"/api/v1/triage-rules/{rule_id}/apply", headers=auth[role])
    if r.status_code == 202:
        jobs.Worker(poll_interval=0).run(burst=True)
    return r


def test_a_rule_can_be_applied_to_existing_active_findings(client, auth, db, users, asset):
    report = native(finding("open"), finding("mine", line=2), finding("closed", line=3))
    ingest_report(db, report, asset, None, IngestOptions())
    by_title = {f.title: f for f in findings(db)}
    by_title["mine"].assignee_id = users["analyst"].id
    by_title["closed"].status = "false_positive"
    db.commit()
    r = rule(db, {"cwe": "89"}, {"tags": ["sqli"], "assignee_id": users["manager"].id})

    assert _apply(client, auth, r.id).json()["job_id"]
    db.expire_all()
    by_title = {f.title: f for f in findings(db)}
    assert by_title["open"].tags == ["sqli"] and by_title["open"].assignee_id == users["manager"].id
    assert by_title["mine"].tags == ["sqli"]
    assert by_title["mine"].assignee_id == users["analyst"].id, "an assignee somebody chose is kept"
    assert by_title["closed"].tags == [], "closed findings are left alone"
    assert db.get(TriageRule, r.id).applied_count == 2
    events = [e.comment for e in by_title["open"].events if e.event == "rule_applied"]
    assert events and "applied to existing findings" in events[0]
    assert db.scalar(select(AuditLog).where(AuditLog.action == "triage_rule.apply")) is not None


def test_a_suppressing_rule_applied_to_existing_findings_closes_them(client, auth, db, asset):
    ingest_report(db, native(finding("in-tests", path="tests/test_x.py")), asset, None, IngestOptions())
    r = rule(db, {"path_glob": "tests/*"}, {"status": "false_positive", "justification": "test fixtures"})
    _apply(client, auth, r.id)
    db.expire_all()
    (f,) = findings(db)
    assert f.status == "false_positive" and f.closed_at is not None
    assert "test fixtures" in f.status_justification


def test_applying_is_for_managers_and_only_reaches_what_they_can_see(client, auth, db, users, asset):
    from app.models import Team

    team = Team(name="other", description="")
    db.add(team)
    db.flush()
    hidden = Asset(name="hidden", tags=[], team_id=team.id)
    db.add(hidden)
    db.commit()
    for a in (asset, hidden):
        ingest_report(db, native(finding("x")), a, None, IngestOptions())
    r = rule(db, {"cwe": "89"}, {"tags": ["sqli"]})

    assert _apply(client, auth, r.id, role="analyst").status_code == 403
    assert _apply(client, auth, r.id, role="manager").status_code == 202  # a manager in no team
    db.expire_all()
    assert {f.asset.name: f.tags for f in findings(db)} == {"svc": ["sqli"], "hidden": []}


def test_rules_for_every_asset_are_for_administrators(client, auth, db, asset):
    """A global rule acts on every team's findings, as the global quality gate does: admins only."""
    body = {"name": "g", "match": {"cwe": "89"}, "action": {"tags": ["sqli"]}}
    assert client.post("/api/v1/triage-rules", json=body, headers=auth["manager"]).status_code == 403
    r = client.post("/api/v1/triage-rules", json=body, headers=auth["admin"])
    assert r.status_code == 201
    rid = r.json()["id"]
    off = client.patch(f"/api/v1/triage-rules/{rid}", json={"enabled": False}, headers=auth["manager"])
    assert off.status_code == 403
    assert client.delete(f"/api/v1/triage-rules/{rid}", headers=auth["manager"]).status_code == 403

    # Nor can a manager turn their asset's rule into a global one.
    mine = {**body, "asset_id": asset.id}
    own = client.post("/api/v1/triage-rules", json=mine, headers=auth["manager"]).json()
    to_all = {"asset_id": None}
    moved = client.patch(f"/api/v1/triage-rules/{own['id']}", json=to_all, headers=auth["manager"])
    assert moved.status_code == 403
    assert client.delete(f"/api/v1/triage-rules/{rid}", headers=auth["admin"]).status_code == 204
