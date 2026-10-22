"""Exploitability: KEV and EPSS feeds, filters, sorting and risk weighting."""

import gzip
import json
from datetime import date

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models import Asset, Finding, VulnIntel
from app.services import intel
from app.services.ingestion import IngestOptions, ingest_report
from app.services.scope import GLOBAL

KEV_FEED = json.dumps(
    {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228",
                "vulnerabilityName": "Apache Log4j2 Remote Code Execution",
                "dueDate": "2021-12-24",
                "knownRansomwareCampaignUse": "Known",
            },
            {
                "cveID": "CVE-2016-1000027",
                "vulnerabilityName": "Spring deserialisation",
                "dueDate": "2023-01-01",
            },
        ],
    }
).encode()

EPSS_FEED = gzip.compress(
    b"#model_version:v2025.03.14,score_date:2026-09-20T00:00:00Z\n"
    b"cve,epss,percentile\n"
    b"CVE-2021-44228,0.97425,0.99982\n"
    b"CVE-2016-1000027,0.01234,0.50000\n"
    b"CVE-2020-0001,0.00042,0.10000\n"  # not held here: must be skipped
)


@pytest.fixture
def asset(db):
    a = Asset(name="svc", tags=[])
    db.add(a)
    db.commit()
    return a


def sca(db, asset, *findings):
    report = {
        "schema": "guardiano/v1",
        "tool": {"name": "Trivy"},
        "scan_type": "sca",
        "findings": [
            {
                "title": f"{cve} in {pkg}",
                "severity": severity,
                "package_name": pkg,
                "package_version": "1.0.0",
                "ecosystem": "maven",
                "cve_id": cve,
            }
            for cve, pkg, severity in findings
        ],
    }
    return ingest_report(db, json.dumps(report).encode(), asset, None, IngestOptions())


@pytest.fixture
def findings(db, asset):
    sca(
        db,
        asset,
        ("CVE-2021-44228", "log4j-core", "critical"),
        ("CVE-2016-1000027", "spring-web", "high"),
        ("CVE-2024-99999", "unknown-lib", "high"),
    )
    return db.scalars(select(Finding).order_by(Finding.id)).all()


# ---- feeds --------------------------------------------------------------------------------------


def test_kev_feed_is_stored_whole(db):
    assert intel.sync_kev(db, KEV_FEED) == 2
    db.commit()
    log4shell = db.get(VulnIntel, "CVE-2021-44228")
    assert log4shell.in_kev is True and log4shell.kev_ransomware is True
    assert log4shell.kev_due_date == date(2021, 12, 24)
    assert db.get(VulnIntel, "CVE-2016-1000027").kev_ransomware is False


def test_epss_is_kept_only_for_cves_we_hold(db, findings):
    assert intel.sync_epss(db, EPSS_FEED) == 2  # the third CVE in the feed is not ours
    db.commit()
    assert db.get(VulnIntel, "CVE-2021-44228").epss == pytest.approx(0.97425)
    assert db.get(VulnIntel, "CVE-2021-44228").epss_percentile == pytest.approx(0.99982)
    assert db.get(VulnIntel, "CVE-2020-0001") is None


def test_epss_parsing_survives_a_messy_feed(db):
    raw = (
        b"#model_version:v1\n"
        b"cve,epss,percentile\n"
        b"CVE-1,notanumber,0.5\n"  # unparseable: skipped, not fatal
        b"CVE-2,0.5\n"  # short row
        b",0.1,0.2\n"  # no CVE
        b"cve-3,0.25,0.75\n"  # lower case: normalised
    )
    rows = intel.parse_epss(raw, {"CVE-1", "CVE-2", "CVE-3"})
    assert rows == [
        # Truncated, but the score itself is usable; the percentile stays unknown.
        {"cve_id": "CVE-2", "epss": 0.5, "epss_percentile": None},
        {"cve_id": "CVE-3", "epss": 0.25, "epss_percentile": 0.75},
    ]


def test_a_cve_leaving_the_catalogue_stops_being_exploited(db):
    intel.sync_kev(db, KEV_FEED)
    db.commit()
    shrunk = json.dumps({"vulnerabilities": [{"cveID": "CVE-2021-44228", "dueDate": "2021-12-24"}]}).encode()
    intel.sync_kev(db, shrunk)
    db.commit()
    assert db.get(VulnIntel, "CVE-2021-44228").in_kev is True
    assert db.get(VulnIntel, "CVE-2016-1000027").in_kev is False  # kept, but no longer flagged


def test_sync_is_idempotent(db, findings):
    intel.sync_kev(db, KEV_FEED)
    intel.sync_epss(db, EPSS_FEED)
    db.commit()
    intel.sync_kev(db, KEV_FEED)
    intel.sync_epss(db, EPSS_FEED)
    db.commit()
    assert db.scalar(select(Finding.id)) is not None
    assert len(db.scalars(select(VulnIntel)).all()) == 2
    # Both feeds write the same row without erasing each other's columns.
    row = db.get(VulnIntel, "CVE-2021-44228")
    assert row.in_kev is True and row.epss == pytest.approx(0.97425)


# ---- reading it back ----------------------------------------------------------------------------


@pytest.fixture
def with_intel(db, findings):
    intel.sync_kev(db, KEV_FEED)
    intel.sync_epss(db, EPSS_FEED)
    db.commit()
    return findings


def test_findings_carry_their_exploitability(client, auth, with_intel):
    items = client.get("/api/v1/findings?sort=title", headers=auth["viewer"]).json()["items"]
    by_cve = {f["cve_id"]: f for f in items}
    log4shell = by_cve["CVE-2021-44228"]
    assert log4shell["in_kev"] is True and log4shell["kev_ransomware"] is True
    assert log4shell["epss"] == pytest.approx(0.97425)
    assert log4shell["kev_due_date"] == "2021-12-24"
    # A CVE the feeds do not cover simply has nothing.
    assert by_cve["CVE-2024-99999"]["in_kev"] is False and by_cve["CVE-2024-99999"]["epss"] is None

    detail = client.get(f"/api/v1/findings/{log4shell['id']}", headers=auth["viewer"]).json()
    assert detail["in_kev"] is True and detail["epss_percentile"] == pytest.approx(0.99982)


def test_filters_and_sorting(client, auth, with_intel):
    def cves(query):
        return [
            f["cve_id"]
            for f in client.get(f"/api/v1/findings?{query}", headers=auth["viewer"]).json()["items"]
        ]

    # Which findings, not their order: the default sort gives findings of equal severity no fixed
    # order, which is why this used to read `== [...] or set(...) == {...}` -- a first clause that
    # could only ever pass or fall through to the second.
    assert set(cves("kev=true")) == {"CVE-2021-44228", "CVE-2016-1000027"}
    assert set(cves("kev=false")) == {"CVE-2024-99999"}
    assert cves("epss_min=0.5") == ["CVE-2021-44228"]
    assert cves("sort=-epss")[0] == "CVE-2021-44228"
    assert cves("sort=epss")[0] == "CVE-2016-1000027"  # nulls last, lowest score first


def test_dashboard_counts_known_exploited(client, auth, with_intel):
    summary = client.get("/api/v1/analytics/summary", headers=auth["viewer"]).json()
    assert summary["known_exploited"] == 2


def test_exports_carry_exploitability(client, auth, with_intel):
    import csv
    import io

    text = client.get("/api/v1/findings/export.csv?kev=true", headers=auth["viewer"]).text
    rows = list(csv.reader(io.StringIO(text)))
    kev_column = rows[0].index("in_kev")
    assert {r[kev_column] for r in rows[1:]} == {"yes"}


# ---- risk weighting -----------------------------------------------------------------------------


def test_risk_scores_are_unchanged_by_default(client, auth, db, with_intel, asset):
    assert settings.risk_use_exploitability is False
    before = client.get(f"/api/v1/assets/{asset.id}", headers=auth["viewer"]).json()["risk_score"]
    # critical 10 + high 5 + high 5, medium criticality multiplier 1.0
    assert before == pytest.approx(20.0)


def test_exploitability_can_weigh_on_risk(client, auth, db, with_intel, asset, monkeypatch):
    monkeypatch.setattr(settings, "risk_use_exploitability", True)
    score = client.get(f"/api/v1/assets/{asset.id}", headers=auth["viewer"]).json()["risk_score"]
    # KEV doubles log4shell (10 -> 20) and spring (5 -> 10); the unknown CVE stays at 5.
    assert score == pytest.approx(35.0)


def test_high_epss_alone_raises_the_weight(db, asset, monkeypatch):
    sca(db, asset, ("CVE-2021-44228", "log4j-core", "high"))
    db.add(VulnIntel(cve_id="CVE-2021-44228", epss=0.9, in_kev=False))
    db.commit()
    monkeypatch.setattr(settings, "risk_use_exploitability", True)

    from app.services.analytics import top_assets

    (row,) = top_assets(db, scope=GLOBAL)
    assert row["risk_score"] == pytest.approx(5.0 * settings.epss_risk_multiplier)


# ---- the scheduled sync -------------------------------------------------------------------------


def test_sync_task_can_be_turned_off(db, monkeypatch):
    from app.services.tasks import intel_sync

    monkeypatch.setattr(settings, "intel_sync_enabled", False)
    called = []
    monkeypatch.setattr(intel, "sync_kev", lambda db: called.append("kev"))
    monkeypatch.setattr(intel, "sync_epss", lambda db: called.append("epss"))
    monkeypatch.setattr(intel, "pending_aliases", lambda db: [])
    intel_sync(db, {})
    assert called == []

    monkeypatch.setattr(settings, "intel_sync_enabled", True)
    intel_sync(db, {})
    assert called == ["kev", "epss"]


# ---- advisory ids to CVEs, through OSV ---------------------------------------------------------------


def _advisory_findings(db):
    asset = Asset(name="aliases", tags=[])
    db.add(asset)
    db.commit()
    report = {"schema": "guardiano/v1", "tool": {"name": "t"}, "scan_type": "sca", "findings": [
        {"title": "a", "severity": "high", "type": "sca", "package_name": "log4j-core",
         "package_version": "2.14.1", "ecosystem": "maven", "vuln_id": "GHSA-jfh8-c2jp-5v3q"},
        {"title": "b", "severity": "low", "type": "sca", "package_name": "x", "package_version": "1",
         "ecosystem": "npm", "vuln_id": "GHSA-none-none-none"},
        {"title": "c", "severity": "low", "type": "sca", "package_name": "y", "package_version": "1",
         "ecosystem": "npm", "vuln_id": "GHSA-keep-keep-keep", "cve_id": "CVE-2020-0001"},
    ]}  # fmt: skip
    ingest_report(db, json.dumps(report).encode(), asset, None, IngestOptions())
    return asset


def test_an_advisory_gains_its_cve_and_with_it_kev(client, auth, db):
    from app.models import Finding, VulnAlias

    _advisory_findings(db)
    intel.sync_kev(db, KEV_FEED)
    asked = []

    def lookup(vuln_id):
        asked.append(vuln_id)
        return {"GHSA-jfh8-c2jp-5v3q": "CVE-2021-44228", "GHSA-keep-keep-keep": "CVE-9999-9999"}.get(vuln_id)

    assert intel.resolve_aliases(db, lookup) == 1
    db.commit()
    by_vuln = {f.vuln_id: f for f in db.scalars(select(Finding))}
    assert by_vuln["GHSA-jfh8-c2jp-5v3q"].cve_id == "CVE-2021-44228"
    # A CVE the scanner gave is never replaced.
    assert by_vuln["GHSA-keep-keep-keep"].cve_id == "CVE-2020-0001"
    assert "GHSA-keep-keep-keep" not in asked, "findings that have a CVE are not looked up"
    assert db.get(VulnAlias, "GHSA-none-none-none").cve_id is None  # remembered: no CVE

    kev = client.get("/api/v1/findings", params={"kev": True}, headers=auth["viewer"]).json()
    assert [i["vuln_id"] for i in kev["items"]] == ["GHSA-jfh8-c2jp-5v3q"]

    asked.clear()
    intel.resolve_aliases(db, lookup)
    assert asked == [], "an advisory looked up recently, with or without a CVE, is not asked again"


def test_a_failing_lookup_does_not_stop_the_sync(db, monkeypatch):
    _advisory_findings(db)

    def broken(vuln_id):
        raise RuntimeError("OSV is down")

    assert intel.resolve_aliases(db, broken) == 0
    monkeypatch.setattr(intel, "resolve_aliases", lambda db: (_ for _ in ()).throw(RuntimeError("boom")))
    empty_epss = b"cve,epss,percentile\n"
    monkeypatch.setattr(intel, "_download", lambda url: KEV_FEED if "cisa" in url else empty_epss)
    counts = intel.sync_all(db)
    assert counts["aliases"] == 0 and counts["kev"] == 2


def test_import_intel_loads_files_fetched_elsewhere(db, findings, tmp_path, monkeypatch, capsys):
    import sys

    from app import cli

    (tmp_path / "kev.json").write_bytes(KEV_FEED)
    epss = b"#model_version:v2025\ncve,epss,percentile\nCVE-2021-44228,0.97,0.999\n"
    (tmp_path / "epss.csv.gz").write_bytes(gzip.compress(epss))
    monkeypatch.setattr(sys, "argv", ["guardiano", "import-intel", "--kev", str(tmp_path / "kev.json"),
                                      "--epss", str(tmp_path / "epss.csv.gz")])  # fmt: skip
    cli.main()
    assert "2 KEV entries and 1 EPSS scores" in capsys.readouterr().out
    db.expire_all()
    row = db.get(VulnIntel, "CVE-2021-44228")
    assert row.in_kev and row.epss == 0.97
