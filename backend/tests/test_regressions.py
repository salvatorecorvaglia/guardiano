"""Regression tests for defects found in the project review."""

import json
import threading

import pytest
from sqlalchemy import select, text

from app.core.db import SessionLocal
from app.models import Asset, Finding, Scan
from app.parsers.base import ParseError
from app.parsers.detect import parse_report
from app.services.ingestion import IngestOptions, get_or_create_asset, ingest_report
from app.services.scope import GLOBAL
from tests.conftest import PASSWORD


@pytest.fixture
def asset(db):
    a = Asset(name="svc", tags=[])
    db.add(a)
    db.commit()
    return a


def native(findings, tool="t", scan_type=None):
    doc = {"schema": "guardiano/v1", "tool": {"name": tool}, "findings": findings}
    if scan_type:
        doc["scan_type"] = scan_type
    return json.dumps(doc).encode()


# ---- B1: oversized / odd values must be sanitized, not crash the insert -----------------------


def test_oversized_and_odd_values_are_sanitized(db, asset):
    report = native(
        [
            {
                "type": "sca",
                "title": "T\x00itle",
                "cve_id": "CVE-" + "9" * 400,
                "package_name": "p" * 400,
                "package_version": 1.2,
                "ecosystem": "e" * 80,
                "fixed_version": ["2.0"],
                "cwe": ["CWE-" + "1" * 30, "CWE-79"],
                "description": "bad\x00byte",
                "references": [{"url": "https://x.test", "title": {"nested": True}}, 42, {"title": "no url"}],
            },
            {
                "type": "sast",
                "title": "SQLi",
                "rule_id": "r" * 500,
                "file_path": "a.py",
                "line_start": 10**12,
                "snippet": "x\x00y",
            },
        ],
        tool="T" * 300,
    )
    scan = ingest_report(db, report, asset, None, IngestOptions(branch="b" * 400))
    assert scan.new_count == 2
    sca, sast = sorted(db.scalars(select(Finding)).all(), key=lambda f: f.type != "sca")
    assert sca.title == "Title" and "\x00" not in sca.description
    assert len(sca.cve_id) <= 50 and len(sca.package_name) <= 300 and len(sca.ecosystem) <= 50
    assert sca.package_version == "1.2"
    assert all(len(c) <= 20 for c in sca.cwe) and "CWE-79" in sca.cwe
    assert all(isinstance(r.get("url"), str) for r in sca.references)
    assert all(r.get("title") is None or isinstance(r["title"], str) for r in sca.references)
    assert all(len(t) <= 100 for t in sca.tools)
    assert len(sast.rule_id) <= 300 and sast.line_start is None and sast.snippet == "xy"
    assert len(db.get(Scan, scan.id).branch) <= 255


# ---- B3: malformed documents are ParseErrors (422), never 500s ---------------------------------


@pytest.mark.parametrize("doc", [{"results": [5]}, {"results": [None]}, {"runs": "x", "version": "2.1.0"}])
def test_malformed_documents_raise_parse_error(doc):
    with pytest.raises(ParseError):
        parse_report(doc)


def test_deeply_nested_json_is_a_parse_error(db, asset):
    raw = b"[" * 100_000 + b"]" * 100_000
    with pytest.raises(ParseError):
        ingest_report(db, raw, asset, None, IngestOptions())


# ---- B2: concurrent ingestion into the same asset ---------------------------------------------


def test_concurrent_ingest_of_same_new_findings(asset):
    report = native(
        [{"title": f"f{i}", "cwe": ["CWE-1"], "file_path": f"f{i}.py", "line_start": 1} for i in range(300)]
    )
    barrier = threading.Barrier(2)
    errors: list[BaseException] = []

    def worker():
        with SessionLocal() as s:
            a = s.get(Asset, asset.id)
            barrier.wait()
            try:
                ingest_report(s, report, a, None, IngestOptions())
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    with SessionLocal() as s:
        assert len(s.scalars(select(Finding).where(Finding.asset_id == asset.id)).all()) == 300


def test_concurrent_asset_auto_create():
    barrier = threading.Barrier(2)
    ids: list[int] = []
    errors: list[BaseException] = []

    def worker():
        with SessionLocal() as s:
            barrier.wait()
            try:
                ids.append(get_or_create_asset(s, "brand-new", GLOBAL).id)
                s.commit()
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors, errors
    assert len(set(ids)) == 1


def test_concurrent_asset_auto_create_in_different_casings():
    """The lookup ignores case but the unique index does not, so two uploads racing as
    "Payments-API" and "payments-api" used to create two assets for one repository."""
    for _ in range(5):  # a race: give it several chances to go wrong
        with SessionLocal() as s:
            s.execute(text("DELETE FROM assets WHERE lower(name) = 'race-me'"))
            s.commit()
        barrier = threading.Barrier(2)
        ids: list[int] = []
        errors: list[BaseException] = []

        def worker(name, barrier=barrier, ids=ids, errors=errors):
            with SessionLocal() as s:
                barrier.wait()
                try:
                    ids.append(get_or_create_asset(s, name, GLOBAL).id)
                    s.commit()
                except BaseException as exc:  # noqa: BLE001
                    errors.append(exc)

        threads = [threading.Thread(target=worker, args=(n,)) for n in ("Race-Me", "race-me")]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors, errors
        assert len(set(ids)) == 1, "two casings of one name became two assets"


def test_asset_auto_create_is_case_insensitive(db):
    a = get_or_create_asset(db, "Payments-API", GLOBAL)
    db.commit()
    assert get_or_create_asset(db, "payments-api", GLOBAL).id == a.id


# ---- B5: changing the password keeps the current session alive --------------------------------


def test_change_password_keeps_current_session(client, auth):
    r = client.post(
        "/api/v1/auth/change-password",
        headers=auth["analyst"],
        json={"current_password": PASSWORD, "new_password": "An0ther-Str0ng-Passw0rd"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["access_token"]
    # The refresh cookie was re-issued with the new token version, so the session survives.
    assert client.post("/api/v1/auth/refresh").status_code == 200


# ---- S3: the published example admin password is refused in production ------------------------


def test_bootstrap_refuses_example_password_in_production(db, monkeypatch):
    from app.core.config import settings
    from app.services import bootstrap

    monkeypatch.setattr(settings, "env", "production")
    monkeypatch.setattr(settings, "guardiano_admin_email", "admin@example.com")
    monkeypatch.setattr(settings, "guardiano_admin_password", bootstrap.EXAMPLE_ADMIN_PASSWORD)
    with pytest.raises(SystemExit):
        bootstrap.ensure_admin(db)


# ---- B4: close_missing ------------------------------------------------------------------------


def _finding(**kw):
    return {"title": "A", "severity": "high", "cwe": ["CWE-1"], "file_path": "a.py", "line_start": 1, **kw}


def test_close_missing_keeps_findings_still_reported_by_another_tool(db, asset):
    from app.models import FindingEvent

    ingest_report(db, native([_finding()], tool="A"), asset, None, IngestOptions())
    ingest_report(db, native([_finding()], tool="B"), asset, None, IngestOptions())
    other = _finding(title="other", file_path="b.py")
    s = ingest_report(db, native([other], tool="B"), asset, None, IngestOptions(close_missing=True))
    f = db.scalar(select(Finding).where(Finding.file_path == "a.py"))
    assert s.auto_resolved_count == 0 and f.status == "open" and f.tools == ["A"]
    assert db.scalar(select(FindingEvent).where(FindingEvent.event == "no_longer_reported"))

    s = ingest_report(db, native([other], tool="A"), asset, None, IngestOptions(close_missing=True))
    db.refresh(f)
    assert s.auto_resolved_count == 1 and f.status == "resolved"


def test_close_missing_covers_per_finding_tools(db, asset):
    ingest_report(db, native([_finding(tool="scanner-x")], tool="suite"), asset, None, IngestOptions())
    s = ingest_report(
        db,
        native([_finding(tool="scanner-x", file_path="z.py")], tool="suite"),
        asset,
        None,
        IngestOptions(close_missing=True),
    )
    assert s.auto_resolved_count == 1


def test_close_missing_ignores_empty_reports_unless_allowed(db, asset):
    ingest_report(db, native([_finding()], tool="A", scan_type="sast"), asset, None, IngestOptions())
    empty = native([], tool="A", scan_type="sast")
    s = ingest_report(db, empty, asset, None, IngestOptions(close_missing=True))
    assert s.auto_resolved_count == 0
    s = ingest_report(db, empty, asset, None, IngestOptions(close_missing=True, allow_empty=True))
    assert s.auto_resolved_count == 1


def test_multi_run_sarif_reports_every_tool():
    doc = {
        "version": "2.1.0",
        "runs": [
            {"tool": {"driver": {"name": "X"}}, "results": []},
            {"tool": {"driver": {"name": "Y"}}, "results": []},
        ],
    }
    assert parse_report(doc).tool_names == ["X", "Y"]


# ---- B6 / B7 / B8: analytics & ordering ------------------------------------------------------


def test_flow_buckets_are_contiguous(client, auth):
    from datetime import date

    t = client.get("/api/v1/analytics/trends", headers=auth["viewer"], params={"days": 90}).json()
    periods = [date.fromisoformat(r["period"]) for r in t["new_vs_closed"]]
    assert len(periods) >= 13
    assert all((b - a).days == 7 for a, b in zip(periods, periods[1:], strict=False))
    d = client.get("/api/v1/analytics/trends", headers=auth["viewer"], params={"days": 30}).json()
    assert len(d["new_vs_closed"]) == 30


def test_overdue_false_includes_info_findings(client, auth, db, asset):
    ingest_report(db, native([_finding(severity="info")]), asset, None, IngestOptions())
    r = client.get("/api/v1/findings", headers=auth["viewer"], params={"overdue": "false"})
    assert r.json()["total"] == 1


def test_events_with_same_timestamp_are_ordered_newest_first(db, asset):
    from app.models.base import utcnow
    from app.models.enums import Status
    from app.services import lifecycle

    ingest_report(db, native([_finding()]), asset, None, IngestOptions())
    f = db.scalar(select(Finding))
    now = utcnow()
    lifecycle.set_status(db, f, Status.in_progress, actor=None, now=now)
    lifecycle.set_status(db, f, Status.resolved, actor=None, now=now)
    db.commit()
    db.expire_all()
    assert [e.to_status for e in db.get(Finding, f.id).events][:2] == ["resolved", "in_progress"]


# ---- S2: session revocation -------------------------------------------------------------------


def test_password_change_revokes_old_access_tokens(client, auth):
    old = auth["analyst"]
    client.post(
        "/api/v1/auth/change-password",
        headers=old,
        json={"current_password": PASSWORD, "new_password": "An0ther-Str0ng-Passw0rd"},
    )
    assert client.get("/api/v1/auth/me", headers=old).status_code == 401


def test_logout_all_revokes_access_and_refresh(client, auth):
    headers = auth["viewer"]  # the client's refresh cookie belongs to the last login (viewer)
    assert client.post("/api/v1/auth/logout-all", headers=headers).status_code == 204
    assert client.get("/api/v1/auth/me", headers=headers).status_code == 401
    assert client.post("/api/v1/auth/refresh").status_code == 401


# ---- risk acceptance --------------------------------------------------------------------------


def test_risk_acceptance_expiry_must_be_future(client, auth, db, asset):
    ingest_report(db, native([_finding()]), asset, None, IngestOptions())
    fid = db.scalar(select(Finding.id))
    body = {"status": "risk_accepted", "justification": "WAF"}
    r = client.patch(
        f"/api/v1/findings/{fid}",
        headers=auth["manager"],
        json={**body, "risk_accepted_until": "2001-01-01T00:00:00Z"},
    )
    assert r.status_code == 422
    # A timestamp without an offset is accepted and treated as UTC.
    r = client.patch(
        f"/api/v1/findings/{fid}",
        headers=auth["manager"],
        json={**body, "risk_accepted_until": "2099-01-01T00:00:00"},
    )
    assert r.status_code == 200 and r.json()["risk_accepted_until"].startswith("2099-01-01T00:00:00")


def test_expire_risk_acceptances(db, asset):
    from datetime import timedelta

    from app.models.base import utcnow
    from app.models.enums import Status
    from app.services import lifecycle

    ingest_report(db, native([_finding()]), asset, None, IngestOptions())
    f = db.scalar(select(Finding))
    lifecycle.set_status(
        db,
        f,
        Status.risk_accepted,
        actor=None,
        justification="x",
        risk_accepted_until=utcnow() - timedelta(days=1),
    )
    db.commit()
    assert lifecycle.expire_risk_acceptances(db) == 1
    db.commit()
    db.expire_all()
    assert f.status == "open" and f.events[0].event == "reopened"


# ---- P4 / B9: asset list computed in SQL -------------------------------------------------------


def test_asset_list_sorting_paging_and_search(client, auth, db):
    specs = [
        ("alpha", "low", ["critical"]),
        ("Bravo", "critical", ["high", "low"]),
        ("charlie_1", "medium", []),
    ]
    for name, crit, sevs in specs:
        a = Asset(name=name, criticality=crit, tags=["t"])
        db.add(a)
        db.commit()
        if sevs:
            ingest_report(
                db,
                native([_finding(severity=s, file_path=f"{s}.py") for s in sevs]),
                a,
                None,
                IngestOptions(),
            )

    def names(**params):
        r = client.get("/api/v1/assets", headers=auth["viewer"], params=params).json()
        return [a["name"] for a in r["items"]], r["total"]

    # risk: alpha 10*0.5=5, Bravo (5+0.5)*2=11, charlie 0
    assert names(sort="-risk") == (["Bravo", "alpha", "charlie_1"], 3)
    assert names(sort="name") == (["alpha", "Bravo", "charlie_1"], 3)
    assert names(sort="-open")[0][0] == "Bravo"
    assert names(sort="-last_scan")[0][-1] == "charlie_1"  # never scanned sorts last
    assert names(sort="name", page=2, page_size=2) == (["charlie_1"], 3)
    assert names(q="LI") == (["charlie_1"], 1)
    assert names(q="%") == ([], 0)  # LIKE wildcards are literal
    assert names(q="e_1") == (["charlie_1"], 1)
    items = client.get("/api/v1/assets", headers=auth["viewer"], params={"sort": "-risk"}).json()["items"]
    assert (
        items[0]["risk_score"] == 11.0
        and items[0]["open_counts"]["high"] == 1
        and items[0]["open_total"] == 2
    )
    assert items[2]["last_scan_at"] is None and items[2]["open_total"] == 0


# ---- P3: CSV export -----------------------------------------------------------------------------


def test_csv_export_rows_and_formula_escape(client, auth, db, asset):
    import csv
    import io

    ingest_report(
        db,
        native([_finding(title="=HYPERLINK(1)"), _finding(title="multi\nline", file_path="b.py")]),
        asset,
        None,
        IngestOptions(),
    )
    r = client.get("/api/v1/findings/export.csv", headers=auth["viewer"])
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert len(rows) == 2 and all(row["asset"] == "svc" for row in rows)
    assert {row["title"] for row in rows} == {"'=HYPERLINK(1)", "multi\nline"}


def test_asset_update_limits_are_validated(client, auth):
    a = client.post("/api/v1/assets", headers=auth["manager"], json={"name": "lim"}).json()
    for body in ({"owner": "o" * 201}, {"repo_url": "u" * 501}, {"tags": ["t" * 65]}, {"tags": ["t"] * 31}):
        assert (
            client.patch(f"/api/v1/assets/{a['id']}", headers=auth["manager"], json=body).status_code == 422
        )
    r = client.patch(f"/api/v1/assets/{a['id']}", headers=auth["manager"], json={"tags": [" pci "]})
    assert r.status_code == 200 and r.json()["tags"] == ["pci"]


def test_meta_version_is_single_sourced(client):
    from app import __version__

    assert client.get("/api/v1/meta").json()["version"] == __version__
    assert client.get("/api/openapi.json").json()["info"]["version"] == __version__


def test_swagger_oauth_redirect_stays_under_api_proxy(client):
    docs = client.get("/api/docs")

    assert docs.status_code == 200
    assert "'/api/docs/oauth2-redirect'" in docs.text
    assert client.get("/api/docs/oauth2-redirect").status_code == 200


def test_legacy_malformed_references_are_served_leniently(client, auth, db, asset):
    ingest_report(db, native([_finding()]), asset, None, IngestOptions())
    f = db.scalar(select(Finding))
    f.references = [{"url": "https://ok.test", "title": {"x": 1}}, "junk", {"title": "no url"}]
    db.commit()
    r = client.get(f"/api/v1/findings/{f.id}", headers=auth["viewer"])
    assert r.status_code == 200
    assert r.json()["references"] == [
        {"url": "https://ok.test", "title": None},
        {"url": None, "title": "no url"},
    ]


# ---- S6: analysts cannot turn a risk acceptance into a permanent suppression ---------------------


def test_risk_accepted_to_false_positive_requires_manager(client, auth, db, asset):
    ingest_report(db, native([_finding(), _finding(file_path="b.py")]), asset, None, IngestOptions())
    accepted, other = db.scalars(select(Finding.id).order_by(Finding.id)).all()
    ok = client.patch(
        f"/api/v1/findings/{accepted}",
        headers=auth["manager"],
        json={
            "status": "risk_accepted",
            "justification": "WAF",
            "risk_accepted_until": "2099-01-01T00:00:00Z",
        },
    )
    assert ok.status_code == 200
    fp = {"status": "false_positive", "justification": "not reachable"}

    r = client.patch(f"/api/v1/findings/{accepted}", headers=auth["analyst"], json=fp)
    assert r.status_code == 403 and "risk-accepted" in r.json()["detail"]
    r = client.post("/api/v1/findings/bulk", headers=auth["analyst"], json={"ids": [accepted, other], **fp})
    assert r.status_code == 403
    assert db.get(Finding, other).status == "open"  # the bulk request is all-or-nothing

    # Analysts can still reopen or resolve it, and still mark other findings as false positives.
    assert client.patch(f"/api/v1/findings/{other}", headers=auth["analyst"], json=fp).status_code == 200
    r = client.patch(f"/api/v1/findings/{accepted}", headers=auth["analyst"], json={"status": "open"})
    assert r.status_code == 200
    r = client.patch(f"/api/v1/findings/{accepted}", headers=auth["manager"], json={**fp})
    assert r.status_code == 200
