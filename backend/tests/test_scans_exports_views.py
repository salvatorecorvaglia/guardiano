"""Scan diff, JSON/SARIF exports and saved views."""

import csv
import io
import json

import pytest
from sqlalchemy import select

from app.models import Asset, Finding, Scan
from app.parsers.detect import parse_report
from app.services.ingestion import IngestOptions, ingest_report


def native(*titles, tool="t", severity="high"):
    return json.dumps(
        {
            "schema": "guardiano/v1",
            "tool": {"name": tool},
            "scan_type": "sast",
            "findings": [
                {
                    "title": t,
                    "severity": severity,
                    "cwe": ["CWE-89"],
                    "file_path": f"src/{t}.py",
                    "line_start": 3,
                }
                for t in titles
            ],
        }
    ).encode()


@pytest.fixture
def asset(db):
    a = Asset(name="svc", tags=[])
    db.add(a)
    db.commit()
    return a


def ids(client, headers, **params):
    r = client.get("/api/v1/findings", params=params, headers=headers)
    assert r.status_code == 200, r.text
    return sorted(f["title"] for f in r.json()["items"])


# ---- scan diff ----------------------------------------------------------------------------------


def test_scan_diff_against_previous_scan_of_same_tool(client, auth, db, asset):
    s1 = ingest_report(db, native("a", "b"), asset, None, IngestOptions())
    ingest_report(db, native("z", tool="other"), asset, None, IngestOptions())  # different tool: ignored
    s2 = ingest_report(db, native("b", "c"), asset, None, IngestOptions())

    d = client.get(f"/api/v1/scans/{s2.id}/diff", headers=auth["viewer"]).json()
    assert d["against"]["id"] == s1.id
    assert (d["new"], d["no_longer_reported"], d["unchanged"]) == (1, 1, 1)
    assert ids(client, auth["viewer"], scan_id=s2.id, not_in_scan_id=s1.id) == ["c"]
    assert ids(client, auth["viewer"], scan_id=s1.id, not_in_scan_id=s2.id) == ["a"]
    assert ids(client, auth["viewer"], scan_id=s2.id) == ["b", "c"]

    first = client.get(f"/api/v1/scans/{s1.id}/diff", headers=auth["viewer"]).json()
    assert first["against"] is None and (first["new"], first["unchanged"]) == (2, 0)

    explicit = client.get(f"/api/v1/scans/{s1.id}/diff?against={s2.id}", headers=auth["viewer"]).json()
    assert (explicit["new"], explicit["no_longer_reported"]) == (1, 1)


def test_scan_diff_errors(client, auth, db, asset):
    other = Asset(name="other", tags=[])
    db.add(other)
    db.commit()
    s1 = ingest_report(db, native("a"), asset, None, IngestOptions())
    s2 = ingest_report(db, native("a"), other, None, IngestOptions())
    assert (
        client.get(f"/api/v1/scans/{s1.id}/diff?against={s2.id}", headers=auth["viewer"]).status_code == 422
    )
    assert client.get("/api/v1/scans/999/diff", headers=auth["viewer"]).status_code == 404


# ---- exports ------------------------------------------------------------------------------------


def test_json_export_matches_the_list(client, auth, db, asset):
    ingest_report(db, native("a", "b", "c"), asset, None, IngestOptions())
    r = client.get("/api/v1/findings/export.json?sort=title", headers=auth["viewer"])
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/json")
    exported = r.json()
    listed = client.get("/api/v1/findings?sort=title", headers=auth["viewer"]).json()["items"]
    assert exported == listed
    assert client.get("/api/v1/findings/export.json?q=nomatch", headers=auth["viewer"]).json() == []


def test_sarif_export_round_trips_through_the_importer(client, auth, db, asset):
    ingest_report(db, native("a", "b"), asset, None, IngestOptions())
    ingest_report(db, native("crit", severity="critical"), asset, None, IngestOptions())
    f = db.scalar(select(Finding).where(Finding.title == "a"))
    f.tags = ["pci"]
    db.commit()

    r = client.get("/api/v1/findings/export.sarif?sort=title", headers=auth["viewer"])
    assert r.status_code == 200
    doc = json.loads(r.content)
    assert doc["version"] == "2.1.0" and doc["runs"][0]["tool"]["driver"]["name"] == "Guardiano"
    first = doc["runs"][0]["results"][0]
    assert first["properties"]["guardiano"]["tags"] == ["pci"]
    assert first["properties"]["tags"] == ["external/cwe/cwe-89"]

    report = parse_report(doc)
    got = sorted((n.title, n.severity, n.cwe, n.file_path, n.line_start) for n in report.findings)
    assert got == [
        ("a", "high", ["CWE-89"], "src/a.py", 3),
        ("b", "high", ["CWE-89"], "src/b.py", 3),
        ("crit", "critical", ["CWE-89"], "src/crit.py", 3),
    ]
    # Filters apply to exports exactly as to the list.
    only_crit = json.loads(
        client.get("/api/v1/findings/export.sarif?severity=critical", headers=auth["viewer"]).content
    )
    assert len(only_crit["runs"][0]["results"]) == 1


def test_sarif_export_reimports_as_a_scan(client, auth, db, asset):
    ingest_report(db, native("a"), asset, None, IngestOptions())
    sarif = client.get("/api/v1/findings/export.sarif", headers=auth["viewer"]).content
    r = client.post(
        "/api/v1/scans",
        files={"file": ("export.sarif", sarif, "application/json")},
        data={"asset_name": "copy"},
        headers=auth["analyst"],
    )
    assert r.status_code == 201 and r.json()["new_count"] == 1 and r.json()["tool_name"] == "Guardiano"


def test_csv_export_appends_tags_column(client, auth, db, asset):
    ingest_report(db, native("a"), asset, None, IngestOptions())
    db.scalar(select(Finding)).tags = ["pci", "q3"]
    db.commit()
    rows = list(
        csv.reader(io.StringIO(client.get("/api/v1/findings/export.csv", headers=auth["viewer"]).text))
    )
    # Columns are only ever appended, so existing positions stay put.
    assert rows[0][-4:] == ["assignee", "tags", "epss", "in_kev"]
    assert rows[1][rows[0].index("tags")] == "pci;q3"


# ---- saved views --------------------------------------------------------------------------------


def test_saved_views(client, auth):
    r = client.post(
        "/api/v1/views",
        json={"name": "Crit open", "query": "?severity=critical&status=open&page=3"},
        headers=auth["analyst"],
    )
    assert r.status_code == 201
    view = r.json()
    assert view["query"] == "severity=critical&status=open" and view["shared"] is False

    # Private: invisible to others and not editable by them.
    assert client.get("/api/v1/views", headers=auth["viewer"]).json() == []
    assert (
        client.patch(f"/api/v1/views/{view['id']}", json={"name": "x"}, headers=auth["viewer"]).status_code
        == 404
    )
    assert client.delete(f"/api/v1/views/{view['id']}", headers=auth["admin"]).status_code == 404

    assert client.patch(f"/api/v1/views/{view['id']}", json={"shared": True}, headers=auth["analyst"]).json()[
        "shared"
    ]
    shared = client.get("/api/v1/views", headers=auth["viewer"]).json()
    assert [v["name"] for v in shared] == ["Crit open"] and shared[0]["user"]["email"] == "analyst@test.io"

    # Viewers keep private views but cannot publish them.
    assert (
        client.post("/api/v1/views", json={"name": "v", "shared": True}, headers=auth["viewer"]).status_code
        == 403
    )
    mine = client.post(
        "/api/v1/views", json={"name": "A mine", "query": "type=sca"}, headers=auth["viewer"]
    ).json()
    assert [v["id"] for v in client.get("/api/v1/views", headers=auth["viewer"]).json()] == [
        mine["id"],
        view["id"],
    ]

    # Admins can remove a shared view someone else owns.
    assert client.delete(f"/api/v1/views/{view['id']}", headers=auth["admin"]).status_code == 204
    assert [v["id"] for v in client.get("/api/v1/views", headers=auth["viewer"]).json()] == [mine["id"]]


def test_saved_views_are_session_only(client, auth):
    token = client.post(
        "/api/v1/tokens", json={"name": "ci", "scopes": ["read"]}, headers=auth["viewer"]
    ).json()
    assert (
        client.get("/api/v1/views", headers={"Authorization": f"Bearer {token['token']}"}).status_code == 403
    )


def test_scan_list_unaffected(client, auth, db, asset):
    ingest_report(db, native("a"), asset, None, IngestOptions())
    assert client.get("/api/v1/scans", headers=auth["viewer"]).json()["total"] == db.query(Scan).count()
