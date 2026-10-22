"""The Prometheus endpoint: what it exposes, who may read it, and that it is off by default."""

import re

import pytest

from app.core.config import settings
from app.models import Asset, Finding
from app.models.base import utcnow
from app.services import metrics
from app.services.ingestion import IngestOptions, ingest_report
from app.services.jobs import enqueue
from tests.conftest import sample


@pytest.fixture(autouse=True)
def clean_registry():
    metrics.reset()
    yield
    metrics.reset()


@pytest.fixture
def on(monkeypatch):
    monkeypatch.setattr(settings, "metrics_enabled", True)


def parse(text: str) -> dict[str, float]:
    """The exposition document as {"name{labels}": value}, ignoring comments."""
    out = {}
    for line in text.splitlines():
        if line and not line.startswith("#"):
            key, _, value = line.rpartition(" ")
            out[key] = float(value)
    return out


# ---- the endpoint --------------------------------------------------------------------------------


def test_it_is_off_unless_switched_on(client):
    assert client.get("/metrics").status_code == 404


def test_it_needs_no_session_when_no_token_is_set(client, on):
    """A scraper is not a person; it reaches the endpoint on an internal network, not through nginx."""
    r = client.get("/metrics")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    assert "guardiano_findings_open" in r.text


def test_a_token_is_enforced_when_configured(client, on, monkeypatch):
    monkeypatch.setattr(settings, "metrics_token", "scrape-me")
    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/metrics", headers={"Authorization": "Bearer scrape-me"}).status_code == 200


# ---- what it says --------------------------------------------------------------------------------


def test_the_gauges_count_what_is_in_the_database(client, on, db, users):
    asset = Asset(name="svc", tags=[])
    db.add(asset)
    db.flush()
    now = utcnow()
    for i, (severity, status) in enumerate(
        [("critical", "open"), ("critical", "in_progress"), ("low", "open"), ("high", "resolved")]
    ):
        db.add(
            Finding(
                asset_id=asset.id,
                type="sast",
                dedup_key=f"k{i}",
                title="t",
                severity=severity,
                status=status,
                cwe=[],
                tools=["x"],
                references=[],
                first_seen_at=now,
                last_seen_at=now,
                closed_at=now if status == "resolved" else None,
            )
        )
    enqueue(db, "deliver_webhook", {"id": 1})
    db.commit()

    m = parse(client.get("/metrics").text)
    assert m['guardiano_findings_open{severity="critical"}'] == 2  # open and in_progress
    assert m['guardiano_findings_open{severity="low"}'] == 1
    assert m['guardiano_findings_open{severity="high"}'] == 0, "a severity with nothing open still reports 0"
    assert m['guardiano_findings_total{status="resolved"}'] == 1
    assert m["guardiano_assets"] == 1
    assert m['guardiano_jobs{status="queued"}'] == 1
    assert m['guardiano_jobs{status="dead"}'] == 0
    assert m["guardiano_users_active"] == len(users)
    assert m["guardiano_job_oldest_queued_seconds"] >= 0


def test_overdue_findings_are_exposed_for_alerting(client, on, db):
    from datetime import timedelta

    asset = Asset(name="svc", tags=[])
    db.add(asset)
    db.flush()
    db.add(
        Finding(
            asset_id=asset.id,
            type="sast",
            dedup_key="old",
            title="t",
            severity="critical",
            status="open",
            cwe=[],
            tools=["x"],
            references=[],
            first_seen_at=utcnow() - timedelta(days=365),
            last_seen_at=utcnow(),
        )
    )
    db.commit()
    assert parse(client.get("/metrics").text)["guardiano_findings_overdue"] == 1


def test_requests_are_counted_by_route_not_by_path(client, on, auth, db):
    """/findings/{id} must not become one time series per finding."""
    asset = Asset(name="svc", tags=[])
    db.add(asset)
    db.flush()
    ids = []
    for i in range(2):
        f = Finding(
            asset_id=asset.id,
            type="sast",
            dedup_key=f"k{i}",
            title="t",
            severity="low",
            status="open",
            cwe=[],
            tools=["x"],
            references=[],
            first_seen_at=utcnow(),
            last_seen_at=utcnow(),
        )
        db.add(f)
        db.flush()
        ids.append(f.id)
    db.commit()

    for finding_id in ids:
        assert client.get(f"/api/v1/findings/{finding_id}", headers=auth["viewer"]).status_code == 200

    text = client.get("/metrics").text
    m = parse(text)
    # The label is the endpoint template, relative to its router (the /api/v1 prefix is constant).
    key = 'guardiano_http_requests_total{method="GET",route="/findings/{finding_id}",status="200"}'
    assert m[key] == 2
    routes = set(re.findall(r'route="([^"]*)"', text))
    assert routes, "requests are being recorded"
    assert not any(re.search(r"/\d", r) for r in routes), f"no route label may carry an id: {routes}"
    assert "guardiano_http_request_duration_seconds_bucket" in text


def test_the_histogram_buckets_are_cumulative_and_well_formed():
    for seconds in (0.001, 0.03, 7.0):
        metrics.observe("t_seconds", seconds, "help", route="/x")
    lines = metrics.render([]).splitlines()
    buckets = [line for line in lines if line.startswith("t_seconds_bucket")]
    values = [float(line.rsplit(" ", 1)[1]) for line in buckets]
    assert values == sorted(values), "each bucket counts everything at or below its edge"
    assert values[-1] == 3  # +Inf holds them all
    assert 'le="+Inf"' in buckets[-1]
    assert 't_seconds_count{route="/x"} 3' in lines
    assert any(line.startswith("t_seconds_sum") for line in lines)
    assert "# TYPE t_seconds histogram" in lines


def test_an_observation_on_an_edge_counts_in_that_bucket():
    """Prometheus buckets are "less than or equal": 0.1s belongs in le="0.1"."""
    metrics.observe("e_seconds", 0.1, "help")
    metrics.observe("e_seconds", 0.1000001, "help")
    lines = metrics.render([]).splitlines()
    assert 'e_seconds_bucket{le="0.1"} 1' in lines
    assert 'e_seconds_bucket{le="0.25"} 2' in lines


def test_a_histogram_does_not_grow_with_traffic():
    """Every observation used to be kept for the life of the process, on every HTTP request, and a
    scrape copied and sorted all of them under the lock."""
    for i in range(20_000):
        metrics.observe("g_seconds", (i % 100) / 10, "help", route="/x")
    (h,) = metrics._histograms["g_seconds"].values()
    assert h.count == 20_000
    assert len(h.buckets) == len(metrics.BUCKETS) + 1  # fixed, however much traffic
    assert 'g_seconds_count{route="/x"} 20000' in metrics.render([]).splitlines()


def test_ingesting_a_report_is_counted_and_timed(client, on, db):
    asset = Asset(name="svc", tags=[])
    db.add(asset)
    db.commit()
    ingest_report(db, sample("osv.json"), asset, None, IngestOptions())

    m = parse(metrics.render([]))
    assert m['guardiano_ingests_total{format="osv",preview="false",type="sca"}'] == 1
    assert m['guardiano_ingest_duration_seconds_count{format="osv",preview="false",type="sca"}'] == 1


def test_nothing_is_recorded_while_the_endpoint_is_off(client, db, auth):
    """The cost of metrics is only paid by installations that asked for them."""
    client.get("/api/v1/findings", headers=auth["viewer"])
    assert metrics.render([]) == "\n"


def test_label_values_are_escaped():
    metrics.counter("weird_total", "help", label='a"b\\c')
    assert 'weird_total{label="a\\"b\\\\c"} 1' in metrics.render([])
