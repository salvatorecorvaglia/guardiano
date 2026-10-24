"""Reproducible load probe; requires an explicitly named disposable *_test database.

Run from backend: DATABASE_URL=.../guardiano_perf_test .venv/bin/python benchmarks/readiness.py
Only benchmark-owned assets are seeded; no schema or existing rows are dropped.
"""

import json
import os
import resource
import ssl
import statistics
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from importlib.metadata import version
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ["ENV"] = "test"
os.environ["LOGIN_RATE_LIMIT"] = "1000/minute"
os.environ.setdefault("LOG_LEVEL", "WARNING")

import httpx  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from pool_probe import PoolProbe  # noqa: E402
from sqlalchemy import create_engine, insert, text  # noqa: E402
from sqlalchemy.engine import make_url  # noqa: E402

from app.core.db import SessionLocal  # noqa: E402
from app.core.schema import initialize_schema  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.core.testdb import validate_test_database  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Asset, Finding, FindingEvent, User  # noqa: E402
from app.models.base import utcnow  # noqa: E402


def main() -> None:
    url = os.environ["DATABASE_URL"]
    validate_test_database(url)
    parsed = make_url(url)
    admin = create_engine(parsed.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        if not connection.scalar(
            text("SELECT 1 FROM pg_database WHERE datname=:name"), {"name": parsed.database}
        ):
            connection.execute(text(f'CREATE DATABASE "{parsed.database}"'))
    admin.dispose()
    initialize_schema()
    tag = uuid.uuid4().hex[:12]
    size = int(os.environ.get("BENCHMARK_FINDINGS", "100000"))
    with SessionLocal() as db:
        user = User(
            email=f"benchmark-{tag}@example.test",
            password_hash=hash_password("Benchmark-Password-2026!"),
            role="admin",
            full_name="Benchmark",
        )
        asset = Asset(name=f"benchmark-{tag}")
        db.add_all([user, asset])
        db.commit()
        asset_id = asset.id
        now = utcnow()
        history_rows = 0
        for offset in range(0, size, 1000):
            inserted = db.execute(
                insert(Finding).returning(Finding.id, Finding.status),
                [
                    {
                        "asset_id": asset_id,
                        "type": "sast",
                        "dedup_key": f"{tag}-{n}",
                        "title": f"Benchmark vulnerability {n}",
                        "severity": "high",
                        "status": ["open", "in_progress", "resolved", "false_positive"][n % 4],
                        "first_seen_at": now - timedelta(days=30),
                        "last_seen_at": now,
                        "tools": ["benchmark"],
                        "file_path": f"src/file-{n}.py",
                    }
                    for n in range(offset, min(offset + 1000, size))
                ],
            ).all()
            history = []
            for finding_id, status in inserted:
                history.extend(
                    [
                        {
                            "finding_id": finding_id,
                            "event": "created",
                            "to_status": "open",
                            "to_severity": "medium",
                            "created_at": now - timedelta(days=30),
                        },
                        {
                            "finding_id": finding_id,
                            "event": "severity_changed",
                            "from_severity": "medium",
                            "to_severity": "high",
                            "created_at": now - timedelta(days=20),
                        },
                    ]
                )
                if status != "open":
                    history.append(
                        {
                            "finding_id": finding_id,
                            "event": "status_changed",
                            "from_status": "open",
                            "to_status": status,
                            "created_at": now - timedelta(days=10),
                        }
                    )
            # Group heterogeneous event shapes so SQLAlchemy batches inserts rather
            # than issuing one statement for each alternating event kind.
            history.sort(key=lambda row: tuple(sorted(row)))
            db.execute(insert(FindingEvent), history)
            history_rows += len(history)
        db.commit()
    # A fresh bulk load needs deterministic planner statistics; relying on the
    # autovacuum timer made identical workloads choose different history plans.
    with SessionLocal() as db:
        for relation in ("findings", "finding_events", "assets"):
            db.execute(text(f"ANALYZE {relation}"))  # noqa: S608 -- fixed relation names above
        db.commit()
    base_url = os.environ.get("BENCHMARK_BASE_URL")
    if base_url and urlsplit(base_url).hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise SystemExit("External load probes are restricted to a local staging proxy")
    transport = "https-reverse-proxy" if base_url else "in-process"
    verify = ssl.create_default_context(cafile=os.environ.get("BENCHMARK_CA_FILE"))
    http = httpx.Client(base_url=base_url, verify=verify, timeout=120) if base_url else TestClient(app)
    from app.core.db import engine

    with PoolProbe(engine.pool) as pool_probe, http as client:
        login = client.post(
            "/api/v1/auth/login", json={"email": user.email, "password": "Benchmark-Password-2026!"}
        )
        login.raise_for_status()
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}

        workload = os.environ.get("BENCHMARK_READ_WORKLOAD", "findings")
        routes = ["/api/v1/findings"]
        if workload == "mixed":
            routes += ["/api/v1/analytics/summary", "/api/v1/analytics/trends", "/api/v1/search"]

        phase = "warmup"
        samples: list[tuple[str, str, float]] = []

        def read(index: int) -> float:
            started = time.perf_counter()
            response = client.get(
                routes[index % len(routes)],
                params={"asset_id": asset_id, "page_size": 50, "days": 30, "q": "Benchmark"},
                headers=headers,
            )
            response.raise_for_status()
            elapsed = time.perf_counter() - started
            samples.append((phase, routes[index % len(routes)], elapsed))
            return elapsed

        def upload(index: int) -> float:
            report = {
                "schema": "guardiano/v1",
                "tool": {"name": "benchmark"},
                "scan_type": "sast",
                "findings": [
                    {
                        "title": f"Upload {n}",
                        "severity": "high",
                        "type": "sast",
                        "rule_id": f"r-{n}",
                        "file_path": f"file-{n}.py",
                        "line_start": 1,
                    }
                    for n in range(1000)
                ],
            }
            started = time.perf_counter()
            response = client.post(
                "/api/v1/scans",
                headers=headers,
                data={"asset_id": asset_id},
                files={"file": ("report.json", json.dumps(report).encode(), "application/json")},
            )
            response.raise_for_status()
            return time.perf_counter() - started

        with ThreadPoolExecutor(max_workers=6) as pool:
            list(pool.map(read, range(12)))  # warm caches before measuring
            phase = "baseline"
            pool_probe.phase = phase
            baseline = list(pool.map(read, range(40)))
            phase = "concurrent"
            pool_probe.phase = phase
            uploads = [pool.submit(upload, i) for i in range(2)]
            concurrent = list(pool.map(read, range(40)))
            upload_seconds = [future.result() for future in uploads]

    def p95(values):
        return statistics.quantiles(values, n=100)[94]

    result = {
        "seeded_findings": size,
        "read_workload": workload,
        "transport": transport,
        "benchmark_runtime_versions": {
            "python": sys.version.split()[0],
            "fastapi": version("fastapi"),
            "sqlalchemy": version("sqlalchemy"),
        },
        "history_rows": history_rows,
        "upload_target": "same-populated-asset",
        "read_routes": routes,
        "upload_findings_each": 1000,
        "concurrent_uploads": 2,
        "pool_queue_wait": pool_probe.summary(),
        "read_p95_seconds": p95(baseline),
        "concurrent_read_p95_seconds": p95(concurrent),
        "upload_seconds": upload_seconds,
        "route_p95_seconds": {
            phase: {
                route: p95([elapsed for stage, path, elapsed in samples if stage == phase and path == route])
                for route in routes
            }
            for phase in ("baseline", "concurrent")
        },
        "process_max_rss": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "rss_unit": "bytes" if sys.platform == "darwin" else "KiB",
    }
    print(json.dumps(result, indent=2))
    if reference_path := os.environ.get("BENCHMARK_BASELINE"):
        reference = json.loads(Path(reference_path).read_text())
        for key in (
            "seeded_findings",
            "transport",
            "history_rows",
            "upload_target",
            "read_workload",
            "read_routes",
            "concurrent_uploads",
            "upload_findings_each",
        ):
            expected = reference.get(key, "in-process" if key == "transport" else None)
            if result[key] != expected:
                raise SystemExit(f"Baseline workload differs: {key}")
        for metric in ("read_p95_seconds", "concurrent_read_p95_seconds"):
            if result[metric] > reference[metric] * 1.10:
                raise SystemExit(f"{metric} regressed more than 10% against the supplied baseline")


if __name__ == "__main__":
    main()
