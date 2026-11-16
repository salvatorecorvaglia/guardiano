"""Compare bounded coverage with a saved pre-change analytics module on a fresh test database."""

import argparse
import hashlib
import importlib.util
import json
import platform
import statistics
import time
import tracemalloc
from datetime import timedelta
from importlib.metadata import version
from pathlib import Path

from sqlalchemy import func, insert, select

from app.core.config import settings
from app.core.db import SessionLocal
from app.core.schema import initialize_schema
from app.core.testdb import validate_test_database
from app.models import Asset, Component, Scan
from app.models.base import utcnow
from app.services import analytics
from app.services.scope import GLOBAL


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline-module", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    validate_test_database(settings.database_url)
    initialize_schema()
    spec = importlib.util.spec_from_file_location("coverage_reference", args.baseline_module)
    reference = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reference)
    now = utcnow()
    analytics.utcnow = reference.utcnow = lambda: now
    with SessionLocal() as db:
        if db.scalar(select(func.count()).select_from(Asset)):
            raise SystemExit("Use a fresh disposable database; existing data was left intact")
        ids = list(
            db.scalars(
                insert(Asset).returning(Asset.id),
                [
                    {"name": f"coverage-{i:05}", "criticality": ("critical", "high", "medium", "low")[i % 4]}
                    for i in range(10_000)
                ],
            )
        )
        db.execute(
            insert(Scan),
            [
                {
                    "asset_id": ident,
                    "scan_type": "sast",
                    "tool_name": "coverage",
                    "format": "guardiano",
                    "created_at": now - timedelta(days=60 if index < 7000 else 1, seconds=index),
                }
                for index, ident in enumerate(ids)
                if index >= 4000
            ],
        )
        db.execute(
            insert(Component),
            [
                {
                    "asset_id": ident,
                    "key": f"component-{index}",
                    "name": "library",
                    "first_seen_at": now,
                    "last_seen_at": now,
                }
                for index, ident in enumerate(ids)
                if index % 10 == 0
            ],
        )
        db.commit()

    def call(function):
        with SessionLocal() as db:
            return function(db, 30, scope=GLOBAL)

    expected = call(reference.coverage)
    assert call(analytics.coverage) == expected, "Coverage output changed"
    result = {
        "baseline_sha256": hashlib.sha256(Path(args.baseline_module).read_bytes()).hexdigest(),
        "python": platform.python_version(), "sqlalchemy": version("sqlalchemy"),
        "assets": 10_000,
        "scans": 6000,
        "components": 1000,
        "returned_limit": 200,
        "payload_parity": True,
        "iterations": 20,
        "scope": "global",
    }
    for label, function in [("before", reference.coverage), ("after", analytics.coverage)]:
        for _ in range(3):
            call(function)
        timings = []
        for _ in range(20):
            start = time.perf_counter()
            assert call(function) == expected
            timings.append(time.perf_counter() - start)
        tracemalloc.start()
        call(function)
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        result[label] = {
            "median_seconds": statistics.median(timings),
            "p95_seconds": statistics.quantiles(timings, n=100)[94],
            "python_peak_bytes": peak,
        }
    result["p95_ratio"] = result["after"]["p95_seconds"] / result["before"]["p95_seconds"]
    Path(args.output).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    if result["p95_ratio"] > 1.10:
        raise SystemExit("Coverage p95 regressed more than 10%")


if __name__ == "__main__":
    main()
