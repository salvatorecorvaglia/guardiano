"""Capture real analytics SQL and EXPLAIN ANALYZE plans on a disposable local database.

BENCHMARK_APP_ROOT may select a saved backend tree for before/after comparisons.
"""

import argparse
import copy
import hashlib
import json
import os
import sys
import time
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, os.environ.get("BENCHMARK_APP_ROOT", str(Path(__file__).resolve().parents[1])))
os.environ["ENV"] = "test"
os.environ.setdefault("LOG_LEVEL", "WARNING")

from sqlalchemy import event, select  # noqa: E402

from app.core.db import SessionLocal, engine  # noqa: E402
from app.core.testdb import validate_test_database  # noqa: E402
from app.models import Asset  # noqa: E402
from app.models.base import utcnow  # noqa: E402
from app.services import analytics  # noqa: E402
from app.services.scope import Scope  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    validate_test_database(str(engine.url))
    if engine.url.host not in {"localhost", "127.0.0.1", "::1"}:
        raise SystemExit("SQL profiling is restricted to a local disposable database")
    with SessionLocal() as db:
        asset_id = db.scalar(select(Asset.id).order_by(Asset.id).limit(1))
    if asset_id is None:
        raise SystemExit("Seed this database with benchmarks/readiness.py first")
    end = utcnow().date()
    calls = {
        "trends": lambda db: analytics.trends(db, 30, asset_id, scope=Scope()),
        "open_series": lambda db: analytics.open_series(
            db, end - timedelta(days=29), end, asset_id, scope=Scope()
        ),
        "summary": lambda db: analytics.summary(db, asset_id, scope=Scope()),
        "breakdown": lambda db: analytics.breakdown(db, "tool", 30, scope=Scope()),
    }
    results = {}
    for name, call in calls.items():
        captured = []

        def capture(connection, cursor, statement, parameters, context, executemany, captured=captured):
            if statement.lstrip().upper().startswith(("SELECT", "WITH")):
                captured.append((statement, copy.deepcopy(parameters)))

        with SessionLocal() as db:
            event.listen(engine, "before_cursor_execute", capture)
            try:
                started = time.perf_counter()
                response = call(db)
                seconds = time.perf_counter() - started
            finally:
                event.remove(engine, "before_cursor_execute", capture)
            plans = []
            for statement, parameters in captured:
                plan = (
                    db.connection()
                    .exec_driver_sql("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) " + statement, parameters)
                    .scalar_one()[0]
                )
                plans.append({"sql": statement, "parameters": parameters, "explain": plan})
        results[name] = {
            "seconds": seconds,
            "result_sha256": hashlib.sha256(json.dumps(response, sort_keys=True).encode()).hexdigest(),
            "queries": plans,
        }
    args.output.write_text(json.dumps(results, indent=2, default=str) + "\n")
    print(
        json.dumps(
            {
                name: {
                    "seconds": r["seconds"],
                    "sql_ms": sum(q["explain"]["Execution Time"] for q in r["queries"]),
                }
                for name, r in results.items()
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
