# Performance validation

Run these probes from `backend` using the project's virtual environment. Use a
fresh local PostgreSQL database whose name ends in `_test` for each readiness or
upload run. The probes create benchmark users, assets and findings; they do not
clean them up. Never point them at application data.

```sh
export DATABASE_URL=postgresql+psycopg://guardiano:guardiano@localhost:5432/guardiano_perf_test
BENCHMARK_READ_WORKLOAD=mixed .venv/bin/python benchmarks/readiness.py > /tmp/readiness.json
.venv/bin/python benchmarks/profile_analytics.py --output /tmp/analytics-plans.json
```

Readiness seeds 100,000 findings and 275,000 history rows, warms caches, then runs
six readers and two uploads against the same populated asset. `BENCHMARK_BASELINE`
can reference an earlier JSON result to enforce a 10% p95 latency regression gate
on an identical workload. Run comparisons sequentially without other builds,
scans or load tests. `BENCHMARK_APP_ROOT` selects a saved backend implementation
for SQL profiling. Profiles include bound SQL, full `EXPLAIN (ANALYZE, BUFFERS)`
plans and response hashes for parity checks.

Queue waits are measured at SQLAlchemy's blocking pool queue, separately from
connection creation, pre-ping and query execution. To exercise contention, use a
fresh test database and `DB_POOL_SIZE=2 DB_MAX_OVERFLOW=0` with readiness. Its
per-phase output records blocking checkouts, p95/maximum waits, timeouts and peak
checked-out connections. This probe uses a protected SQLAlchemy queue API only
inside the benchmark; regression tests cover real contention and timeout behavior.

```sh
export DATABASE_URL=postgresql+psycopg://guardiano:guardiano@localhost:5432/guardiano_upload_test
.venv/bin/python benchmarks/upload_limits.py --output /tmp/upload-memory.json
```

The upload probe sends two exact-limit multipart reports to a separate Uvicorn
process, checks new and duplicate counts and persisted rows, and records that
server process's peak RSS. Client-side report construction is excluded. Results
are workload-specific, not memory ceilings or production sizing guarantees.

See `remediation-validation.json` for the earlier audit validation and
`performance-completion.json` for the remaining-work completion evidence.
