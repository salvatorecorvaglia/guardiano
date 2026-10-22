"""Prometheus metrics, in the exposition format, without a client library.

Two kinds of number live here and they behave differently, which the HELP text on each one says out loud:

- **Counters and histograms** are recorded in this process as requests and ingests happen. Behind gunicorn
  each worker keeps its own, and a scrape reaches one worker at random, so they are a sample of the
  traffic rather than a total. That is the usual bargain for in-process metrics; ``WEB_CONCURRENCY=1``
  makes them exact.
- **Gauges** are read from the database at scrape time, so they are the same whichever replica answers and
  survive a restart. Anything an alert should fire on — queue depth, dead jobs, overdue findings — is one
  of these.

The endpoint is off unless ``METRICS_ENABLED=true``, is not proxied by the bundled nginx (it lives outside
``/api``), and can require a bearer token of its own.
"""

import threading
import time
from bisect import bisect_left
from collections import defaultdict
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import Asset, Component, Finding, Job, Scan, User
from app.models.enums import Status
from app.services.jobs import DEAD, DONE, QUEUED, RUNNING
from app.services.queries import ACTIVE, overdue_expr

# Seconds. Web requests, so the interesting range is milliseconds to a few seconds.
BUCKETS = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)

_lock = threading.Lock()
_counters: dict[str, dict[tuple[tuple[str, str], ...], float]] = defaultdict(dict)
# Per label set: [count in each bucket (not cumulative), then +Inf], sum, count. Fixed size whatever the
# traffic -- keeping every observation, as this once did, grew for the life of the process.
_histograms: dict[str, dict[tuple[tuple[str, str], ...], "_Histogram"]] = defaultdict(dict)
_help: dict[str, tuple[str, str]] = {}


def _key(labels: dict[str, str]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((k, str(v)) for k, v in labels.items()))


def counter(name: str, help_text: str, **labels: str) -> None:
    """Add one to a counter, creating it on first use."""
    with _lock:
        _help[name] = (help_text, "counter")
        bucket = _counters[name]
        key = _key(labels)
        bucket[key] = bucket.get(key, 0.0) + 1.0


class _Histogram:
    __slots__ = ("buckets", "total", "count")

    def __init__(self) -> None:
        self.buckets = [0] * (len(BUCKETS) + 1)  # the last slot is everything above the top edge
        self.total = 0.0
        self.count = 0

    def add(self, seconds: float) -> None:
        self.buckets[bisect_left(BUCKETS, seconds)] += 1
        self.total += seconds
        self.count += 1

    def copy(self) -> "_Histogram":
        other = _Histogram()
        other.buckets, other.total, other.count = list(self.buckets), self.total, self.count
        return other


def observe(name: str, seconds: float, help_text: str, **labels: str) -> None:
    with _lock:
        _help[name] = (help_text, "histogram")
        _histograms[name].setdefault(_key(labels), _Histogram()).add(seconds)


@contextmanager
def timed(name: str, help_text: str, **labels: str) -> Iterator[None]:
    start = time.perf_counter()
    try:
        yield
    finally:
        observe(name, time.perf_counter() - start, help_text, **labels)


def reset() -> None:
    """Only for tests: start from a clean slate."""
    with _lock:
        _counters.clear()
        _histograms.clear()
        _help.clear()


# ---- recording ------------------------------------------------------------------------------------

REQUESTS = "guardiano_http_requests_total"
LATENCY = "guardiano_http_request_duration_seconds"
INGESTS = "guardiano_ingests_total"
INGEST_TIME = "guardiano_ingest_duration_seconds"

_SAMPLED = " Recorded in the serving process, so behind several gunicorn workers this samples the traffic."


def record_request(method: str, route: str, status: int, seconds: float) -> None:
    if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"}:
        method = "OTHER"
    labels = {"method": method, "route": route, "status": str(status)}
    counter(REQUESTS, "HTTP requests served." + _SAMPLED, **labels)
    observe(LATENCY, seconds, "HTTP request duration in seconds." + _SAMPLED, **{**labels, "status": ""})


def record_ingest(fmt: str, scan_type: str, seconds: float, *, preview: bool) -> None:
    labels = {"format": fmt, "type": scan_type, "preview": str(preview).lower()}
    counter(INGESTS, "Scan reports ingested." + _SAMPLED, **labels)
    observe(INGEST_TIME, seconds, "Time to parse and store one report, in seconds." + _SAMPLED, **labels)


# ---- rendering ------------------------------------------------------------------------------------


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _labels(key: tuple[tuple[str, str], ...], extra: tuple[str, str] | None = None) -> str:
    pairs = [(k, v) for k, v in key if v != ""]
    if extra:
        pairs.append(extra)
    if not pairs:
        return ""
    return "{" + ",".join(f'{k}="{_escape(v)}"' for k, v in pairs) + "}"


def _number(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else repr(value)


def render(gauges: list[tuple[str, str, dict[str, str], float]]) -> str:
    """The whole exposition document: gauges passed in, counters and histograms from this process."""
    lines: list[str] = []
    seen: set[str] = set()

    for name, help_text, labels, value in gauges:
        if name not in seen:
            lines += [f"# HELP {name} {help_text}", f"# TYPE {name} gauge"]
            seen.add(name)
        lines.append(f"{name}{_labels(_key(labels))} {_number(value)}")

    with _lock:
        counters = {name: dict(rows) for name, rows in _counters.items()}
        histograms = {name: {k: h.copy() for k, h in rows.items()} for name, rows in _histograms.items()}
        helps = dict(_help)

    for name, rows in sorted(counters.items()):
        help_text, _ = helps[name]
        lines += [f"# HELP {name} {help_text}", f"# TYPE {name} counter"]
        for key, value in sorted(rows.items()):
            lines.append(f"{name}{_labels(key)} {_number(value)}")

    for name, rows in sorted(histograms.items()):
        help_text, _ = helps[name]
        lines += [f"# HELP {name} {help_text}", f"# TYPE {name} histogram"]
        for key, h in sorted(rows.items()):
            # Exposition buckets are cumulative: each counts every observation at or below its edge.
            below = 0
            for edge, n in zip(BUCKETS, h.buckets, strict=False):
                below += n
                lines.append(f"{name}_bucket{_labels(key, ('le', str(edge)))} {below}")
            lines.append(f"{name}_bucket{_labels(key, ('le', '+Inf'))} {h.count}")
            lines.append(f"{name}_sum{_labels(key)} {round(h.total, 6)}")
            lines.append(f"{name}_count{_labels(key)} {h.count}")

    return "\n".join(lines) + "\n"


# ---- gauges, read from the database -----------------------------------------------------------------


def collect(db: Session) -> list[tuple[str, str, dict[str, str], float]]:
    """Everything an alert should fire on, counted in the database so every replica agrees."""
    out: list[tuple[str, str, dict[str, str], float]] = []

    def add(name: str, help_text: str, value: float | None, **labels: str) -> None:
        out.append((name, help_text, labels, float(value or 0)))

    severity_rows = db.execute(
        select(Finding.severity, func.count()).where(Finding.status.in_(ACTIVE)).group_by(Finding.severity)
    ).all()
    counts = dict(severity_rows)
    for severity in ("critical", "high", "medium", "low", "info"):
        add(
            "guardiano_findings_open",
            "Open and in-progress findings, by severity.",
            counts.get(severity, 0),
            severity=severity,
        )
    add(
        "guardiano_findings_overdue",
        "Open findings past their remediation SLA.",
        db.scalar(select(func.count()).select_from(Finding).where(overdue_expr())),
    )
    for status in Status:
        add(
            "guardiano_findings_total",
            "Findings by status, including closed ones.",
            db.scalar(select(func.count()).select_from(Finding).where(Finding.status == status.value)),
            status=status.value,
        )

    job_rows = dict(db.execute(select(Job.status, func.count()).group_by(Job.status)).all())
    for status in (QUEUED, RUNNING, DONE, DEAD):
        add(
            "guardiano_jobs",
            "Background jobs by status. A rising 'dead' count means work is being dropped.",
            job_rows.get(status, 0),
            status=status,
        )
    add(
        "guardiano_job_oldest_queued_seconds",
        "Age of the oldest job still waiting to run; the honest measure of queue lag.",
        db.scalar(
            select(func.extract("epoch", func.now() - func.min(Job.created_at))).where(Job.status == QUEUED)
        ),
    )

    add("guardiano_assets", "Assets under management.", db.scalar(select(func.count()).select_from(Asset)))
    add("guardiano_scans_total", "Scans ingested.", db.scalar(select(func.count()).select_from(Scan)))
    add(
        "guardiano_components",
        "Component rows in the inventory.",
        db.scalar(select(func.count()).select_from(Component)),
    )
    add(
        "guardiano_users_active",
        "Accounts that can sign in.",
        db.scalar(select(func.count()).select_from(User).where(User.is_active.is_(True))),
    )
    return out
