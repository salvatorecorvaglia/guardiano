"""Benchmark-only queue-wait instrumentation for the pinned SQLAlchemy QueuePool.

Timing queue.get(block=True) separates actual pool waiting from connection creation,
pre-ping, SQL execution and HTTP latency. No application pool behavior is changed.
"""

import threading
import time
from collections import defaultdict
from statistics import quantiles
from unittest.mock import patch

from sqlalchemy import event
from sqlalchemy.pool import QueuePool
from sqlalchemy.util.queue import Empty


class PoolProbe:
    def __init__(self, pool: QueuePool):
        if not isinstance(pool, QueuePool):
            raise TypeError("The pool probe requires SQLAlchemy QueuePool")
        self.pool = pool
        self.phase = "warmup"
        self._lock = threading.Lock()
        self.waiting = 0
        self._samples = defaultdict(list)
        self._peaks = defaultdict(int)

    def __enter__(self):
        # This protected queue is intentionally used only by benchmarks. The real
        # contention/timeout tests pin its contract when SQLAlchemy is upgraded.
        queue = self.pool._pool
        original = queue.get

        def get(block=True, timeout=None):
            if not block:
                return original(block, timeout)
            phase = self.phase
            started = time.perf_counter()
            timed_out = False
            with self._lock:
                self.waiting += 1
            try:
                return original(block, timeout)
            except Empty:
                timed_out = True
                raise
            finally:
                seconds = time.perf_counter() - started
                with self._lock:
                    self.waiting -= 1
                    self._samples[phase].append((seconds, timed_out))

        self._patch = patch.object(queue, "get", get)
        self._patch.start()

        def checkout(connection, record, proxy):
            with self._lock:
                self._peaks[self.phase] = max(self._peaks[self.phase], self.pool.checkedout())

        self._checkout = checkout
        event.listen(self.pool, "checkout", checkout)
        return self

    def __exit__(self, *exc):
        self._patch.stop()
        event.remove(self.pool, "checkout", self._checkout)

    def summary(self):
        with self._lock:
            samples = {phase: list(rows) for phase, rows in self._samples.items()}
            peaks = dict(self._peaks)
        for phase in ("warmup", "baseline", "concurrent"):
            samples.setdefault(phase, [])
        return {
            phase: {
                "blocking_checkouts": len(rows),
                "timeouts": sum(timed_out for _, timed_out in rows),
                "wait_p95_seconds": quantiles([s for s, _ in rows], n=100, method="inclusive")[94]
                if len(rows) > 1
                else rows[0][0]
                if rows
                else 0,
                "wait_max_seconds": max((s for s, _ in rows), default=0),
                "peak_checked_out": peaks.get(phase, 0),
            }
            for phase, rows in samples.items()
        }
