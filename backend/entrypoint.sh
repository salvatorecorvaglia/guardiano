#!/bin/sh
set -e

wait_for_db() {
  python - <<'PY'
import sys, time
from sqlalchemy import create_engine, text
from app.core.config import settings
engine = create_engine(settings.database_url, pool_pre_ping=True)
for attempt in range(60):
    try:
        with engine.connect() as c:
            c.execute(text("SELECT 1"))
        sys.exit(0)
    except Exception as exc:
        print(f"waiting for database ({attempt + 1}/60): {exc.__class__.__name__}", flush=True)
        time.sleep(2)
sys.exit("database not reachable")
PY
}

case "$1" in
  serve)
    wait_for_db
    python -m app.cli init-db
    python -m app.cli bootstrap
    exec gunicorn app.main:app \
      --worker-class uvicorn.workers.UvicornWorker \
      --workers "${WEB_CONCURRENCY}" \
      --bind "0.0.0.0:${PORT}" \
      --forwarded-allow-ips "${FORWARDED_ALLOW_IPS}" \
      --timeout "${GUNICORN_TIMEOUT:-120}" \
      --graceful-timeout 30 \
      --error-logfile -
    ;;
  dev)
    wait_for_db
    python -m app.cli init-db
    python -m app.cli bootstrap
    exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT}" --reload --proxy-headers \
      --forwarded-allow-ips "${FORWARDED_ALLOW_IPS}"
    ;;
  worker)
    # The web container initializes the schema before becoming healthy.
    wait_for_db
    exec python -m app.cli worker --heartbeat /tmp/guardiano-worker.heartbeat
    ;;
  init-db)
    wait_for_db
    exec python -m app.cli init-db
    ;;
  test)
    shift
    wait_for_db
    exec pytest "$@"
    ;;
  *)
    exec "$@"
    ;;
esac
