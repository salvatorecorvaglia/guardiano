"""Upload an exact-limit report over HTTP to a separate API process and measure its peak RSS.

Requires a local disposable *_test database. The client and report construction run
outside the measured server process. Two full uploads verify creation and reingestion.
"""

import argparse
import json
import os
import resource
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ["ENV"] = "test"
os.environ.setdefault("LOG_LEVEL", "WARNING")


def serve(port, memory):
    from contextlib import asynccontextmanager

    import uvicorn

    from app.main import create_app

    app = create_app()
    original = app.router.lifespan_context

    @asynccontextmanager
    async def measured_lifespan(app):
        async with original(app):
            try:
                yield
            finally:
                peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                memory.write_text(
                    json.dumps(
                        {
                            "peak_rss_bytes": peak if sys.platform == "darwin" else peak * 1024,
                        }
                    )
                )

    app.router.lifespan_context = measured_lifespan
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--port", type=int)
    parser.add_argument("--memory", type=Path)
    args = parser.parse_args()
    if args.serve:
        serve(args.port, args.memory)
        return
    if args.output is None:
        parser.error("--output is required")

    import httpx
    from sqlalchemy import create_engine, func, select, text
    from sqlalchemy.engine import make_url

    from app.core.config import settings
    from app.core.db import SessionLocal
    from app.core.schema import initialize_schema
    from app.core.security import create_access_token, hash_password
    from app.core.testdb import validate_test_database
    from app.models import Asset, Finding, User

    validate_test_database(settings.database_url)
    url = make_url(settings.database_url)
    if url.host not in {"127.0.0.1", "localhost", "::1"}:
        raise SystemExit("Maximum-upload checks require a local disposable database")
    admin = create_engine(url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        if not connection.scalar(text("SELECT 1 FROM pg_database WHERE datname=:n"), {"n": url.database}):
            connection.execute(text(f'CREATE DATABASE "{url.database}"'))
    admin.dispose()
    initialize_schema()
    with SessionLocal() as db:
        user = User(
            email=f"limits-{uuid.uuid4().hex}@example.test",
            role="admin",
            password_hash=hash_password(secrets.token_urlsafe(24)),
            token_version=0,
        )
        asset = Asset(name=f"limits-{uuid.uuid4().hex}")
        db.add_all([user, asset])
        db.commit()
        asset_id = asset.id
        token = create_access_token(user.id, user.role, user.token_version)

    with tempfile.TemporaryDirectory(prefix="guardiano-upload-limits-") as directory:
        directory = Path(directory)
        report, memory = directory / "report.json", directory / "memory.json"
        with report.open("wb") as target:
            target.write(b'{"schema":"guardiano/v1","tool":"limits","findings":[')
            for index in range(settings.max_report_findings):
                if index:
                    target.write(b",")
                target.write(
                    json.dumps(
                        {
                            "title": f"Finding {index}",
                            "severity": "high",
                            "file_path": f"src/{index}.py",
                            "line_start": 1,
                            "rule_id": "limits",
                            "description": "x" * 256,
                        },
                        separators=(",", ":"),
                    ).encode()
                )
            target.write(b"]")
            padding = settings.max_upload_bytes - target.tell() - 1
            if padding < 0:
                raise SystemExit("Configured byte limit cannot fit this finding-count fixture")
            target.write(b" " * padding + b"}")
        assert report.stat().st_size == settings.max_upload_bytes
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        timings = []
        with (directory / "server.log").open("wb") as log:
            process = subprocess.Popen(  # noqa: S603 -- this script and the active Python interpreter only
                [sys.executable, __file__, "--serve", "--port", str(port), "--memory", str(memory)],
                stdout=log,
                stderr=log,
            )
            try:
                with httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=600) as client:
                    for _ in range(100):
                        try:
                            if client.get("/healthz").is_success:
                                break
                        except httpx.TransportError:
                            pass
                        if process.poll() is not None:
                            raise RuntimeError(
                                "API process exited: " + (directory / "server.log").read_text()
                            )
                        time.sleep(0.1)
                    else:
                        raise RuntimeError("API startup timed out")
                    for run in range(2):
                        started = time.perf_counter()
                        with report.open("rb") as source:
                            response = client.post(
                                "/api/v1/scans",
                                headers={"Authorization": f"Bearer {token}"},
                                data={"asset_id": asset_id},
                                files={"file": ("limit.json", source, "application/json")},
                            )
                        response.raise_for_status()
                        counts = response.json()
                        expected = "new_count" if run == 0 else "duplicate_count"
                        assert counts[expected] == settings.max_report_findings, counts
                        timings.append(time.perf_counter() - started)
            finally:
                process.terminate()
                process.wait(timeout=30)
        with SessionLocal() as db:
            count = db.scalar(select(func.count()).select_from(Finding).where(Finding.asset_id == asset_id))
        assert count == settings.max_report_findings
        result = {
            "transport": "HTTP multipart to separate uvicorn process",
            "worker_processes": 1,
            "report_bytes": report.stat().st_size,
            "findings": count,
            "uploads": len(timings),
            "upload_seconds": timings,
            **json.loads(memory.read_text()),
            "client_memory_excluded": True,
        }
        args.output.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
