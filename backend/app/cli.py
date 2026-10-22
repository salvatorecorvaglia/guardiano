"""Guardiano management commands.

python -m app.cli bootstrap                 # first admin from env; encrypt legacy secrets (idempotent)
python -m app.cli init-db                   # apply versioned database upgrades
python -m app.cli create-admin EMAIL        # prompts for a password
python -m app.cli expire-risk-acceptances   # reopen findings whose risk acceptance expired (cron)
python -m app.cli sync-intel                # refresh the CISA KEV and EPSS feeds now
python -m app.cli import-intel --kev F --epss F  # load feeds downloaded elsewhere (air-gapped)
python -m app.cli prune [--dry-run]         # apply the configured retention rules now
python -m app.cli reset-mfa EMAIL           # clear a second factor for somebody who lost their phone
python -m app.cli worker [--burst]          # run background jobs and periodic tasks
python -m app.cli seed-demo                 # load demo users, assets and scans (development only)
python -m app.cli openapi [PATH]            # write the OpenAPI schema (frontend types are generated from it)
"""

import argparse
import getpass
import signal
import sys
from pathlib import Path

from sqlalchemy import select

from app.core.config import settings
from app.core.db import SessionLocal
from app.core.security import hash_password
from app.models import User
from app.models.enums import Role
from app.services import lifecycle, lockout
from app.services.bootstrap import ensure_admin
from app.services.webhooks import encrypt_legacy_secrets


def cmd_init_db(_: argparse.Namespace) -> None:
    from app.core.schema import initialize_schema

    initialize_schema()


def cmd_check_db(_: argparse.Namespace) -> None:
    from app.core.schema import check_schema

    check_schema()


def cmd_bootstrap(_: argparse.Namespace) -> None:
    with SessionLocal() as db:
        ensure_admin(db)
        encrypt_legacy_secrets(db)


def cmd_create_admin(args: argparse.Namespace) -> None:
    password = args.password or getpass.getpass("Password (min 12 chars): ")
    if len(password) < 12:
        sys.exit("Password must be at least 12 characters")
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == args.email.lower()))
        if user:
            user.role, user.is_active = Role.admin.value, True
            user.password_hash = hash_password(password)
            user.token_version += 1
            # This is the way back in for a locked-out administrator, so it clears the lockout too.
            lockout.record_success(user)
        else:
            db.add(
                User(
                    email=args.email.lower(),
                    full_name=args.name or "Administrator",
                    password_hash=hash_password(password),
                    role=Role.admin.value,
                )
            )
        db.commit()
    print(f"Administrator {args.email} ready.")


def cmd_expire(_: argparse.Namespace) -> None:
    with SessionLocal() as db:
        n = lifecycle.expire_risk_acceptances(db)
        db.commit()
    print(f"Reopened {n} finding(s) with expired risk acceptance.")


def cmd_prune(args: argparse.Namespace) -> None:
    """Retention, on demand. The same rules the daily task applies."""
    from app.core.config import settings
    from app.services import retention

    configured = {
        "scans": settings.retention_scan_days,
        "webhook deliveries": settings.retention_delivery_days,
        "audit log": settings.retention_audit_days,
    }
    if not any(configured.values()):
        print("No retention rule is configured; nothing to do.")
        return
    print("Keeping: " + ", ".join(f"{k} {v} days" if v else f"{k} forever" for k, v in configured.items()))
    with SessionLocal() as db:
        removed = retention.run(db)
        if args.dry_run:
            db.rollback()
        else:
            db.commit()
    done = "would remove" if args.dry_run else "removed"
    print(f"{done}: " + ", ".join(f"{n} {k.replace('_', ' ')}" for k, n in removed.items()))


def cmd_reset_mfa(args: argparse.Namespace) -> None:
    from app.services import mfa

    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == args.email.lower()))
        if user is None:
            sys.exit(f"No account for {args.email}")
        mfa.disable(db, user)
        db.commit()
    print(f"Two-factor authentication cleared for {args.email}. They can enrol again from Settings.")


def cmd_sync_intel(_: argparse.Namespace) -> None:
    from app.services import intel

    with SessionLocal() as db:
        counts = intel.sync_all(db)
        db.commit()
    print(f"Exploitability feeds synced: {counts['kev']} KEV entries, {counts['epss']} EPSS scores.")


def cmd_import_intel(args: argparse.Namespace) -> None:
    """For installations that cannot reach the feeds: load files fetched elsewhere."""
    from app.services import intel

    if not args.kev and not args.epss:
        sys.exit("Give --kev, --epss, or both")
    with SessionLocal() as db:
        done = []
        if args.kev:
            done.append(f"{intel.sync_kev(db, Path(args.kev).read_bytes())} KEV entries")
        if args.epss:
            done.append(f"{intel.sync_epss(db, Path(args.epss).read_bytes())} EPSS scores")
        db.commit()
    print("Imported " + " and ".join(done) + ".")


def cmd_worker(args: argparse.Namespace) -> None:
    from app.core.logging import configure_logging
    from app.services.jobs import Worker

    cmd_check_db(args)
    configure_logging(settings.log_level, settings.log_json)
    worker = Worker(heartbeat=Path(args.heartbeat) if args.heartbeat else None)
    signal.signal(signal.SIGTERM, worker.stop)
    signal.signal(signal.SIGINT, worker.stop)
    worker.run(burst=args.burst)


def cmd_seed(args: argparse.Namespace) -> None:
    if settings.env == "production" and not args.force:
        sys.exit("Refusing to seed demo data when ENV=production (use --force to override).")
    from app.services.seed import seed_demo

    with SessionLocal() as db:
        seed_demo(db)


def cmd_openapi(args: argparse.Namespace) -> None:
    import json

    from app.main import app

    text = json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n"
    if args.path == "-":
        sys.stdout.write(text)
    else:
        with open(args.path, "w", encoding="utf-8") as fh:
            fh.write(text)


def main() -> None:
    p = argparse.ArgumentParser(prog="guardiano")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init-db").set_defaults(func=cmd_init_db)
    sub.add_parser("check-db").set_defaults(func=cmd_check_db)
    sub.add_parser("bootstrap").set_defaults(func=cmd_bootstrap)
    ca = sub.add_parser("create-admin")
    ca.add_argument("email")
    ca.add_argument("--name")
    ca.add_argument("--password", help="Non-interactive password (prefer the prompt)")
    ca.set_defaults(func=cmd_create_admin)
    sub.add_parser("expire-risk-acceptances").set_defaults(func=cmd_expire)
    sub.add_parser("sync-intel").set_defaults(func=cmd_sync_intel)
    ii = sub.add_parser("import-intel", help="load KEV / EPSS files fetched elsewhere (air-gapped)")
    ii.add_argument("--kev", help="CISA KEV catalogue (known_exploited_vulnerabilities.json)")
    ii.add_argument("--epss", help="EPSS scores (epss_scores-current.csv.gz, or the unzipped .csv)")
    ii.set_defaults(func=cmd_import_intel)
    pr = sub.add_parser("prune")
    pr.add_argument("--dry-run", action="store_true", help="report what would go, and change nothing")
    pr.set_defaults(func=cmd_prune)
    rm = sub.add_parser("reset-mfa")
    rm.add_argument("email")
    rm.set_defaults(func=cmd_reset_mfa)
    wk = sub.add_parser("worker")
    wk.add_argument("--burst", action="store_true", help="Drain the queue once and exit (e.g. from cron)")
    wk.add_argument("--heartbeat", help="File touched on every loop, for container health checks")
    wk.set_defaults(func=cmd_worker)
    sd = sub.add_parser("seed-demo")
    sd.add_argument("--force", action="store_true")
    sd.set_defaults(func=cmd_seed)
    oa = sub.add_parser("openapi")
    oa.add_argument("path", nargs="?", default="-")
    oa.set_defaults(func=cmd_openapi)
    args = p.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
