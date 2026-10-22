"""Scan ingestion orchestration: prepare -> match -> preview or persist."""

import hashlib
import logging
import time

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import Asset, Finding, Scan, User
from app.models.base import utcnow
from app.parsers.base import NormalizedFinding
from app.services import metrics
from app.services.errors import Busy, NotFound
from app.services.scan_context import ScanContext
from app.services.scan_persistence import persist_scan
from app.services.scan_preview import preview_scan
from app.services.scan_report import (
    _SCAN_LIMITS,
    _clean,
    prepare_report,
)
from app.services.scan_report import (
    IngestOptions as IngestOptions,
)
from app.services.scan_report import (
    is_preview as is_preview,
)
from app.services.scan_report import (
    prepare_findings as prepare_findings,
)
from app.services.scan_report import (
    sanitize as sanitize,
)
from app.services.scan_report import (
    sanitize_component as sanitize_component,
)
from app.services.scope import Scope

log = logging.getLogger(__name__)
_CHUNK = 1000
_LOCK_NAMESPACE = 0x6764
_NAME_LOCK_NAMESPACE = 0x6765


def get_or_create_asset(db: Session, name: str, scope: Scope) -> Asset:
    """Case-insensitive lookup; creation is race-safe, including between different casings.

    ``scope`` is required, not defaulted: naming an asset must not be a way around the check the
    ``asset_id`` path performs. An existing asset the caller may not see is reported as missing,
    exactly as looking it up by id would be.
    """
    name = name.strip()
    stmt = select(Asset).where(func.lower(Asset.name) == name.lower()).order_by(Asset.id).limit(1)
    asset = db.scalar(stmt)
    if asset is None:
        # The unique index is on the exact name but lookup ignores case, so ON CONFLICT alone let two
        # concurrent uploads as "Payments-API" and "payments-api" both insert, splitting one repo's
        # findings across two assets for good. Creation is serialised on the lower-cased name, and
        # the lookup repeated once the lock is held. (A unique index on lower(name) would say the
        # same, but could not be added to an installation that already has such a pair.)
        db.execute(select(func.pg_advisory_xact_lock(_NAME_LOCK_NAMESPACE, func.hashtext(name.lower()))))
        asset = db.scalar(stmt)
    if asset is None:
        now = utcnow()
        db.execute(
            pg_insert(Asset)
            .values(
                name=name,
                type="repository",
                description="Created automatically on scan ingestion",
                criticality="medium",
                tags=[],
                created_at=now,
                updated_at=now,
            )
            .on_conflict_do_nothing(index_elements=["name"])
        )
        asset = db.scalar(stmt)
    # Checked last, so it also covers an asset another request created while this one waited.
    if not scope.owns(asset):
        raise NotFound("Asset not found")
    return asset


def match_by_fingerprint(
    db: Session, asset: Asset, batch: dict[str, NormalizedFinding], existing: dict[str, Finding]
) -> dict[str, Finding]:
    """Findings whose key changed (the code moved) but whose scanner fingerprint is unchanged.

    Only used when DEDUP_FINGERPRINTS is on. Matching is per asset, type, rule and fingerprint, and only
    against findings the report did not already match by key, so one stored finding is claimed at most once.
    """
    wanted = {key: nf for key, nf in batch.items() if key not in existing and nf.fingerprint}
    if not wanted:
        return {}
    claimed = {f.id for f in existing.values()}
    rows = []
    fingerprints = sorted({nf.fingerprint for nf in wanted.values()})
    for start in range(0, len(fingerprints), _CHUNK):
        rows.extend(
            db.scalars(
                select(Finding)
                .where(
                    Finding.asset_id == asset.id,
                    Finding.fingerprint.in_(fingerprints[start : start + _CHUNK]),
                )
                .order_by(Finding.id)
            )
        )
    by_identity: dict[tuple[str, str | None, str], Finding] = {}
    for f in rows:
        # A duplicate identity would be ambiguous, so keep the oldest and ignore the rest.
        by_identity.setdefault((f.type, (f.rule_id or "").lower(), f.fingerprint), f)

    moved: dict[str, Finding] = {}
    for key, nf in wanted.items():
        f = by_identity.get((nf.type, (nf.rule_id or "").lower(), nf.fingerprint))
        if f is not None and f.id not in claimed:
            claimed.add(f.id)
            moved[key] = f
    return moved


def ingest_report(db: Session, raw: bytes, asset: Asset, user: User | None, opts: IngestOptions) -> Scan:
    """Parse, deduplicate and store one report. Timed in one place, for both the preview and full paths."""
    started = time.perf_counter()
    # Shared by API processes and CLI callers, released on transaction completion or disconnect.
    for slot in range(settings.max_concurrent_ingests):
        if db.scalar(select(func.pg_try_advisory_xact_lock(0x6769, slot))):
            break
    else:
        raise Busy("Scan ingestion is busy; retry the upload shortly")
    scan = _ingest_report(db, raw, asset, user, opts)
    if settings.metrics_enabled:
        metrics.record_ingest(
            scan.format or "unknown",
            scan.scan_type,
            time.perf_counter() - started,
            preview=scan.source == "preview",
        )
    return scan


def _ingest_report(db: Session, raw: bytes, asset: Asset, user: User | None, opts: IngestOptions) -> Scan:
    now = opts.now or utcnow()
    prepared = prepare_report(raw, asset.id, opts)
    report, scan_type = prepared.report, prepared.scan_type
    tool_name = prepared.findings.tool_name
    batch = prepared.findings.by_key
    # Serialise ingestion per asset: concurrent uploads would otherwise race on new dedup keys.
    db.execute(select(func.pg_advisory_xact_lock(_LOCK_NAMESPACE, asset.id)))

    preview = is_preview(asset, opts)
    scan = Scan(
        asset_id=asset.id,
        scan_type=scan_type,
        tool_name=tool_name,
        tool_version=_clean(report.tool_version, _SCAN_LIMITS["tool_version"]) or None,
        format=report.format,
        branch=_clean(opts.branch, _SCAN_LIMITS["branch"]) or None,
        commit_sha=_clean(opts.commit_sha, _SCAN_LIMITS["commit_sha"]) or None,
        source="preview" if preview else opts.source,
        uploaded_by_id=user.id if user else None,
        file_name=_clean(opts.file_name, _SCAN_LIMITS["file_name"]) or None,
        file_sha256=hashlib.sha256(raw).hexdigest(),
        inventory_complete=report.inventory_complete,
        created_at=now,
    )
    db.add(scan)
    db.flush()

    # Lock in ID order, shared with bulk triage, before reading mutable finding state.
    if not preview:
        db.execute(
            select(Finding.id)
            .where(Finding.asset_id == asset.id)
            .order_by(Finding.id)
            .with_for_update(of=Finding)
        ).all()

    # 2. Load existing findings for these keys.
    existing: dict[str, Finding] = {}
    keys = list(batch)
    for i in range(0, len(keys), _CHUNK):
        rows = db.scalars(
            select(Finding)
            .where(Finding.asset_id == asset.id, Finding.dedup_key.in_(keys[i : i + _CHUNK]))
            .execution_options(populate_existing=True)
        ).all()
        existing.update({f.dedup_key: f for f in rows})

    # 2a. Follow findings whose line moved, when the scanner gave us a fingerprint.
    moved = match_by_fingerprint(db, asset, batch, existing) if settings.dedup_fingerprints else {}
    existing.update(moved)

    context = ScanContext(asset, scan, opts, prepared, existing, moved, now)
    return preview_scan(db, context) if preview else persist_scan(db, context)
