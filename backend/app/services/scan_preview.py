"""Preview projection and gate evaluation, without mutating the main inventory."""

import logging
from collections import Counter
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Asset, Finding, Scan
from app.models.enums import ACTIVE_STATUSES
from app.parsers.base import NormalizedFinding
from app.services import gate, triage
from app.services.scan_context import ScanContext
from app.services.scan_events import _emit_scan_events
from app.services.scan_report import IngestOptions, _new_finding, reconcile_tools, reported_severity

log = logging.getLogger(__name__)


def preview_projection(db: Session, context: ScanContext) -> tuple[gate.Projection, Counter[str], int]:
    asset, scan, opts, now = context.asset, context.scan, context.options, context.now
    batch, existing = context.prepared.findings.by_key, context.existing
    report, report_tools = context.prepared.report, context.prepared.findings.tools
    projection = gate.Projection()
    new_counts: Counter[str] = Counter()
    reopened = 0
    rules = triage.load_rules(db, asset.id, now)
    ctx = triage.context(db, asset, rules, (nf.cve_id for nf in batch.values())) if rules else None
    for key, nf in batch.items():
        stored = existing.get(key)
        if stored is None:
            f = _new_finding(asset, key, nf, scan, now)
            if rules:
                triage.apply_rules(db, f, rules, now=now, ctx=ctx, record=False)
            new_counts[f.severity] += 1
            projection.additions.append(gate.GateFinding.of(f))
        else:
            f = gate.GateFinding.of(stored)
            tools = reconcile_tools(
                stored.tools or [], context.prepared.findings.sources[key], report_tools, opts.close_missing
            )
            f.severity = stored.severity_override or reported_severity(stored, nf, tools=tools)
            if stored.status == "resolved" or (
                stored.status == "risk_accepted"
                and stored.risk_accepted_until is not None
                and stored.risk_accepted_until <= now
            ):
                f.status = "open"
                reopened += 1
            projection.replacements[stored.id] = f
    if opts.close_missing and (batch or opts.allow_empty):
        matched = {f.id for f in existing.values()}
        stale = db.scalars(
            select(Finding)
            .where(
                Finding.asset_id == asset.id,
                Finding.type.in_({scan.scan_type, *report.covered_types}),
                Finding.status.in_([s.value for s in ACTIVE_STATUSES]),
                Finding.tools.overlap(sorted(report_tools)),
                Finding.first_seen_at <= now,
            )
            .execution_options(yield_per=500)
        )
        for stored in stale:
            if stored.id not in matched and not set(stored.tools or []) - report_tools:
                f = gate.GateFinding.of(stored)
                f.status = "resolved"
                projection.replacements[stored.id] = f
    return projection, new_counts, reopened


_PREVIEW_LIMIT = 200


def _preview_result(
    asset: Asset, opts: IngestOptions, batch: dict[str, NormalizedFinding], existing: dict[str, Finding]
) -> dict[str, Any]:
    new = [nf for key, nf in batch.items() if key not in existing]
    return {
        "branch": opts.branch,
        "default_branch": asset.default_branch,
        "counts": {
            "total": len(batch),
            "new": len(new),
            "known": len(batch) - len(new),
            "new_by_severity": dict(Counter(nf.severity for nf in new)),
        },
        "truncated": len(new) > _PREVIEW_LIMIT,
        "new": [
            {
                "title": nf.title,
                "type": nf.type,
                "severity": nf.severity,
                "cvss_score": nf.cvss_score,
                "rule_id": nf.rule_id,
                "file_path": nf.file_path,
                "line_start": nf.line_start,
                "package_name": nf.package_name,
                "package_version": nf.package_version,
                "cve_id": nf.cve_id,
                "fixed_version": nf.fixed_version,
            }
            for nf in new[:_PREVIEW_LIMIT]
        ],
    }


def preview_scan(db: Session, context: ScanContext) -> Scan:
    asset, scan, opts = context.asset, context.scan, context.options
    batch, existing = context.prepared.findings.by_key, context.existing
    tool_name = context.prepared.findings.tool_name
    new_in_scan = [nf for key, nf in batch.items() if key not in existing]
    components = context.prepared.components
    scan.total_count = len(batch)
    scan.new_count = sum(1 for key in batch if key not in existing)
    scan.duplicate_count = len(batch) - scan.new_count
    scan.preview_result = _preview_result(asset, opts, batch, existing)
    preview_new = scan.preview_result["new"]
    projection, new_counts, reopened_count = preview_projection(db, context)
    scan.preview_result["counts"]["new_by_severity"] = dict(new_counts)
    scan.reopened_count = reopened_count
    scan.gate_result = gate.evaluate(
        db,
        asset=asset,
        new_by_severity=scan.preview_result["counts"]["new_by_severity"],
        reopened=reopened_count,
        policy=gate.policy_for(db, asset.id),
        new=new_in_scan,
        components=components,
        projection=projection,
    )
    _emit_scan_events(db, scan, asset, True, preview_new)
    db.commit()
    log.info(
        "scan %s previewed: asset=%s tool=%s branch=%s total=%d new=%d gate=%s",
        scan.id,
        asset.name,
        tool_name,
        opts.branch,
        scan.total_count,
        scan.new_count,
        gate.summary_line(scan),
    )
    return scan
