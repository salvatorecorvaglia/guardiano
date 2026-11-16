"""Preview projection and gate evaluation, without mutating the main inventory."""

import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Finding, Scan
from app.models.enums import ACTIVE_STATUSES
from app.parsers.base import NormalizedFinding
from app.services import gate, triage
from app.services.scan_context import ScanContext
from app.services.scan_events import _emit_scan_events
from app.services.scan_report import _new_finding, reconcile_tools, reopen_reason, reported_severity

log = logging.getLogger(__name__)


_PREVIEW_LIMIT = 200


@dataclass
class PreviewProjection:
    inventory: gate.Projection = field(default_factory=gate.Projection)
    new_findings: list[NormalizedFinding] = field(default_factory=list)
    new_counts: Counter[str] = field(default_factory=Counter)
    details: list[dict[str, Any]] = field(default_factory=list)
    reopened: int = 0
    would_resolve: int = 0


def preview_projection(db: Session, context: ScanContext) -> PreviewProjection:
    asset, scan, opts, now = context.asset, context.scan, context.options, context.now
    batch, existing = context.prepared.findings.by_key, context.existing
    report, report_tools = context.prepared.report, context.prepared.findings.tools
    result = PreviewProjection()
    projection = result.inventory
    rules = triage.load_rules(db, asset.id, now)
    ctx = triage.context(db, asset, rules, (nf.cve_id for nf in batch.values())) if rules else None
    for key, nf in batch.items():
        stored = existing.get(key)
        if stored is None:
            f = _new_finding(asset, key, nf, scan, now)
            if rules:
                triage.apply_rules(db, f, rules, now=now, ctx=ctx, record=False)
            result.new_findings.append(nf)
            result.new_counts[f.severity] += 1
            if len(result.details) < _PREVIEW_LIMIT:
                detail = {
                    name: getattr(f, name)
                    for name in (
                        "title",
                        "type",
                        "severity",
                        "cvss_score",
                        "rule_id",
                        "file_path",
                        "line_start",
                        "package_name",
                        "package_version",
                        "cve_id",
                        "fixed_version",
                        "status",
                    )
                }
                detail["scanner_severity"] = nf.severity
                result.details.append(detail)
            projection.additions.append(gate.GateFinding.of(f))
        else:
            f = gate.GateFinding.of(stored)
            tools = reconcile_tools(
                stored.tools or [], context.prepared.findings.sources[key], report_tools, opts.close_missing
            )
            f.severity = stored.severity_override or reported_severity(stored, nf, tools=tools)
            if reopen_reason(stored, nf.tool_name, now):
                f.status = "open"
                result.reopened += 1
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
                result.would_resolve += 1
    return result


def _preview_result(context: ScanContext, result: PreviewProjection) -> dict[str, Any]:
    total = len(context.prepared.findings.by_key)
    new = len(result.new_findings)
    return {
        "branch": context.options.branch,
        "default_branch": context.asset.default_branch,
        "counts": {
            "total": total,
            "new": new,
            "known": total - new,
            "new_by_severity": dict(result.new_counts),
        },
        "would_resolve": result.would_resolve,
        "truncated": new > _PREVIEW_LIMIT,
        "new": result.details,
    }


def preview_scan(db: Session, context: ScanContext) -> Scan:
    asset, scan, opts = context.asset, context.scan, context.options
    batch = context.prepared.findings.by_key
    tool_name = context.prepared.findings.tool_name
    projected = preview_projection(db, context)
    components = context.prepared.components
    scan.total_count = len(batch)
    scan.new_count = len(projected.new_findings)
    scan.duplicate_count = len(batch) - scan.new_count
    scan.preview_result = _preview_result(context, projected)
    preview_new = scan.preview_result["new"]
    scan.reopened_count = projected.reopened
    scan.gate_result = gate.evaluate(
        db,
        asset=asset,
        new_by_severity=scan.preview_result["counts"]["new_by_severity"],
        reopened=projected.reopened,
        policy=gate.policy_for(db, asset.id),
        new=projected.new_findings,
        components=components,
        projection=projected.inventory,
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
