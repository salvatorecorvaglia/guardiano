"""Reporting scan results back to GitHub and GitLab.

Two things are posted, both from the worker so a slow or broken forge never delays or fails an upload:

- a **commit status** on the scanned commit, which is what branch protection and merge checks read;
- for a scan of a branch with an open pull or merge request, a **comment** summarising what the branch
  would add. There is one per asset and pull request, edited by later scans rather than added to.

Only integrations with ``scm_feedback`` on take part, and only GitHub and GitLab: Jira has no commits.
Nothing is posted for a scan without a commit sha, since there would be nothing to attach it to.
"""

import logging
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import Asset, Integration, PrComment, Scan
from app.models.base import utcnow
from app.models.enums import TrackerKind
from app.services import jobs
from app.services.trackers.base import TrackerError

log = logging.getLogger(__name__)

FEEDBACK_JOB = "scm.feedback"
CONTEXT = "guardiano/security"
KINDS = (TrackerKind.github.value, TrackerKind.gitlab.value)


def targets(db: Session, asset_id: int) -> list[Integration]:
    return list(
        db.scalars(
            select(Integration).where(
                Integration.enabled.is_(True),
                Integration.scm_feedback.is_(True),
                Integration.kind.in_(KINDS),
                or_(Integration.asset_id == asset_id, Integration.asset_id.is_(None)),
            )
        )
    )


def outcome(scan: Scan) -> tuple[str, str]:
    """The commit status state and its one-line description."""
    counts = scan.preview_result["counts"] if scan.source == "preview" and scan.preview_result else None
    new = counts["new"] if counts else scan.new_count
    gate = scan.gate_result
    if gate and not gate.get("passed"):
        first = (gate.get("violations") or [{}])[0].get("message", "quality gate failed")
        extra = len(gate.get("violations") or []) - 1
        return "failure", f"{first}{f' (+{extra} more)' if extra > 0 else ''}"
    scanned = f"{scan.tool_name}: {new} new finding(s)"
    return "success", f"{scanned}, quality gate passed" if gate else scanned


def aggregate_outcome(db: Session, integration: Integration, sha: str) -> tuple[str, str]:
    """One status context combines the latest result of each asset/scanner/type for this commit."""
    ranked = select(
        Scan.id,
        func.row_number()
        .over(
            partition_by=(Scan.asset_id, Scan.tool_name, Scan.scan_type),
            order_by=Scan.id.desc(),
        )
        .label("position"),
    ).where(Scan.commit_sha == sha)
    if integration.asset_id is not None:
        ranked = ranked.where(Scan.asset_id == integration.asset_id)
    ranked = ranked.subquery()
    scans = list(
        db.scalars(
            select(Scan)
            .where(Scan.id.in_(select(ranked.c.id).where(ranked.c.position == 1)))
            .order_by(Scan.id)
        )
    )
    if not scans:
        return "pending", "Waiting for scan results"
    failures = [s for s in scans if s.gate_result and not s.gate_result.get("passed")]
    if len(scans) == 1:
        return outcome(scans[0])
    if failures:
        return "failure", f"{len(failures)} of {len(scans)} scanner results failed: {outcome(failures[0])[1]}"
    return "success", f"All {len(scans)} scanner results passed"


def comment_body(scan: Scan, asset: Asset) -> str:
    """The pull-request comment: what this branch would add, and the gate outcome."""
    preview = scan.preview_result or {}
    counts = preview.get("counts") or {}
    base = (settings.public_url or "").rstrip("/")
    lines = [f"### Guardiano · {asset.name}", ""]
    if scan.source == "preview":
        by_severity = counts.get("new_by_severity") or {}
        summary = ", ".join(f"{n} {sev}" for sev, n in by_severity.items()) or "none"
        lines.append(f"**{counts.get('new', 0)} new finding(s)** this branch would add ({summary}).")
        for f in (preview.get("new") or [])[:10]:
            where = f.get("file_path") or f.get("package_name") or ""
            line = f":{f['line_start']}" if f.get("line_start") else ""
            lines.append(f"- **{f.get('severity')}** {f.get('title')} — `{where}{line}`")
        if counts.get("new", 0) > 10:
            lines.append(f"- … and {counts['new'] - 10} more")
    else:
        lines.append(
            f"**{scan.new_count} new**, {scan.duplicate_count} already known, "
            f"{scan.reopened_count} reopened, {scan.auto_resolved_count} resolved."
        )
    gate = scan.gate_result
    if gate:
        lines.append("")
        if gate.get("passed"):
            lines.append("Quality gate: **passed** ✅")
        else:
            lines.append("Quality gate: **failed** ❌")
            lines += [f"- {v['message']}" for v in gate.get("violations", [])]
    if base:
        lines += ["", f"[Full results in Guardiano]({base}/scans/{scan.id})"]
    return "\n".join(lines)


def queue_feedback(db: Session, scan: Scan, asset: Asset) -> int:
    """Queue commit-status (and pull-request comment) jobs for this scan. The caller commits."""
    if not scan.commit_sha:
        return 0
    integrations = targets(db, asset.id)
    for integration in integrations:
        jobs.enqueue(db, FEEDBACK_JOB, {"scan_id": scan.id, "integration_id": integration.id})
    if integrations:
        log.info("queued SCM feedback for scan %s on %d integration(s)", scan.id, len(integrations))
    return len(integrations)


def payload_for(scan: Scan, asset: Asset) -> dict[str, Any]:
    state, description = outcome(scan)
    base = (settings.public_url or "").rstrip("/")
    return {
        "state": state,
        "description": description,
        "target_url": f"{base}/scans/{scan.id}" if base else None,
        "context": CONTEXT,
        "branch": scan.branch,
        "comment": comment_body(scan, asset),
    }


def post_or_update_comment(
    db: Session, api: Any, integration: Integration, asset: Asset, number: str, text: str
) -> None:
    """Edit this asset's comment on the pull request if Guardiano has one there, else post one.

    An edit that fails (the comment was deleted, or the token may no longer edit it) falls back to a new
    comment: at worst that is one more comment, which is what every scan used to add.
    """
    kept = db.scalar(
        select(PrComment).where(
            PrComment.integration_id == integration.id,
            PrComment.asset_id == asset.id,
            PrComment.pr_number == number,
        )
    )
    from app.services.remote_io import network_io, snapshot

    config = snapshot(integration)
    integration_id, asset_id = integration.id, asset.id
    kept_id, previous_id = (kept.id, kept.comment_id) if kept is not None else (None, None)
    updated = False
    with network_io(db):
        if previous_id is not None:
            try:
                api.update_pr_comment(config, number, previous_id, text)
                updated = True
            except TrackerError as exc:
                log.info("could not edit comment %s on %s; posting a new one: %s", previous_id, number, exc)
        comment_id = previous_id if updated else api.comment_on_pr(config, number, text)
    if not comment_id:
        return
    kept = db.get(PrComment, kept_id, with_for_update=True, populate_existing=True) if kept_id else None
    if kept is None:
        kept = PrComment(integration_id=integration_id, asset_id=asset_id, pr_number=number)
        db.add(kept)
    kept.comment_id, kept.updated_at = comment_id, utcnow()
