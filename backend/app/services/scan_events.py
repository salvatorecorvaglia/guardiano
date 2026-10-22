"""Transactional scan event and SCM feedback publication."""

from typing import Any

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import Asset, Scan
from app.services import events, scm

_EVENT_CAP = 20


def _scan_payload(scan: Scan, asset: Asset, preview: bool, notable: list[dict[str, Any]]) -> dict[str, Any]:
    base = (settings.public_url or "").rstrip("/")
    return {
        "scan_id": scan.id,
        "asset": asset.name,
        "asset_id": asset.id,
        "tool": scan.tool_name,
        "scan_type": scan.scan_type,
        "branch": scan.branch,
        "commit_sha": scan.commit_sha,
        "preview": preview,
        "counts": {
            "total": scan.total_count,
            "new": scan.new_count,
            "duplicate": scan.duplicate_count,
            "reopened": scan.reopened_count,
            "auto_resolved": scan.auto_resolved_count,
        },
        "gate": scan.gate_result,
        "new_findings": notable[:_EVENT_CAP],
        "url": f"{base}/scans/{scan.id}" if base else None,
    }


def _emit_scan_events(
    db: Session, scan: Scan, asset: Asset, preview: bool, notable: list[dict[str, Any]]
) -> None:
    """Queue this scan's events. They are sent by the worker after the ingestion transaction commits."""
    payload = _scan_payload(scan, asset, preview, notable)
    scm.queue_feedback(db, scan, asset)
    events.emit(db, events.SCAN_COMPLETED, payload, asset_id=asset.id)
    if scan.gate_result and not scan.gate_result.get("passed"):
        events.emit(
            db,
            events.GATE_FAILED,
            {**payload, "violations": [v["message"] for v in scan.gate_result.get("violations", [])]},
            asset_id=asset.id,
        )
