"""Typed hand-off between report matching, preview evaluation and persistence."""

from dataclasses import dataclass
from datetime import datetime

from app.models import Asset, Finding, Scan
from app.services.scan_report import IngestOptions, PreparedReport


@dataclass(frozen=True)
class ScanContext:
    asset: Asset
    scan: Scan
    options: IngestOptions
    prepared: PreparedReport
    existing: dict[str, Finding]
    moved: dict[str, Finding]
    now: datetime
