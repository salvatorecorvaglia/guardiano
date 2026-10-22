from datetime import datetime
from typing import Any, Literal

from pydantic import AliasChoices, BaseModel, Field

from app.models.enums import ScanType
from app.schemas.common import ORMModel
from app.schemas.user import UserBrief


class AssetRef(ORMModel):
    id: int
    name: str


class GateViolation(BaseModel):
    rule: str  # max_new | max_open | fail_on_overdue | fail_on_reopened
    severity: str | None = None
    limit: float | None = None
    actual: int
    message: str


class GateResult(BaseModel):
    passed: bool
    policy_id: int
    policy_scope: Literal["asset", "global"]
    violations: list[GateViolation]
    evaluated_at: datetime


class PreviewCounts(BaseModel):
    total: int
    new: int
    known: int
    new_by_severity: dict[str, int]


class PreviewResult(BaseModel):
    """What a preview scan would add, had it been ingested."""

    branch: str | None
    default_branch: str | None
    counts: PreviewCounts
    truncated: bool  # more new findings than the preview lists
    new: list[dict[str, Any]]


class ScanOut(ORMModel):
    id: int
    asset: AssetRef
    scan_type: ScanType
    tool_name: str
    tool_version: str | None
    format: str
    branch: str | None
    commit_sha: str | None
    source: Literal["upload", "api", "preview"]
    file_name: str | None
    uploaded_by: UserBrief | None
    total_count: int
    new_count: int
    duplicate_count: int
    reopened_count: int
    auto_resolved_count: int
    # Null when no quality gate applied to this scan.
    gate: GateResult | None = Field(None, validation_alias=AliasChoices("gate", "gate_result"))
    # Only for source="preview".
    preview: PreviewResult | None = Field(None, validation_alias=AliasChoices("preview", "preview_result"))
    created_at: datetime


class ScanDiff(BaseModel):
    """How a scan's findings compare with an earlier scan of the same asset.

    List the findings themselves with ``GET /findings?scan_id=&not_in_scan_id=``: ``new`` is
    ``scan_id=<scan>&not_in_scan_id=<against>`` and ``no_longer_reported`` is the reverse.
    """

    scan: ScanOut
    against: ScanOut | None  # None: this is the first scan of its tool on the asset
    new: int  # reported by the scan but not by `against`
    no_longer_reported: int  # reported by `against` but not by the scan
    unchanged: int  # reported by both
