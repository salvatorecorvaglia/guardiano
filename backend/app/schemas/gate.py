from datetime import datetime

from pydantic import BaseModel, Field

from app.models.enums import Severity
from app.schemas.common import ORMModel
from app.schemas.scan import AssetRef


class GateConditions(BaseModel):
    """All conditions are optional; a policy with none always passes."""

    max_new: dict[Severity, int] = Field(
        default_factory=dict, description="Most new findings this scan may introduce, per severity"
    )
    max_open: dict[Severity, int] = Field(
        default_factory=dict, description="Most active findings the asset may carry, per severity"
    )
    fail_on_overdue: bool = Field(False, description="Fail when the asset has findings past their SLA")
    fail_on_reopened: bool = Field(False, description="Fail when the scan reopens a resolved finding")
    fail_on_kev: bool = Field(
        False,
        description="Fail when the asset carries an open finding whose CVE is in CISA's "
        "Known Exploited Vulnerabilities catalogue",
    )
    max_open_epss: float | None = Field(
        None,
        ge=0,
        le=1,
        description="Fail when the asset carries an open finding whose EPSS probability is above this "
        "(0-1). Scores arrive with the daily intel sync, so a CVE first seen today counts from tomorrow",
    )
    max_new_cvss: float | None = Field(
        None, ge=0, le=10, description="Fail when this scan introduces a finding with a CVSS score above this"
    )
    fail_on_new_secrets: bool = Field(
        False,
        description="Fail when this scan introduces a hard-coded credential (CWE-798, CWE-259 or "
        "CWE-321, as Gitleaks and secret scanners report them)",
    )
    fail_on_denied_license: bool = Field(
        False, description="Fail when the report lists a component whose licence the licence policy denies"
    )

    def non_negative(self) -> "GateConditions":
        for field in (self.max_new, self.max_open):
            for severity, limit in field.items():
                if limit < 0:
                    raise ValueError(f"Limit for '{severity.value}' must be zero or more")
        return self


class GatePolicyUpsert(BaseModel):
    asset_id: int | None = Field(None, description="null is the global policy, used by assets without one")
    enabled: bool = True
    conditions: GateConditions = Field(default_factory=GateConditions)


class GatePolicyOut(ORMModel):
    id: int
    asset: AssetRef | None
    enabled: bool
    conditions: GateConditions
    created_at: datetime
    updated_at: datetime
