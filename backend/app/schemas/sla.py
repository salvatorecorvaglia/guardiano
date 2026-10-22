from pydantic import BaseModel, Field


class SlaMatrix(BaseModel):
    """Remediation SLA in days, by severity (rows) and asset criticality (columns).

    ``days[severity]["any"]`` is the effective default for the severity. The other columns hold a
    criticality-specific override, or ``null`` when that criticality uses the default.
    """

    severities: list[str]
    criticalities: list[str]  # "any" first, then low..critical
    days: dict[str, dict[str, int | None]]
    env_defaults: dict[str, int]  # SLA_*_DAYS, used for "any" when no policy overrides it


class SlaUpdate(BaseModel):
    """Replaces every policy. ``null`` (or omission) means inherit: "any" falls back to SLA_*_DAYS."""

    days: dict[str, dict[str, int | None]] = Field(
        examples=[{"critical": {"any": 7, "critical": 3}, "high": {"any": 30}}]
    )
