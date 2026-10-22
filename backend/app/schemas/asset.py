from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, Field, StringConstraints, model_validator

from app.models.enums import AssetType, Criticality, Environment
from app.schemas.common import ORMModel

NAME_PATTERN = r"^[\w.\-/ @:]+$"
Tag = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]


class AssetBase(BaseModel):
    name: str = Field(min_length=1, max_length=200, pattern=NAME_PATTERN)
    type: AssetType = AssetType.repository
    description: str = ""
    repo_url: str | None = Field(None, max_length=500)
    owner: str | None = Field(None, max_length=200)
    criticality: Criticality = Criticality.medium
    tags: list[Tag] = Field(default_factory=list, max_length=30)
    default_assignee_id: int | None = Field(None, description="New findings are assigned to this user")
    default_branch: str | None = Field(
        None,
        max_length=255,
        description="Scans of other branches are ingested as previews and never change the inventory",
    )
    team_id: int | None = Field(
        None, description="Restricts the asset to this team's members; null means everyone can see it"
    )
    product_id: int | None = Field(None, description="The product this asset is part of")
    environment: Environment | None = None


class AssetCreate(AssetBase):
    pass


class AssetUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=200, pattern=NAME_PATTERN)
    type: AssetType | None = None
    description: str | None = None
    repo_url: str | None = Field(None, max_length=500)
    owner: str | None = Field(None, max_length=200)
    criticality: Criticality | None = None
    tags: list[Tag] | None = Field(None, max_length=30)
    default_assignee_id: int | None = None
    default_branch: str | None = Field(None, max_length=255)
    team_id: int | None = None
    product_id: int | None = None
    environment: Environment | None = None

    @model_validator(mode="after")
    def required_values(self):
        for name in ("name", "type", "description", "criticality", "tags"):
            if name in self.model_fields_set and getattr(self, name) is None:
                raise ValueError(f"{name} cannot be null; omit the field to keep its value")
        return self


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class AssetOut(ORMModel):
    id: int
    name: str
    type: AssetType
    description: str
    repo_url: str | None
    owner: str | None
    criticality: Criticality
    tags: list[str]
    default_assignee_id: int | None = None
    default_branch: str | None = None
    team_id: int | None = None
    product_id: int | None = None
    environment: Environment | None = None
    created_at: datetime


class AssetSummary(AssetOut):
    open_counts: SeverityCounts
    open_total: int
    risk_score: float
    last_scan_at: datetime | None


class ProductBody(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field("", max_length=5000)


class ProductUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=200)
    description: str | None = Field(None, max_length=5000)


class ProductOut(ORMModel):
    """A product, with totals over the assets of it that you can see."""

    id: int
    name: str
    description: str
    assets: int = 0
    open_total: int = 0
    open_counts: SeverityCounts = Field(default_factory=SeverityCounts)
