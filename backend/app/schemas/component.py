from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel
from app.schemas.scan import AssetRef


class ComponentOut(ORMModel):
    """One package shipped by one asset: the answer to "what is in this service?"."""

    id: int
    name: str
    version: str | None
    ecosystem: str | None
    purl: str | None
    licenses: list[str]
    licence_rule: str  # allowed | denied | review | unknown, from the licence policy
    first_seen_at: datetime
    last_seen_at: datetime


class ComponentUse(BaseModel):
    """One package version, and everywhere it is used."""

    name: str
    version: str | None
    ecosystem: str | None
    purl: str | None
    licenses: list[str]
    licence_rule: str  # allowed | denied | review | unknown
    assets: list[AssetRef]
    last_seen_at: datetime


class LicenceCount(BaseModel):
    licence: str
    components: int
    rule: str  # allowed | denied | review, from the licence policy


class LicenceRule(BaseModel):
    licence: str = Field(min_length=1, max_length=100)
    rule: Literal["allowed", "denied", "review"]
    note: str | None = Field(None, max_length=500)


class LicensePolicyOut(BaseModel):
    """The policy, plus what unlisted licences default to."""

    rules: list[LicenceRule]
    default: str


class LicensePolicyUpdate(BaseModel):
    rules: list[LicenceRule] = Field(max_length=500)


class InventoryStats(BaseModel):
    components: int
    distinct: int
    assets: int
    last_seen_at: datetime | None


class VexImportResult(BaseModel):
    format: str
    statements: int
    changed: int
    unmatched: list[str]
    informational: int
    already_closed: int
