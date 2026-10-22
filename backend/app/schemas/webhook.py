from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from app.core.urlguard import check_url
from app.models.enums import Severity
from app.schemas.common import ORMModel
from app.schemas.scan import AssetRef
from app.services.events import EVENTS
from app.services.webhooks import FORMATS

EventName = Literal[EVENTS]  # type: ignore[valid-type]


def _check_url(v: str) -> str:
    """Scheme plus the SSRF guard, so an unreachable target is refused where it is typed in."""
    return check_url(v)


class WebhookBase(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    url: str = Field(max_length=2000, examples=["https://hooks.slack.com/services/…"])
    format: Literal[FORMATS] = "guardiano"  # type: ignore[valid-type]
    events: list[EventName] = Field(min_length=1)
    min_severity: Severity = Field(
        Severity.high, description="Ignored by scan.completed, gate.failed and test events"
    )
    asset_id: int | None = Field(None, description="null sends events for every asset")
    enabled: bool = True

    _url = field_validator("url")(_check_url)


class WebhookCreate(WebhookBase):
    pass


class WebhookUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=100)
    url: str | None = Field(None, max_length=2000)
    format: Literal[FORMATS] | None = None  # type: ignore[valid-type]
    events: list[EventName] | None = Field(None, min_length=1)
    min_severity: Severity | None = None
    asset_id: int | None = None
    enabled: bool | None = None
    rotate_secret: bool = False

    _url = field_validator("url")(lambda cls, v: v if v is None else _check_url(v))


class WebhookOut(ORMModel):
    id: int
    name: str
    url: str
    format: str
    events: list[str]
    min_severity: str
    asset: AssetRef | None
    enabled: bool
    last_status: int | None
    last_error: str | None
    last_delivery_at: datetime | None
    created_at: datetime


class WebhookCreated(WebhookOut):
    """The signing secret is returned only here and when it is rotated."""

    secret: str


class DeliveryOut(ORMModel):
    id: int
    event: str
    payload: dict[str, Any]
    status_code: int | None
    error: str | None
    attempts: int
    created_at: datetime
    delivered_at: datetime | None
