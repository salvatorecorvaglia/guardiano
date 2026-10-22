from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from app.schemas.common import ORMModel
from app.schemas.user import UserBrief


def _clean_query(v: str | None) -> str | None:
    # Stored without the leading "?" and without paging, so a view always opens on its first page.
    if v is None:
        return None
    from urllib.parse import parse_qsl, urlencode

    pairs = [(k, val) for k, val in parse_qsl(v.strip().lstrip("?"), keep_blank_values=False) if k != "page"]
    return urlencode(pairs)


class SavedViewCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    query: str = Field(
        "", max_length=2000, description="Findings page query string, e.g. severity=high&status=open"
    )
    shared: bool = False

    _query = field_validator("query")(_clean_query)


class SavedViewUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=100)
    query: str | None = Field(None, max_length=2000)
    shared: bool | None = None

    _query = field_validator("query")(_clean_query)


class SavedViewOut(ORMModel):
    id: int
    name: str
    query: str
    shared: bool
    user: UserBrief
    created_at: datetime
    updated_at: datetime
