from pydantic import BaseModel, Field, model_validator

from app.schemas.common import ORMModel
from app.schemas.user import UserBrief


class TeamCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100, pattern=r"^[\w.\-/ @]+$")
    description: str = Field("", max_length=1000)


class TeamUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=100, pattern=r"^[\w.\-/ @]+$")
    description: str | None = Field(None, max_length=1000)

    @model_validator(mode="after")
    def required_values(self):
        for name in ("name", "description"):
            if name in self.model_fields_set and getattr(self, name) is None:
                raise ValueError(f"{name} cannot be null; omit the field to keep its value")
        return self


class TeamMembers(BaseModel):
    user_ids: list[int] = Field(default_factory=list, max_length=500)


class TeamOut(ORMModel):
    id: int
    name: str
    description: str
    member_count: int = 0
    asset_count: int = 0
    members: list[UserBrief] = Field(default_factory=list)
