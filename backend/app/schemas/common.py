from pydantic import BaseModel, ConfigDict


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Page[T](BaseModel):
    items: list[T]
    total: int
    page: int
    page_size: int


class PickerPage[T](Page[T]):
    """Bounded search results plus the currently selected item, even outside this page."""

    selected: T | None = None
