from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.models.base import TimestampMixin


class Product(TimestampMixin, Base):
    """What a set of assets is together: the checkout service is its API, its web app and its images.

    A grouping only. Who may see an asset is still its team's business (services/scope.py), so one
    product can span teams and each person sees the part of it they may.
    """

    __tablename__ = "products"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True)
    description: Mapped[str] = mapped_column(Text, default="")
