from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.models.base import TimestampMixin


class Asset(TimestampMixin, Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    type: Mapped[str] = mapped_column(String(20), default="repository")
    description: Mapped[str] = mapped_column(Text, default="")
    repo_url: Mapped[str | None] = mapped_column(String(500))
    owner: Mapped[str | None] = mapped_column(String(200))
    criticality: Mapped[str] = mapped_column(String(20), default="medium")
    tags: Mapped[list[str]] = mapped_column(ARRAY(String(64)), default=list)
    # Restricts the asset to one team's members; NULL means everybody can see it.
    team_id: Mapped[int | None] = mapped_column(ForeignKey("teams.id", ondelete="SET NULL"), index=True)
    # Scans of other branches are ingested as previews, leaving the inventory untouched.
    default_branch: Mapped[str | None] = mapped_column(String(255))
    # New findings on this asset are assigned to this user (see services/ingestion.py).
    default_assignee_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    # Which product the asset belongs to, and where it runs (models/product.py).
    product_id: Mapped[int | None] = mapped_column(ForeignKey("products.id", ondelete="SET NULL"), index=True)
    environment: Mapped[str | None] = mapped_column(String(20))
