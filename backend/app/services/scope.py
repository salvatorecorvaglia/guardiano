"""Who can see which assets.

A team is a **restriction you add**, not a default:

- an asset with no team is visible to everyone, so an installation that uses no teams behaves exactly as it
  did before they existed;
- an asset in a team is visible to that team's members;
- administrators see everything, because they manage the assets and the teams themselves.

Everything anybody reads about findings, scans, components and analytics is narrowed by the one condition
built here, so there is a single place to get right and a single place to audit. The teams somebody belongs
to are read once per request into a :class:`Scope`; the condition itself is pure SQL, so the query builders
stay free of session lookups.
"""

from dataclasses import dataclass

from sqlalchemy import ColumnElement, Select, or_, select, true
from sqlalchemy.orm import Session, selectinload

from app.models import Asset, Team, User, team_members
from app.models.enums import Role


@dataclass(frozen=True)
class Scope:
    """The assets one person may see. ``team_ids is None`` means "everything"."""

    team_ids: tuple[int, ...] | None = None

    @property
    def unrestricted(self) -> bool:
        return self.team_ids is None

    def assets(self) -> ColumnElement:
        """A condition over the ``assets`` table itself."""
        if self.unrestricted:
            return true()
        untamed = Asset.team_id.is_(None)
        return or_(untamed, Asset.team_id.in_(self.team_ids)) if self.team_ids else untamed

    def owns(self, asset: Asset | None) -> bool:
        if asset is None:
            return False
        return self.unrestricted or asset.team_id is None or asset.team_id in (self.team_ids or ())

    def where(self, column: ColumnElement) -> ColumnElement:
        """The same rule for any column holding an asset id (findings, scans, components)."""
        if self.unrestricted:
            return true()
        return column.in_(select(Asset.id).where(self.assets()))

    def narrow(self, stmt: Select, column: ColumnElement) -> Select:
        return stmt if self.unrestricted else stmt.where(self.where(column))


GLOBAL = Scope()


def scope_for(db: Session, user: User | None) -> Scope:
    """What this person can see. Administrators, and requests with no user, are unrestricted."""
    if user is None or user.role == Role.admin.value:
        return GLOBAL
    ids = db.scalars(select(team_members.c.team_id).where(team_members.c.user_id == user.id))
    return Scope(team_ids=tuple(sorted(ids)))


def teams_of(db: Session, user: User) -> list[Team]:
    # Members are loaded with the teams: the caller lists them, and reading team.members lazily was
    # one more query per team.
    return list(
        db.scalars(
            select(Team)
            .join(team_members, team_members.c.team_id == Team.id)
            .where(team_members.c.user_id == user.id)
            .options(selectinload(Team.members))
            .order_by(Team.name)
        )
    )


class ScopeCache:
    """Authorization snapshots shared only within one mutation operation."""

    def __init__(self, db: Session):
        self.db = db
        self.scopes: dict[int, Scope] = {}
        self.users: dict[int, User | None] = {}

    def user(self, user_id: int) -> User | None:
        if user_id not in self.users:
            self.users[user_id] = self.db.get(User, user_id)
        return self.users[user_id]

    def scope(self, user: User) -> Scope:
        if user.id not in self.scopes:
            self.scopes[user.id] = scope_for(self.db, user)
        return self.scopes[user.id]
