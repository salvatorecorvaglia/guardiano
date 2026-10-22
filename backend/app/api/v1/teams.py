"""Teams: who may see which assets.

Only administrators create teams or move assets between them. Everybody else can read the teams they
belong to, so the UI can say why something is restricted.
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.core.db import get_db
from app.core.deps import admin_only, require
from app.models import Asset, Team, User
from app.models.enums import Role
from app.schemas.team import TeamCreate, TeamMembers, TeamOut, TeamUpdate
from app.services import audit
from app.services.scope import teams_of

router = APIRouter(prefix="/teams", tags=["teams"])
viewer = require(Role.viewer)


def _out(db: Session, teams: list[Team]) -> list[TeamOut]:
    ids = [t.id for t in teams]
    assets = (
        dict(
            db.execute(
                select(Asset.team_id, func.count()).where(Asset.team_id.in_(ids)).group_by(Asset.team_id)
            ).all()
        )
        if ids
        else {}
    )
    return [
        TeamOut(
            id=t.id,
            name=t.name,
            description=t.description,
            member_count=len(t.members),
            asset_count=assets.get(t.id, 0),
            members=t.members,
        )
        for t in teams
    ]


def _get(db: Session, team_id: int) -> Team:
    team = db.get(Team, team_id, options=[selectinload(Team.members)])
    if team is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Team not found")
    return team


@router.get("", response_model=list[TeamOut])
def list_teams(user: User = Depends(viewer), db: Session = Depends(get_db)):
    """Every team for an administrator; for anybody else, the teams they are in."""
    if user.role == Role.admin.value:
        teams = list(db.scalars(select(Team).options(selectinload(Team.members)).order_by(Team.name)))
    else:
        teams = teams_of(db, user)
    return _out(db, teams)


@router.post("", response_model=TeamOut, status_code=status.HTTP_201_CREATED)
def create_team(
    body: TeamCreate, request: Request, user: User = Depends(admin_only), db: Session = Depends(get_db)
):
    team = Team(name=body.name.strip(), description=body.description)
    db.add(team)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "A team with this name already exists")
    audit.record(
        db,
        "team.create",
        actor=user,
        request=request,
        target_type="team",
        target_id=team.id,
        target_label=team.name,
    )
    db.commit()
    return _out(db, [team])[0]


@router.patch("/{team_id}", response_model=TeamOut)
def update_team(
    team_id: int,
    body: TeamUpdate,
    request: Request,
    user: User = Depends(admin_only),
    db: Session = Depends(get_db),
):
    team = _get(db, team_id)
    before = audit.snapshot(team, ("name", "description"))
    for key, value in body.model_dump(exclude_unset=True).items():
        setattr(team, key, value.strip() if isinstance(value, str) else value)
    if diff := audit.diff(before, team):
        audit.record(
            db,
            "team.update",
            actor=user,
            request=request,
            target_type="team",
            target_id=team.id,
            target_label=team.name,
            changes=diff,
        )
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "A team with this name already exists")
    return _out(db, [team])[0]


@router.put("/{team_id}/members", response_model=TeamOut)
def set_members(
    team_id: int,
    body: TeamMembers,
    request: Request,
    user: User = Depends(admin_only),
    db: Session = Depends(get_db),
):
    """Replace the membership. Anybody removed loses sight of the team's assets immediately."""
    team = _get(db, team_id)
    wanted = list(db.scalars(select(User).where(User.id.in_(body.user_ids)))) if body.user_ids else []
    if len(wanted) != len(set(body.user_ids)):
        raise HTTPException(422, "One of those users does not exist")
    before = sorted(m.email for m in team.members)
    team.members[:] = wanted
    after = sorted(m.email for m in wanted)
    if before != after:
        audit.record(
            db,
            "team.members",
            actor=user,
            request=request,
            target_type="team",
            target_id=team.id,
            target_label=team.name,
            changes={"members": {"from": before, "to": after}},
        )
    db.commit()
    return _out(db, [team])[0]


@router.delete("/{team_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_team(
    team_id: int, request: Request, user: User = Depends(admin_only), db: Session = Depends(get_db)
):
    """Deleting a team releases its assets: they become visible to everyone again, rather than to nobody."""
    team = _get(db, team_id)
    released = db.execute(
        select(func.count()).select_from(Asset).where(Asset.team_id == team.id)
    ).scalar_one()
    audit.record(
        db,
        "team.delete",
        actor=user,
        request=request,
        target_type="team",
        target_id=team.id,
        target_label=team.name,
        changes={"assets_released": released},
    )
    db.delete(team)  # assets.team_id is ON DELETE SET NULL
    db.commit()
