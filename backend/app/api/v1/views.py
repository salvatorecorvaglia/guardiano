from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import case, or_, select
from sqlalchemy.orm import Session, joinedload

from app.core.db import get_db
from app.core.deps import session_user
from app.models import SavedView, User
from app.models.enums import ROLE_RANK, Role
from app.schemas.view import SavedViewCreate, SavedViewOut, SavedViewUpdate

router = APIRouter(prefix="/views", tags=["saved views"])


def _ensure_can_share(user: User) -> None:
    # Shared views appear for everyone, so publishing one takes the analyst role.
    if ROLE_RANK[Role(user.role)] < ROLE_RANK[Role.analyst]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Sharing a view requires the analyst role or higher")


def _own(db: Session, view_id: int, user: User, *, admin_ok: bool = False) -> SavedView:
    view = db.get(SavedView, view_id)
    allowed = view is not None and (
        view.user_id == user.id or (admin_ok and view.shared and user.role == Role.admin.value)
    )
    if not allowed:
        # Other users' views are invisible here, even shared ones: only their owner may change them.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "View not found")
    return view


@router.get("", response_model=list[SavedViewOut])
def list_views(user: User = Depends(session_user), db: Session = Depends(get_db)):
    """Your views first, then views other users shared, each alphabetically."""
    mine = case((SavedView.user_id == user.id, 0), else_=1)
    return db.scalars(
        select(SavedView)
        .options(joinedload(SavedView.user))
        .where(or_(SavedView.user_id == user.id, SavedView.shared.is_(True)))
        .order_by(mine, SavedView.name, SavedView.id)
    ).all()


@router.post("", response_model=SavedViewOut, status_code=status.HTTP_201_CREATED)
def create_view(body: SavedViewCreate, user: User = Depends(session_user), db: Session = Depends(get_db)):
    if body.shared:
        _ensure_can_share(user)
    view = SavedView(user_id=user.id, name=body.name.strip(), query=body.query, shared=body.shared)
    db.add(view)
    db.commit()
    db.refresh(view)
    return view


@router.patch("/{view_id}", response_model=SavedViewOut)
def update_view(
    view_id: int, body: SavedViewUpdate, user: User = Depends(session_user), db: Session = Depends(get_db)
):
    view = _own(db, view_id, user)
    if body.shared:
        _ensure_can_share(user)
    if body.name is not None:
        view.name = body.name.strip()
    if body.query is not None:
        view.query = body.query
    if body.shared is not None:
        view.shared = body.shared
    db.commit()
    db.refresh(view)
    return view


@router.delete("/{view_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_view(view_id: int, user: User = Depends(session_user), db: Session = Depends(get_db)):
    """Owners delete their views; administrators can also remove anyone's shared view."""
    db.delete(_own(db, view_id, user, admin_ok=True))
    db.commit()
