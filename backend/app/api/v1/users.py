from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.deps import admin_only, require
from app.core.security import hash_password
from app.models import User
from app.models.enums import Role
from app.schemas.user import UserBrief, UserCreate, UserOut, UserUpdate
from app.services import audit

router = APIRouter(prefix="/users", tags=["users"])


def _active_admins(db: Session) -> int:
    return db.scalar(select(func.count()).where(User.role == Role.admin.value, User.is_active.is_(True))) or 0


@router.get("/directory", response_model=list[UserBrief])
def directory(_: User = Depends(require(Role.viewer)), db: Session = Depends(get_db)):
    """Active users, for assignee pickers."""
    return db.scalars(select(User).where(User.is_active.is_(True)).order_by(User.full_name, User.email)).all()


@router.get("", response_model=list[UserOut])
def list_users(_: User = Depends(admin_only), db: Session = Depends(get_db)):
    return db.scalars(select(User).order_by(User.created_at)).all()


@router.post("", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    body: UserCreate, request: Request, admin: User = Depends(admin_only), db: Session = Depends(get_db)
):
    user = User(
        email=body.email.lower(),
        full_name=body.full_name,
        password_hash=hash_password(body.password),
        role=body.role.value,
    )
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "A user with this email already exists")
    audit.record(
        db,
        "user.create",
        actor=admin,
        request=request,
        target_type="user",
        target_id=user.id,
        target_label=user.email,
        changes={"role": user.role},
    )
    db.commit()
    return user


@router.patch("/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    body: UserUpdate,
    request: Request,
    admin: User = Depends(admin_only),
    db: Session = Depends(get_db),
):
    db.execute(text("SELECT pg_advisory_xact_lock(26468, 1)"))
    user = db.get(User, user_id, populate_existing=True)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    demoting = body.role is not None and body.role != Role.admin and user.role == Role.admin.value
    disabling = body.is_active is False and user.role == Role.admin.value
    if (demoting or disabling) and _active_admins(db) <= 1:
        raise HTTPException(status.HTTP_409_CONFLICT, "Cannot remove the last active administrator")
    before = audit.snapshot(user, ("full_name", "role", "is_active"))
    if body.full_name is not None:
        user.full_name = body.full_name
    if body.role is not None:
        user.role = body.role.value
        user.token_version += 1
    if body.is_active is not None:
        user.is_active = body.is_active
        user.token_version += 1
    if body.password:
        user.password_hash = hash_password(body.password)
        user.token_version += 1
    changes = audit.diff(before, user)
    if body.password:
        changes["password"] = "changed"
    if changes:
        audit.record(
            db,
            "user.update",
            actor=admin,
            request=request,
            target_type="user",
            target_id=user.id,
            target_label=user.email,
            changes=changes,
        )
    db.commit()
    return user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int, request: Request, admin: User = Depends(admin_only), db: Session = Depends(get_db)
):
    db.execute(text("SELECT pg_advisory_xact_lock(26468, 1)"))
    user = db.get(User, user_id, populate_existing=True)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    if user.id == admin.id:
        raise HTTPException(status.HTTP_409_CONFLICT, "You cannot delete your own account")
    if user.role == Role.admin.value and _active_admins(db) <= 1:
        raise HTTPException(status.HTTP_409_CONFLICT, "Cannot remove the last active administrator")
    audit.record(
        db,
        "user.delete",
        actor=admin,
        request=request,
        target_type="user",
        target_id=user.id,
        target_label=user.email,
        changes={"role": user.role},
    )
    db.delete(user)
    db.commit()
