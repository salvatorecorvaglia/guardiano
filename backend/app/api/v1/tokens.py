from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.core.db import get_db
from app.core.deps import session_user
from app.core.security import generate_api_token
from app.models import ApiToken, User
from app.models.base import utcnow
from app.models.enums import ROLE_RANK, Role, TokenScope
from app.schemas.user import TokenCreate, TokenCreated, TokenOut
from app.services import audit

router = APIRouter(prefix="/tokens", tags=["api tokens"])


@router.get("", response_model=list[TokenOut])
def list_tokens(all: bool = False, user: User = Depends(session_user), db: Session = Depends(get_db)):
    q = select(ApiToken).options(joinedload(ApiToken.user)).order_by(ApiToken.created_at.desc())
    if not (all and user.role == Role.admin.value):
        q = q.where(ApiToken.user_id == user.id)
    return db.scalars(q).all()


@router.post("", response_model=TokenCreated, status_code=status.HTTP_201_CREATED)
def create_token(
    body: TokenCreate, request: Request, user: User = Depends(session_user), db: Session = Depends(get_db)
):
    scopes = sorted({s.value for s in body.scopes})
    if not scopes:
        raise HTTPException(422, "At least one scope is required")
    for scope in (TokenScope.ingest.value, TokenScope.triage.value):
        if scope in scopes and ROLE_RANK[Role(user.role)] < ROLE_RANK[Role.analyst]:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN, f"The '{scope}' scope requires the analyst role or higher"
            )
    raw, prefix, digest = generate_api_token()
    token = ApiToken(
        user_id=user.id,
        name=body.name,
        prefix=prefix,
        token_hash=digest,
        scopes=scopes,
        expires_at=utcnow() + timedelta(days=body.expires_in_days) if body.expires_in_days else None,
    )
    db.add(token)
    db.flush()
    audit.record(
        db,
        "token.create",
        actor=user,
        request=request,
        target_type="token",
        target_id=token.id,
        target_label=f"{token.name} ({token.prefix}…)",
        changes={"scopes": scopes, "expires_at": token.expires_at.isoformat() if token.expires_at else None},
    )
    db.commit()
    db.refresh(token)
    return TokenCreated(**TokenOut.model_validate(token).model_dump(), token=raw)


@router.delete("/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_token(
    token_id: int, request: Request, user: User = Depends(session_user), db: Session = Depends(get_db)
):
    token = db.get(ApiToken, token_id)
    if token is None or (token.user_id != user.id and user.role != Role.admin.value):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Token not found")
    if token.revoked_at is None:
        token.revoked_at = utcnow()
        audit.record(
            db,
            "token.revoke",
            actor=user,
            request=request,
            target_type="token",
            target_id=token.id,
            target_label=f"{token.name} ({token.prefix}…)",
            changes={"owner_id": token.user_id},
        )
        db.commit()
