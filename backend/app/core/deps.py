from collections.abc import Callable
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload

from app.core.config import settings
from app.core.db import get_db
from app.core.security import TOKEN_PREFIX, decode_token, hash_api_token
from app.models import ApiToken, User
from app.models.base import utcnow
from app.models.enums import ROLE_RANK, Role, TokenScope
from app.services.scope import Scope, scope_for


@dataclass
class Principal:
    user: User
    token: ApiToken | None = None


def _unauthorized(detail: str = "Not authenticated") -> HTTPException:
    return HTTPException(status.HTTP_401_UNAUTHORIZED, detail, headers={"WWW-Authenticate": "Bearer"})


_bearer = HTTPBearer(auto_error=False, description="Session access token or API token (gdn_...)")


def get_principal(
    request: Request,
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> Principal:
    if creds is None or creds.scheme.lower() != "bearer" or not creds.credentials:
        raise _unauthorized()
    credential = creds.credentials.strip()

    if credential.startswith(TOKEN_PREFIX):
        token = db.scalar(
            select(ApiToken)
            .options(joinedload(ApiToken.user))  # always read below; one query rather than two
            .where(ApiToken.token_hash == hash_api_token(credential))
        )
        now = utcnow()
        if (
            token is None
            or token.revoked_at is not None
            or (token.expires_at is not None and token.expires_at <= now)
            or not token.user.is_active
        ):
            raise _unauthorized("Invalid or expired API token")
        # Avoid a write on every request: only bump last_used_at once a minute.
        if token.last_used_at is None or (now - token.last_used_at).total_seconds() > 60:
            token.last_used_at = now
            db.commit()
        request.state.user_id = token.user_id
        request.state.via_token = True
        return Principal(user=token.user, token=token)

    payload = decode_token(credential, "access")
    if payload is None:
        raise _unauthorized("Invalid or expired session")
    if not settings.local_login and not payload.get("sso"):
        raise _unauthorized("This server requires single sign-on")
    user = db.get(User, int(payload["sub"]))
    if user is None or not user.is_active:
        raise _unauthorized("User is disabled")
    # token_version is bumped on password/role changes and "sign out everywhere".
    if payload.get("ver") != user.token_version:
        raise _unauthorized("Session was revoked")
    enforced = {role.strip().lower() for role in settings.mfa_enforced_roles.split(",") if role.strip()}
    enrollment_paths = {
        "/api/v1/auth/me",
        "/api/v1/auth/mfa",
        "/api/v1/auth/mfa/setup",
        "/api/v1/auth/mfa/enable",
        "/api/v1/auth/logout",
        "/api/v1/auth/logout-all",
    }
    if (
        user.role in enforced
        and not user.mfa_enabled
        and not payload.get("sso")
        and request.url.path not in enrollment_paths
    ):
        raise HTTPException(403, "Set up two-factor authentication before accessing the application")
    request.state.user_id = user.id
    return Principal(user=user)


def require(
    min_role: Role = Role.viewer, token_scope: TokenScope | None = TokenScope.read
) -> Callable[..., User]:
    """Authorize by minimum role. API tokens are only accepted when ``token_scope`` is granted to them;
    ``token_scope=None`` makes the endpoint session-only (interactive users)."""

    def dependency(principal: Principal = Depends(get_principal)) -> User:
        if principal.token is not None and (
            token_scope is None or token_scope.value not in (principal.token.scopes or [])
        ):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "API token is not allowed to perform this action")
        if ROLE_RANK[Role(principal.user.role)] < ROLE_RANK[min_role]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Requires role '{min_role.value}' or higher")
        return principal.user

    return dependency


def get_scope(principal: Principal = Depends(get_principal), db: Session = Depends(get_db)) -> Scope:
    """The assets this request may see. An API token carries the scope of whoever owns it."""
    return scope_for(db, principal.user)


current_user = require(Role.viewer, TokenScope.read)
session_user = require(Role.viewer, None)
# Administrators only, and never through an API token: configuration is changed by a person.
admin_only = require(Role.admin, None)
