from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db import Base
from app.models.base import TimestampMixin, utcnow


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(200), default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(20), default="viewer")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # Bumped on password change / logout-all to invalidate outstanding refresh tokens.
    token_version: Mapped[int] = mapped_column(Integer, default=0)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Consecutive failed sign-ins, and the lockout they earned (services/lockout.py). The IP-keyed
    # rate limit lives in one worker process; this is per account and shared, so it is what actually
    # stops a slow distributed attack on one person's password.
    failed_logins: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Stable identifier from the identity provider (the "sub" claim), set on first SSO sign-in.
    oidc_subject: Mapped[str | None] = mapped_column(String(255), unique=True, index=True)

    # Second factor for local sign-in (core/totp.py). The secret is encrypted at rest.
    mfa_secret: Mapped[str | None] = mapped_column(Text)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    mfa_confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # The last time step used, so a code cannot be replayed.
    mfa_last_step: Mapped[int | None] = mapped_column(Integer)
    mfa_failed_logins: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    mfa_locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Email notifications (services/email.py); nothing is sent unless SMTP is configured.
    digest_frequency: Mapped[str] = mapped_column(String(10), default="off", server_default="off")
    notify_on_assignment: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    last_digest_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    api_tokens: Mapped[list["ApiToken"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class ApiToken(TimestampMixin, Base):
    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    prefix: Mapped[str] = mapped_column(String(16))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    scopes: Mapped[list[str]] = mapped_column(ARRAY(String(20)), default=list)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped[User] = relationship(back_populates="api_tokens")


class PasswordReset(Base):
    """A single-use password-reset link. Only the hash of the token is stored."""

    __tablename__ = "password_resets"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    requested_ip: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    user: Mapped[User] = relationship()


class OidcState(Base):
    """One in-flight single sign-on attempt.

    Kept in the database rather than a cookie so the flow works across replicas and needs no session
    middleware. Each row is single use and short lived.
    """

    __tablename__ = "oidc_states"

    state: Mapped[str] = mapped_column(String(64), primary_key=True)
    nonce: Mapped[str] = mapped_column(String(64))
    code_verifier: Mapped[str] = mapped_column(String(128))
    redirect_to: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class RecoveryCode(Base):
    """A single-use way back in when the authenticator is gone. Stored hashed."""

    __tablename__ = "recovery_codes"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    code_hash: Mapped[str] = mapped_column(String(64), index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RevokedToken(Base):
    """A refresh token that has been signed out.

    Sessions are stateless JWTs, so signing out can only mean remembering the one token id that must
    no longer be accepted. Rows are keyed by the token's ``jti`` and swept once it has expired on its
    own, which bounds the table by the refresh lifetime rather than by how often people sign out.

    ``users.token_version`` still exists for "sign out everywhere"; this is the single-session case.
    """

    __tablename__ = "revoked_tokens"

    jti: Mapped[str] = mapped_column(String(32), primary_key=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RefreshSession(Base):
    """One browser's refresh family; only its current token may rotate it."""

    __tablename__ = "refresh_sessions"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    current_jti: Mapped[str] = mapped_column(String(32))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_sso: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
