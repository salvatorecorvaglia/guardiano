import re
from datetime import datetime
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, Field

from app.models.enums import Role, TokenScope
from app.schemas.common import ORMModel

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _email(v: str) -> str:
    # Deliberately permissive: internal domains (.local, .corp, .internal) are common on-prem.
    v = v.strip().lower()
    if len(v) > 320 or not _EMAIL_RE.match(v):
        raise ValueError("invalid email address")
    return v


Email = Annotated[str, AfterValidator(_email)]


class UserOut(ORMModel):
    id: int
    email: str
    full_name: str
    role: Role
    is_active: bool
    last_login_at: datetime | None
    created_at: datetime
    mfa_enabled: bool = False
    # True when this role must set up a second factor and has not yet.
    mfa_setup_required: bool = False
    mfa_enrollment_required: bool = False


class UserBrief(ORMModel):
    id: int
    email: str
    full_name: str


class UserCreate(BaseModel):
    email: Email
    full_name: str = Field("", max_length=200)
    password: str = Field(min_length=12, max_length=256)
    role: Role = Role.viewer


class UserUpdate(BaseModel):
    full_name: str | None = Field(None, max_length=200)
    role: Role | None = None
    is_active: bool | None = None
    password: str | None = Field(None, min_length=12, max_length=256)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserOut


class ChangePassword(BaseModel):
    current_password: str
    new_password: str = Field(min_length=12, max_length=256)


class TokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    scopes: list[TokenScope] = Field(default_factory=lambda: [TokenScope.ingest])
    expires_in_days: int | None = Field(90, ge=1, le=3650)


class TokenOut(ORMModel):
    id: int
    name: str
    prefix: str
    scopes: list[TokenScope]
    expires_at: datetime | None
    last_used_at: datetime | None
    revoked_at: datetime | None
    created_at: datetime
    user: UserBrief


class TokenCreated(TokenOut):
    token: str


class ForgotPassword(BaseModel):
    email: str = Field(max_length=320)


class ResetPassword(BaseModel):
    token: str = Field(min_length=16, max_length=128)
    new_password: str = Field(min_length=12, max_length=256)


class NotificationPrefs(ORMModel):
    """Email preferences. Nothing is sent unless the server has SMTP configured."""

    digest_frequency: Literal["off", "daily", "weekly"] = "off"
    notify_on_assignment: bool = True


class NotificationPrefsUpdate(BaseModel):
    digest_frequency: Literal["off", "daily", "weekly"] | None = None
    notify_on_assignment: bool | None = None


class MfaChallenge(BaseModel):
    """Returned instead of a session when the account has a second factor."""

    mfa_required: bool = True
    mfa_token: str
    expires_in: int


class MfaVerify(BaseModel):
    mfa_token: str
    code: str = Field(min_length=6, max_length=20, description="A TOTP code or a recovery code")


class MfaSetup(BaseModel):
    secret: str
    otpauth_uri: str


class MfaEnabled(BaseModel):
    """The recovery codes are shown once, here."""

    recovery_codes: list[str]
    session: LoginResponse | None = None


class MfaEnrollment(MfaEnabled):
    session: LoginResponse


class MfaStatus(BaseModel):
    enabled: bool
    required: bool  # this role must set it up
    confirmed_at: datetime | None
    recovery_codes_left: int


class MfaCode(BaseModel):
    code: str = Field(min_length=6, max_length=20)


class MfaDisable(BaseModel):
    password: str = Field(max_length=256)
    code: str = Field(min_length=6, max_length=20)
