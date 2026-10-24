import logging
import secrets
import uuid
from datetime import timedelta
from hmac import compare_digest
from urllib.parse import parse_qs, quote, urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import get_db
from app.core.deps import session_user
from app.core.ratelimit import limiter
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_api_token,
    hash_password,
    needs_rehash,
    verify_password,
)
from app.models import PasswordReset, RefreshSession, User
from app.models.base import utcnow
from app.schemas.user import (
    ChangePassword,
    ForgotPassword,
    LoginResponse,
    MfaChallenge,
    MfaCode,
    MfaDisable,
    MfaEnabled,
    MfaEnrollment,
    MfaSetup,
    MfaStatus,
    MfaVerify,
    NotificationPrefs,
    NotificationPrefsUpdate,
    ResetPassword,
    UserOut,
)
from app.services import audit, email, jobs, lockout, mfa, oidc, sessions

router = APIRouter(prefix="/auth", tags=["auth"])
log = logging.getLogger(__name__)

REFRESH_COOKIE = "guardiano_refresh"
COOKIE_PATH = "/api/v1/auth"
# Verifying against a dummy hash keeps response time similar for unknown emails.
_DUMMY_HASH = hash_password("guardiano-timing-equalizer")


class LoginRequest(BaseModel):
    email: str = Field(max_length=320)
    password: str = Field(max_length=256)


def _out(user: User, *, sso: bool = False) -> UserOut:
    out = UserOut.model_validate(user)
    out.mfa_setup_required = mfa.setup_required(user)
    out.mfa_enrollment_required = (
        user.role in {r.strip().lower() for r in settings.mfa_enforced_roles.split(",")}
        and not user.mfa_enabled
        and not sso
    )
    return out


def _issue(
    response: Response, user: User, db: Session, family: RefreshSession | None = None, *, sso: bool = False
) -> LoginResponse:
    if family is None:
        family = RefreshSession(id=uuid.uuid4().hex, user_id=user.id, is_sso=sso)
        db.add(family)
    token = create_refresh_token(user.id, user.token_version, session_id=family.id)
    payload = decode_token(token, "refresh")
    family.current_jti = payload["jti"]
    family.expires_at = utcnow() + timedelta(days=settings.refresh_token_ttl_days)
    db.commit()
    response.set_cookie(
        REFRESH_COOKIE,
        token,
        max_age=settings.refresh_token_ttl_days * 86400,
        httponly=True,
        secure=bool(settings.cookie_secure),
        # "strict" would never send this cookie from a UI on another origin, so /auth/refresh -- the
        # only way the SPA recovers a session -- would silently fail in exactly the deployment
        # CORS_ORIGINS exists for. "lax" still withholds it from cross-site POSTs, and /refresh is
        # POST-only, so the CSRF that matters here is still covered.
        samesite="lax" if settings.cors_origins else "strict",
        path=COOKIE_PATH,
    )
    out = _out(user, sso=family.is_sso)
    return LoginResponse(
        access_token=create_access_token(user.id, user.role, user.token_version, sso=family.is_sso),
        expires_in=settings.access_token_ttl_minutes * 60,
        user=out,
    )


@router.post("/login", response_model=LoginResponse | MfaChallenge)
@limiter.limit(settings.login_rate_limit)
def login(request: Request, body: LoginRequest, response: Response, db: Session = Depends(get_db)):
    if not settings.local_login:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "This server requires single sign-on; password sign-in is disabled"
        )
    email = body.email.strip().lower()
    user = db.scalar(select(User).where(func.lower(User.email) == email).with_for_update())
    # The password is always verified, even for a locked or unknown account, so that the response
    # time does not say which of the three happened.
    locked = lockout.is_locked(user)
    if user is None:
        verify_password(body.password, _DUMMY_HASH)
        correct = False
    else:
        correct = verify_password(body.password, user.password_hash)
    if locked or not correct or user is None or not user.is_active:
        if not locked and correct is False:
            lockout.record_failure(user)
        audit.record(
            db,
            "auth.login_locked" if locked or lockout.is_locked(user) else "auth.login_failed",
            actor=None,
            request=request,
            target_type="user",
            target_id=user.id if user else None,
            target_label=email,
        )
        db.commit()
        # One message for every failure: saying "this account is locked" would confirm it exists.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    lockout.record_success(user)
    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)
    if user.mfa_enabled:
        # The password was right, which is not the same as being signed in.
        audit.record(
            db,
            "auth.mfa_challenged",
            actor=user,
            request=request,
            target_type="user",
            target_id=user.id,
            target_label=user.email,
        )
        db.commit()
        return MfaChallenge(
            mfa_token=mfa.challenge_token(user),
            expires_in=settings.mfa_challenge_ttl_minutes * 60,
        )
    user.last_login_at = utcnow()
    audit.record(
        db,
        "auth.login",
        actor=user,
        request=request,
        target_type="user",
        target_id=user.id,
        target_label=user.email,
    )
    db.commit()
    return _issue(response, user, db)


@router.post("/refresh", response_model=LoginResponse)
def refresh(request: Request, response: Response, db: Session = Depends(get_db)):
    token = request.cookies.get(REFRESH_COOKIE)
    payload = decode_token(token, "refresh") if token else None
    user = db.get(User, int(payload["sub"]), with_for_update=True) if payload else None
    if (
        user is None
        or not user.is_active
        or payload.get("ver") != user.token_version
        or sessions.is_revoked(db, payload.get("jti"))
    ):
        response.delete_cookie(REFRESH_COOKIE, path=COOKIE_PATH)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session expired")
    family = None
    if payload.get("sid"):
        family = db.get(RefreshSession, payload["sid"], with_for_update=True)
        if (
            family is None
            or family.user_id != user.id
            or family.revoked_at
            or family.expires_at <= utcnow()
            or family.current_jti != payload["jti"]
        ):
            if family is not None and family.user_id == user.id:
                family.revoked_at = utcnow()
                db.commit()
            raise HTTPException(401, "Session expired")
    else:
        # Consume pre-upgrade tokens before moving them into a tracked family.
        sessions.revoke(db, payload)
    if not settings.local_login and (family is None or not family.is_sso):
        raise HTTPException(401, "This server requires single sign-on")
    return _issue(response, user, db, family)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    """Sign this session out. Deleting the cookie only asks the browser to forget the token; the
    token itself stays valid until it expires, so the one presented here is recorded as revoked."""
    if token := request.cookies.get(REFRESH_COOKIE):
        payload = decode_token(token, "refresh")
        sessions.revoke(db, payload)
        if payload and payload.get("sid"):
            db.execute(
                update(RefreshSession)
                .where(RefreshSession.id == payload["sid"], RefreshSession.user_id == int(payload["sub"]))
                .values(revoked_at=utcnow())
            )
        db.commit()
    response.delete_cookie(REFRESH_COOKIE, path=COOKIE_PATH)


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
def logout_all(
    request: Request, response: Response, user: User = Depends(session_user), db: Session = Depends(get_db)
):
    """Revoke every session of the current user, on all devices."""
    user.token_version += 1
    audit.record(
        db,
        "auth.logout_all",
        actor=user,
        request=request,
        target_type="user",
        target_id=user.id,
        target_label=user.email,
    )
    db.commit()
    response.delete_cookie(REFRESH_COOKIE, path=COOKIE_PATH)


@router.get("/me", response_model=UserOut)
def me(request: Request, user: User = Depends(session_user)):
    token = request.headers.get("authorization", "").removeprefix("Bearer ")
    payload = decode_token(token, "access") or {}
    return _out(user, sso=bool(payload.get("sso")))


@router.post("/change-password", response_model=LoginResponse)
def change_password(
    body: ChangePassword,
    request: Request,
    response: Response,
    user: User = Depends(session_user),
    db: Session = Depends(get_db),
):
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")
    user.password_hash = hash_password(body.new_password)
    user.token_version += 1  # invalidate other sessions
    audit.record(
        db,
        "auth.password_change",
        actor=user,
        request=request,
        target_type="user",
        target_id=user.id,
        target_label=user.email,
        changes={"password": "changed"},
    )
    db.commit()
    # Re-issue this session with the new token version so only *other* sessions are signed out.
    return _issue(response, user, db)


# ---- self-service password reset ----------------------------------------------------------------
#
# Only available when the server can send email. The response never says whether an address exists,
# so this endpoint cannot be used to find out who has an account.


@router.post("/forgot-password", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit(settings.login_rate_limit)
def forgot_password(request: Request, body: ForgotPassword, db: Session = Depends(get_db)):
    if not settings.local_login:
        raise HTTPException(403, "Password recovery is disabled; use single sign-on")
    if not email.enabled():
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "Password reset by email is not configured on this server"
        )
    user = db.scalar(select(User).where(func.lower(User.email) == body.email.strip().lower()))
    if user is not None and user.is_active:
        raw = secrets.token_urlsafe(32)
        db.add(
            PasswordReset(
                user_id=user.id,
                token_hash=hash_api_token(raw),
                expires_at=utcnow() + timedelta(minutes=settings.password_reset_ttl_minutes),
                requested_ip=audit.client_ip(request),
            )
        )
        message = email.password_reset(raw, settings.password_reset_ttl_minutes)
        jobs.enqueue(db, email.SEND_JOB, {**message.as_payload(user.email), "kind": "password_reset"})
        audit.record(
            db,
            "auth.password_reset_requested",
            actor=None,
            request=request,
            target_type="user",
            target_id=user.id,
            target_label=user.email,
        )
        db.commit()


@router.post("/reset-password", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit(settings.login_rate_limit)
def reset_password(request: Request, body: ResetPassword, response: Response, db: Session = Depends(get_db)):
    """Consume recovery proof, revoke sessions, and require the normal sign-in flow."""
    if not settings.local_login:
        raise HTTPException(403, "Password recovery is disabled; use single sign-on")
    reset = db.scalar(select(PasswordReset).where(PasswordReset.token_hash == hash_api_token(body.token)))
    now = utcnow()
    if reset is None or reset.used_at is not None or reset.expires_at <= now or not reset.user.is_active:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "This reset link is invalid or has expired")
    user = db.get(User, reset.user_id, with_for_update=True, populate_existing=True)
    db.refresh(reset, with_for_update={"of": PasswordReset})
    if reset.used_at is not None or not user.is_active:
        raise HTTPException(400, "This reset link is invalid or has expired")
    reset.used_at = now
    db.execute(
        update(PasswordReset)
        .where(PasswordReset.user_id == user.id, PasswordReset.used_at.is_(None))
        .values(used_at=now)
    )
    user.password_hash = hash_password(body.new_password)
    user.token_version += 1
    # Proving control of the address clears a lockout: otherwise somebody locked out by an attacker
    # guessing their password would have no way back in until it expired.
    lockout.record_success(user)
    audit.record(
        db,
        "auth.password_reset",
        actor=user,
        request=request,
        target_type="user",
        target_id=user.id,
        target_label=user.email,
        changes={"password": "reset"},
    )
    db.commit()
    response.delete_cookie(REFRESH_COOKIE, path=COOKIE_PATH)


# ---- notification preferences --------------------------------------------------------------------


@router.get("/preferences", response_model=NotificationPrefs)
def get_preferences(user: User = Depends(session_user)):
    return user


@router.patch("/preferences", response_model=NotificationPrefs)
def update_preferences(
    body: NotificationPrefsUpdate, user: User = Depends(session_user), db: Session = Depends(get_db)
):
    if body.digest_frequency is not None:
        user.digest_frequency = body.digest_frequency
    if body.notify_on_assignment is not None:
        user.notify_on_assignment = body.notify_on_assignment
    db.commit()
    return user


# ---- single sign-on ------------------------------------------------------------------------------


@router.get("/oidc/login", include_in_schema=False)
@limiter.limit(settings.login_rate_limit)
def oidc_login(request: Request, next: str | None = None, db: Session = Depends(get_db)):
    """Send the browser to the identity provider."""
    try:
        url = oidc.start(db, next)
    except oidc.SsoError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
    db.commit()
    redirect = RedirectResponse(url, status_code=status.HTTP_307_TEMPORARY_REDIRECT)
    state = parse_qs(urlsplit(url).query)["state"][0]
    redirect.set_cookie(
        "guardiano_oidc_state",
        state,
        max_age=int(oidc.STATE_TTL.total_seconds()),
        httponly=True,
        secure=bool(settings.cookie_secure),
        samesite="lax",
        path=COOKIE_PATH,
    )
    return redirect


@router.get("/oidc/callback", include_in_schema=False)
def oidc_callback(
    request: Request,
    response: Response,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
    db: Session = Depends(get_db),
):
    """Finish the sign-in: verify the token, issue the session and go back to the app."""
    home = (settings.public_url or "").rstrip("/")

    def failed(reason: str) -> RedirectResponse:
        audit.record(
            db,
            "auth.sso_failed",
            actor=None,
            request=request,
            target_type="user",
            target_label=reason[:300],
        )
        db.commit()
        log.warning("single sign-on failed: %s", reason)
        # Back to the sign-in page with a short reason, never a stack trace.
        return RedirectResponse(f"{home}/?sso_error={quote(reason[:200])}", status_code=303)

    if error:
        # Provider-controlled text must not enter redirects, logs or the audit trail.
        return failed("The identity provider declined this sign-in attempt")
    if not code or not state:
        return failed("The identity provider did not return a code")

    browser_state = request.cookies.get("guardiano_oidc_state", "")
    if not browser_state or not compare_digest(browser_state, state):
        return failed("This sign-in attempt belongs to another browser; start again")

    # Spend the attempt in its own transaction. Rolling back further down would otherwise undo the
    # delete and leave the state -- and its code_verifier -- replayable for the rest of its lifetime.
    try:
        attempt = oidc.take_state(db, state)
        verifier, nonce, redirect_to = attempt.code_verifier, attempt.nonce, attempt.redirect_to
        db.commit()
    except oidc.SsoError as exc:
        db.rollback()
        return failed(str(exc))

    try:
        tokens = oidc.exchange_code(code, verifier)
        claims = oidc.verify_id_token(tokens.get("id_token", ""), nonce)
        user = oidc.sign_in(db, claims)
    except oidc.SsoError as exc:
        db.rollback()
        return failed(str(exc))

    db.flush()
    audit.record(
        db,
        "auth.sso_login",
        actor=user,
        request=request,
        target_type="user",
        target_id=user.id,
        target_label=user.email,
        changes={"role": user.role},
    )
    db.commit()

    target = f"{home}{oidc.safe_redirect(redirect_to) or '/'}"
    redirect = RedirectResponse(target, status_code=303)
    # The SPA keeps no token in storage: it calls /auth/refresh on load, which this cookie answers.
    _issue(redirect, user, db, sso=True)
    redirect.delete_cookie("guardiano_oidc_state", path=COOKIE_PATH)
    return redirect


# ---- two-factor authentication -------------------------------------------------------------------


def _management_user(db: Session, user: User) -> None:
    db.refresh(user, with_for_update=True)
    if mfa.is_locked(user):
        raise HTTPException(429, "Too many second-factor attempts; try again later")


def _management_code(db: Session, user: User, request: Request, code: str, *, recovery: bool = False):
    valid = mfa.check_code(user, code)
    if not valid and recovery:
        valid = mfa.spend_recovery_code(db, user, code)
    if valid:
        mfa.record_success(user)
        return
    mfa.record_failure(user)
    audit.record(
        db,
        "auth.mfa_failed",
        actor=user,
        request=request,
        target_type="user",
        target_id=user.id,
        target_label=user.email,
        changes={"management": True},
    )
    db.commit()  # failures must survive the error response, across API replicas
    raise HTTPException(400, "That code is not valid; check the clock or wait for the next code")


@router.post("/login/mfa", response_model=LoginResponse)
@limiter.limit(settings.login_rate_limit)
def login_mfa(request: Request, body: MfaVerify, response: Response, db: Session = Depends(get_db)):
    """Exchange a challenge for a session, with a TOTP code or a recovery code."""
    user = mfa.read_challenge(db, body.mfa_token)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "This sign-in attempt has expired; start again")
    if mfa.is_locked(user):
        raise HTTPException(401, "Too many second-factor attempts; try again later")

    used_recovery = False
    if not mfa.check_code(user, body.code):
        used_recovery = mfa.spend_recovery_code(db, user, body.code)
        if not used_recovery and mfa.spent(user, body.code):
            mfa.record_failure(user)
            db.commit()
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "That code has already been used; wait for the next one"
            )
        if not used_recovery:
            mfa.record_failure(user)
            audit.record(
                db,
                "auth.mfa_failed",
                actor=user,
                request=request,
                target_type="user",
                target_id=user.id,
                target_label=user.email,
            )
            db.commit()
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "That code is not valid")

    mfa.record_success(user)
    user.last_login_at = utcnow()
    audit.record(
        db,
        "auth.login",
        actor=user,
        request=request,
        target_type="user",
        target_id=user.id,
        target_label=user.email,
        changes={"second_factor": "recovery code" if used_recovery else "app"},
    )
    db.commit()
    return _issue(response, user, db)


@router.get("/mfa", response_model=MfaStatus)
def mfa_status(user: User = Depends(session_user), db: Session = Depends(get_db)):
    return MfaStatus(
        enabled=user.mfa_enabled,
        required=mfa.required_for(user),
        confirmed_at=user.mfa_confirmed_at,
        recovery_codes_left=mfa.unused_recovery_codes(db, user) if user.mfa_enabled else 0,
    )


@router.post("/mfa/setup", response_model=MfaSetup)
def mfa_setup(user: User = Depends(session_user), db: Session = Depends(get_db)):
    """Start enrolment: a new secret, inactive until a code from it is confirmed."""
    if user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "Two-factor authentication is already on")
    secret, uri = mfa.begin_setup(user)
    db.commit()
    return MfaSetup(secret=secret, otpauth_uri=uri)


@router.post("/mfa/enable", response_model=MfaEnrollment)
@limiter.limit(settings.login_rate_limit)
def mfa_enable(
    body: MfaCode,
    request: Request,
    response: Response,
    user: User = Depends(session_user),
    db: Session = Depends(get_db),
):
    """Confirm enrolment with a code from the app, and hand back the recovery codes."""
    _management_user(db, user)
    if user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "Two-factor authentication is already on")
    _management_code(db, user, request, body.code)
    user.mfa_enabled = True
    user.token_version += 1
    mfa.record_success(user)
    user.mfa_confirmed_at = utcnow()
    codes = mfa.issue_recovery_codes(db, user)
    audit.record(
        db,
        "auth.mfa_enabled",
        actor=user,
        request=request,
        target_type="user",
        target_id=user.id,
        target_label=user.email,
    )
    payload = decode_token(request.headers.get("authorization", "").removeprefix("Bearer "), "access") or {}
    session = _issue(response, user, db, sso=bool(payload.get("sso")))
    return MfaEnrollment(recovery_codes=codes, session=session)


@router.post("/mfa/recovery-codes", response_model=MfaEnabled)
@limiter.limit(settings.login_rate_limit)
def mfa_new_recovery_codes(
    body: MfaCode, request: Request, user: User = Depends(session_user), db: Session = Depends(get_db)
):
    """Replace the recovery codes, proving possession of the authenticator first."""
    _management_user(db, user)
    if not user.mfa_enabled:
        raise HTTPException(400, "Two-factor authentication is not enabled")
    _management_code(db, user, request, body.code)
    codes = mfa.issue_recovery_codes(db, user)
    audit.record(
        db,
        "auth.mfa_recovery_codes",
        actor=user,
        request=request,
        target_type="user",
        target_id=user.id,
        target_label=user.email,
    )
    db.commit()
    return MfaEnabled(recovery_codes=codes)


@router.post("/mfa/disable", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit(settings.login_rate_limit)
def mfa_disable(
    body: MfaDisable, request: Request, user: User = Depends(session_user), db: Session = Depends(get_db)
):
    """Turn it off. The current password is required, so a borrowed session cannot weaken the account."""
    _management_user(db, user)
    if not verify_password(body.password, user.password_hash):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")
    if not user.mfa_enabled:
        raise HTTPException(400, "Two-factor authentication is not enabled")
    _management_code(db, user, request, body.code, recovery=True)
    mfa.disable(db, user)
    user.token_version += 1
    audit.record(
        db,
        "auth.mfa_disabled",
        actor=user,
        request=request,
        target_type="user",
        target_id=user.id,
        target_label=user.email,
    )
    db.commit()
