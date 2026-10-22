"""Single sign-on over OpenID Connect.

The authorization-code flow with PKCE, verified strictly:

- the ``state`` is a single-use row in the database, so the flow survives a restart or a second replica and
  is bound to the initiating browser by a short-lived HttpOnly state cookie;
- the ``id_token``'s signature is checked against the provider's published keys, along with its issuer,
  audience, expiry and the ``nonce`` that belongs to this attempt;
- the redirect back into the app is only ever to this installation's own URL;
- every request to the provider (discovery, token, keys) is checked by core/urlguard.py on every hop and
  read within a size limit, like any other operator-supplied URL.

Local accounts keep working unless ``LOCAL_LOGIN=false``. A first sign-in creates the account (unless
``OIDC_AUTO_CREATE=false``), and group claims decide the role.
"""

import json
import logging
import secrets
import time
from datetime import timedelta
from hashlib import sha256
from typing import Any
from urllib.parse import unquote, urlencode

import httpx
import jwt
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientConnectionError
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import hash_password
from app.core.urlguard import BlockedURL, check_url, guarded_client, read_capped
from app.models import OidcState, User
from app.models.base import utcnow
from app.models.enums import Role

log = logging.getLogger(__name__)

STATE_TTL = timedelta(minutes=10)
# Discovery documents and key sets are a few kilobytes; a provider answering with more is misbehaving.
_MAX_RESPONSE = 1024 * 1024
_MAX_REDIRECTS = 5
_discovery_cache: dict[str, Any] = {}
_jwk_clients: dict[str, PyJWKClient] = {}


class SsoError(RuntimeError):
    """Anything that stops a sign-in; the message is safe to show."""


def _b64url(raw: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _client() -> httpx.Client:
    return guarded_client(timeout=settings.oidc_timeout, follow_redirects=False)


def _fetch(method: str, url: str, *, follow: bool = False, **kwargs: Any) -> tuple[int, bytes]:
    """Status and body of one request to the provider.

    The token and key endpoints come from the discovery document, not from configuration, so they are
    checked like the issuer is. Redirects are followed by hand (and only when ``follow``), so that every
    hop is checked too: a discovery URL that redirects to the metadata service must not be followed.
    Raises BlockedURL or TooLarge (both ValueErrors) or an httpx.HTTPError.
    """
    with _client() as client:
        for _ in range(_MAX_REDIRECTS + 1):
            check_url(url)
            with client.stream(method, url, **kwargs) as response:
                if follow and response.is_redirect and response.next_request is not None:
                    url = str(response.next_request.url)
                    continue
                return response.status_code, read_capped(response, _MAX_RESPONSE)
    raise BlockedURL(f"The identity provider redirected more than {_MAX_REDIRECTS} times")


def discovery() -> dict[str, Any]:
    """The provider's configuration, fetched once per process."""
    issuer = settings.oidc_issuer.rstrip("/")
    if issuer not in _discovery_cache:
        url = f"{issuer}/.well-known/openid-configuration"
        try:
            status, body = _fetch("GET", url, follow=True)
            if status >= 400:
                raise ValueError(f"HTTP {status}")
            config = json.loads(body)
        except (httpx.HTTPError, ValueError) as exc:
            raise SsoError(f"Could not read the identity provider's configuration: {exc}")
        if not isinstance(config, dict):
            raise SsoError("The identity provider's configuration is not a JSON object")
        _discovery_cache[issuer] = config
    return _discovery_cache[issuer]


class _GuardedJwkClient(PyJWKClient):
    """PyJWKClient, fetching through _fetch instead of its own unguarded, unbounded urllib request.

    Only the fetch is replaced: key caching, kid lookup and the refetch cooldown stay PyJWT's. The
    cooldown reads ``_last_successful_fetch``, so it is kept up to date here as the original does;
    without it, tokens naming unknown key ids would each trigger a request to the provider.
    """

    def fetch_data(self) -> Any:
        try:
            status, body = _fetch("GET", self.uri)
            if status >= 400:
                raise ValueError(f"HTTP {status}")
            jwk_set = json.loads(body)
        except (httpx.HTTPError, ValueError) as exc:
            raise PyJWKClientConnectionError(f"Could not fetch the identity provider's keys: {exc}") from exc
        if self.jwk_set_cache is not None:
            self.jwk_set_cache.put(jwk_set)
        self._last_successful_fetch = time.monotonic()
        return jwk_set


def _jwk_client() -> PyJWKClient:
    config = discovery()
    uri = config.get("jwks_uri")
    if not uri:
        raise SsoError("The identity provider publishes no jwks_uri")
    if uri not in _jwk_clients:
        _jwk_clients[uri] = _GuardedJwkClient(uri, cache_keys=True)
    return _jwk_clients[uri]


def start(db: Session, redirect_to: str | None = None) -> str:
    """Record an attempt and return the URL to send the browser to."""
    if not settings.oidc_enabled:
        raise SsoError("Single sign-on is not configured on this server")
    if not settings.oidc_callback:
        raise SsoError("PUBLIC_URL (or OIDC_REDIRECT_URL) must be set for single sign-on")
    config = discovery()
    endpoint = config.get("authorization_endpoint")
    if not endpoint:
        raise SsoError("The identity provider publishes no authorization_endpoint")

    state, nonce = secrets.token_urlsafe(32)[:64], secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(64)[:128]
    db.execute(delete(OidcState).where(OidcState.expires_at < utcnow()))  # tidy as we go
    db.add(
        OidcState(
            state=state,
            nonce=nonce,
            code_verifier=verifier,
            redirect_to=safe_redirect(redirect_to),
            expires_at=utcnow() + STATE_TTL,
        )
    )
    query = {
        "response_type": "code",
        "client_id": settings.oidc_client_id,
        "redirect_uri": settings.oidc_callback,
        "scope": settings.oidc_scopes,
        "state": state,
        "nonce": nonce,
        "code_challenge": _b64url(sha256(verifier.encode()).digest()),
        "code_challenge_method": "S256",
    }
    return f"{endpoint}?{urlencode(query)}"


def safe_redirect(target: str | None) -> str | None:
    """Only ever back into this installation: an open redirect is a phishing tool."""
    if (
        not target
        or not target.startswith("/")
        or target.startswith("//")
        or "\\" in unquote(target)
        or any(ord(c) < 32 for c in unquote(target))
    ):
        return None
    return target[:500]


def take_state(db: Session, state: str) -> OidcState:
    row = db.get(OidcState, state, with_for_update=True)
    if row is None:
        raise SsoError("This sign-in attempt is unknown or has already been used")
    expired = row.expires_at <= utcnow()
    db.delete(row)  # single use, whatever happens next
    db.flush()
    if expired:
        raise SsoError("This sign-in attempt has expired; please try again")
    return row


def exchange_code(code: str, verifier: str) -> dict[str, Any]:
    config = discovery()
    endpoint = config.get("token_endpoint")
    if not endpoint:
        raise SsoError("The identity provider publishes no token_endpoint")
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": settings.oidc_callback,
        "client_id": settings.oidc_client_id,
        "code_verifier": verifier,
    }
    if settings.oidc_client_secret:
        data["client_secret"] = settings.oidc_client_secret
    try:
        status, body = _fetch("POST", endpoint, data=data)
    except httpx.HTTPError as exc:
        raise SsoError(f"Could not reach the identity provider: {type(exc).__name__}")
    except ValueError:  # BlockedURL or TooLarge may include provider-controlled URL or response details
        log.warning("OIDC exchange failed an outbound safety check")
        raise SsoError("The identity provider's token endpoint cannot be used; see the server log")
    # A redirect is not followed: the request carries the client secret.
    if status >= 300:
        raise SsoError(f"The identity provider rejected the sign-in (HTTP {status})")
    try:
        return json.loads(body)
    except ValueError:
        raise SsoError("The identity provider returned a token response that is not JSON")


def verify_id_token(token: str, nonce: str) -> dict[str, Any]:
    """Check the signature and every claim that matters, then return the claims."""
    if not token:
        raise SsoError("The identity provider returned no id_token")
    try:
        key = _jwk_client().get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token,
            key,
            algorithms=["RS256", "RS512", "ES256", "PS256"],
            audience=settings.oidc_client_id,
            issuer=settings.oidc_issuer.rstrip("/"),
            options={"require": ["exp", "iat", "sub"]},
        )
    except (jwt.PyJWTError, RecursionError) as exc:
        raise SsoError(f"The identity provider's token could not be verified: {exc}")
    if claims.get("nonce") != nonce:
        raise SsoError("The identity provider's token does not match this sign-in attempt")
    return claims


def role_for(claims: dict[str, Any], current: str | None) -> str:
    """The role a person's group claims map to.

    With a mapping configured, unmatched groups receive OIDC_DEFAULT_ROLE. Without a mapping,
    existing accounts keep their manually managed role.
    """
    groups = claims.get(settings.oidc_groups_claim) or []
    if isinstance(groups, str):
        groups = [g.strip() for g in groups.replace(",", " ").split()]
    names = {str(g).lower() for g in groups}
    for group, role in settings.role_mapping:
        if group.lower() in names and role in {r.value for r in Role}:
            return role
    return settings.oidc_default_role if settings.role_mapping else (current or settings.oidc_default_role)


def sign_in(db: Session, claims: dict[str, Any]) -> User:
    """Find or create the account this token belongs to."""
    subject = str(claims.get("sub") or "")
    email = str(claims.get("email") or "").strip().lower()
    if not subject:
        raise SsoError("The identity provider's token carries no subject")

    # An address is only believed when the provider says it verified it. Without that, anyone who can
    # set their own email at the provider could claim an existing account -- including an admin's.
    verified = email and claims.get("email_verified") is True

    user = db.scalar(select(User).where(User.oidc_subject == subject))
    if user is None and email and settings.oidc_link_by_email:
        # First sign-in for somebody who already has a local account: adopt it, by verified address.
        existing = db.scalar(select(User).where(User.email == email))
        if existing is not None:
            if not verified:
                raise SsoError(
                    "An account with this address already exists, but the identity provider did not "
                    "report the address as verified"
                )
            if existing.oidc_subject and existing.oidc_subject != subject:
                raise SsoError("This account is already linked to a different single sign-on identity")
            user = existing
    if user is not None and not user.is_active:
        # Checked here, before creation: a brand-new object has no column defaults applied yet.
        raise SsoError("This account is disabled")
    if user is None:
        if not settings.oidc_auto_create:
            raise SsoError("This account does not exist in Guardiano and automatic creation is off")
        if not email:
            raise SsoError("The identity provider's token carries no email address")
        if db.scalar(select(User).where(User.email == email)) is not None:
            # Reachable with OIDC_LINK_BY_EMAIL off; creating would violate the unique address.
            raise SsoError("An account with this address already exists and is not linked to sign-on")
        user = User(
            email=email,
            full_name=str(claims.get("name") or claims.get("preferred_username") or "")[:200],
            # Local sign-in is impossible for this account until somebody sets a password.
            password_hash=hash_password(secrets.token_urlsafe(32)),
            role=role_for(claims, None),
        )
        db.add(user)
        log.info("created account for %s from single sign-on", email)

    user.oidc_subject = subject
    if verified:
        # Same reasoning as linking: an unverified address must not rewrite the one already on file,
        # which would otherwise let somebody point an existing account at an address they control.
        user.email = email
    if name := str(claims.get("name") or "").strip():
        user.full_name = name[:200]
    role = role_for(claims, user.role)
    if user.id is not None and role != user.role:
        user.token_version += 1
    user.role = role
    user.last_login_at = utcnow()
    return user
