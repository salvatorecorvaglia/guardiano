from functools import lru_cache
from typing import Annotated, Literal, get_args

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict
from sqlalchemy import URL

DEFAULT_SECRET = "change-me-in-production-please-use-a-long-random-value"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    env: Literal["development", "test", "production"] = "development"
    app_name: str = "Guardiano"
    log_level: str = "INFO"
    log_json: bool = True

    database_url: str = ""
    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "guardiano"
    postgres_user: str = "guardiano"
    postgres_password: str = "guardiano"
    # Per worker process: keep WEB_CONCURRENCY x (pool + overflow) below Postgres max_connections (100).
    db_pool_size: int = 5
    db_max_overflow: int = 5

    secret_key: str = DEFAULT_SECRET
    access_token_ttl_minutes: int = 30
    refresh_token_ttl_days: int = 7
    cookie_secure: bool | None = None  # defaults to True in production

    cors_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)

    max_upload_mb: int = 50
    max_report_findings: int = Field(100_000, ge=1)
    max_report_components: int = Field(100_000, ge=1)
    max_concurrent_ingests: int = Field(2, ge=1, le=32)
    # Keyed on the client address, and held per worker process, so it is a coarse throttle only.
    login_rate_limit: str = "10/minute"
    # Per account, in the database: what actually stops a distributed attack on one password.
    login_max_failures: int = 10
    login_lockout_seconds: int = 60  # doubles with each further failure
    login_lockout_max_seconds: int = 3600

    # Hosts that outbound requests (webhooks, issue trackers, feeds) may reach even though they
    # resolve to a private or reserved address. For an internal Jira or a feed mirror.
    outbound_allow_hosts: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # Remediation SLA (days) per severity, used for "overdue" analytics.
    sla_critical_days: int = 7
    sla_high_days: int = 30
    sla_medium_days: int = 90
    sla_low_days: int = 180

    # Follow a SAST finding when its line moves, using the scanner's own fingerprint.
    # Off by default: it changes which results are treated as the same finding.
    dedup_fingerprints: bool = False
    # Treat the ecosystem names different scanners use (go / golang / go-module) as one when
    # matching SCA findings. Off by default for the same reason.
    dedup_canonical_ecosystems: bool = False

    # What to do with a licence that is not in the policy list: "allowed" or "review".
    license_default: Literal["allowed", "review"] = "allowed"

    # Exploitability feeds. Point them at a mirror, or turn the sync off.
    intel_sync_enabled: bool = True
    epss_feed_url: str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
    kev_feed_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    intel_timeout: float = 120.0
    # Where advisory ids (GHSA, PYSEC, ...) are looked up for their CVE; empty turns the lookup off.
    osv_api_url: str = "https://api.osv.dev"
    osv_alias_limit: int = 200  # advisories looked up per daily sync
    # Let exploitability weigh on asset risk scores. Off by default: it changes existing numbers.
    risk_use_exploitability: bool = False
    kev_risk_multiplier: float = 2.0
    epss_risk_multiplier: float = 1.5
    epss_risk_threshold: float = 0.5

    # Encrypts issue-tracker tokens and TOTP secrets. Defaults to deriving a key from SECRET_KEY.
    integrations_key: str = ""
    tracker_timeout: float = 15.0
    # Optional inbound polling: how often to ask a tracker about a linked ticket. 0 turns it off.
    # A finished ticket only ever *suggests* resolving the finding; it never changes its status.
    tracker_poll_hours: int = 0
    tracker_poll_limit: int = 100  # tickets checked per hourly sweep
    # The most tickets one scan may open automatically; the first scan of a large codebase is the risk.
    auto_ticket_per_scan: int = 20
    # Uploads per credential, e.g. "60/minute"; empty means no limit.
    ingest_rate_limit: str = ""

    # Two-factor authentication for local sign-in.
    # Roles that must set it up, e.g. "admin,manager"; they can still sign in and are asked to enrol.
    mfa_required_roles: str = ""
    mfa_enforced_roles: str = ""
    mfa_challenge_ttl_minutes: int = 5

    # Single sign-on (OIDC). Without OIDC_ISSUER only local accounts can sign in.
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_scopes: str = "openid profile email"
    oidc_redirect_url: str = ""  # defaults to PUBLIC_URL + /api/v1/auth/oidc/callback
    oidc_button_label: str = "Sign in with SSO"
    oidc_groups_claim: str = "groups"
    # "idp-admins:admin,appsec:manager" — the first match wins, in the order written.
    oidc_role_map: str = ""
    oidc_default_role: Literal["viewer", "analyst", "manager", "admin"] = "viewer"
    oidc_auto_create: bool = True  # create an account on first sign-in
    # On a first single sign-on, adopt an existing local account with the same address. The address is
    # only ever believed when the provider marks it verified, so it cannot be used to claim an account.
    oidc_link_by_email: bool = True
    oidc_timeout: float = 15.0
    local_login: bool = True  # turn off to require single sign-on

    # Email (SMTP). Without SMTP_HOST nothing is sent and the email features stay hidden.
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_security: Literal["starttls", "ssl", "none"] = "starttls"
    smtp_from: str = "guardiano@localhost"
    smtp_timeout: int = 15
    digest_hour_utc: int = Field(7, ge=0, le=23)  # when the daily/weekly digest goes out
    password_reset_ttl_minutes: int = 60

    # Outbound events (webhooks and email).
    public_url: str = ""  # e.g. https://guardiano.example.com, used for links in notifications
    # Deprecated compatibility setting: the SLA sweep now drains the entire durable backlog.
    sla_breach_window_hours: int = 24
    # finding.risk_acceptance_expiring is sent this many days before an acceptance ends; 0 turns it off.
    risk_acceptance_warning_days: int = 14
    # Bounds on every risk acceptance, however it is granted. 0 days = no limit.
    risk_acceptance_require_expiry: bool = False
    risk_acceptance_max_days: int = 0
    # A second person must approve: managers cannot accept a risk directly, only approve a request.
    risk_acceptance_four_eyes: bool = False
    event_batch_limit: int = 200  # most findings one periodic sweep may announce

    # Background worker (python -m app.cli worker).
    worker_poll_seconds: float = 2.0
    job_max_attempts: int = 5
    job_retention_days: int = 14  # finished jobs older than this are pruned; dead jobs are kept

    # Prometheus. Off by default; the endpoint sits outside /api so the bundled nginx never proxies it.
    # Retention. 0 means keep forever; deleting history is the operator's decision, not ours.
    retention_scan_days: int = 0  # findings and their events are always kept
    retention_delivery_days: int = 0
    retention_audit_days: int = 0

    metrics_enabled: bool = False
    metrics_token: str = ""  # when set, /metrics requires 'Authorization: Bearer <token>'

    # First-admin bootstrap (only used when no users exist).
    guardiano_admin_email: str | None = None
    guardiano_admin_password: str | None = None

    @field_validator("outbound_allow_hosts", mode="before")
    @classmethod
    def _split_hosts(cls, v: object) -> object:
        if isinstance(v, str):
            return [h.strip().lower() for h in v.split(",") if h.strip()]
        return v

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, v: object) -> object:
        if isinstance(v, str):
            v = v.strip()
            if not v:
                return []
            if v.startswith("["):
                import json

                v = json.loads(v)
            else:
                v = [o.strip() for o in v.split(",") if o.strip()]
        if isinstance(v, list) and "*" in v:
            # Starlette pairs allow_all_origins with allow_credentials by reflecting whatever Origin
            # asked, so "*" here would let any site on the internet call this API as the signed-in
            # user. Naming the origins is the only safe way to run cross-origin.
            raise ValueError("CORS_ORIGINS cannot be '*' because credentials are allowed; list the origins")
        return v

    @model_validator(mode="after")
    def _check_production(self) -> "Settings":
        if not self.database_url:
            self.database_url = URL.create(
                "postgresql+psycopg",
                username=self.postgres_user,
                password=self.postgres_password,
                host=self.postgres_host,
                port=self.postgres_port,
                database=self.postgres_db,
            ).render_as_string(hide_password=False)
        if self.env == "production" and (self.secret_key == DEFAULT_SECRET or len(self.secret_key) < 32):
            raise ValueError(
                "SECRET_KEY must be set to a random value of at least 32 characters when ENV=production"
            )
        if self.cookie_secure is None:
            self.cookie_secure = self.env == "production"
        # Refusing every way in would lock the installation out of itself.
        if not self.local_login and not self.oidc_enabled:
            raise ValueError("LOCAL_LOGIN=false requires single sign-on to be configured (OIDC_ISSUER)")
        self._warn_about_quiet_traps()
        return self

    def _warn_about_quiet_traps(self) -> None:
        """Configuration that is valid, does something surprising, and says nothing about it.

        Warnings rather than errors: each of these is a legitimate way to run Guardiano, and refusing
        to start would be worse than the surprise. Printed rather than logged because logging is
        configured from these settings and so is not set up yet.
        """
        import warnings

        if self.integrations_key.strip() == "" and self.env == "production":
            warnings.warn(
                "INTEGRATIONS_KEY is unset, so issue-tracker tokens and two-factor secrets are "
                "encrypted with a key derived from SECRET_KEY. Rotating SECRET_KEY will make all of "
                "them unreadable: every tracker token must be entered again and everybody with "
                "two-factor must be reset with `python -m app.cli reset-mfa`.",
                stacklevel=2,
            )
        # Read off oidc_default_role's own type rather than imported from app.models: importing any
        # model pulls in app.core.db, which imports this module, and settings does not exist yet.
        roles = set(get_args(type(self).model_fields["oidc_default_role"].annotation))
        for entry in self.oidc_role_map.split(","):
            group, _, role = entry.partition(":")
            if group.strip() and role.strip().lower() not in roles:
                warnings.warn(
                    f"OIDC_ROLE_MAP maps '{group.strip()}' to '{role.strip()}', which is not a role "
                    f"({', '.join(sorted(roles))}). That entry is ignored and the group falls "
                    "through to OIDC_DEFAULT_ROLE.",
                    stacklevel=2,
                )

    @property
    def mfa_roles(self) -> set[str]:
        return {r.strip().lower() for r in self.mfa_required_roles.split(",") if r.strip()}

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.oidc_issuer.strip() and self.oidc_client_id.strip())

    @property
    def oidc_callback(self) -> str:
        base = (self.public_url or "").rstrip("/")
        return self.oidc_redirect_url or (f"{base}/api/v1/auth/oidc/callback" if base else "")

    @property
    def role_mapping(self) -> list[tuple[str, str]]:
        pairs = []
        for entry in self.oidc_role_map.split(","):
            group, _, role = entry.partition(":")
            if group.strip() and role.strip():
                pairs.append((group.strip(), role.strip().lower()))
        return pairs

    @property
    def email_enabled(self) -> bool:
        return bool(self.smtp_host.strip())

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024

    @property
    def sla_days(self) -> dict[str, int]:
        return {
            "critical": self.sla_critical_days,
            "high": self.sla_high_days,
            "medium": self.sla_medium_days,
            "low": self.sla_low_days,
        }


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
