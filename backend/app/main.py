import logging
import re
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded

from app import __version__
from app.api.v1 import (
    acceptances,
    admin,
    analytics,
    assets,
    auth,
    components,
    findings,
    gate,
    health,
    integrations,
    notifications,
    products,
    report_schedules,
    scans,
    search,
    sla,
    teams,
    tokens,
    triage,
    users,
    views,
    vulnerabilities,
    webhooks,
)
from app.core.config import settings
from app.core.logging import configure_logging, request_id_ctx
from app.core.ratelimit import limiter
from app.services import metrics
from app.services.errors import DomainError

configure_logging(settings.log_level, settings.log_json)
log = logging.getLogger("guardiano.http")

# Tracing ids from a proxy in front of us: hex, dashes, at a length that cannot bloat a log line.
_REQUEST_ID = re.compile(r"[A-Za-z0-9._-]{1,64}")


def create_app() -> FastAPI:
    # The bundled nginx proxies everything under /api, so in production these would publish the whole
    # API surface -- every route, model and parameter -- to anyone who can reach the site. They stay
    # on everywhere else, where they are the quickest way to try an endpoint.
    interactive_docs = settings.env != "production"
    app = FastAPI(
        title="Guardiano API",
        version=__version__,
        description="Self-hosted application vulnerability management platform",
        docs_url="/api/docs" if interactive_docs else None,
        redoc_url="/api/redoc" if interactive_docs else None,
        openapi_url="/api/openapi.json" if interactive_docs else None,
        swagger_ui_oauth2_redirect_url="/api/docs/oauth2-redirect" if interactive_docs else None,
    )
    app.state.limiter = limiter

    @app.exception_handler(RateLimitExceeded)
    async def rate_limited(request: Request, exc: RateLimitExceeded) -> JSONResponse:
        # slowapi's own handler answers {"error": ...}; every other error here is {"detail": ...}, which
        # is what clients -- this UI included -- read the message from.
        response = JSONResponse({"detail": f"Too many requests ({exc.detail}); try again shortly"}, 429)
        applied = getattr(request.state, "view_rate_limit", None)
        return request.app.state.limiter._inject_headers(response, applied)

    @app.exception_handler(DomainError)
    async def domain_error(_: Request, exc: DomainError) -> JSONResponse:
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        # Echoed back and written into every log line for this request, so it is accepted only when
        # it looks like an id: anything else is somebody else's text in our logs, at their length.
        offered = request.headers.get("x-request-id", "")
        rid = offered if _REQUEST_ID.fullmatch(offered) else uuid.uuid4().hex
        token = request_id_ctx.set(rid)
        start = time.perf_counter()
        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = rid
            elapsed = time.perf_counter() - start
            if settings.metrics_enabled:
                route = request.scope.get("route")
                # The endpoint template, never the raw path, or /findings/{id} would become one time
                # series per finding. Routers are nested, so this is relative to the router: the
                # constant /api/v1 prefix is not part of it.
                metrics.record_request(
                    request.method,
                    getattr(route, "path", "unmatched"),
                    response.status_code,
                    elapsed,
                )
            if request.url.path not in ("/healthz", "/readyz", "/metrics"):
                log.info(
                    "request",
                    extra={
                        "method": request.method,
                        "path": request.url.path,
                        "status": response.status_code,
                        "duration_ms": round(elapsed * 1000, 1),
                        "user_id": getattr(request.state, "user_id", None),
                    },
                )
            return response
        except Exception:
            log.exception("unhandled error", extra={"method": request.method, "path": request.url.path})
            raise
        finally:
            request_id_ctx.reset(token)

    app.include_router(health.router)
    for r in (
        auth,
        users,
        tokens,
        assets,
        scans,
        findings,
        analytics,
        admin,
        sla,
        views,
        gate,
        triage,
        webhooks,
        integrations,
        components,
        teams,
        acceptances,
        notifications,
        vulnerabilities,
        search,
        products,
        report_schedules,
    ):
        app.include_router(r.router, prefix="/api/v1")
    return app


app = create_app()
