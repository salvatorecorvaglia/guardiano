from hmac import compare_digest

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.db import get_db
from app.core.schema import check_schema
from app.schemas.analytics import Meta

router = APIRouter(tags=["health"])


@router.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz")
def readyz(db: Session = Depends(get_db)) -> dict[str, str]:
    try:
        db.execute(text("SELECT 1"))
        check_schema(db.connection())
    except Exception as exc:
        raise HTTPException(503, "database unavailable or schema incompatible") from exc
    return {"status": "ready"}


@router.get("/metrics", include_in_schema=False)
def metrics(request: Request, db: Session = Depends(get_db)) -> Response:
    """Prometheus exposition. Off unless METRICS_ENABLED, and never proxied by the bundled nginx."""
    from app.core.config import settings
    from app.services import metrics as m

    if not settings.metrics_enabled:
        raise HTTPException(404, "Not Found")
    if settings.metrics_token:
        offered = (request.headers.get("authorization") or "").removeprefix("Bearer ").strip()
        if not compare_digest(offered, settings.metrics_token):
            raise HTTPException(401, "Invalid metrics token", headers={"WWW-Authenticate": "Bearer"})
    return Response(m.render(m.collect(db)), media_type="text/plain; version=0.0.4; charset=utf-8")


@router.get("/api/v1/meta", response_model=Meta)
def meta(db: Session = Depends(get_db)):
    from app import __version__
    from app.core.config import settings
    from app.parsers.detect import SUPPORTED_FORMATS
    from app.services import sla

    return {
        "name": settings.app_name,
        "version": __version__,
        "formats": list(SUPPORTED_FORMATS),
        "max_upload_mb": settings.max_upload_mb,
        "sla_days": sla.get_policy(db).default_days(),
        "email_enabled": settings.email_enabled,
        "local_login": settings.local_login,
        "oidc_enabled": settings.oidc_enabled,
        "oidc_label": settings.oidc_button_label,
        "docs_enabled": settings.env != "production",
    }
