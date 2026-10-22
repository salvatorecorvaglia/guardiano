from typing import Any

from app.core.config import settings
from app.models import Finding
from app.models.base import utcnow
from app.models.enums import ACTIVE_STATUSES
from app.schemas.finding import FindingDetail, FindingOut
from app.services import sla
from app.services.priority import priority

_ACTIVE = {s.value for s in ACTIVE_STATUSES}


def _sla(f: Finding) -> tuple:
    due = sla.due_at(f)
    if due is None:
        return None, False
    return due, f.status in _ACTIVE and due < utcnow()


def _intel(f: Finding) -> dict[str, Any]:
    """Exploitability, when the feeds know this CVE (services/intel.py)."""
    intel = f.intel
    if intel is None:
        return {}
    return {
        "epss": intel.epss,
        "epss_percentile": intel.epss_percentile,
        "in_kev": intel.in_kev,
        "kev_due_date": intel.kev_due_date,
        "kev_ransomware": intel.kev_ransomware,
    }


def finding_out(f: Finding) -> FindingOut:
    due, overdue = _sla(f)
    out = FindingOut.model_validate(f)
    out.sla_due_at, out.overdue, out.priority = due, overdue, priority(f)
    for key, value in _intel(f).items():
        setattr(out, key, value)
    return out


def finding_detail(f: Finding) -> FindingDetail:
    due, overdue = _sla(f)
    out = FindingDetail.model_validate(f)
    out.sla_due_at, out.overdue, out.priority = due, overdue, priority(f)
    for key, value in _intel(f).items():
        setattr(out, key, value)
    return out


def finding_url(finding_id: int) -> str | None:
    """Link back to the finding, when PUBLIC_URL is configured."""
    base = (settings.public_url or "").rstrip("/")
    return f"{base}/findings/{finding_id}" if base else None


def finding_payload(f: Finding, **extra: Any) -> dict[str, Any]:
    """The shape of a finding inside an outbound event (services/events.py)."""
    due, overdue = _sla(f)
    return {
        "finding_id": f.id,
        "title": f.title,
        "type": f.type,
        "severity": f.severity,
        "status": f.status,
        "asset": f.asset.name if f.asset else None,
        "asset_id": f.asset_id,
        "cve": f.cve_id,
        "package": f.package_name,
        "file_path": f.file_path,
        "line_start": f.line_start,
        "tags": list(f.tags or []),
        "due_at": due.isoformat() if due else None,
        "overdue": overdue,
        "priority": priority(f),
        "url": finding_url(f.id),
        **{k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in _intel(f).items()},
        **extra,
    }
