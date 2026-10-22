"""CI quality gates: pass/fail rules evaluated when a scan is ingested.

A gate never changes what is ingested. It records an outcome on the scan, which `POST /scans` returns as
``gate`` so a pipeline can fail the build (``jq -e '.gate.passed'``). Preview scans (services/ingestion.py)
are gated the same way, which lets a pull-request scan fail a build without touching the inventory.

Rules come from the asset's policy, or the global policy (``asset_id IS NULL``) when the asset has none.

Conditions look at one of three things. ``max_new``, ``max_new_cvss``, ``fail_on_new_secrets`` and
``fail_on_reopened`` look at what this scan changed; ``max_open``, ``fail_on_overdue``, ``fail_on_kev`` and
``max_open_epss`` at what the asset carries; ``fail_on_denied_license`` at the components this report lists
(the inventory keeps components a later SBOM no longer lists, so it cannot be asked instead).
"""

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models import Asset, Finding, GatePolicy, Scan, VulnIntel
from app.models.base import utcnow
from app.models.enums import SEVERITY_ORDER
from app.parsers.base import NormalizedComponent, NormalizedFinding
from app.services import licenses, sla
from app.services.queries import ACTIVE, kev_expr, overdue_expr

SEVERITIES = [s.value for s in SEVERITY_ORDER]
# Hard-coded credentials, passwords and cryptographic keys: what a secret scanner reports.
SECRET_CWES = frozenset({"CWE-798", "CWE-259", "CWE-321"})


@dataclass
class GateFinding:
    status: str
    severity: str
    first_seen_at: datetime
    due_at_override: datetime | None
    cve_id: str | None

    @classmethod
    def of(cls, finding: Finding):
        return cls(**{name: getattr(finding, name) for name in cls.__dataclass_fields__})


@dataclass
class Projection:
    replacements: dict[int, GateFinding] = field(default_factory=dict)
    additions: list[GateFinding] = field(default_factory=list)

    def inventory(self, db: Session, asset: Asset):
        """Stream unchanged rows and overlay this scan, without writing preview findings."""
        counts: Counter[str] = Counter()
        overdue = 0
        cves: set[str] = set()
        policy, now = sla.get_policy(), utcnow()

        def include(f):
            nonlocal overdue
            if f.status not in ACTIVE:
                return
            counts[f.severity] += 1
            days = policy.days_for(f.severity, asset.criticality)
            due = f.due_at_override or (f.first_seen_at + timedelta(days=days) if days is not None else None)
            overdue += int(due is not None and due < now)
            if f.cve_id:
                cves.add(f.cve_id)

        rows = db.execute(
            select(
                Finding.id,
                Finding.status,
                Finding.severity,
                Finding.first_seen_at,
                Finding.due_at_override,
                Finding.cve_id,
            )
            .where(Finding.asset_id == asset.id)
            .execution_options(yield_per=500)
        )
        for row in rows:
            include(self.replacements.get(row.id, row))
        for finding in self.additions:
            include(finding)
        intel = {}
        keys = sorted(cves)
        for start in range(0, len(keys), 1000):
            for item in db.scalars(select(VulnIntel).where(VulnIntel.cve_id.in_(keys[start : start + 1000]))):
                intel[item.cve_id] = item
        return counts, overdue, intel


def policy_for(db: Session, asset_id: int) -> GatePolicy | None:
    """The asset's policy, else the global one. Disabled policies do not fall back to the global one."""
    # IN (id, NULL) would never match the global row: NULL is not equal to anything.
    policies = db.scalars(
        select(GatePolicy).where(
            or_(GatePolicy.asset_id == asset_id, GatePolicy.asset_id.is_(None)),
        )
    ).all()
    by_asset = {p.asset_id: p for p in policies}
    policy = by_asset.get(asset_id) or by_asset.get(None)
    return policy if policy is not None and policy.enabled else None


def _open_by_severity(db: Session, asset_id: int) -> dict[str, int]:
    rows = db.execute(
        select(Finding.severity, func.count())
        .where(Finding.asset_id == asset_id, Finding.status.in_(ACTIVE))
        .group_by(Finding.severity)
    ).all()
    return {sev: n for sev, n in rows}


def _violation(
    rule: str, message: str, limit: float | None, actual: int, severity: str | None = None
) -> dict:
    return {"rule": rule, "severity": severity, "limit": limit, "actual": actual, "message": message}


def _listing(items: list[str]) -> str:
    return ", ".join(items[:3]) + (f" and {len(items) - 3} more" if len(items) > 3 else "")


def evaluate(
    db: Session,
    *,
    asset: Asset,
    new_by_severity: Counter[str] | dict[str, int],
    reopened: int,
    policy: GatePolicy | None,
    new: Sequence[NormalizedFinding] = (),
    components: Sequence[NormalizedComponent] = (),
    projection: Projection | None = None,
) -> dict[str, Any] | None:
    """The gate outcome for a scan, or None when no policy applies (nothing is recorded then).

    ``new`` is the findings this scan introduces and ``components`` what its report lists; conditions
    that need neither ignore them.
    """
    if policy is None:
        return None
    conditions = policy.conditions or {}
    projected = (
        projection.inventory(db, asset)
        if projection is not None
        and any(
            conditions.get(key) is not None and conditions.get(key) is not False
            for key in ("max_open", "fail_on_overdue", "fail_on_kev", "max_open_epss")
        )
        else None
    )
    violations: list[dict[str, Any]] = []

    for severity, limit in (conditions.get("max_new") or {}).items():
        actual = int(new_by_severity.get(severity, 0))
        if actual > limit:
            violations.append(
                _violation(
                    "max_new",
                    f"{actual} new {severity} finding(s), limit {limit}",
                    limit,
                    actual,
                    severity,
                )
            )

    max_open = conditions.get("max_open") or {}
    if max_open:
        open_counts = projected[0] if projected is not None else _open_by_severity(db, asset.id)
        for severity, limit in max_open.items():
            actual = open_counts.get(severity, 0)
            if actual > limit:
                violations.append(
                    _violation(
                        "max_open",
                        f"{actual} open {severity} finding(s) on {asset.name}, limit {limit}",
                        limit,
                        actual,
                        severity,
                    )
                )

    if conditions.get("fail_on_overdue"):
        overdue = (
            projected[1]
            if projected is not None
            else (
                db.scalar(
                    select(func.count())
                    .select_from(Finding)
                    .where(Finding.asset_id == asset.id, overdue_expr())
                )
                or 0
            )
        )
        if overdue:
            violations.append(
                _violation("fail_on_overdue", f"{overdue} finding(s) past their SLA", None, overdue)
            )

    if conditions.get("fail_on_kev"):
        # Asset-wide, like fail_on_overdue: something already being exploited in the wild does not stop
        # mattering because this particular scan did not introduce it.
        if projected is not None:
            cves = sorted(k for k, item in projected[2].items() if item.in_kev)
        else:
            exploited = db.scalars(
                select(Finding.cve_id).where(
                    Finding.asset_id == asset.id, Finding.status.in_(ACTIVE), kev_expr()
                )
            )
            cves = sorted({cve for cve in exploited if cve})
        if cves:
            violations.append(
                _violation(
                    "fail_on_kev",
                    f"{len(cves)} known-exploited vulnerability(ies) open on {asset.name}: {_listing(cves)}",
                    None,
                    len(cves),
                )
            )

    if (epss_limit := conditions.get("max_open_epss")) is not None:
        if projected is not None:
            cves = sorted(
                k for k, item in projected[2].items() if item.epss is not None and item.epss > epss_limit
            )
        else:
            likely = db.scalars(
                select(Finding.cve_id)
                .join(VulnIntel, VulnIntel.cve_id == Finding.cve_id)
                .where(Finding.asset_id == asset.id, Finding.status.in_(ACTIVE), VulnIntel.epss > epss_limit)
            )
            cves = sorted({cve for cve in likely if cve})
        if cves:
            violations.append(
                _violation(
                    "max_open_epss",
                    f"{len(cves)} open vulnerability(ies) on {asset.name} with EPSS above "
                    f"{epss_limit:.0%}: {_listing(cves)}",
                    epss_limit,
                    len(cves),
                )
            )

    if (cvss_limit := conditions.get("max_new_cvss")) is not None:
        scores = [nf.cvss_score for nf in new if nf.cvss_score is not None and nf.cvss_score > cvss_limit]
        if scores:
            violations.append(
                _violation(
                    "max_new_cvss",
                    f"{len(scores)} new finding(s) with CVSS above {cvss_limit:g} (highest {max(scores):g})",
                    cvss_limit,
                    len(scores),
                )
            )

    if conditions.get("fail_on_new_secrets"):
        secrets = [nf for nf in new if SECRET_CWES & {c.upper() for c in nf.cwe}]
        if secrets:
            where = sorted({nf.file_path for nf in secrets if nf.file_path})
            violations.append(
                _violation(
                    "fail_on_new_secrets",
                    f"{len(secrets)} new hard-coded secret(s)" + (f" in {_listing(where)}" if where else ""),
                    None,
                    len(secrets),
                )
            )

    if conditions.get("fail_on_denied_license") and components:
        policy_rules = licenses.load(db)
        denied = sorted(
            {
                f"{c.name}@{c.version}" if c.version else c.name
                for c in components
                if policy_rules.verdict(c.licenses) == "denied"
            }
        )
        if denied:
            violations.append(
                _violation(
                    "fail_on_denied_license",
                    f"{len(denied)} component(s) under a denied licence: {_listing(denied)}",
                    None,
                    len(denied),
                )
            )

    if conditions.get("fail_on_reopened") and reopened:
        violations.append(
            _violation("fail_on_reopened", f"{reopened} finding(s) reopened by this scan", None, reopened)
        )

    return {
        "passed": not violations,
        "policy_id": policy.id,
        "policy_scope": "asset" if policy.asset_id else "global",
        "violations": violations,
        "evaluated_at": utcnow().isoformat(),
    }


def summary_line(scan: Scan) -> str:
    """One-line outcome for CI logs."""
    result = scan.gate_result
    if not result:
        return "no quality gate configured"
    if result["passed"]:
        return "quality gate passed"
    return "quality gate FAILED: " + "; ".join(v["message"] for v in result["violations"])
