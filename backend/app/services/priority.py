"""How urgently a finding should be fixed, as one number.

Severity says how bad a flaw is; it does not say whether anyone is exploiting it or how much the asset
matters. The priority multiplies the three, with the same weights the asset risk score uses
(services/analytics.py, top_assets), so the two never disagree about what matters:

    severity weight (critical 10, high 5, medium 2, low 0.5, info 0)
  x exploitability (in CISA KEV: KEV_RISK_MULTIPLIER; else EPSS >= EPSS_RISK_THRESHOLD: EPSS_RISK_MULTIPLIER)
  x asset criticality (low 0.5, medium 1, high 1.5, critical 2)

With the default settings it runs from 0 to 40. Unlike the asset risk score, exploitability always
counts here (RISK_USE_EXPLOITABILITY does not apply): ranking by it is the point of a priority.

It is computed, never stored: intel and criticality change without the finding changing. ``priority``
computes it for one loaded finding; ``priority_expr`` is the same in SQL, for sorting. They must agree
(tests/test_priority.py).
"""

from sqlalchemy import case, literal, select
from sqlalchemy.sql.elements import ColumnElement

from app.core.config import settings
from app.models import Asset, Finding, VulnIntel
from app.models.enums import CRITICALITY_MULTIPLIER, SEVERITY_WEIGHT


def priority(f: Finding) -> float:
    """The priority of a finding whose ``asset`` and ``intel`` are loaded (lists eager-load both)."""
    weight = SEVERITY_WEIGHT.get(f.severity, 0.0)
    intel = f.intel
    if intel is not None and intel.in_kev:
        exploit = settings.kev_risk_multiplier
    elif intel is not None and intel.epss is not None and intel.epss >= settings.epss_risk_threshold:
        exploit = settings.epss_risk_multiplier
    else:
        exploit = 1.0
    criticality = CRITICALITY_MULTIPLIER.get(f.asset.criticality if f.asset else "", 1.0)
    return round(weight * exploit * criticality, 2)


def _correlated(column: ColumnElement, where: ColumnElement) -> ColumnElement:
    # A subquery rather than a join: findings_query already joins the asset (aliased, for eager
    # loading), and naming Asset in ORDER BY would add a second, unjoined copy of the table.
    return select(column).where(where).correlate(Finding).scalar_subquery()


def priority_expr() -> ColumnElement:
    weight = case(
        *[(Finding.severity == s, literal(w)) for s, w in SEVERITY_WEIGHT.items()], else_=literal(0.0)
    )
    in_kev = _correlated(VulnIntel.in_kev, VulnIntel.cve_id == Finding.cve_id)
    epss = _correlated(VulnIntel.epss, VulnIntel.cve_id == Finding.cve_id)
    exploit = case(
        (in_kev.is_(True), literal(settings.kev_risk_multiplier)),
        (epss >= literal(settings.epss_risk_threshold), literal(settings.epss_risk_multiplier)),
        else_=literal(1.0),
    )
    criticality = _correlated(Asset.criticality, Asset.id == Finding.asset_id)
    multiplier = case(
        *[(criticality == c, literal(m)) for c, m in CRITICALITY_MULTIPLIER.items()], else_=literal(1.0)
    )
    return weight * exploit * multiplier
