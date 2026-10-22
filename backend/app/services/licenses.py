"""Licence policy over the component inventory.

A licence is *denied*, *allowed* or needs *review*. Anything not listed follows ``LICENSE_DEFAULT``, which
starts at "allowed": an installation that never opens this page sees no licence noise at all.

Matching is exact and case-insensitive against what the SBOM said. SPDX expressions ("MIT OR Apache-2.0")
are matched as written, because deciding what a dual licence means is a legal call, not a parsing one.
"""

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import LicensePolicy

RULES = ("allowed", "denied", "review")
UNKNOWN = "unknown"  # the component carries no licence at all


@dataclass(frozen=True)
class Policy:
    rules: dict[str, str]

    def verdict(self, licences: list[str]) -> str:
        """The strictest verdict over a component's licences."""
        if not licences:
            return UNKNOWN
        verdicts = {
            self.rules.get(x.strip().lower(), settings.license_default) for x in licences if x.strip()
        }
        for rule in ("denied", "review"):
            if rule in verdicts:
                return rule
        return "allowed" if verdicts else UNKNOWN

    def listed(self, rule: str) -> list[str]:
        return sorted(licence for licence, value in self.rules.items() if value == rule)


def load(db: Session) -> Policy:
    rows = db.execute(select(LicensePolicy.licence, LicensePolicy.rule)).all()
    return Policy({licence.lower(): rule for licence, rule in rows})
