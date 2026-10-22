"""The component inventory: what each asset ships, from the SBOMs it uploads.

Rows are upserted, never deleted by a scan: an SBOM that stops mentioning a package leaves the row with an
older ``last_seen_at``, which is what tells you a component is gone rather than losing the fact it was ever
there. Previews write nothing, like everything else about them.
"""

import hashlib
import json
import logging
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.models import Asset, Component, ComponentScan, Scan
from app.parsers.base import NormalizedComponent
from app.services.scope import Scope

log = logging.getLogger(__name__)

_CHUNK = 500


def component_key(component: NormalizedComponent) -> str:
    identity = [(component.ecosystem or "").lower(), component.name.lower(), component.version or ""]
    return hashlib.sha256(json.dumps(identity, ensure_ascii=True).encode()).hexdigest()


def record(
    db: Session, asset: Asset, scan: Scan, components: list[NormalizedComponent], now: datetime
) -> int:
    """Upsert an asset's components. Returns how many rows the report covered."""
    if not components:
        return 0
    rows = {}
    for component in components:
        if not component.name:
            continue
        rows[component_key(component)] = {
            "asset_id": asset.id,
            "key": component_key(component),
            "name": component.name,
            "version": component.version,
            "ecosystem": component.ecosystem,
            "purl": component.purl,
            "licenses": component.licenses or [],
            "first_seen_at": now,
            "last_seen_at": now,
            "last_scan_id": scan.id,
            "created_at": now,
            "updated_at": now,
        }
    values = list(rows.values())
    for i in range(0, len(values), _CHUNK):
        chunk = values[i : i + _CHUNK]
        statement = pg_insert(Component).values(chunk)
        recorded = db.execute(
            statement.on_conflict_do_update(
                index_elements=["asset_id", "key"],
                set_={
                    # first_seen_at is deliberately left alone.
                    "version": statement.excluded.version,
                    "ecosystem": statement.excluded.ecosystem,
                    "purl": statement.excluded.purl,
                    "licenses": statement.excluded.licenses,
                    "last_seen_at": statement.excluded.last_seen_at,
                    "last_scan_id": statement.excluded.last_scan_id,
                    "updated_at": statement.excluded.updated_at,
                },
            ).returning(Component.id)
        )
        ids = list(recorded.scalars())
        db.execute(
            pg_insert(ComponentScan)
            .values([{"component_id": ident, "scan_id": scan.id} for ident in ids])
            .on_conflict_do_nothing()
        )
    log.info("scan %s: recorded %d component(s) for %s", scan.id, len(values), asset.name)
    return len(values)


def licenses_in_use(db: Session, scope: Scope) -> list[tuple[str, int]]:
    """Every licence seen, with how many component rows carry it."""
    from sqlalchemy import func

    licence = func.unnest(Component.licenses).label("licence")
    inner = scope.narrow(select(licence), Component.asset_id).subquery()
    rows = db.execute(
        select(inner.c.licence, func.count().label("n"))
        .group_by(inner.c.licence)
        .order_by(func.count().desc())
    )
    return [(r.licence, r.n) for r in rows]
