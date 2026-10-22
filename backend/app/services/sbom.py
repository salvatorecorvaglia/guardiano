"""SBOM export: an asset's component inventory as CycloneDX 1.5 or SPDX 2.3 JSON.

The inventory never forgets a component, so the export chooses what the asset ships *now*: for each tool
that feeds it, the components that tool's latest scan listed. Per tool, because an asset can have a
repository SBOM and a container-image SBOM, and the newer of the two must not hide the other.

Licences are written as the SBOM gave them. Nothing is inferred: several licences on one component are
not turned into an AND or an OR, so SPDX gets NOASSERTION for those, with
the licences kept in a comment.
"""

import re
import uuid
from datetime import UTC, datetime
from typing import Any, Literal

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import Asset, Component, ComponentScan, Scan

Include = Literal["current", "all"]
# One SPDX licence id or a ready-made expression of them: safe to declare as written.
_SPDX_LICENSE = re.compile(r"^[A-Za-z0-9.+-]+( (AND|OR|WITH) [A-Za-z0-9.+-]+)*$")


def latest_inventory_scans(asset_id: int | None = None):
    known_members = select(ComponentScan.component_id).where(ComponentScan.scan_id == Scan.id).exists()
    stmt = select(func.max(Scan.id)).where(
        Scan.source != "preview",
        or_(Scan.inventory_complete.is_(True), Scan.inventory_complete.is_(None) & known_members),
    )
    if asset_id is not None:
        stmt = stmt.where(Scan.asset_id == asset_id)
    return stmt.group_by(Scan.asset_id, Scan.tool_name, Scan.scan_type)


def components(db: Session, asset: Asset, include: Include = "current") -> list[Component]:
    stmt = select(Component).where(Component.asset_id == asset.id)
    if include == "current":
        membership = select(ComponentScan.component_id).where(
            ComponentScan.scan_id.in_(latest_inventory_scans(asset.id))
        )
        stmt = stmt.where(Component.id.in_(membership))
    return list(db.scalars(stmt.order_by(Component.ecosystem, Component.name, Component.version)))


def _version() -> str:
    from app import __version__

    return __version__


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _ref(c: Component) -> str:
    return c.purl or f"{c.ecosystem or 'generic'}:{c.name}@{c.version or ''}"


def cyclonedx(asset: Asset, rows: list[Component]) -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _now(),
            "tools": {"components": [{"type": "application", "name": "Guardiano", "version": _version()}]},
            "component": {"type": "application", "bom-ref": f"asset:{asset.name}", "name": asset.name},
        },
        "components": [
            {
                "type": "library",
                "bom-ref": _ref(c),
                "name": c.name,
                **({"version": c.version} if c.version else {}),
                **({"purl": c.purl} if c.purl else {}),
                # "name" is valid for any licence string; "id" would have to be a real SPDX id.
                **({"licenses": [{"license": {"name": x}} for x in c.licenses]} if c.licenses else {}),
            }
            for c in _unique(rows)
        ],
    }


def spdx(asset: Asset, rows: list[Component]) -> dict[str, Any]:
    base = (settings.public_url or "https://guardiano.invalid").rstrip("/")
    root = "SPDXRef-Asset"
    packages: list[dict[str, Any]] = [
        {
            "SPDXID": root,
            "name": asset.name,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "primaryPackagePurpose": "APPLICATION",
        }
    ]
    relationships = [
        {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": root}
    ]
    for n, c in enumerate(_unique(rows), start=1):
        ident = f"SPDXRef-Package-{n}"
        single = c.licenses[0] if len(c.licenses) == 1 else None
        declared = single if single and _SPDX_LICENSE.match(single) else "NOASSERTION"
        package: dict[str, Any] = {
            "SPDXID": ident,
            "name": c.name,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": declared,
        }
        if c.version:
            package["versionInfo"] = c.version
        if c.purl:
            package["externalRefs"] = [
                {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": c.purl}
            ]
        if c.licenses and declared == "NOASSERTION":
            package["comment"] = "Licences as reported: " + "; ".join(c.licenses)
        packages.append(package)
        relationships.append(
            {"spdxElementId": root, "relationshipType": "CONTAINS", "relatedSpdxElement": ident}
        )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{asset.name} (Guardiano component inventory)",
        "documentNamespace": f"{base}/spdx/{asset.id}/{uuid.uuid4()}",
        "creationInfo": {"created": _now(), "creators": [f"Tool: Guardiano-{_version()}"]},
        "packages": packages,
        "relationships": relationships,
    }


def _unique(rows: list[Component]) -> list[Component]:
    """One entry per bom-ref: two tools can list the same package, and a BOM's refs must be unique."""
    seen: dict[str, Component] = {}
    for c in rows:
        seen.setdefault(_ref(c), c)
    return list(seen.values())
