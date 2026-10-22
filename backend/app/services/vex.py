"""VEX: triage decisions on dependency findings, as statements other tools read, and back.

Export states what Guardiano knows about each vulnerable package on an asset:

| finding status   | OpenVEX               | CycloneDX analysis.state      |
|------------------|-----------------------|-------------------------------|
| false_positive   | not_affected          | false_positive                |
| resolved         | fixed                 | resolved                      |
| risk_accepted    | affected              | exploitable (will_not_fix)    |
| in_progress      | affected              | exploitable (update)          |
| open             | under_investigation   | in_triage                     |

Import applies a supplier's statements to the asset's *active* findings: not_affected marks them false
positive and fixed resolves them, each with the statement as the justification. Other statuses change
nothing. Only findings that exist are touched: a statement is about one package version (or, without a
version in its purl, all of them), and turning it into a rule for future findings would reach further
than the statement does. A finding a statement made a false positive stays one when scanned again.
"""

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.core.config import settings
from app.models import Asset, Finding, User
from app.models.enums import ACTIVE_STATUSES, Status
from app.services import status
from app.services.dedup import canonical_ecosystem
from app.services.errors import ValidationFailed

_OPENVEX = {
    "false_positive": "not_affected",
    "resolved": "fixed",
    "risk_accepted": "affected",
    "in_progress": "affected",
    "open": "under_investigation",
}
_CYCLONEDX = {
    "false_positive": ("false_positive", []),
    "resolved": ("resolved", []),
    "risk_accepted": ("exploitable", ["will_not_fix"]),
    "in_progress": ("exploitable", ["update"]),
    "open": ("in_triage", []),
}
# Incoming statuses, from either format, and what they do to an active finding.
_APPLY = {
    "not_affected": Status.false_positive,
    "false_positive": Status.false_positive,
    "fixed": Status.resolved,
    "resolved": Status.resolved,
    "resolved_with_pedigree": Status.resolved,
}
_ACTIVE = {s.value for s in ACTIVE_STATUSES}
MAX_STATEMENTS = 20_000


# ---- purls ------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Package:
    ecosystem: str
    name: str
    version: str | None  # None: every version


def parse_purl(purl: str | None) -> Package | None:
    """pkg:type/namespace/name@version?qualifiers#subpath, reduced to what identifies a package."""
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("#", 1)[0].split("?", 1)[0]
    path, _, version = body.partition("@")
    parts = [unquote(p) for p in path.split("/") if p]
    if len(parts) < 2:
        return None
    kind, name = parts[0], "/".join(parts[1:])
    return Package(canonical_ecosystem(kind), name.lower(), unquote(version) or None)


def _package_of(f: Finding) -> Package | None:
    """What package a finding is about: its purl, or else what the scanner said about it."""
    if parsed := parse_purl(f.purl):
        return parsed
    if not f.package_name:
        return None
    return Package(canonical_ecosystem(f.ecosystem), f.package_name.lower(), f.package_version or None)


def _names(pkg: Package) -> set[str]:
    """A scanner may name "org.apache/log4j" as "org.apache:log4j" or just "log4j"; all are the same."""
    # Namespace is identity, not decoration. Maven's ':' is an alternative separator.
    return {pkg.name.replace(":", "/") if pkg.ecosystem == "maven" else pkg.name}


def _matches(statement: Package, f: Finding) -> bool:
    found = _package_of(f)
    if found is None or statement.ecosystem != found.ecosystem:
        return False
    if not (_names(statement) & _names(found)):
        return False
    return statement.version is None or statement.version == found.version


# ---- export -----------------------------------------------------------------------------------------


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _purl(f: Finding) -> str | None:
    if f.purl:
        return f.purl
    if f.package_name and f.ecosystem:
        return f"pkg:{canonical_ecosystem(f.ecosystem)}/{f.package_name}" + (
            f"@{f.package_version}" if f.package_version else ""
        )
    return None


def exportable(db: Session, asset: Asset) -> list[Finding]:
    """Dependency findings that name a vulnerability and a package: what a VEX statement can be about."""
    rows = db.scalars(
        select(Finding)
        .where(Finding.asset_id == asset.id, Finding.type == "sca")
        .order_by(Finding.cve_id, Finding.vuln_id, Finding.package_name, Finding.id)
    ).all()
    return [f for f in rows if (f.cve_id or f.vuln_id) and _purl(f)]


def openvex(asset: Asset, findings: list[Finding]) -> dict[str, Any]:
    base = (settings.public_url or "https://guardiano.invalid").rstrip("/")
    statements = []
    for f in findings:
        state = _OPENVEX.get(f.status, "under_investigation")
        s: dict[str, Any] = {
            "vulnerability": {"name": f.cve_id or f.vuln_id},
            "products": [{"@id": _purl(f)}],
            "status": state,
        }
        why = (f.status_justification or "").strip()
        if state == "not_affected":
            # OpenVEX wants a justification from a fixed list or an impact statement; the reason a
            # person gave is the second.
            s["impact_statement"] = why or "Marked a false positive in Guardiano"
        elif state == "affected":
            if f.status == "risk_accepted":
                until = f" until {f.risk_accepted_until:%Y-%m-%d}" if f.risk_accepted_until else ""
                s["action_statement"] = f"Risk accepted{until}" + (f": {why}" if why else "")
            else:
                s["action_statement"] = "Remediation in progress" + (
                    f"; fixed in {f.fixed_version}" if f.fixed_version else ""
                )
        statements.append(s)
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"{base}/vex/{asset.id}/{uuid.uuid4()}",
        "author": "Guardiano",
        "role": "Document Creator",
        "timestamp": _now(),
        "version": 1,
        "statements": statements,
    }


def cyclonedx(asset: Asset, findings: list[Finding]) -> dict[str, Any]:
    components: dict[str, dict[str, Any]] = {}
    vulnerabilities = []
    for f in findings:
        ref = _purl(f)
        components.setdefault(
            ref,
            {"type": "library", "bom-ref": ref, "name": f.package_name or ref, "purl": ref}
            | ({"version": f.package_version} if f.package_version else {}),
        )
        state, response = _CYCLONEDX.get(f.status, ("in_triage", []))
        analysis: dict[str, Any] = {"state": state}
        if response:
            analysis["response"] = response
        if (f.status_justification or "").strip():
            analysis["detail"] = f.status_justification.strip()
        vulnerabilities.append({"id": f.cve_id or f.vuln_id, "affects": [{"ref": ref}], "analysis": analysis})
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {"timestamp": _now(), "component": {"type": "application", "name": asset.name}},
        "components": list(components.values()),
        "vulnerabilities": vulnerabilities,
    }


# ---- import -----------------------------------------------------------------------------------------


@dataclass
class Statement:
    vulnerability: str
    products: list[Package]
    status: str
    reason: str


@dataclass
class ImportResult:
    statements: int = 0
    changed: int = 0
    already_closed: int = 0
    informational: int = 0  # affected / under_investigation / in_triage: nothing to change
    unmatched: list[str] = field(default_factory=list)


def _parse(raw: bytes) -> tuple[str, list[Statement]]:
    """The statements in an OpenVEX or CycloneDX VEX document."""
    try:
        doc = json.loads(raw)
    except ValueError:
        raise ValidationFailed("The VEX document is not JSON")
    if not isinstance(doc, dict):
        raise ValidationFailed("The VEX document is not a JSON object")
    if "statements" in doc and "openvex" in str(doc.get("@context", "")):
        author = str(doc.get("author") or "supplier")
        out = []
        for s in doc.get("statements") or []:
            if not isinstance(s, dict):
                continue
            vuln = s.get("vulnerability") or {}
            name = vuln.get("name") if isinstance(vuln, dict) else vuln
            raw_products = s.get("products") or []
            if not isinstance(raw_products, list):
                raise ValidationFailed("VEX products must be an array")
            products = [parse_purl(p.get("@id") if isinstance(p, dict) else p) for p in raw_products]
            why = s.get("impact_statement") or s.get("justification") or s.get("status_notes") or ""
            out.append(
                Statement(
                    str(name or ""),
                    [p for p in products if p],
                    str(s.get("status") or ""),
                    f"VEX from {author}: {why}".rstrip(": "),
                )
            )
        return "openvex", out
    if doc.get("bomFormat") == "CycloneDX":
        refs = {c.get("bom-ref"): c.get("purl") for c in doc.get("components") or [] if isinstance(c, dict)}
        out = []
        for v in doc.get("vulnerabilities") or []:
            if not isinstance(v, dict):
                continue
            analysis = v.get("analysis") or {}
            if not isinstance(analysis, dict):
                raise ValidationFailed("VEX analysis must be an object")
            products = []
            for a in v.get("affects") or []:
                ref = a.get("ref") if isinstance(a, dict) else None
                products.append(parse_purl(refs.get(ref) or ref))
            why = analysis.get("detail") or analysis.get("justification") or ""
            out.append(
                Statement(
                    str(v.get("id") or ""),
                    [p for p in products if p],
                    str(analysis.get("state") or ""),
                    f"VEX: {why}".rstrip(": "),
                )
            )
        return "cyclonedx", out
    raise ValidationFailed("Not an OpenVEX or CycloneDX VEX document")


def parse(raw: bytes) -> tuple[str, list[Statement]]:
    try:
        return _parse(raw)
    except ValidationFailed:
        raise
    except (ValueError, TypeError, AttributeError, KeyError, RecursionError, OverflowError) as exc:
        raise ValidationFailed("Malformed VEX document: invalid field shape or nesting") from exc


def apply(db: Session, asset: Asset, statements: list[Statement], actor: User) -> ImportResult:
    """Apply statements to the asset's findings. The caller commits."""
    if len(statements) > MAX_STATEMENTS:
        raise ValidationFailed(f"A VEX document may hold at most {MAX_STATEMENTS} statements")
    findings = db.scalars(
        select(Finding)
        .where(Finding.asset_id == asset.id, Finding.type == "sca")
        .options(selectinload(Finding.links), selectinload(Finding.asset))
        .order_by(Finding.id)
        .with_for_update(of=Finding)
        .execution_options(populate_existing=True)
    ).all()
    by_vuln: dict[str, list[Finding]] = {}
    for f in findings:
        for ident in {f.cve_id, f.vuln_id} - {None}:
            by_vuln.setdefault(ident.upper(), []).append(f)

    result = ImportResult()
    hooks: dict = {}
    for s in statements:
        result.statements += 1
        target = _APPLY.get(s.status)
        if target is None:
            result.informational += 1
            continue
        known = by_vuln.get(s.vulnerability.upper(), [])
        hits = [f for f in known if any(_matches(p, f) for p in s.products)]
        if not hits:
            if len(result.unmatched) < 50:
                product = s.products[0] if s.products else None
                where = f"{product.name}@{product.version or '*'}" if product else "no product"
                result.unmatched.append(f"{s.vulnerability} on {where}")
            continue
        for f in hits:
            if f.status not in _ACTIVE:
                result.already_closed += 1
                continue
            if status.change(db, f, target, actor=actor, justification=s.reason[:5000], hooks=hooks):
                result.changed += 1
    return result
