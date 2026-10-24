"""Pure report preparation, column-safe normalization, and finding construction."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.core.config import settings
from app.models import Asset, Component, Finding, Scan
from app.models.enums import SCAN_TYPES, SEVERITY_RANK, Status
from app.parsers.base import NormalizedComponent, NormalizedFinding, ParsedReport, ParseError, truncate
from app.parsers.detect import load_json, parse_report
from app.services.dedup import dedup_key, normalize_path

# Column length limits come from the model so parsers can't produce values the database rejects.
_FINDING_LIMITS = {c.name: getattr(c.type, "length", None) for c in Finding.__table__.columns}
_SCAN_LIMITS = {c.name: getattr(c.type, "length", None) for c in Scan.__table__.columns}
_TOOL_LIMIT = Finding.__table__.c.tools.type.item_type.length
_CWE_LIMIT = Finding.__table__.c.cwe.type.item_type.length
_TEXT_LIMIT = 100_000  # unbounded Text columns (description, remediation)
_INT32 = 2**31
_MAX_REFERENCES = 50


def _clean(value: Any, limit: int | None) -> str | None:
    """Coerce a scalar to a NUL-free string within ``limit``; containers and other types become None."""
    if value is None or isinstance(value, bool) or not isinstance(value, str | int | float):
        return None
    return truncate(str(value).replace("\x00", ""), limit or _TEXT_LIMIT)


def _int32(value: Any) -> int | None:
    return (
        value
        if isinstance(value, int) and not isinstance(value, bool) and -_INT32 <= value < _INT32
        else None
    )


def _references(refs: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for r in refs if isinstance(refs, list) else []:
        url = _clean(r.get("url"), 2000) if isinstance(r, dict) else None
        if url:
            out.append({"url": url, "title": _clean(r.get("title"), 500) or None})
        if len(out) >= _MAX_REFERENCES:
            break
    return out


def sanitize(nf: NormalizedFinding) -> NormalizedFinding:
    """Normalise parser output so every value fits its column (see models/finding.py)."""
    for attr in (
        "description",
        "remediation",
        "rule_id",
        "file_path",
        "snippet",
        "package_name",
        "package_version",
        "ecosystem",
        "purl",
        "cve_id",
        "vuln_id",
        "fixed_version",
        "fingerprint",
        "resource",
        "url",
        "parameter",
    ):
        setattr(nf, attr, _clean(getattr(nf, attr), _FINDING_LIMITS[attr]))
    nf.http_method = (_clean(nf.http_method, _FINDING_LIMITS["http_method"]) or "").upper() or None
    nf.description = nf.description or ""
    nf.remediation = nf.remediation or ""
    nf.title = _clean(nf.title, _FINDING_LIMITS["title"]) or nf.rule_id or "Finding"
    nf.tool_name = _clean(nf.tool_name, _TOOL_LIMIT) or "unknown"
    nf.line_start, nf.line_end = _int32(nf.line_start), _int32(nf.line_end)
    nf.cwe = [c for c in nf.cwe if isinstance(c, str) and len(c) <= _CWE_LIMIT]
    nf.references = _references(nf.references)
    return nf


_COMPONENT_LIMITS = {c.name: getattr(c.type, "length", None) for c in Component.__table__.columns}
_LICENCE_LIMIT = Component.__table__.c.licenses.type.item_type.length
_MAX_LICENCES = 20


def sanitize_component(c: NormalizedComponent) -> NormalizedComponent | None:
    """The component equivalent of sanitize(). Components had none: a name that was a list in the
    SBOM reached component_key() and failed there, and an over-long one failed at the database --
    either way the upload was a 500 rather than a stored scan. Returns None for one with no usable name.
    """
    c.name = _clean(c.name, _COMPONENT_LIMITS["name"])
    if not c.name:
        return None
    for attr in ("version", "ecosystem", "purl"):
        setattr(c, attr, _clean(getattr(c, attr), _COMPONENT_LIMITS[attr]))
    licences = c.licenses if isinstance(c.licenses, list) else []
    c.licenses = [lic for lic in (_clean(x, _LICENCE_LIMIT) for x in licences) if lic][:_MAX_LICENCES]
    return c


@dataclass
class IngestOptions:
    fmt: str | None = None
    scan_type: str | None = None
    branch: str | None = None
    commit_sha: str | None = None
    source: str = "upload"
    file_name: str | None = None
    close_missing: bool = False
    allow_empty: bool = False  # let close_missing act on a report with no findings
    preview: bool = False  # evaluate the report without changing the inventory
    now: datetime | None = None  # overridable for seeding historical data


def _merge(into: NormalizedFinding, other: NormalizedFinding) -> None:
    """Merge a duplicate inside the same report: keep the highest severity and the richest data."""
    if SEVERITY_RANK.get(other.severity, 0) > SEVERITY_RANK.get(into.severity, 0):
        into.severity = other.severity
        into.cvss_score = other.cvss_score or into.cvss_score
    for attr in ("description", "remediation", "snippet", "fixed_version", "purl"):
        if not getattr(into, attr) and getattr(other, attr):
            setattr(into, attr, getattr(other, attr))
    for c in other.cwe:
        if c not in into.cwe:
            into.cwe.append(c)


@dataclass(frozen=True)
class PreparedFindings:
    tool_name: str
    tools: set[str]
    by_key: dict[str, NormalizedFinding]
    sources: dict[str, list[str]]


def prepare_findings(report: ParsedReport, asset_id: int) -> PreparedFindings:
    """Pure normalization stage; retain every scanner before merging duplicate content."""
    tool_name = _clean(report.tool_name, _TOOL_LIMIT) or "unknown"
    tools = {tool_name}
    tools.update(t for t in (_clean(x, _TOOL_LIMIT) for x in report.tool_names) if t)
    batch: dict[str, NormalizedFinding] = {}
    sources: dict[str, list[str]] = {}
    for raw in report.findings:
        nf = sanitize(raw)
        tools.add(nf.tool_name)
        key = dedup_key(asset_id, nf)
        if nf.tool_name not in sources.setdefault(key, []):
            sources[key].append(nf.tool_name)
        if key in batch:
            _merge(batch[key], nf)
        else:
            batch[key] = nf
    return PreparedFindings(tool_name, tools, batch, sources)


def reconcile_tools(
    previous: list[str], sources: list[str], report_tools: set[str], complete: bool
) -> list[str]:
    """Keep sources outside this report, replacing its sources only for complete scans."""
    retained = [t for t in previous if not complete or t not in report_tools or t in sources]
    return list(dict.fromkeys([*retained, *sources]))


def reported_severity(f: Finding, nf: NormalizedFinding, *, tools: list[str] | None = None) -> str:
    reported = f.scanner_severity or f.severity
    sources = f.tools if tools is None else tools
    if not sources or sources[0] == nf.tool_name:
        return nf.severity or reported
    return nf.severity if SEVERITY_RANK.get(nf.severity, 0) > SEVERITY_RANK.get(reported, 0) else reported


def _new_finding(asset: Asset, key: str, nf: NormalizedFinding, scan: Scan, now: datetime) -> Finding:
    return Finding(
        asset_id=asset.id,
        type=nf.type,
        dedup_key=key,
        title=nf.title,
        description=nf.description,
        remediation=nf.remediation,
        severity=nf.severity,
        scanner_severity=nf.severity,
        cvss_score=nf.cvss_score,
        status=Status.open.value,
        cwe=nf.cwe,
        rule_id=nf.rule_id,
        tools=[nf.tool_name],
        file_path=(normalize_path(nf.file_path) or None) if nf.type in ("sast", "iac") else nf.file_path,
        resource=nf.resource,
        url=nf.url,
        http_method=nf.http_method,
        parameter=nf.parameter,
        line_start=nf.line_start,
        line_end=nf.line_end,
        snippet=nf.snippet,
        fingerprint=nf.fingerprint,
        package_name=nf.package_name,
        package_version=nf.package_version,
        ecosystem=nf.ecosystem,
        purl=nf.purl,
        cve_id=nf.cve_id,
        vuln_id=nf.vuln_id,
        fixed_version=nf.fixed_version,
        references=nf.references,
        first_seen_at=now,
        last_seen_at=now,
        first_scan_id=scan.id,
        last_scan_id=scan.id,
        occurrence_count=1,
        created_at=now,
        updated_at=now,
    )


def is_preview(asset: Asset, opts: IngestOptions) -> bool:
    """Scans of a branch other than the asset's default branch are previews (and can be forced)."""
    return bool(
        opts.preview or (asset.default_branch and opts.branch and opts.branch != asset.default_branch)
    )


@dataclass(frozen=True)
class PreparedReport:
    report: ParsedReport
    scan_type: str
    findings: PreparedFindings
    components: list[NormalizedComponent]


def prepare_report(raw: bytes, asset_id: int, opts: IngestOptions) -> PreparedReport:
    try:
        data = load_json(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ParseError(f"File is not valid JSON: {exc}") from exc
    except RecursionError as exc:
        raise ParseError("File is not valid JSON: nesting is too deep") from exc

    report = parse_report(data, opts.fmt)
    if opts.close_missing and not report.complete_for_resolution:
        raise ParseError(
            "Cannot resolve missing findings from a failed or incomplete scan; "
            "upload with close_missing=false"
        )
    scan_type = (opts.scan_type or report.scan_type).lower()
    if scan_type not in SCAN_TYPES:
        raise ParseError(f"scan_type must be one of: {', '.join(SCAN_TYPES)}")
    if len(report.findings) > settings.max_report_findings:
        raise ParseError(f"Report exceeds MAX_REPORT_FINDINGS ({settings.max_report_findings})")
    findings = prepare_findings(report, asset_id)
    components = [c for c in (sanitize_component(c) for c in report.components) if c is not None]
    return PreparedReport(report, scan_type, findings, components)
