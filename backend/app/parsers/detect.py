import json
from collections.abc import Callable
from typing import Any

from app.core.config import settings
from app.parsers import (
    checkov,
    cyclonedx,
    dependency_check,
    gitleaks,
    grype,
    guardiano_json,
    kics,
    npm_audit,
    nuclei,
    osv,
    sarif,
    semgrep_json,
    trivy_json,
    zap,
)
from app.parsers.base import ParsedReport, ParseError, parse_budget

PARSERS: dict[str, Callable[[Any], ParsedReport]] = {
    "sarif": sarif.parse,
    "cyclonedx": cyclonedx.parse,
    "trivy": trivy_json.parse,
    "semgrep": semgrep_json.parse,
    "grype": grype.parse,
    "osv": osv.parse,
    "dependency-check": dependency_check.parse,
    "npm-audit": npm_audit.parse,
    "gitleaks": gitleaks.parse,
    "checkov": checkov.parse,
    "kics": kics.parse,
    "zap": zap.parse,
    "nuclei": nuclei.parse,
    "guardiano": guardiano_json.parse,
}

# Formats that are (or can be) a JSON array rather than an object. Nuclei's JSON Lines output arrives
# here as an array too (see load_json).
_ARRAY_FORMATS = ("gitleaks", "checkov", "nuclei")

SUPPORTED_FORMATS = tuple(PARSERS)


def detect_format(data: Any) -> str:
    if isinstance(data, list):
        first = data[0] if data else None
        if isinstance(first, dict) and "template-id" in first:
            return "nuclei"
        if isinstance(first, dict) and "check_type" in first:
            return "checkov"  # several frameworks, one object each
        if not data or (isinstance(first, dict) and {"RuleID", "Match"} & set(first)):
            return "gitleaks"
        raise ParseError(
            "Unrecognised JSON array: Gitleaks, Checkov (several frameworks) and Nuclei use arrays"
        )
    if not isinstance(data, dict):
        raise ParseError("Report must be a JSON object")
    if data.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    if "kics_version" in data and isinstance(data.get("queries"), list):
        return "kics"
    if isinstance(data.get("site"), list) and ("@programName" in data or "@version" in data):
        return "zap"
    if "check_type" in data and isinstance(data.get("results"), dict):
        return "checkov"
    if "template-id" in data and "info" in data:
        return "nuclei"  # a single result
    if isinstance(data.get("runs"), list) and (
        "sarif" in str(data.get("$schema", "")).lower() or data.get("version")
    ):
        return "sarif"
    if "SchemaVersion" in data and isinstance(data.get("Results"), list):
        return "trivy"
    if isinstance(data.get("matches"), list) and "descriptor" in data:
        return "grype"
    if isinstance(data.get("dependencies"), list) and ("reportSchema" in data or "projectInfo" in data):
        return "dependency-check"
    if "auditReportVersion" in data and isinstance(data.get("vulnerabilities"), dict):
        return "npm-audit"
    results_list = data.get("results")
    first = results_list[0] if isinstance(results_list, list) and results_list else None
    if isinstance(first, dict) and ("packages" in first or "source" in first):
        return "osv"
    if "guardiano" in data or str(data.get("schema", "")).startswith("guardiano"):
        return "guardiano"
    results = data.get("results")
    if isinstance(results, list) and (not results or "check_id" in results[0]):
        return "semgrep"
    if isinstance(data.get("findings"), list):
        return "guardiano"
    raise ParseError(
        "Unrecognised report format. Supported: SARIF 2.1.0, CycloneDX JSON, Trivy JSON, Semgrep JSON, "
        "Grype JSON, OSV-Scanner JSON, OWASP Dependency-Check JSON, npm audit JSON, Gitleaks JSON, "
        "Checkov JSON, KICS JSON, ZAP JSON, Nuclei JSON(L) and Guardiano JSON."
    )


def load_json(raw: bytes) -> Any:
    """The report's JSON. JSON Lines (one object per line, as Nuclei writes by default) becomes a list.

    Only tried when the whole file is not one JSON document, so no report that parsed before parses
    differently now.
    """
    try:
        return json.loads(raw)
    except json.JSONDecodeError as whole:
        lines = [line for line in raw.decode("utf-8", "replace").splitlines() if line.strip()]
        if len(lines) < 2 or not lines[0].lstrip().startswith("{"):
            raise
        try:
            rows = [json.loads(line) for line in lines]
        except json.JSONDecodeError:
            raise whole from None
        if not all(isinstance(r, dict) for r in rows):
            raise whole
        return rows


def parse_report(data: Any, fmt: str | None = None) -> ParsedReport:
    fmt = (fmt or "").strip().lower()
    try:
        fmt = fmt or detect_format(data)
        if fmt not in PARSERS:
            raise ParseError(f"Unsupported format '{fmt}'. Supported: {', '.join(SUPPORTED_FORMATS)}")
        if not isinstance(data, dict) and fmt not in _ARRAY_FORMATS:
            raise ParseError("Report must be a JSON object")
        with parse_budget(settings.max_report_findings, settings.max_report_components):
            return PARSERS[fmt](data)
    except ParseError:
        raise
    except RecursionError as exc:
        raise ParseError(f"Malformed {fmt or 'unknown'} report: nesting is too deep") from exc
    except (KeyError, TypeError, AttributeError, IndexError, ValueError, OverflowError) as exc:
        raise ParseError(f"Malformed {fmt or 'unknown'} report: {exc}") from exc
