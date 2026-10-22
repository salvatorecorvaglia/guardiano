"""Checkov JSON (`checkov -d . -o json`): failed infrastructure-as-code checks.

A single framework gives one object; several (Terraform and Kubernetes in one repository, say) give a
list of them. Only failed checks become findings. Open-source Checkov leaves severity empty, so an
unrated check counts as medium; the Prisma Cloud-connected version fills it in.
"""

from typing import Any

from app.parsers.base import NormalizedFinding, ParsedReport, ParseError, normalize_severity, to_int, truncate


def _checks(block: dict[str, Any]) -> list[dict[str, Any]]:
    results = block.get("results") or {}
    failed = results.get("failed_checks") if isinstance(results, dict) else None
    return [c for c in failed or [] if isinstance(c, dict)]


def parse(data: Any) -> ParsedReport:
    blocks = data if isinstance(data, list) else [data]
    if not all(isinstance(b, dict) for b in blocks):
        raise ParseError("Checkov reports are an object, or a list of objects, with 'results'")
    version = None
    findings: list[NormalizedFinding] = []
    for block in blocks:
        version = version or (block.get("summary") or {}).get("checkov_version")
        framework = block.get("check_type")
        for check in _checks(block):
            lines = check.get("file_line_range") or []
            guideline = check.get("guideline")
            findings.append(
                NormalizedFinding(
                    type="iac",
                    title=truncate(check.get("check_name") or check.get("check_id") or "Failed check", 500)
                    or "Failed check",
                    severity=normalize_severity(check.get("severity")),
                    tool_name="Checkov",
                    description=f"Framework: {framework}" if framework else "",
                    rule_id=check.get("check_id"),
                    file_path=check.get("repo_file_path") or check.get("file_path"),
                    line_start=to_int(lines[0]) if len(lines) > 0 else None,
                    line_end=to_int(lines[1]) if len(lines) > 1 else None,
                    resource=check.get("resource"),
                    references=[{"url": guideline}] if isinstance(guideline, str) and guideline else [],
                )
            )
    return ParsedReport("checkov", "iac", "Checkov", version, findings)
