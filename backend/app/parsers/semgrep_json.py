"""Semgrep JSON output parser (`semgrep --json`)."""

from typing import Any

from app.parsers.base import (
    NormalizedFinding,
    ParsedReport,
    ParseError,
    normalize_severity,
    to_int,
    truncate,
    unique_cwes,
)

_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
# Semgrep writes this instead of a value for anonymous users.
_NO_FINGERPRINT = {"requires login", "", "0"}


def _fingerprint(extra: dict[str, Any]) -> str | None:
    value = extra.get("fingerprint")
    if isinstance(value, str) and value.strip().lower() not in _NO_FINGERPRINT:
        return truncate(value.strip(), 200)
    return None


def parse(data: dict[str, Any]) -> ParsedReport:
    results = data.get("results")
    if not isinstance(results, list):
        raise ParseError("Semgrep report has no 'results' array")

    findings: list[NormalizedFinding] = []
    for r in results:
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        cwe_raw = meta.get("cwe") or []
        if isinstance(cwe_raw, str):
            cwe_raw = [cwe_raw]
        refs = meta.get("references") or []
        if isinstance(refs, str):
            refs = [refs]
        sev_raw = extra.get("severity") or ""
        severity = _SEV.get(sev_raw.upper()) or normalize_severity(sev_raw)
        message = (extra.get("message") or "").strip()
        check_id = r.get("check_id") or "semgrep-rule"
        lines = extra.get("lines")
        findings.append(
            NormalizedFinding(
                type="sast",
                title=truncate(message.split("\n", 1)[0] or check_id, 500) or check_id,
                severity=severity,
                tool_name="Semgrep",
                description=message,
                remediation=(extra.get("fix") or "").strip(),
                cwe=unique_cwes(cwe_raw),
                rule_id=check_id,
                file_path=r.get("path"),
                line_start=to_int((r.get("start") or {}).get("line")),
                line_end=to_int((r.get("end") or {}).get("line")),
                snippet=None if not lines or lines == "requires login" else truncate(lines, 4000),
                fingerprint=_fingerprint(extra),
                references=[{"url": u} for u in refs if isinstance(u, str)],
            )
        )
    paths = data.get("paths") or {}
    skipped = paths.get("skipped") or [] if isinstance(paths, dict) else []
    incomplete = bool(data.get("errors")) or any(
        isinstance(item, dict)
        and item.get("reason")
        in {
            "analysis_failed_parser_or_internal_error",
            "too_many_matches",
            "timeout",
            "out_of_memory",
        }
        for item in skipped
    )
    return ParsedReport(
        "semgrep",
        "sast",
        "Semgrep",
        data.get("version"),
        findings,
        complete_for_resolution=not incomplete,
    )
