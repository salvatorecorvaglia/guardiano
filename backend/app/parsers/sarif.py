"""SARIF 2.1.0 parser (CodeQL, Semgrep, Snyk Code, Checkmarx, SonarQube exports, Bandit, ...)."""

import re
from typing import Any

from app.parsers.base import (
    NormalizedFinding,
    ParsedReport,
    ParseError,
    normalize_severity,
    severity_from_score,
    to_float,
    to_int,
    truncate,
    unique_cwes,
)

_CWE_RE = re.compile(r"cwe[-_/:]?\s*0*(\d+)", re.IGNORECASE)
_LEVEL_MAP = {"error": "high", "warning": "medium", "note": "low", "none": "info"}


def _suppressed(result: dict[str, Any]) -> bool:
    """Whether a suppression is in force. SARIF gives each one a status; only "accepted" (or no status,
    which the spec says means accepted) hides the result. A "rejected" suppression is somebody saying
    the finding is real, and one "underReview" has not been decided -- both are still live."""
    return any(
        isinstance(s, dict) and s.get("status", "accepted") == "accepted"
        for s in result.get("suppressions") or []
    )


# Semgrep emits this placeholder instead of a fingerprint for anonymous users.
_NO_FINGERPRINT = {"requires login", "", "0"}


def _fingerprint(res: dict[str, Any]) -> str | None:
    """A stable per-result id: SARIF partialFingerprints, else fingerprints; the line hash wins."""
    for key in ("partialFingerprints", "fingerprints"):
        prints = res.get(key)
        if not isinstance(prints, dict):
            continue
        for name in sorted(prints, key=lambda k: (0 if "primaryLocationLineHash" in k else 1, k)):
            value = prints[name]
            if isinstance(value, str | int) and str(value).strip().lower() not in _NO_FINGERPRINT:
                return truncate(str(value).strip(), 200)
    return None


def _text(obj: Any) -> str:
    if isinstance(obj, dict):
        return obj.get("markdown") or obj.get("text") or ""
    return obj or ""


def _cwes_from(rule: dict[str, Any], result: dict[str, Any]) -> list[str]:
    raw: list[str] = []
    for props in (rule.get("properties") or {}, result.get("properties") or {}):
        for tag in props.get("tags") or []:
            raw.extend(f"CWE-{m}" for m in _CWE_RE.findall(str(tag)))
        for key in ("cwe", "CWE", "cwes"):
            val = props.get(key)
            if isinstance(val, list):
                raw.extend(str(v) for v in val)
            elif val:
                raw.append(str(val))
    for rel in rule.get("relationships") or []:
        target = rel.get("target") or {}
        comp = (target.get("toolComponent") or {}).get("name", "")
        if comp.upper() == "CWE" and target.get("id"):
            raw.append(str(target["id"]))
    return unique_cwes(raw)


def _rule_index(driver: dict[str, Any], extensions: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    for comp in [driver, *extensions]:
        for r in comp.get("rules") or []:
            if r.get("id"):
                rules[r["id"]] = r
    return rules


def _severity(rule: dict[str, Any], result: dict[str, Any]) -> tuple[str, float | None]:
    score = None
    for props in (result.get("properties") or {}, rule.get("properties") or {}):
        score = to_float(props.get("security-severity"))
        if score is not None:
            break
    sev = severity_from_score(score)
    if sev:
        return sev, score
    for props in (result.get("properties") or {}, rule.get("properties") or {}):
        if props.get("severity"):
            return normalize_severity(props["severity"]), None
    level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level") or "warning"
    return _LEVEL_MAP.get(level, "medium"), None


def _artifact_uri(location: dict[str, Any], run: dict[str, Any]) -> str | None:
    """Resolve an indexed artifact without fetching scanner-controlled locations."""
    if location.get("uri"):
        return location["uri"]
    index = location.get("index")
    artifacts = run.get("artifacts") or []
    if isinstance(index, int) and not isinstance(index, bool) and 0 <= index < len(artifacts):
        return (artifacts[index].get("location") or {}).get("uri")
    return None


def parse(data: dict[str, Any]) -> ParsedReport:
    runs = data.get("runs")
    if not isinstance(runs, list):
        raise ParseError("SARIF document has no 'runs' array")

    findings: list[NormalizedFinding] = []
    tool_name, tool_version = "sarif", None
    run_tools: list[str] = []
    for run in runs:
        tool = run.get("tool") or {}
        driver = tool.get("driver") or {}
        run_tool = driver.get("name") or "sarif"
        if run_tool not in run_tools:
            run_tools.append(run_tool)
        if tool_name == "sarif":
            tool_name = run_tool
            tool_version = driver.get("semanticVersion") or driver.get("version")
        rules = _rule_index(driver, tool.get("extensions") or [])
        driver_rules = driver.get("rules") or []

        for res in run.get("results") or []:
            if res.get("kind") not in (None, "fail", "open", "review"):
                continue
            if _suppressed(res):
                continue
            rule_id = res.get("ruleId") or (res.get("rule") or {}).get("id")
            rule = rules.get(rule_id or "", {})
            index = res.get("ruleIndex")
            # -1 is SARIF's "no rule" sentinel, and driver_rules[-1] is the *last* rule: the result
            # would inherit another rule's CWEs and severity. Only a real position counts.
            if not rule and isinstance(index, int) and 0 <= index < len(driver_rules):
                rule = driver_rules[index]
                rule_id = rule_id or rule.get("id")

            file_path = line_start = line_end = snippet = None
            for loc in res.get("locations") or []:
                phys = loc.get("physicalLocation") or {}
                art = phys.get("artifactLocation") or {}
                uri = _artifact_uri(art, run)
                if uri:
                    file_path = uri
                    region = phys.get("region") or {}
                    line_start = to_int(region.get("startLine"))
                    line_end = to_int(region.get("endLine")) or line_start
                    snippet = _text(region.get("snippet")) or _text(
                        (phys.get("contextRegion") or {}).get("snippet")
                    )
                    break

            severity, score = _severity(rule, res)
            message = _text(res.get("message"))
            short = _text(rule.get("shortDescription"))
            if short.startswith("Semgrep Finding:"):
                short = ""  # Semgrep's short description is just the rule id; the message is better.
            title = short or message.split("\n", 1)[0] or rule.get("name") or rule_id or "SAST finding"
            full = _text(rule.get("fullDescription"))
            description = message if not full or full == message else f"{message}\n\n{full}"
            refs = [{"url": rule["helpUri"]}] if rule.get("helpUri") else []

            findings.append(
                NormalizedFinding(
                    type="sast",
                    title=truncate(title.strip(), 500) or "SAST finding",
                    severity=severity,
                    cvss_score=score,
                    tool_name=run_tool,
                    description=description.strip(),
                    remediation=_text(rule.get("help")).strip(),
                    cwe=_cwes_from(rule, res),
                    rule_id=rule_id,
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    snippet=truncate(snippet or None, 4000),
                    fingerprint=_fingerprint(res),
                    references=refs,
                )
            )

    incomplete = any(
        invocation.get("executionSuccessful") is False
        or any(
            note.get("level") == "error"
            for key in ("toolExecutionNotifications", "toolConfigurationNotifications")
            for note in invocation.get(key) or []
        )
        for run in runs
        for invocation in run.get("invocations") or []
    )
    return ParsedReport(
        "sarif",
        "sast",
        tool_name,
        tool_version,
        findings,
        run_tools,
        complete_for_resolution=not incomplete,
    )
