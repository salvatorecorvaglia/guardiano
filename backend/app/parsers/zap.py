"""OWASP ZAP JSON report (the "Traditional JSON Report" template, `-J report.json`).

Each alert lists the requests it was seen on. Every instance (URL, method, parameter) becomes a finding,
so fixing one endpoint resolves that one; the same alert on ?id=1 and ?id=2 is still one finding, because
the URL's query values are not part of the key (services/dedup.py).
"""

import html
import re
from typing import Any

from app.parsers.base import NormalizedFinding, ParsedReport, ParseError, normalize_cwe, truncate

# ZAP's riskcode: 0 informational, 1 low, 2 medium, 3 high. It has no "critical".
_RISK = {"0": "info", "1": "low", "2": "medium", "3": "high"}
_TAGS = re.compile(r"<[^>]+>")


def _text(value: Any) -> str:
    """ZAP writes descriptions as HTML paragraphs."""
    if not value:
        return ""
    return html.unescape(_TAGS.sub("\n", str(value))).strip()


def parse(data: Any) -> ParsedReport:
    sites = data.get("site") if isinstance(data, dict) else None
    if not isinstance(sites, list):
        raise ParseError("ZAP report has no 'site' array")
    findings: list[NormalizedFinding] = []
    for site in sites:
        if not isinstance(site, dict):
            continue
        for alert in site.get("alerts") or []:
            if not isinstance(alert, dict):
                continue
            # ZAP writes -1 (or 0) for "no CWE".
            raw_cwe = str(alert.get("cweid", ""))
            cwe = normalize_cwe(raw_cwe) if raw_cwe not in ("", "-1", "0") else None
            refs = [{"url": u} for u in _text(alert.get("reference")).split() if u.startswith("http")][:10]
            # An alert without instances was seen on the site as a whole.
            instances = [i for i in alert.get("instances") or [] if isinstance(i, dict)]
            instances = instances or [{"uri": site.get("@name")}]
            for inst in instances:
                evidence = inst.get("evidence") or inst.get("attack")
                findings.append(
                    NormalizedFinding(
                        type="dast",
                        title=truncate(alert.get("name") or alert.get("alert") or "Alert", 500) or "Alert",
                        severity=_RISK.get(str(alert.get("riskcode")), "medium"),
                        tool_name="ZAP",
                        description=_text(alert.get("desc")),
                        remediation=_text(alert.get("solution")),
                        cwe=[cwe] if cwe else [],
                        rule_id=str(alert.get("pluginid") or alert.get("alertRef") or "") or None,
                        url=inst.get("uri"),
                        http_method=inst.get("method"),
                        parameter=inst.get("param") or None,
                        snippet=truncate(str(evidence), 1000) if evidence else None,
                        references=refs,
                    )
                )
    return ParsedReport("zap", "dast", "ZAP", data.get("@version"), findings)
