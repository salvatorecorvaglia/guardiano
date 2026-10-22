"""Streaming finding exports (JSON and SARIF 2.1.0). CSV lives next to its endpoint in api/v1/findings.py.

Both formats are written incrementally from an iterator of findings, so exporting a large inventory never
holds it in memory. The SARIF document streams its ``results`` first and the ``tool`` (with the rules seen)
last; JSON object key order carries no meaning, so this is a valid SARIF log.
"""

import json
from collections.abc import Iterable, Iterator
from typing import Any

from app import __version__
from app.models import Finding
from app.parsers.base import severity_from_score
from app.services.serializers import finding_out

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
# A representative CVSS-like score per severity, for SARIF consumers (e.g. GitHub) that rank by it.
_SCORE = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 2.0, "info": 0.0}


def json_stream(rows: Iterable[Finding]) -> Iterator[str]:
    yield "["
    for i, f in enumerate(rows):
        yield ("," if i else "") + "\n" + finding_out(f).model_dump_json()
    yield "\n]\n"


def _security_severity(f: Finding) -> float:
    # Keep the finding's own score when it agrees with its severity; importers derive severity from it.
    if f.cvss_score is not None and severity_from_score(f.cvss_score) == f.severity:
        return f.cvss_score
    return _SCORE.get(f.severity, 0.0)


def _rule_id(f: Finding) -> str:
    return f.rule_id or (f.cwe[0] if f.cwe else f"guardiano/{f.type}")


def sarif_result(f: Finding) -> dict[str, Any]:
    text = f.title if not f.description else f"{f.title}\n\n{f.description}"
    if f.type == "sca" and f.package_name:
        pkg = f"{f.package_name}@{f.package_version}" if f.package_version else f.package_name
        text += f"\n\nPackage: {pkg}" + (f" (fixed in {f.fixed_version})" if f.fixed_version else "")
    result: dict[str, Any] = {
        "ruleId": _rule_id(f),
        "level": _LEVEL.get(f.severity, "warning"),
        "message": {"text": text},
        "partialFingerprints": {"guardiano/dedupKey/v1": f.dedup_key},
        "properties": {
            "security-severity": str(_security_severity(f)),
            # CWE tags only: importers scan this list for CWE ids, so user tags go under "guardiano".
            "tags": [f"external/cwe/cwe-{c[4:]}" for c in f.cwe],
            "guardiano": {
                "id": f.id,
                "asset": f.asset.name,
                "type": f.type,
                "severity": f.severity,
                "status": f.status,
                "tools": list(f.tools or []),
                "tags": list(f.tags or []),
                "cve": f.cve_id,
                "advisory": f.vuln_id,
                "package": f.package_name,
                "version": f.package_version,
                "fixed_version": f.fixed_version,
                "purl": f.purl,
                "first_seen_at": f.first_seen_at.isoformat(),
            },
        },
    }
    if f.file_path:
        region: dict[str, Any] = {}
        if f.line_start:
            region = {"startLine": f.line_start, "endLine": f.line_end or f.line_start}
            if f.snippet:
                region["snippet"] = {"text": f.snippet}
        location: dict[str, Any] = {"artifactLocation": {"uri": f.file_path}}
        if region:
            location["region"] = region
        result["locations"] = [{"physicalLocation": location}]
    elif f.purl or f.package_name:
        result["locations"] = [{"logicalLocations": [{"name": f.purl or f.package_name, "kind": "package"}]}]
    return result


def _rule(f: Finding) -> dict[str, Any]:
    rule: dict[str, Any] = {"id": _rule_id(f), "properties": {}}
    if f.cwe:
        rule["properties"]["tags"] = [f"external/cwe/cwe-{c[4:]}" for c in f.cwe]
    if f.remediation:
        rule["help"] = {"text": f.remediation}
    return rule


def sarif_stream(rows: Iterable[Finding]) -> Iterator[str]:
    yield f'{{"$schema": {json.dumps(SARIF_SCHEMA)}, "version": "2.1.0", "runs": [{{"results": ['
    rules: dict[str, dict[str, Any]] = {}
    for i, f in enumerate(rows):
        rules.setdefault(_rule_id(f), _rule(f))
        yield ("," if i else "") + "\n" + json.dumps(sarif_result(f), default=str)
    tool = {"driver": {"name": "Guardiano", "version": __version__, "rules": list(rules.values())}}
    # Close the results array, add the tool, then close the run, the runs array and the document.
    yield '\n], "tool": ' + json.dumps(tool) + "}]}\n"
