"""Trivy JSON report parser (`trivy fs|image|repo|config --format json`).

One run can hold three kinds of result, told apart by each result's Class:

- vulnerable packages (os-pkgs, lang-pkgs) become SCA findings;
- failed misconfiguration checks (config) become IaC findings, on the resource that failed;
- secrets (secret) become SAST findings with CWE-798, like Gitleaks. The matched text is never kept.

The report says which kinds were scanned even where nothing was found, which is what lets
close_missing resolve the last misconfiguration once it is fixed (ParsedReport.covered_types).
"""

from typing import Any

from app.parsers.base import (
    NormalizedComponent,
    NormalizedFinding,
    ParsedReport,
    ParseError,
    first_score,
    normalize_severity,
    purl_ecosystem,
    severity_from_score,
    truncate,
    unique_cwes,
)

_CVSS_SOURCES = ("nvd", "ghsa", "redhat")


def _cvss(v: dict[str, Any]) -> float | None:
    cvss = v.get("CVSS") or {}
    for src in (*_CVSS_SOURCES, *cvss.keys()):
        entry = cvss.get(src) or {}
        score = first_score(entry.get("V3Score"), entry.get("V40Score"), entry.get("V2Score"))
        if score is not None:
            return score
    return None


def _packages(res: dict[str, Any]) -> list[NormalizedComponent]:
    """Present only when Trivy ran with --list-all-pkgs."""
    out = []
    for pkg in res.get("Packages") or []:
        name = pkg.get("Name")
        if not name:
            continue
        purl = (pkg.get("Identifier") or {}).get("PURL")
        licenses = [str(x) for x in (pkg.get("Licenses") or []) if x]
        out.append(
            NormalizedComponent(
                name=truncate(name, 300),
                version=truncate(pkg.get("Version"), 100),
                ecosystem=purl_ecosystem(purl) or res.get("Type"),
                purl=truncate(purl, 1000),
                licenses=[truncate(x, 100) for x in dict.fromkeys(licenses)],
            )
        )
    return out


def parse(data: dict[str, Any]) -> ParsedReport:
    results = data.get("Results")
    if not isinstance(results, list):
        raise ParseError("Trivy report has no 'Results' array")
    version = (data.get("Trivy") or {}).get("Version")

    findings: list[NormalizedFinding] = []
    components: list[NormalizedComponent] = []
    covered: set[str] = set()
    for res in results:
        if not isinstance(res, dict):
            continue
        target = res.get("Target")
        cls = str(res.get("Class") or "")
        if cls in _PACKAGE_CLASSES or "Vulnerabilities" in res:
            covered.add("sca")
        if cls == "config" or "Misconfigurations" in res or "MisconfSummary" in res:
            covered.add("iac")
        if cls == "secret" or "Secrets" in res:
            covered.add("sast")
        findings += _misconfigurations(res, target)
        findings += _secrets(res, target)
        eco_hint = res.get("Type")
        components += _packages(res)
        for v in res.get("Vulnerabilities") or []:
            vid = v.get("VulnerabilityID") or ""
            purl = (v.get("PkgIdentifier") or {}).get("PURL")
            score = _cvss(v)
            sev = v.get("Severity")
            severity = (
                normalize_severity(sev)
                if sev and sev != "UNKNOWN"
                else (severity_from_score(score) or "medium")
            )
            refs = [{"url": v["PrimaryURL"]}] if v.get("PrimaryURL") else []
            refs += [{"url": u} for u in (v.get("References") or [])[:10] if u != v.get("PrimaryURL")]
            fixed = v.get("FixedVersion")
            findings.append(
                NormalizedFinding(
                    type="sca",
                    title=truncate(v.get("Title") or f"{vid} in {v.get('PkgName')}", 500) or vid,
                    severity=severity,
                    cvss_score=score,
                    tool_name="Trivy",
                    description=(v.get("Description") or "").strip(),
                    remediation=f"Upgrade {v.get('PkgName')} to {fixed}." if fixed else "",
                    cwe=unique_cwes(v.get("CweIDs") or []),
                    rule_id=vid or None,
                    file_path=target,
                    package_name=v.get("PkgName"),
                    package_version=v.get("InstalledVersion"),
                    ecosystem=purl_ecosystem(purl) or eco_hint,
                    purl=purl,
                    cve_id=vid.upper() if vid.upper().startswith("CVE-") else None,
                    vuln_id=vid or None,
                    fixed_version=fixed,
                    references=refs,
                )
            )
    # The run's main kind: packages when it looked at any, which is what every earlier version said.
    primary = next((t for t in ("sca", "iac", "sast") if t in covered), "sca")
    return ParsedReport(
        "trivy",
        primary,
        "Trivy",
        version,
        findings,
        components=components,
        covered_types=sorted(covered),
        inventory_complete=bool(
            inventory_results := [
                r
                for r in results
                if isinstance(r, dict)
                and (r.get("Class") in _PACKAGE_CLASSES or "Vulnerabilities" in r or "Packages" in r)
            ]
        )
        and all("Packages" in r for r in inventory_results),
    )


_PACKAGE_CLASSES = {"os-pkgs", "lang-pkgs"}


def _references(item: dict[str, Any]) -> list[dict[str, Any]]:
    primary = item.get("PrimaryURL")
    refs = [{"url": primary}] if primary else []
    more = [u for u in (item.get("References") or [])[:10] if isinstance(u, str) and u != primary]
    return refs + [{"url": u} for u in more]


def _misconfigurations(res: dict[str, Any], target: str | None) -> list[NormalizedFinding]:
    out = []
    for m in res.get("Misconfigurations") or []:
        if not isinstance(m, dict) or str(m.get("Status") or "FAIL").upper() != "FAIL":
            continue  # --include-non-failures also lists the checks that passed
        cause = m.get("CauseMetadata") or {}
        rule = m.get("AVDID") or m.get("ID")
        detail = "\n\n".join(x for x in (m.get("Description"), m.get("Message")) if x)
        out.append(
            NormalizedFinding(
                type="iac",
                title=truncate(m.get("Title") or rule or "Misconfiguration", 500) or "Misconfiguration",
                severity=normalize_severity(m.get("Severity")),
                tool_name="Trivy",
                description=detail.strip(),
                remediation=(m.get("Resolution") or "").strip(),
                rule_id=rule,
                file_path=target,
                line_start=cause.get("StartLine") if isinstance(cause.get("StartLine"), int) else None,
                line_end=cause.get("EndLine") if isinstance(cause.get("EndLine"), int) else None,
                resource=cause.get("Resource") or None,
                references=_references(m),
            )
        )
    return out


def _secrets(res: dict[str, Any], target: str | None) -> list[NormalizedFinding]:
    out = []
    for item in res.get("Secrets") or []:
        if not isinstance(item, dict):
            continue
        out.append(
            NormalizedFinding(
                type="sast",
                title=truncate(item.get("Title") or "Hard-coded secret", 500) or "Hard-coded secret",
                severity=normalize_severity(item.get("Severity"), default="high"),
                tool_name="Trivy",
                description=f"Category: {item.get('Category')}" if item.get("Category") else "",
                remediation="Revoke the credential, then remove it from the file and from the git history.",
                cwe=["CWE-798"],
                rule_id=item.get("RuleID"),
                file_path=target,
                line_start=item.get("StartLine") if isinstance(item.get("StartLine"), int) else None,
                line_end=item.get("EndLine") if isinstance(item.get("EndLine"), int) else None,
                # No snippet: "Match" and "Code" hold the line with the secret in it.
            )
        )
    return out
