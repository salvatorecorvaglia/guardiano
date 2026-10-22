"""CycloneDX JSON (1.4 - 1.6) SBOM/VEX parser for vulnerability data."""

from typing import Any

from app.parsers.base import (
    NormalizedComponent,
    NormalizedFinding,
    ParsedReport,
    ParseError,
    normalize_severity,
    purl_ecosystem,
    severity_from_score,
    to_float,
    truncate,
    unique_cwes,
)

_METHOD_PREFERENCE = ["CVSSv4", "CVSSv31", "CVSSv3", "CVSSv2", "OWASP", "SSVC", "other"]
_SKIP_STATES = {"not_affected", "false_positive", "resolved", "resolved_with_pedigree"}


def _best_rating(ratings: list[dict[str, Any]]) -> tuple[str | None, float | None]:
    if not ratings:
        return None, None

    def rank(r: dict[str, Any]) -> int:
        m = r.get("method") or "other"
        return _METHOD_PREFERENCE.index(m) if m in _METHOD_PREFERENCE else len(_METHOD_PREFERENCE)

    # Severity and score come from the same rating. Picking each independently could pair a CVSSv2
    # score with another rating's severity and show "low, 9.8".
    for rating in sorted(ratings, key=rank):
        score = to_float(rating.get("score"))
        sev = rating.get("severity") if rating.get("severity") not in (None, "", "unknown") else None
        if score is not None or sev:
            return (normalize_severity(sev) if sev else severity_from_score(score)), score
    return None, None


def _licenses(component: dict[str, Any]) -> list[str]:
    """CycloneDX allows an SPDX id, a free-text name, or an expression; keep whichever is there."""
    out: list[str] = []
    for entry in component.get("licenses") or []:
        if not isinstance(entry, dict):
            continue
        if expression := entry.get("expression"):
            out.append(str(expression))
            continue
        licence = entry.get("license") or {}
        value = licence.get("id") or licence.get("name")
        if value:
            out.append(str(value))
    return [truncate(v, 100) for v in dict.fromkeys(out) if v]


def _full_name(component: dict[str, Any]) -> str | None:
    name = component.get("name")
    if name and component.get("group"):
        sep = ":" if purl_ecosystem(component.get("purl")) == "maven" else "/"
        name = f"{component['group']}{sep}{name}"
    return name


def _inventory(components: dict[str, dict[str, Any]]) -> list[NormalizedComponent]:
    out = []
    for component in components.values():
        name = _full_name(component)
        if not name:
            continue
        out.append(
            NormalizedComponent(
                name=truncate(name, 300),
                version=truncate(component.get("version"), 100),
                ecosystem=purl_ecosystem(component.get("purl")),
                purl=truncate(component.get("purl"), 1000),
                licenses=_licenses(component),
            )
        )
    return out


def _tool(data: dict[str, Any]) -> tuple[str, str | None]:
    tools = (data.get("metadata") or {}).get("tools")
    candidates: list[dict[str, Any]] = []
    if isinstance(tools, list):
        candidates = tools
    elif isinstance(tools, dict):
        candidates = (tools.get("components") or []) + (tools.get("services") or [])
    for t in candidates:
        if t.get("name"):
            return str(t["name"]), t.get("version")
    return "cyclonedx", None


def _component_index(components: list[dict[str, Any]], out: dict[str, dict[str, Any]]) -> None:
    for c in components or []:
        # bom-ref and purl are optional: anonymous packages still belong in the inventory.
        ref = c.get("bom-ref") or c.get("purl") or f"guardiano-anonymous:{len(out)}"
        out[ref] = c
        _component_index(c.get("components") or [], out)


def _fixed_version(vuln: dict[str, Any], ref: str) -> str | None:
    for aff in vuln.get("affects") or []:
        if aff.get("ref") != ref:
            continue
        for v in aff.get("versions") or []:
            if v.get("status") == "unaffected" and v.get("version"):
                return v["version"]
    props = {p.get("name"): p.get("value") for p in vuln.get("properties") or [] if isinstance(p, dict)}
    for key in ("fixedVersion", "fixed_version", "aquasecurity:trivy:FixedVersion"):
        if props.get(key):
            return str(props[key])
    return None


def parse(data: dict[str, Any]) -> ParsedReport:
    if data.get("bomFormat") != "CycloneDX":
        raise ParseError("Not a CycloneDX document (bomFormat != 'CycloneDX')")

    tool_name, tool_version = _tool(data)
    components: dict[str, dict[str, Any]] = {}
    meta_comp = (data.get("metadata") or {}).get("component")
    if meta_comp:
        _component_index([meta_comp], components)
    # Indexed separately: metadata.component is the thing the SBOM describes (the application itself),
    # so it must resolve vulnerability references without appearing in the asset's inventory.
    shipped: dict[str, dict[str, Any]] = {}
    _component_index(data.get("components") or [], shipped)
    components.update(shipped)

    findings: list[NormalizedFinding] = []
    for vuln in data.get("vulnerabilities") or []:
        state = (vuln.get("analysis") or {}).get("state")
        if state in _SKIP_STATES:
            continue
        vid = str(vuln.get("id") or "").strip()
        refs = vuln.get("references") or []
        cve = vid if vid.upper().startswith("CVE-") else None
        if not cve:
            cve = next(
                (r["id"] for r in refs if str(r.get("id", "")).upper().startswith("CVE-")),
                None,
            )
        severity, score = _best_rating(vuln.get("ratings") or [])
        links: list[dict[str, Any]] = []
        for adv in vuln.get("advisories") or []:
            if adv.get("url"):
                links.append({"url": adv["url"], "title": adv.get("title")})
        src_url = (vuln.get("source") or {}).get("url")
        if src_url:
            links.insert(0, {"url": src_url, "title": (vuln.get("source") or {}).get("name")})

        affects = vuln.get("affects") or [{"ref": None}]
        for aff in affects:
            ref = aff.get("ref")
            comp = components.get(ref or "", {})
            name = comp.get("name")
            if comp.get("group") and name:
                sep = ":" if purl_ecosystem(comp.get("purl")) == "maven" else "/"
                name = f"{comp['group']}{sep}{name}"
            purl = comp.get("purl") or (ref if ref and ref.startswith("pkg:") else None)
            if not name and purl:
                name = purl[4:].split("/", 1)[-1].split("@", 1)[0]
            version = comp.get("version")
            if not version and purl and "@" in purl:
                version = purl.rsplit("@", 1)[1].split("?", 1)[0]
            title_id = cve or vid or "Vulnerability"
            findings.append(
                NormalizedFinding(
                    type="sca",
                    title=truncate(f"{title_id} in {name or 'unknown package'}", 500) or title_id,
                    severity=severity or "medium",
                    cvss_score=score,
                    tool_name=tool_name,
                    description=(vuln.get("description") or vuln.get("detail") or "").strip(),
                    remediation=(vuln.get("recommendation") or "").strip(),
                    cwe=unique_cwes(vuln.get("cwes") or []),
                    rule_id=vid or None,
                    package_name=name,
                    package_version=version,
                    ecosystem=purl_ecosystem(purl),
                    purl=purl,
                    cve_id=cve.upper() if cve else None,
                    vuln_id=vid or None,
                    fixed_version=_fixed_version(vuln, ref) if ref else None,
                    references=links,
                )
            )

    return ParsedReport(
        "cyclonedx",
        "sca",
        tool_name,
        tool_version,
        findings,
        components=_inventory(shipped),
        inventory_complete=isinstance(data.get("components"), list),
    )
