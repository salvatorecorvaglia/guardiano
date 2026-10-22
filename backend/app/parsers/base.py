import logging
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)


class ParseError(ValueError):
    """Raised when a report cannot be parsed."""


_budget: ContextVar[dict | None] = ContextVar("parser_budget", default=None)


@contextmanager
def parse_budget(findings: int, components: int):
    token = _budget.set({"findings": [0, findings], "components": [0, components]})
    try:
        yield
    finally:
        _budget.reset(token)


def _consume(kind: str) -> None:
    budget = _budget.get()
    if budget is not None:
        counter = budget[kind]
        counter[0] += 1
        if counter[0] > counter[1]:
            raise ParseError(f"Report exceeds MAX_REPORT_{kind.upper()} ({counter[1]})")


@dataclass
class NormalizedFinding:
    type: str  # sast | sca | iac | dast
    title: str
    severity: str
    tool_name: str
    description: str = ""
    remediation: str = ""
    cvss_score: float | None = None
    cwe: list[str] = field(default_factory=list)
    rule_id: str | None = None
    # SAST
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    snippet: str | None = None
    # Scanner-provided identity of the result, stable when surrounding lines move.
    fingerprint: str | None = None
    # SCA
    package_name: str | None = None
    package_version: str | None = None
    ecosystem: str | None = None
    purl: str | None = None
    cve_id: str | None = None
    vuln_id: str | None = None
    fixed_version: str | None = None
    references: list[dict[str, Any]] = field(default_factory=list)
    # IaC: the resource the rule failed on, e.g. "aws_s3_bucket.logs".
    resource: str | None = None
    # DAST: where the running application answered, and with which request.
    url: str | None = None
    http_method: str | None = None
    parameter: str | None = None

    def __post_init__(self):
        _consume("findings")


@dataclass
class NormalizedComponent:
    """A package an SBOM says is present, whether or not it has a known vulnerability."""

    name: str
    version: str | None = None
    ecosystem: str | None = None
    purl: str | None = None
    licenses: list[str] = field(default_factory=list)

    def __post_init__(self):
        _consume("components")


@dataclass
class ParsedReport:
    format: str
    scan_type: str
    tool_name: str
    tool_version: str | None
    findings: list[NormalizedFinding]
    # Every tool that ran, including ones with no results (e.g. multi-run SARIF); drives close_missing.
    tool_names: list[str] = field(default_factory=list)
    # The inventory an SBOM carries; empty for formats that only report findings.
    components: list["NormalizedComponent"] = field(default_factory=list)
    # The finding types this run looked for, even where it found nothing: close_missing resolves what
    # each of them no longer reports. Empty means just scan_type. Trivy, for one, can look for
    # vulnerable packages, misconfigurations and secrets in one run.
    covered_types: list[str] = field(default_factory=list)
    inventory_complete: bool = False
    # False when the scanner explicitly reports a failed or incomplete analysis.
    complete_for_resolution: bool = True


# ---- shared helpers -------------------------------------------------------

SEVERITIES = ("critical", "high", "medium", "low", "info")

_SEVERITY_ALIASES = {
    "critical": "critical",
    "crit": "critical",
    "blocker": "critical",
    "high": "high",
    "error": "high",
    "major": "high",
    "important": "high",  # Red Hat, SUSE and Oracle advisories, which Trivy passes through
    "severe": "high",
    "medium": "medium",
    "moderate": "medium",
    "warning": "medium",
    "warn": "medium",
    "low": "low",
    "minor": "low",
    "trivial": "low",
    "note": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "none": "info",
    "negligible": "info",
    "unimportant": "info",  # Debian
    "unknown": "info",
}
_UNRECOGNISED: set[str] = set()


def normalize_severity(value: Any, default: str = "medium") -> str:
    if value is None:
        return default
    word = str(value).strip().lower()
    if word in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[word]
    word = word[:100]
    if word and word not in _UNRECOGNISED:
        # Said once per word: an unmapped vocabulary otherwise silently becomes the default, and
        # "Important" read as medium is a downgrade nobody would ever notice.
        if len(_UNRECOGNISED) >= 256:
            _UNRECOGNISED.clear()
        _UNRECOGNISED.add(word[:100])
        log.warning("unrecognised severity, using the configured default")
    return default


def first_score(*values: Any) -> float | None:
    """The first value that is a number, 0.0 included. ``to_float(a) or to_float(b)`` skipped a
    legitimate CVSS score of 0.0 as if it were missing."""
    for value in values:
        if (score := to_float(value)) is not None:
            return score
    return None


def severity_from_score(score: float | None) -> str | None:
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def to_float(value: Any) -> float | None:
    try:
        f = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return f if 0.0 <= f <= 10.0 else None


def to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def normalize_cwe(value: Any) -> str | None:
    """Accept 79, "79", "CWE-79", "cwe-079", "external/cwe/cwe-079" -> "CWE-79"."""
    if value is None:
        return None
    s = str(value).strip().lower()
    if "cwe" in s:
        s = s[s.rfind("cwe") + 3 :].lstrip("-_: ")
    digits = ""
    for ch in s:
        if ch.isdigit():
            digits += ch
        elif digits:
            break
    if not digits:
        return None
    return f"CWE-{int(digits)}"


def unique_cwes(values: list[Any]) -> list[str]:
    out: list[str] = []
    for v in values:
        c = normalize_cwe(v)
        if c and c not in out:
            out.append(c)
    return sorted(out, key=lambda c: int(c[4:]))


def purl_ecosystem(purl: str | None) -> str | None:
    """ "pkg:npm/lodash@4.17.20" -> "npm"."""
    if purl and purl.startswith("pkg:"):
        return purl[4:].split("/", 1)[0].lower() or None
    return None


def truncate(s: str | None, n: int) -> str | None:
    if s is None:
        return None
    return s if len(s) <= n else s[: n - 1] + "…"
