"""Deduplication keys.

SAST findings are identified by (normalized file path, start line, primary CWE); when a result
carries no CWE the rule id is used instead.  SCA findings are identified by
(ecosystem:package, version, CVE); the advisory id (GHSA, OSV, ...) is used when there is no CVE.
IaC findings by (file, rule, resource), and DAST findings by (method, URL without query values,
parameter, rule). The SAST and SCA keys must never change: tests/test_dedup_golden.py pins them.

The scanner name is intentionally *not* part of the key, so the same flaw reported by two tools
collapses into one finding whose ``tools`` array lists both sources.
"""

import hashlib
import re
from urllib.parse import unquote, urlsplit

from app.core.config import settings
from app.parsers.base import NormalizedFinding

_URI_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")
_BASE_ID = re.compile(r"^%[A-Z_]+%/?")


def normalize_path(path: str | None) -> str:
    if not path:
        return ""
    p = unquote(path.strip()).replace("\\", "/")
    p = _URI_SCHEME.sub("", p)
    p = _BASE_ID.sub("", p)
    while p.startswith("./"):
        p = p[2:]
    p = re.sub(r"/{2,}", "/", p)
    return p.lstrip("/")


def primary_cwe(cwes: list[str]) -> str | None:
    if not cwes:
        return None
    # Parsers normalise CWEs to "CWE-<n>"; the lowest id is the most general, stable choice.
    return min(cwes, key=lambda c: int(c[4:]))


def _digest(*parts: object) -> str:
    raw = "|".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(raw.encode()).hexdigest()


def sast_key(asset_id: int, f: NormalizedFinding) -> str:
    path = normalize_path(f.file_path)
    discriminator = primary_cwe(f.cwe) or f"rule:{f.rule_id or ''}"
    if not path:
        # No physical location: fall back to the rule + title so distinct results don't collapse.
        discriminator = f"{discriminator}|{f.rule_id or ''}|{f.title}"
    return _digest(asset_id, "sast", path, f.line_start or 0, discriminator)


# Every scanner has its own word for a package ecosystem: OSV says "go", a purl says "golang", Syft
# (and so Grype) says "go-module", Trivy's fallback says "gobinary". The ecosystem is part of the SCA
# key, so the same CVE in the same Go module reported by three tools became three findings. These map
# each tool's words onto the purl type. OS package ecosystems (debian, alpine, ...) are already shared.
_ECOSYSTEMS = {
    **dict.fromkeys(("go", "golang", "gobinary", "gomod", "go-module"), "golang"),
    **dict.fromkeys(("pypi", "pip", "pipenv", "poetry", "python", "python-pkg"), "pypi"),
    **dict.fromkeys(("npm", "node-pkg", "nodejs", "yarn", "pnpm"), "npm"),
    **dict.fromkeys(("maven", "jar", "pom", "java-archive", "gradle"), "maven"),
    **dict.fromkeys(("cargo", "crates.io", "rust-crate", "rust-binary"), "cargo"),
    **dict.fromkeys(("gem", "rubygems", "bundler", "gemspec"), "gem"),
    **dict.fromkeys(("nuget", "dotnet", "dotnet-core", "dotnet-deps"), "nuget"),
    **dict.fromkeys(("composer", "packagist", "php-composer"), "composer"),
    **dict.fromkeys(("pub", "dart-pub"), "pub"),
}


def canonical_ecosystem(value: str | None) -> str:
    word = (value or "").strip().lower()
    return _ECOSYSTEMS.get(word, word)


def sca_key(asset_id: int, f: NormalizedFinding) -> str:
    # Opt-in, like DEDUP_FINGERPRINTS: it changes the key of any finding whose tool spelled its
    # ecosystem differently, which an existing installation would see as those findings being new.
    ecosystem = (
        canonical_ecosystem(f.ecosystem)
        if settings.dedup_canonical_ecosystems
        else ((f.ecosystem or "").lower())
    )
    pkg = f"{ecosystem}:{(f.package_name or '').lower()}"
    vuln = (f.cve_id or f.vuln_id or f.rule_id or f.title).upper()
    return _digest(asset_id, "sca", pkg, (f.package_version or "").strip(), vuln)


def iac_key(asset_id: int, f: NormalizedFinding) -> str:
    """The same rule failing on the same resource of the same file. Lines are left out, so an edit
    above the resource does not make a new finding; without a resource name the line has to do."""
    where = (f.resource or "").strip().lower() or f"line:{f.line_start or 0}"
    rule = (f.rule_id or "").strip().lower() or f.title.strip().lower()
    return _digest(asset_id, "iac", normalize_path(f.file_path), rule, where)


def normalize_url(url: str | None) -> str:
    """Scheme, host and path, lower-cased where URLs are case-insensitive, without the query's values.

    A scanner that sends ?id=1 and then ?id=2 has found one issue, not two; the parameter that matters
    is part of the key separately.
    """
    if not url:
        return ""
    try:
        parts = urlsplit(url.strip())
        port = parts.port  # raises for a port that is not a number
    except ValueError:
        # Not a URL a parser could make sense of ("[::bad", "host:port:extra"): still one place,
        # compared as written, rather than an error that fails the whole upload.
        return url.strip().lower()
    path = re.sub(r"/{2,}", "/", parts.path or "/").rstrip("/") or "/"
    names = sorted({q.split("=", 1)[0] for q in parts.query.split("&") if q})
    host = (parts.hostname or "").lower() + (f":{port}" if port else "")
    return f"{parts.scheme.lower()}://{host}{path}" + (f"?{'&'.join(names)}" if names else "")


def dast_key(asset_id: int, f: NormalizedFinding) -> str:
    rule = (f.rule_id or "").strip().lower() or primary_cwe(f.cwe) or f.title.strip().lower()
    method = (f.http_method or "").upper()
    return _digest(asset_id, "dast", method, normalize_url(f.url), (f.parameter or "").strip(), rule)


def dedup_key(asset_id: int, f: NormalizedFinding) -> str:
    if f.type == "sca":
        return sca_key(asset_id, f)
    if f.type == "iac":
        return iac_key(asset_id, f)
    if f.type == "dast":
        return dast_key(asset_id, f)
    return sast_key(asset_id, f)
