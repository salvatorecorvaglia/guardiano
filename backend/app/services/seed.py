"""Demo data generator (development only).

Creates demo users for each role, four assets and ~18 weeks of weekly SAST/SCA scan history with
realistic fix/triage activity.
"""

import json
import random
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.models import Asset, Finding, Scan, User
from app.models.base import utcnow
from app.models.enums import Role, Status
from app.services import lifecycle
from app.services.ingestion import IngestOptions, ingest_report

DEMO_PASSWORD = "Guardiano-Demo-2026!"
DEMO_USERS = [
    ("admin@guardiano.local", "Ada Admin", Role.admin),
    ("manager@guardiano.local", "Marco Manager", Role.manager),
    ("analyst@guardiano.local", "Alex Analyst", Role.analyst),
    ("viewer@guardiano.local", "Vera Viewer", Role.viewer),
]

ASSETS = [
    dict(
        name="payments-api",
        type="application",
        criticality="critical",
        owner="Payments Team",
        tags=["pci", "nodejs", "internet-facing"],
        repo_url="https://git.example.com/fin/payments-api",
        description="Card payment processing API",
        lang="js",
        eco="npm",
        sast_tool="CodeQL",
        sca_tool="Trivy",
    ),
    dict(
        name="web-portal",
        type="application",
        criticality="high",
        owner="Customer Experience",
        tags=["frontend", "react", "internet-facing"],
        repo_url="https://git.example.com/cx/web-portal",
        description="Customer self-service portal",
        lang="js",
        eco="npm",
        sast_tool="Semgrep",
        sca_tool="OWASP Dependency-Track",
    ),
    dict(
        name="inventory-service",
        type="service",
        criticality="medium",
        owner="Supply Chain",
        tags=["python", "django"],
        repo_url="https://git.example.com/scm/inventory-service",
        description="Warehouse inventory microservice",
        lang="py",
        eco="pypi",
        sast_tool="Semgrep",
        sca_tool="Trivy",
    ),
    dict(
        name="reporting-worker",
        type="container",
        criticality="low",
        owner="Data Platform",
        tags=["java", "batch"],
        repo_url="https://git.example.com/data/reporting-worker",
        description="Nightly reporting batch jobs",
        lang="java",
        eco="maven",
        sast_tool="SonarQube",
        sca_tool="Grype",
    ),
]

SAST_TEMPLATES = [
    ("SQL injection via string concatenation", "CWE-89", "high", "Use parameterized queries."),
    ("Reflected cross-site scripting", "CWE-79", "medium", "Encode output and use auto-escaping templates."),
    (
        "Path traversal in file download",
        "CWE-22",
        "high",
        "Canonicalize paths and enforce an allow-listed root.",
    ),
    ("Hard-coded credentials", "CWE-798", "critical", "Move secrets to a vault and rotate them."),
    ("OS command injection", "CWE-78", "critical", "Avoid shell invocation; pass argument arrays."),
    ("Insecure deserialization", "CWE-502", "high", "Never deserialize untrusted data with unsafe loaders."),
    ("Server-side request forgery", "CWE-918", "high", "Validate outbound URLs against an allow-list."),
    ("Weak hash algorithm (MD5)", "CWE-327", "low", "Use SHA-256 or a password hashing function."),
    ("Open redirect", "CWE-601", "medium", "Only redirect to relative, validated paths."),
    ("Missing CSRF protection", "CWE-352", "medium", "Enable CSRF middleware for state-changing routes."),
    ("Sensitive data written to logs", "CWE-532", "low", "Mask secrets and PII before logging."),
    (
        "XML external entity processing",
        "CWE-611",
        "high",
        "Disable DTDs and external entities in the parser.",
    ),
    ("Insecure randomness for tokens", "CWE-338", "medium", "Use a CSPRNG for security tokens."),
    (
        "Regular expression denial of service",
        "CWE-1333",
        "low",
        "Bound input size and avoid nested quantifiers.",
    ),
    (
        "Debug mode enabled in production config",
        "CWE-489",
        "info",
        "Disable debug flags in production builds.",
    ),
]

SCA_TEMPLATES = {
    "npm": [
        ("lodash", "4.17.20", "CVE-2021-23337", "high", 7.2, "4.17.21", "CWE-94"),
        ("minimist", "1.2.5", "CVE-2021-44906", "critical", 9.8, "1.2.6", "CWE-1321"),
        ("axios", "0.21.1", "CVE-2021-3749", "high", 7.5, "0.21.2", "CWE-1333"),
        ("node-fetch", "2.6.1", "CVE-2022-0235", "high", 8.8, "2.6.7", "CWE-601"),
        ("jsonwebtoken", "8.5.1", "CVE-2022-23540", "medium", 6.4, "9.0.0", "CWE-287"),
        ("express", "4.17.1", "CVE-2024-29041", "medium", 6.1, "4.19.2", "CWE-601"),
        ("ws", "7.4.5", "CVE-2024-37890", "high", 7.5, "7.5.10", "CWE-476"),
        ("semver", "5.7.1", "CVE-2022-25883", "medium", 5.3, "5.7.2", "CWE-1333"),
        ("tough-cookie", "4.0.0", "CVE-2023-26136", "medium", 6.5, "4.1.3", "CWE-1321"),
        ("follow-redirects", "1.14.7", "CVE-2022-0536", "medium", 5.9, "1.14.8", "CWE-200"),
    ],
    "pypi": [
        ("django", "3.2.0", "CVE-2021-35042", "critical", 9.8, "3.2.5", "CWE-89"),
        ("pyyaml", "5.3.1", "CVE-2020-14343", "critical", 9.8, "5.4", "CWE-20"),
        ("urllib3", "1.26.4", "CVE-2021-33503", "high", 7.5, "1.26.5", "CWE-400"),
        ("requests", "2.25.1", "CVE-2023-32681", "medium", 6.1, "2.31.0", "CWE-200"),
        ("jinja2", "2.11.2", "CVE-2024-22195", "medium", 5.4, "3.1.3", "CWE-79"),
        ("pillow", "8.1.0", "CVE-2021-25289", "critical", 9.8, "8.1.1", "CWE-787"),
        ("cryptography", "3.3.1", "CVE-2023-50782", "high", 7.5, "42.0.0", "CWE-208"),
        ("sqlparse", "0.4.1", "CVE-2023-30608", "medium", 6.5, "0.4.4", "CWE-1333"),
    ],
    "maven": [
        (
            "org.apache.logging.log4j:log4j-core",
            "2.14.1",
            "CVE-2021-44228",
            "critical",
            10.0,
            "2.17.1",
            "CWE-502",
        ),
        (
            "com.fasterxml.jackson.core:jackson-databind",
            "2.9.10.1",
            "CVE-2020-36518",
            "high",
            7.5,
            "2.12.6.1",
            "CWE-787",
        ),
        ("org.springframework:spring-web", "5.3.17", "CVE-2016-1000027", "critical", 9.8, "6.0.0", "CWE-502"),
        ("org.yaml:snakeyaml", "1.29", "CVE-2022-1471", "high", 8.3, "2.0", "CWE-502"),
        ("commons-io:commons-io", "2.6", "CVE-2021-29425", "medium", 4.8, "2.7", "CWE-22"),
        ("com.google.guava:guava", "29.0-jre", "CVE-2023-2976", "high", 7.1, "32.0.0-jre", "CWE-552"),
        ("org.postgresql:postgresql", "42.2.18", "CVE-2022-31197", "high", 8.0, "42.2.26", "CWE-89"),
    ],
}

EXT = {"js": "js", "py": "py", "java": "java"}
DIRS = {
    "js": ["src/routes", "src/services", "src/lib"],
    "py": ["app/views", "app/services", "app/utils"],
    "java": ["src/main/java/com/example/reports", "src/main/java/com/example/io"],
}

WEEKS = 18


def _pool(rng: random.Random, spec: dict) -> tuple[list[dict], list[dict]]:
    sast, sca = [], []
    for i in range(rng.randint(14, 22)):
        title, cwe, sev, fix = rng.choice(SAST_TEMPLATES)
        d = rng.choice(DIRS[spec["lang"]])
        start = rng.randint(0, WEEKS - 1)
        fixed = start + rng.randint(1, 10) if rng.random() < 0.55 else None
        sast.append(
            dict(
                item=dict(
                    title=title,
                    severity=sev,
                    cwe=[cwe],
                    remediation=fix,
                    rule_id=f"demo.{cwe.lower()}",
                    file_path=f"{d}/module_{i:02d}.{EXT[spec['lang']]}",
                    line_start=rng.randint(5, 400),
                    description=f"{title} detected by static analysis.",
                ),
                start=start,
                fixed=fixed,
            )
        )
    for pkg, ver, cve, sev, score, fixed_v, cwe in SCA_TEMPLATES[spec["eco"]]:
        if rng.random() < 0.2:
            continue
        start = rng.randint(0, WEEKS - 1)
        fixed = start + rng.randint(2, 12) if rng.random() < 0.45 else None
        sca.append(
            dict(
                item=dict(
                    title=f"{cve} in {pkg}",
                    severity=sev,
                    cvss_score=score,
                    cwe=[cwe],
                    cve_id=cve,
                    package_name=pkg,
                    package_version=ver,
                    ecosystem=spec["eco"],
                    fixed_version=fixed_v,
                    purl=f"pkg:{spec['eco']}/{pkg.replace(':', '/')}@{ver}",
                    remediation=f"Upgrade {pkg} to {fixed_v} or later.",
                    description=f"{pkg} {ver} is affected by {cve}.",
                ),
                start=start,
                fixed=fixed,
            )
        )
    return sast, sca


def _report(tool: str, scan_type: str, items: list[dict]) -> bytes:
    return json.dumps(
        {
            "schema": "guardiano/v1",
            "tool": {"name": tool},
            "scan_type": scan_type,
            "findings": [i["item"] for i in items],
        }
    ).encode()


def _triage(db: Session, rng: random.Random, asset: Asset, users: dict[Role, User], when) -> None:
    open_findings = db.scalars(
        select(Finding).where(Finding.asset_id == asset.id, Finding.status == Status.open.value)
    ).all()
    for f in open_findings:
        roll = rng.random()
        if roll < 0.03:
            lifecycle.set_status(
                db,
                f,
                Status.false_positive,
                actor=users[Role.analyst],
                now=when,
                justification="Input is validated by the API gateway schema; not exploitable.",
            )
        elif roll < 0.045 and f.severity in ("low", "medium"):
            lifecycle.set_status(
                db,
                f,
                Status.risk_accepted,
                actor=users[Role.manager],
                now=when,
                justification="Compensating control: WAF rule in place. Fix scheduled for next quarter.",
                risk_accepted_until=when + timedelta(days=120),
            )
        elif roll < 0.12:
            lifecycle.set_status(db, f, Status.in_progress, actor=users[Role.analyst], now=when)
            f.assignee_id = users[Role.analyst].id
    db.commit()


def seed_demo(db: Session) -> None:
    if db.scalar(select(func.count()).select_from(Scan)):
        print("Scans already exist - skipping demo seed.")
        return
    rng = random.Random(1337)

    users: dict[Role, User] = {}
    for email, name, role in DEMO_USERS:
        user = db.scalar(select(User).where(User.email == email))
        if user is None:
            user = User(
                email=email, full_name=name, role=role.value, password_hash=hash_password(DEMO_PASSWORD)
            )
            db.add(user)
        users[role] = user
    db.commit()

    now = utcnow().replace(minute=0, second=0, microsecond=0)
    for spec in ASSETS:
        asset = db.scalar(select(Asset).where(Asset.name == spec["name"]))
        if asset is None:
            asset = Asset(
                **{
                    k: spec[k]
                    for k in ("name", "type", "criticality", "owner", "tags", "repo_url", "description")
                }
            )
            db.add(asset)
            db.commit()
        sast, sca = _pool(rng, spec)
        for w in range(WEEKS):
            when = now - timedelta(days=(WEEKS - w) * 7 - rng.randint(0, 2), hours=rng.randint(0, 8))
            for tool, stype, pool in ((spec["sast_tool"], "sast", sast), (spec["sca_tool"], "sca", sca)):
                items = [p for p in pool if p["start"] <= w and (p["fixed"] is None or p["fixed"] > w)]
                ingest_report(
                    db,
                    _report(tool, stype, items),
                    asset,
                    users[Role.analyst],
                    IngestOptions(
                        source="api",
                        branch="main",
                        commit_sha=f"{rng.getrandbits(160):040x}",
                        file_name=f"{tool.lower().replace(' ', '-')}-{stype}.json",
                        close_missing=True,
                        now=when,
                    ),
                )
            _triage(db, rng, asset, users, when + timedelta(hours=3))

    print("Demo data loaded. See the demo setup documentation for sign-in credentials.")
