from enum import StrEnum


class Role(StrEnum):
    admin = "admin"
    manager = "manager"
    analyst = "analyst"
    viewer = "viewer"


ROLE_RANK = {Role.viewer: 0, Role.analyst: 1, Role.manager: 2, Role.admin: 3}


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


SEVERITY_ORDER = [Severity.critical, Severity.high, Severity.medium, Severity.low, Severity.info]
SEVERITY_RANK = {s: i for i, s in enumerate(reversed(SEVERITY_ORDER))}  # info=0 .. critical=4
SEVERITY_WEIGHT = {"critical": 10.0, "high": 5.0, "medium": 2.0, "low": 0.5, "info": 0.0}


class Status(StrEnum):
    open = "open"
    in_progress = "in_progress"
    false_positive = "false_positive"
    risk_accepted = "risk_accepted"
    resolved = "resolved"


ACTIVE_STATUSES = (Status.open, Status.in_progress)
CLOSED_STATUSES = (Status.false_positive, Status.risk_accepted, Status.resolved)


class ScanType(StrEnum):
    sast = "sast"
    sca = "sca"
    iac = "iac"  # infrastructure as code: Checkov, KICS, Trivy misconfigurations
    dast = "dast"  # running applications: ZAP, Nuclei


SCAN_TYPES = tuple(t.value for t in ScanType)


class AssetType(StrEnum):
    repository = "repository"
    application = "application"
    service = "service"
    container = "container"


class Environment(StrEnum):
    production = "production"
    staging = "staging"
    development = "development"
    test = "test"


class Criticality(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


CRITICALITIES = [c.value for c in Criticality]
ANY_CRITICALITY = "any"  # SLA policy row that applies to every criticality without its own row

CRITICALITY_MULTIPLIER = {"low": 0.5, "medium": 1.0, "high": 1.5, "critical": 2.0}


class TrackerKind(StrEnum):
    jira = "jira"
    github = "github"
    gitlab = "gitlab"


TRACKER_KINDS = tuple(k.value for k in TrackerKind)


class TokenScope(StrEnum):
    ingest = "ingest"
    read = "read"
    triage = "triage"  # change status, assignee, tags, dates and severity, and comment


class EventType(StrEnum):
    created = "created"
    seen_again = "seen_again"
    status_changed = "status_changed"
    reopened = "reopened"
    auto_resolved = "auto_resolved"
    no_longer_reported = "no_longer_reported"
    assigned = "assigned"
    comment = "comment"
    rule_applied = "rule_applied"
    tags_changed = "tags_changed"
    due_date_changed = "due_date_changed"
    severity_changed = "severity_changed"
    acceptance_requested = "acceptance_requested"
    acceptance_rejected = "acceptance_rejected"
