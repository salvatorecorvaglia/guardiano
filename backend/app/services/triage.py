"""Automatic triage: rules applied to findings as a scan creates them.

A rule is a set of conditions (all must match) and an action. Rules run in ``priority`` order, lowest first,
and every rule that matches is applied, so a later rule can override the severity or assignee set by an
earlier one while tags accumulate.

Rules touch findings a scan has just created, and the active findings a manager explicitly applies one to
(``apply_to_existing``, run as a job). They never reopen or re-suppress a closed finding, and never replace an
assignee a person chose. A status change goes through ``lifecycle.set_status`` so the audit trail and
``closed_at`` stay correct.

The same matcher backs ``POST /triage-rules/preview``, so a dry run cannot disagree with what ingestion does.
"""

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from fnmatch import fnmatchcase
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models import Asset, Finding, FindingEvent, TriageRule, User, VulnIntel
from app.models.base import utcnow
from app.models.enums import ACTIVE_STATUSES, ROLE_RANK, EventType, Role, Status
from app.services import lifecycle, tickets
from app.services.dedup import canonical_ecosystem, normalize_path
from app.services.queries import FindingFilters, findings_query
from app.services.scope import Scope, scope_for

log = logging.getLogger(__name__)

APPLY_JOB = "triage.apply_existing"
_INTEL_CONDITIONS = ("kev", "epss_min")
_APPLY_CHUNK = 500


@dataclass(frozen=True)
class Context:
    """What the matcher needs beyond the finding itself, loaded once for a whole scan.

    Ingestion matches findings it has not flushed yet, and SQLAlchemy does not load relationships of a
    pending object: ``f.asset`` and ``f.intel`` read as None there, so exploitability and asset conditions
    would never match. Without a context the matcher reads those relationships, which is right for
    findings loaded with them (the preview, and applying a rule to existing findings).
    """

    asset: Asset | None = None
    intel: Mapping[str, VulnIntel] | None = None


def context(db: Session, asset: Asset, rules: Iterable[TriageRule], cves: Iterable[str | None]) -> Context:
    """The context for one scan. Exploitability is only looked up when some rule asks about it."""
    wanted = sorted({c for c in cves if c})
    if not wanted or not any(k in (r.match or {}) for r in rules for k in _INTEL_CONDITIONS):
        return Context(asset=asset, intel={})
    intel = {}
    for start in range(0, len(wanted), 1000):
        rows = db.scalars(select(VulnIntel).where(VulnIntel.cve_id.in_(wanted[start : start + 1000])))
        intel.update({item.cve_id: item for item in rows})
    return Context(asset=asset, intel=intel)


def load_rules(db: Session, asset_id: int, now: datetime | None = None) -> list[TriageRule]:
    """Enabled, unexpired rules for an asset (its own and the ones for every asset), in priority order."""
    now = now or utcnow()
    return list(
        db.scalars(
            select(TriageRule)
            .where(
                TriageRule.enabled.is_(True),
                or_(TriageRule.asset_id == asset_id, TriageRule.asset_id.is_(None)),
                or_(TriageRule.expires_at.is_(None), TriageRule.expires_at > now),
            )
            .order_by(TriageRule.priority, TriageRule.id)
        )
    )


def _contains(haystack: str | None, needle: str) -> bool:
    return bool(haystack) and needle.lower() in haystack.lower()


def matches(rule_match: dict[str, Any], f: Finding, ctx: Context | None = None) -> bool:
    """Whether a finding satisfies every condition of a rule. An empty condition set matches nothing."""
    if not rule_match:
        return False
    if (cve := rule_match.get("cve")) and (f.cve_id or "").upper() != cve.upper():
        return False
    if (eco := rule_match.get("ecosystem")) and canonical_ecosystem(f.ecosystem) != canonical_ecosystem(eco):
        return False
    if any(k in rule_match for k in _INTEL_CONDITIONS):
        preloaded = ctx is not None and ctx.intel is not None
        intel = (ctx.intel or {}).get(f.cve_id or "") if preloaded else f.intel
        if (kev := rule_match.get("kev")) is not None and bool(intel and intel.in_kev) != kev:
            return False
        if (epss_min := rule_match.get("epss_min")) is not None and (
            intel is None or intel.epss is None or intel.epss < epss_min
        ):
            return False
    if rule_match.get("asset_tags") or rule_match.get("asset_criticality"):
        asset = ctx.asset if ctx is not None and ctx.asset is not None else f.asset
        carried = {t.lower() for t in (asset.tags or [])} if asset else set()
        if not {t.lower() for t in rule_match.get("asset_tags") or []} <= carried:
            return False
        levels = rule_match.get("asset_criticality")
        if levels and (asset is None or asset.criticality not in levels):
            return False
    if (t := rule_match.get("type")) and f.type != t:
        return False
    if (severities := rule_match.get("severity")) and f.severity not in severities:
        return False
    if (tool := rule_match.get("tool")) and tool.lower() not in [x.lower() for x in (f.tools or [])]:
        return False
    if (rule_id := rule_match.get("rule_id")) and (f.rule_id or "").lower() != rule_id.lower():
        return False
    if cwe := rule_match.get("cwe"):
        wanted = cwe.upper() if cwe.upper().startswith("CWE-") else f"CWE-{cwe}"
        if wanted not in (f.cwe or []):
            return False
    if (package := rule_match.get("package")) and (f.package_name or "").lower() != package.lower():
        return False
    if glob := rule_match.get("path_glob"):
        # fnmatchcase, not fnmatch: fnmatch follows the host filesystem's case rules, so the same rule
        # would behave differently on macOS and Linux. "tests/*" also matches "tests/unit/x.py",
        # because "*" spans path separators here.
        path = normalize_path(f.file_path)
        if not path or not fnmatchcase(path.lower(), glob.lower()):
            return False
    title = rule_match.get("title_contains")
    return not (title and not _contains(f.title, title))


def apply_rules(
    db: Session,
    finding: Finding,
    rules: Iterable[TriageRule],
    *,
    scan_id: int | None = None,
    now: datetime | None = None,
    ctx: Context | None = None,
    existing: bool = False,
    record: bool = True,
) -> list[TriageRule]:
    """Apply every matching rule to a finding. Returns the rules that fired.

    ``existing`` is for a finding that was already in the inventory: an assignee somebody chose is kept.
    """
    now = now or utcnow()
    fired: list[TriageRule] = []
    notes: list[str] = []
    status: tuple[Status, str, TriageRule] | None = None

    for rule in rules:
        if not matches(rule.match or {}, finding, ctx):
            continue
        action = rule.action or {}
        fired.append(rule)
        if record:
            rule.applied_count = (rule.applied_count or 0) + 1

        severity = action.get("severity")
        if severity and severity != finding.severity:
            before_severity = finding.severity
            notes.append(f"severity {finding.severity} -> {severity}")
            # An override, so the next scan does not put the scanner's severity back.
            finding.severity = finding.severity_override = severity
            if record:
                db.add(
                    FindingEvent(
                        finding=finding,
                        event=EventType.severity_changed.value,
                        from_severity=before_severity,
                        to_severity=severity,
                        scan_id=scan_id,
                        created_at=now,
                        comment=f"Auto-triage rule '{rule.name}'",
                    )
                )
        if tags := action.get("tags"):
            merged = lifecycle.normalize_tags([*(finding.tags or []), *tags])
            if merged != (finding.tags or []):
                notes.append(f"tagged {', '.join(t for t in merged if t not in (finding.tags or []))}")
                finding.tags = merged
        if (assignee_id := action.get("assignee_id")) is not None and not (existing and finding.assignee_id):
            assignee = db.get(User, assignee_id)
            asset = ctx.asset if ctx is not None else finding.asset
            if assignee is not None and assignee.is_active and scope_for(db, assignee).owns(asset):
                finding.assignee_id = assignee.id
                notes.append(f"assigned to {assignee.full_name or assignee.email}")
        if new_status := action.get("status"):
            reason = action.get("justification") or f"Auto-triage rule '{rule.name}'"
            status = (Status(new_status), reason, rule)

    if not fired:
        return []

    names = ", ".join(f"'{r.name}'" for r in fired)
    if notes and record:
        applied = "applied to existing findings" if existing else ""
        db.add(
            FindingEvent(
                finding=finding,
                event=EventType.rule_applied.value,
                comment=f"Auto-triage {names}{f' ({applied})' if applied else ''}: {'; '.join(notes)}",
                scan_id=scan_id,
                created_at=now,
            )
        )
    if status is not None:
        target, justification, rule = status
        if not record:
            finding.status = target.value
            finding.closed_at = now
            return fired
        lifecycle.set_status(
            db,
            finding,
            target,
            actor=None,
            justification=f"{justification} (rule '{rule.name}')",
            event=EventType.rule_applied,
            scan_id=scan_id,
            now=now,
        )
    log.info("auto-triage applied %s to finding '%s'", names, finding.title)
    return fired


def prefilter(match: dict[str, Any], asset_id: int | None, scope: Scope) -> FindingFilters:
    """The conditions that map to SQL, to narrow the candidates before the matcher sees them.

    A superset of what the rule matches: the matcher then decides. Shared by the preview and by
    apply_to_existing, so the two cannot examine different findings.
    """
    return FindingFilters(
        asset_id=[asset_id] if asset_id else [],
        type=match.get("type"),
        severity=match.get("severity", []),
        tool=match.get("tool"),
        cwe=match.get("cwe"),
        package=match.get("package"),
        cve=match.get("cve"),
        kev=True if match.get("kev") else None,
        epss_min=match.get("epss_min"),
        scope=scope,
    )


def apply_to_existing(
    db: Session, rule_id: int, scope: Scope, actor: str, *, actor_id: int | None = None
) -> int:
    """Apply one rule to the active findings it matches, in chunks, committing each. Returns how many.

    Closed findings are left alone: re-suppressing or reopening what somebody decided is not a rule's
    call. ``scope`` is the requester's, so a rule a team manager runs cannot reach another team's assets.
    """
    rule = db.get(TriageRule, rule_id)
    if rule is None:  # deleted before the worker got here
        return 0
    match = rule.match or {}
    filters = prefilter(match, rule.asset_id, scope)
    filters.status = [s.value for s in ACTIVE_STATUSES]
    ids = list(db.scalars(findings_query(filters, "first_seen").with_only_columns(Finding.id)))
    applied = 0
    for i in range(0, len(ids), _APPLY_CHUNK):
        if actor_id is not None:
            person = db.get(User, actor_id, populate_existing=True)
            if (
                person is None
                or not person.is_active
                or ROLE_RANK[Role(person.role)] < ROLE_RANK[Role.manager]
            ):
                break
            current_scope = scope_for(db, person)
            if scope.unrestricted:
                filters.scope = current_scope
            elif current_scope.unrestricted:
                filters.scope = scope
            else:
                filters.scope = Scope(tuple(sorted(set(scope.team_ids) & set(current_scope.team_ids))))
        chunk = ids[i : i + _APPLY_CHUNK]
        rows = (
            findings_query(filters, "first_seen")
            .where(Finding.id.in_(chunk))
            .order_by(None)
            .order_by(Finding.id)
            .with_for_update(of=Finding)
            .execution_options(populate_existing=True)
        )
        for f in db.scalars(rows).unique():
            previous = f.status
            if apply_rules(db, f, [rule], existing=True):
                applied += 1
                if f.status != previous:
                    tickets.queue_status_sync(db, f, previous, actor)
        from app.services.jobs import commit_owned

        commit_owned(db)
    log.info("triage rule %s applied to %d existing finding(s) at %s's request", rule.id, applied, actor)
    return applied
