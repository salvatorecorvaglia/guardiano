"""Exploitability feeds: CISA KEV and FIRST EPSS.

Two questions a triage queue needs answered, which a CVSS score cannot answer:

- **Is it being exploited right now?** CISA's Known Exploited Vulnerabilities catalogue (~1,200 entries)
  is small, so all of it is stored: a CVE can then be recognised the moment a scan first reports it.
- **How likely is exploitation?** FIRST's EPSS covers every published CVE (hundreds of thousands), so only
  the scores for CVEs this installation actually has are kept. A CVE that arrives between syncs gets its
  score at the next one.

Both feeds are plain downloads over HTTPS, so an air-gapped install can point the URLs at an internal mirror
or turn the sync off with ``INTEL_SYNC_ENABLED=false``.

The data is joined to findings when they are read; the inventory is never rewritten by a sync.
"""

import csv
import io
import json
import logging
import math
import zlib
from collections.abc import Callable
from datetime import date, datetime, timedelta
from typing import Any
from urllib.parse import quote

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, selectinload

from app.core.config import settings
from app.core.urlguard import BlockedURL, TooLarge, check_url, guarded_client, read_capped
from app.models import Finding, KevAnnouncement, VulnAlias, VulnIntel
from app.models.base import utcnow
from app.models.enums import ACTIVE_STATUSES
from app.services import events, notifications
from app.services.serializers import finding_payload

log = logging.getLogger(__name__)

_CHUNK = 1000
_MAX_REDIRECTS = 5
# Today the KEV catalogue is about 1.5 MB and the gzipped EPSS feed a few MB, inflating to tens. The
# limits leave ample room for growth while making sure a broken or hostile mirror cannot exhaust the
# worker's memory -- by sending an endless body, or a small gzip file that inflates to gigabytes.
_MAX_DOWNLOAD = 64 * 1024 * 1024
_MAX_INFLATED = 512 * 1024 * 1024


def _download(url: str) -> bytes:
    # Redirects are followed by hand so every hop is checked: these feeds are served from CDNs that
    # do redirect, but a mirror that redirects to the metadata service must not be followed.
    with guarded_client(timeout=settings.intel_timeout, follow_redirects=False) as client:
        for _ in range(_MAX_REDIRECTS + 1):
            check_url(url)
            with client.stream("GET", url, headers={"User-Agent": "Guardiano"}) as response:
                if not response.is_redirect:
                    response.raise_for_status()
                    return read_capped(response, _MAX_DOWNLOAD)
                url = str(response.next_request.url)
    raise BlockedURL(f"Feed redirected more than {_MAX_REDIRECTS} times")


def _inflate(raw: bytes) -> bytes:
    """gunzip, refusing to produce more than _MAX_INFLATED bytes."""
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = inflater.decompress(raw, _MAX_INFLATED)
    if inflater.unconsumed_tail:
        raise TooLarge(f"feed inflates past {_MAX_INFLATED} bytes")
    return out


def known_cves(db: Session) -> set[str]:
    """The CVEs this installation has findings for."""
    rows = db.scalars(select(Finding.cve_id).where(Finding.cve_id.is_not(None)).distinct())
    return {c.upper() for c in rows if c}


def parse_kev(raw: bytes) -> list[dict[str, Any]]:
    import json

    catalogue = json.loads(raw)
    out = []
    for item in catalogue.get("vulnerabilities", []):
        cve = str(item.get("cveID") or "").upper().strip()
        if not cve:
            continue
        due = item.get("dueDate")
        out.append(
            {
                "cve_id": cve,
                "in_kev": True,
                "kev_due_date": date.fromisoformat(due) if due else None,
                "kev_name": (item.get("vulnerabilityName") or "")[:2000] or None,
                "kev_ransomware": str(item.get("knownRansomwareCampaignUse", "")).lower() == "known",
            }
        )
    return out


def parse_epss(raw: bytes, wanted: set[str]) -> list[dict[str, Any]]:
    """EPSS ships as gzipped CSV with a comment line on top. Only ``wanted`` CVEs are kept."""
    data = _inflate(raw) if raw[:2] == b"\x1f\x8b" else raw
    # Read line by line from the buffer rather than splitting it: the feed is ~280,000 rows, and a
    # list of every line plus a sliced copy of it was several hundred MB for a routine daily task.
    # The file starts with a "#model_version..." comment line before the header.
    text = io.TextIOWrapper(io.BytesIO(data), encoding="utf-8", errors="replace", newline="")
    lines = (line for line in text if not line.startswith("#"))
    rows: list[dict[str, Any]] = []
    for row in csv.DictReader(lines):
        cve = str(row.get("cve") or "").upper().strip()
        if not cve or cve not in wanted:
            continue
        try:
            score = float(row["epss"])
        except (KeyError, TypeError, ValueError):
            continue  # a row without a usable score tells us nothing
        if not math.isfinite(score) or not 0 <= score <= 1:
            continue
        try:
            # A truncated row keeps its score; a missing percentile stays unknown rather than
            # becoming 0.0, which would read as "lowest ranked of every CVE".
            percentile = float(row["percentile"])
            if not math.isfinite(percentile) or not 0 <= percentile <= 1:
                percentile = None
        except (KeyError, TypeError, ValueError):
            percentile = None
        rows.append({"cve_id": cve, "epss": score, "epss_percentile": percentile})
    return rows


def _upsert(db: Session, rows: list[dict[str, Any]], now: datetime) -> int:
    """Insert or update, touching only the columns each feed owns."""
    written = 0
    for i in range(0, len(rows), _CHUNK):
        chunk = [{**r, "updated_at": now} for r in rows[i : i + _CHUNK]]
        statement = pg_insert(VulnIntel).values(chunk)
        updatable = {k: statement.excluded[k] for k in chunk[0] if k != "cve_id"}
        db.execute(statement.on_conflict_do_update(index_elements=["cve_id"], set_=updatable))
        written += len(chunk)
    return written


def sync_kev(db: Session, raw: bytes | None = None) -> int:
    rows = parse_kev(raw if raw is not None else _download(settings.kev_feed_url))
    if not rows:
        # The real catalogue has well over a thousand entries. An empty one is a broken download or
        # mirror, and taking it at its word would clear every KEV flag in the installation.
        raise ValueError("The KEV catalogue came back empty; keeping the flags from the last sync")
    now = utcnow()
    current = [r["cve_id"] for r in rows]
    # What was already listed, to tell which CVEs this sync adds. Nothing listed at all means this is the
    # first sync: the whole catalogue would look new, so it becomes the baseline and nothing is announced.
    listed = set(db.scalars(select(VulnIntel.cve_id).where(VulnIntel.in_kev.is_(True))))
    # A CVE removed from the catalogue is no longer exploited-in-the-wild per CISA. One statement,
    # rather than a lookup per stale CVE that could also find the row gone.
    db.execute(
        update(VulnIntel)
        .where(VulnIntel.in_kev.is_(True), VulnIntel.cve_id.not_in(current))
        .values(in_kev=False, updated_at=now)
    )
    written = _upsert(db, rows, now)
    if listed:
        announce_kev_additions(db, set(current) - listed)
    else:
        drain_kev_announcements(db)
    return written


def announce_kev_additions(db: Session, cves: set[str]) -> int:
    """Emit finding.kev_added for each active finding whose CVE CISA has just listed. The caller commits."""
    if cves:
        eligible = select(Finding.id, Finding.cve_id).where(
            Finding.cve_id.in_(sorted(cves)), Finding.status.in_([s.value for s in ACTIVE_STATUSES])
        )
        db.execute(
            pg_insert(KevAnnouncement)
            .from_select(["finding_id", "cve_id"], eligible)
            .on_conflict_do_nothing()
        )
    return drain_kev_announcements(db)


def drain_kev_announcements(db: Session) -> int:
    pending = db.scalars(
        select(KevAnnouncement)
        .where(KevAnnouncement.announced_at.is_(None))
        .order_by(KevAnnouncement.finding_id)
        .limit(settings.event_batch_limit)
        .with_for_update(skip_locked=True)
    ).all()
    expected = {(row.finding_id, row.cve_id) for row in pending}
    ids = [row.finding_id for row in pending]
    findings = db.scalars(
        select(Finding)
        .where(Finding.id.in_(ids), Finding.status.in_([s.value for s in ACTIVE_STATUSES]))
        .options(selectinload(Finding.intel), selectinload(Finding.asset), selectinload(Finding.assignee))
        .execution_options(populate_existing=True)
    ).all()
    findings = [f for f in findings if (f.id, f.cve_id) in expected]
    for row in pending:
        row.announced_at = utcnow()
    hooks: dict = {}
    for f in findings:
        events.emit(
            db, events.KEV_ADDED, finding_payload(f), asset_id=f.asset_id, severity=f.severity, cache=hooks
        )
        if f.assignee is not None:
            notifications.notify(db, [f.assignee], "kev_added", f, "Now known to be exploited (CISA KEV)")
    if findings:
        log.info("emitted %s for %d finding(s)", events.KEV_ADDED, len(findings))
    return len(findings)


def sync_epss(db: Session, raw: bytes | None = None) -> int:
    wanted = known_cves(db)
    if not wanted:
        return 0
    rows = parse_epss(raw if raw is not None else _download(settings.epss_feed_url), wanted)
    return _upsert(db, rows, utcnow()) if rows else 0


ALIAS_RECHECK = timedelta(days=30)


def _osv_cve(vuln_id: str) -> str | None:
    """The CVE OSV lists among an advisory's aliases, if any."""
    base = settings.osv_api_url.rstrip("/")
    record = json.loads(_download(f"{base}/v1/vulns/{quote(vuln_id, safe='')}"))
    ids = [record.get("id"), *(record.get("aliases") or [])] if isinstance(record, dict) else []
    return next((str(a).upper() for a in ids if isinstance(a, str) and a.upper().startswith("CVE-")), None)


def resolve_aliases(
    db: Session,
    lookup: Callable[[str], str | None] | None = None,
    *,
    only: list[str] | None = None,
) -> int:
    """Give findings known only by an advisory id (GHSA, PYSEC, ...) the CVE it is also known as.

    The one place a sync writes to findings, and narrowly: it fills a cve_id that is empty, never
    changes one a scanner gave, and dedup keys are unaffected (they are computed from what the scanner
    reports, which still has no CVE). With the CVE in place, KEV, EPSS, priority and gates apply.
    Returns how many findings gained a CVE. The caller commits.
    """
    if not settings.osv_api_url:
        return 0
    lookup = lookup or _osv_cve
    now = utcnow()
    aliases = select(VulnAlias)
    candidates = select(Finding.vuln_id)
    if only is not None:
        aliases = aliases.where(VulnAlias.vuln_id.in_(only))
        candidates = candidates.where(Finding.vuln_id.in_(only))
    known = {a.vuln_id: a for a in db.scalars(aliases)}
    wanted = db.scalars(
        candidates.where(
            Finding.type == "sca", Finding.cve_id.is_(None), Finding.vuln_id.is_not(None)
        ).distinct()
    ).all()
    due = [v for v in wanted if v not in known or known[v].checked_at < now - ALIAS_RECHECK]
    for vuln_id in sorted(due)[: settings.osv_alias_limit]:
        try:
            cve = lookup(vuln_id)
        except Exception as exc:  # one unreachable or odd answer must not stop the sync
            log.warning("could not look up %s on OSV: %s", vuln_id, exc)
            continue
        row = known.get(vuln_id) or VulnAlias(vuln_id=vuln_id)
        row.cve_id, row.checked_at = cve, now
        db.add(row)
        known[vuln_id] = row
    filled = 0
    for alias in known.values():
        if alias.cve_id:
            filled += (
                db.execute(
                    update(Finding)
                    .where(Finding.vuln_id == alias.vuln_id, Finding.cve_id.is_(None))
                    .values(cve_id=alias.cve_id)
                ).rowcount
                or 0
            )
    if filled:
        log.info("gave %d finding(s) the CVE their advisory is also known as", filled)
    return filled


def pending_aliases(db: Session) -> list[str]:
    if not settings.osv_api_url:
        return []
    recent = select(VulnAlias.vuln_id).where(VulnAlias.checked_at >= utcnow() - ALIAS_RECHECK)
    return list(
        db.scalars(
            select(Finding.vuln_id)
            .where(
                Finding.type == "sca",
                Finding.cve_id.is_(None),
                Finding.vuln_id.is_not(None),
                Finding.vuln_id.not_in(recent),
            )
            .distinct()
            .order_by(Finding.vuln_id)
            .limit(settings.osv_alias_limit)
        )
    )


def sync_all(db: Session) -> dict[str, int]:
    """Refresh both feeds, and the CVEs of advisory-only findings in between. The caller commits."""
    counts = {"kev": sync_kev(db)}
    try:
        counts["aliases"] = resolve_aliases(db)
    except Exception as exc:  # the feeds matter more than the lookup; never lose them over it
        log.warning("advisory lookup failed: %s", exc)
        counts["aliases"] = 0
    counts["epss"] = sync_epss(db)  # after the lookup, so newly known CVEs get a score today
    log.info("exploitability feeds synced: %s", counts)
    return counts
