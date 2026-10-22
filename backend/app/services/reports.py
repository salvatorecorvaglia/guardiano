"""Scheduled security reports: the Reports page's headline figures, emailed.

Each recipient gets their own copy, computed with their own scope (services/scope.py): the same
numbers they would see on the Reports page, never more.
"""

import html
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import Asset, ReportSchedule, User
from app.services import analytics
from app.services.email import Message, _link, _wrap
from app.services.scope import scope_for

FREQUENCIES = ("weekly", "monthly")
_GAP = {"weekly": timedelta(days=6, hours=23), "monthly": timedelta(days=27)}


def due(schedule: ReportSchedule, now: datetime) -> bool:
    """Weekly on Mondays, monthly on the 1st, at DIGEST_HOUR_UTC; never twice in one period."""
    if not schedule.enabled or now.hour != settings.digest_hour_utc:
        return False
    if schedule.frequency == "weekly" and now.weekday() != 0:
        return False
    if schedule.frequency == "monthly" and now.day != 1:
        return False
    return schedule.last_sent_at is None or now - schedule.last_sent_at >= _GAP[schedule.frequency]


def _table(headers: list[str], rows: list[list[Any]]) -> tuple[str, str]:
    cell = "padding:2px 8px;border-bottom:1px solid #ddd;text-align:left"
    head = "".join(f"<th style='{cell}'>{html.escape(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td style='{cell}'>{html.escape(str(v))}</td>" for v in row) + "</tr>"
        for row in rows
    )
    text = "\n".join("  " + " | ".join(str(v) for v in row) for row in rows)
    return f"<table style='border-collapse:collapse'><tr>{head}</tr>{body}</table>", text


def build(db: Session, schedule: ReportSchedule, user: User) -> Message:
    scope = scope_for(db, user)
    period = "week" if schedule.frequency == "weekly" else "month"
    days = 7 if schedule.frequency == "weekly" else 30
    parts_html: list[str] = []
    parts_text: list[str] = []

    def section(title: str, headers: list[str], rows: list[list[Any]]) -> None:
        if not rows:
            return
        table, text = _table(headers, rows)
        parts_html.append(f"<h3 style='font-size:14px'>{html.escape(title)}</h3>{table}")
        parts_text.append(f"{title}\n{text}\n")

    products = analytics.breakdown(db, "product", days, scope=scope)
    if schedule.product_id is not None:
        name = schedule.product.name if schedule.product else "the product"
        row = next((r for r in products if r["key"] == str(schedule.product_id)), None)
        section(
            f"{name}: where it stands",
            ["Open", "Critical/high", "Past SLA", "Risk accepted", f"Resolved this {period}", "MTTR (days)"],
            [[row["open"], row["critical_high"], row["overdue"], row["accepted"], row["resolved"],
              row["mttr_days"] or "—"]] if row else [],
        )  # fmt: skip
        in_product = set(db.scalars(select(Asset.id).where(Asset.product_id == schedule.product_id)))
        riskiest = [a for a in analytics.top_assets(db, 50, scope=scope) if a["id"] in in_product][:5]
        link = _link(f"/findings?product_id={schedule.product_id}&status=open&status=in_progress")
    else:
        s = analytics.summary(db, scope=scope)
        sev = s["open_by_severity"]
        section(
            "Where the estate stands",
            ["Open", "Critical", "High", "Past SLA", "Known exploited", "New (30 d)", "Resolved (30 d)"],
            [[s["open_total"], sev["critical"], sev["high"], s["overdue"], s["known_exploited"],
              s["new_last_30d"], s["resolved_last_30d"]]],
        )  # fmt: skip
        sla = analytics.sla_performance(db, days, scope=scope)
        section(
            "Remediation against SLA",
            ["Open within SLA", f"Resolved on time (last {days} days)"],
            [[f"{sla['within_sla_pct']}%" if sla["within_sla_pct"] is not None else "—",
              f"{sla['resolved_on_time_pct']}%" if sla["resolved_on_time_pct"] is not None else "—"]],
        )  # fmt: skip
        section(
            "By product",
            ["Product", "Open", "Critical/high", "Past SLA", "MTTR (days)"],
            [
                [r["label"], r["open"], r["critical_high"], r["overdue"], r["mttr_days"] or "—"]
                for r in products[:8]
            ],
        )
        riskiest = analytics.top_assets(db, 5, scope=scope)
        link = _link("/reports")
    section(
        "Assets carrying the most risk",
        ["Asset", "Risk score", "Open", "Critical", "High"],
        [[a["name"], a["risk_score"], a["open"], a["critical"], a["high"]] for a in riskiest],
    )
    if not parts_html:
        parts_html.append("<p>Nothing is open on the assets you can see.</p>")
        parts_text.append("Nothing is open on the assets you can see.\n")
    if link:
        parts_html.append(f"<p><a href='{html.escape(link)}'>Open in Guardiano</a></p>")
        parts_text.append(f"Open in Guardiano: {link}\n")
    title = f"{schedule.name}: this {period}"
    return Message(f"[Guardiano] {title}", "\n".join(parts_text), _wrap(title, "".join(parts_html)))


def recipients(db: Session, schedule: ReportSchedule) -> list[User]:
    if not schedule.recipient_ids:
        return []
    return list(db.scalars(select(User).where(User.id.in_(schedule.recipient_ids), User.is_active.is_(True))))
