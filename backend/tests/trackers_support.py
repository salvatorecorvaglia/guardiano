"""Shared by the issue-tracker test modules: an HTTP stub for every provider, and a finding to ticket.

These lived in test_trackers.py and test_ticket_polling.py imported them from there, so a change to
one test module could quietly break another. Registered as a plugin in conftest, so the fixtures resolve
by name; a module that wants every provider stubbed says so with
``pytestmark = pytest.mark.usefixtures("fake_http")``.
"""

import json

import pytest
from sqlalchemy import select

from app.core import crypto
from app.models import Asset, Finding, Integration
from app.services.ingestion import IngestOptions, ingest_report
from app.services.trackers import base as trackers_base

CALLS: list[dict] = []
RESPONSES: list[dict | Exception] = []


@pytest.fixture
def fake_http(monkeypatch):
    """Every provider goes through base.request, so one stub covers Jira, GitHub and GitLab."""
    CALLS.clear()
    RESPONSES.clear()

    def _request(method, url, **kwargs):
        CALLS.append({"method": method, "url": url, **kwargs})
        if not RESPONSES:
            return {}
        reply = RESPONSES.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return reply

    monkeypatch.setattr(trackers_base, "request", _request)
    # The providers imported the function directly, so patch it there too.
    for module in ("jira", "github", "gitlab"):
        monkeypatch.setattr(f"app.services.trackers.{module}.request", _request)


@pytest.fixture
def asset(db):
    a = Asset(name="payments-api", tags=[])
    db.add(a)
    db.commit()
    return a


@pytest.fixture
def finding(db, asset):
    ingest_report(
        db,
        json.dumps(
            {
                "schema": "guardiano/v1",
                "tool": {"name": "Semgrep"},
                "scan_type": "sast",
                "findings": [
                    {
                        "title": "SQL injection",
                        "severity": "critical",
                        "cwe": ["CWE-89"],
                        "file_path": "app/db.py",
                        "line_start": 42,
                        "description": "User input reaches a raw query.",
                        "remediation": "Use a parameterised query.",
                    }
                ],
            }
        ).encode(),
        asset,
        None,
        IngestOptions(),
    )
    return db.scalar(select(Finding))


def integration(db, kind="github", **kw):
    defaults = {
        "kind": kind,
        "name": f"{kind} tracker",
        "enabled": True,
        "base_url": {"github": "https://api.github.com", "gitlab": "https://gitlab.com"}.get(
            kind, "https://acme.atlassian.net"
        ),
        "project": {"github": "acme/payments", "gitlab": "acme/payments"}.get(kind, "SEC"),
        "secret_encrypted": crypto.encrypt("s3cret-token"),
        "labels": ["security"],
    }
    i = Integration(**{**defaults, **kw})
    db.add(i)
    db.commit()
    return i
