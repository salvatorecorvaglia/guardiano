"""Checks for ids a request body refers to.

A missing *referenced* row makes the body invalid, so it is a 422 -- the same answer the asset form
gives for a missing team or assignee. 404 stays for the resource named in the URL. Webhooks, trackers
and triage rules each had their own copy of this check, all answering 404.
"""

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import Asset


def ensure_asset(db: Session, asset_id: int | None) -> None:
    if asset_id is not None and db.get(Asset, asset_id) is None:
        raise HTTPException(422, "Asset not found")
