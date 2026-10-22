"""Bounded upload reading shared by scan and asset upload endpoints."""

import io

from fastapi import HTTPException, UploadFile, status

from app.core.config import settings


def read_limited(upload: UploadFile) -> bytes:
    limit = settings.max_upload_bytes
    chunks, size = io.BytesIO(), 0
    while chunk := upload.file.read(1024 * 1024):
        size += len(chunk)
        if size > limit:
            raise HTTPException(
                status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                f"File exceeds the {settings.max_upload_mb} MB limit",
            )
        chunks.write(chunk)
    if not size:
        raise HTTPException(422, "Uploaded file is empty")
    return chunks.getvalue()
