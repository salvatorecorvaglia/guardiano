"""Encryption for stored third-party credentials (issue-tracker tokens).

The key is derived from ``SECRET_KEY`` with HKDF, or from ``INTEGRATIONS_KEY`` when that is set. Rotating
the key it derives from makes stored tokens unreadable, exactly as rotating ``SECRET_KEY`` invalidates
sessions; the UI then asks for the token again.
"""

import base64
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import settings

_INFO = b"guardiano-integration-credentials-v1"


@lru_cache
def _cipher() -> Fernet:
    source = (settings.integrations_key or settings.secret_key).encode()
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_INFO).derive(source)
    return Fernet(base64.urlsafe_b64encode(key))


def encrypt(value: str) -> str:
    return _cipher().encrypt(value.encode()).decode()


def decrypt(value: str) -> str:
    """Raises ValueError when the stored value cannot be read with the current key."""
    try:
        return _cipher().decrypt(value.encode()).decode()
    except InvalidToken:
        raise ValueError(
            "Stored credential cannot be decrypted. It was encrypted with a different SECRET_KEY "
            "(or INTEGRATIONS_KEY); re-enter the token."
        )
