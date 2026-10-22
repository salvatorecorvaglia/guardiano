"""Time-based one-time passwords (RFC 6238), the second factor for local sign-in.

Implemented on the standard library: TOTP is an HMAC of the time step, and a dependency for thirty lines
of arithmetic is a dependency to keep patched. Verified against the RFC's own test vectors in
tests/test_mfa.py.
"""

import base64
import hashlib
import hmac
import secrets
import struct
from urllib.parse import quote

DIGITS = 6
STEP = 30  # seconds per code, as every authenticator app assumes
WINDOW = 1  # how many steps either side are accepted, for clock drift


def generate_secret() -> str:
    """A base32 secret, the format authenticator apps expect."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _decode(secret: str) -> bytes:
    padded = secret.strip().replace(" ", "").upper()
    padded += "=" * (-len(padded) % 8)
    return base64.b32decode(padded, casefold=True)


def code_at(secret: str, step: int) -> str:
    digest = hmac.new(_decode(secret), struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % 10**DIGITS).zfill(DIGITS)


def current_step(now: float) -> int:
    return int(now // STEP)


def verify(secret: str, code: str, now: float, *, last_step: int | None = None) -> int | None:
    """The step a code is valid for, or None.

    ``last_step`` is the step already used by this account: a code is accepted once, so watching somebody
    type it (or replaying an intercepted request) does not give a second sign-in.
    """
    candidate = (code or "").strip().replace(" ", "")
    if not candidate.isdigit() or len(candidate) != DIGITS:
        return None
    now_step = current_step(now)
    for step in range(now_step - WINDOW, now_step + WINDOW + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(code_at(secret, step), candidate):
            return step
    return None


def already_used(secret: str, code: str, now: float, last_step: int | None) -> bool:
    """Whether a code is genuine but belongs to a step already spent.

    Worth telling apart from a wrong code: the person is holding a valid authenticator and only has to
    wait for the next one.
    """
    if last_step is None:
        return False
    candidate = (code or "").strip().replace(" ", "")
    now_step = current_step(now)
    return any(
        hmac.compare_digest(code_at(secret, step), candidate)
        for step in range(now_step - WINDOW, min(last_step, now_step + WINDOW) + 1)
    )


def provisioning_uri(secret: str, account: str, issuer: str = "Guardiano") -> str:
    """The otpauth:// URI an authenticator app reads from a QR code."""
    label = quote(f"{issuer}:{account}")
    query = f"secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits={DIGITS}&period={STEP}"
    return f"otpauth://totp/{label}?{query}"


def generate_recovery_codes(count: int = 10) -> list[str]:
    """Single-use codes for when the phone is gone. Shown once, stored hashed."""
    return [f"{secrets.token_hex(2)}-{secrets.token_hex(2)}-{secrets.token_hex(2)}" for _ in range(count)]


def hash_recovery_code(code: str) -> str:
    return hashlib.sha256(code.strip().lower().replace(" ", "").encode()).hexdigest()
