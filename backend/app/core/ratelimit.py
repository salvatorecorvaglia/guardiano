import hashlib

from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request

# Client IP comes from uvicorn's proxy-header handling (FORWARDED_ALLOW_IPS), so this works behind nginx.
limiter = Limiter(key_func=get_remote_address)


def credential_key(request: Request) -> str:
    """One bucket per credential rather than per address: CI runners often share one.

    A digest of the Authorization header, never the header: limiter storage must not hold tokens.
    Requests without one (a browser session sends its token the same way) fall back to the address.
    """
    header = request.headers.get("authorization")
    if not header:
        return get_remote_address(request)
    return "cred:" + hashlib.sha256(header.encode()).hexdigest()[:32]
