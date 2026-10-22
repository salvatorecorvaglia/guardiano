"""Refuses outbound HTTP aimed at the network Guardiano itself sits in (SSRF).

Guardiano makes requests to addresses an operator supplies: webhook endpoints, issue-tracker base
URLs and the exploitability feeds. Those requests leave from inside the deployment, so without a
guard they reach the cloud metadata service, the database, and anything else on the private network
-- and the tracker path reports what it got back, which makes it a read primitive, not just a write.

Two places call this, deliberately:

* when the URL is *stored*, so an operator finds out immediately rather than at delivery time;
* immediately before the request is *made*, because the name may resolve somewhere else by then.

A name that does not resolve is allowed at storage time and left to fail at request time: a tracker
that is simply down, or private DNS the API container cannot see, is not an attack.
"""

import ipaddress
import socket
from contextlib import contextmanager
from urllib.parse import urlsplit

import httpcore
import httpx

from app.core.config import settings


class BlockedURL(ValueError):
    """The URL points somewhere outbound requests are not allowed to go."""


class GuardedBackend(httpcore.SyncBackend):
    """Resolve once at connect time and use the checked numeric address.

    httpcore retains the original hostname for Host and TLS SNI/certificate checks.
    """

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        addresses = _addresses(host)
        if not addresses:
            raise BlockedURL(f"Cannot resolve outbound host {host}")
        if host.lower() not in settings.outbound_allow_hosts and any(_blocked(ip) for ip in addresses):
            raise BlockedURL(f"{host} resolves to a private or reserved address")
        last_error = None
        for address in addresses:
            try:
                return super().connect_tcp(str(address), port, timeout, local_address, socket_options)
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_error = exc
        raise last_error


def guarded_client(**kwargs) -> httpx.Client:
    transport = httpx.HTTPTransport()
    transport._pool._network_backend = GuardedBackend()
    return httpx.Client(transport=transport, trust_env=False, **kwargs)


@contextmanager
def guarded_stream(method: str, url: str, **kwargs):
    timeout = kwargs.pop("timeout", 15)
    follow = kwargs.pop("follow_redirects", False)
    with (
        guarded_client(timeout=timeout, follow_redirects=follow) as client,
        client.stream(method, url, **kwargs) as response,
    ):
        yield response


def _blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast:
        return True
    if ip.is_reserved or ip.is_unspecified:
        return True
    # An IPv4 address wrapped in IPv6 ("::ffff:169.254.169.254") is the same address.
    mapped = getattr(ip, "ipv4_mapped", None)
    return bool(mapped and _blocked(mapped))


def _addresses(host: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address] | None:
    """Every address ``host`` resolves to, or None when it does not resolve."""
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    try:
        info = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return None
    return [ipaddress.ip_address(item[4][0]) for item in info]


def check_url(url: str, *, resolve: bool = True) -> str:
    """Return ``url`` unchanged, or raise :class:`BlockedURL`.

    Every address the name resolves to is checked, not just the first: a name that answers with one
    public and one private address must not be usable to reach the private one.
    """
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise BlockedURL("URL must start with http:// or https://")
    host = parts.hostname
    if not host:
        raise BlockedURL("URL has no host")
    if host.lower() in settings.outbound_allow_hosts:
        return url
    if not resolve:
        return url
    addresses = _addresses(host)
    if addresses is None:  # does not resolve here; let the request itself fail
        return url
    if any(_blocked(ip) for ip in addresses):
        raise BlockedURL(
            f"{host} resolves to an address on a private or reserved network. "
            "Set OUTBOUND_ALLOW_HOSTS to allow a specific internal host."
        )
    return url


class TooLarge(ValueError):
    """A response body bigger than the caller was prepared to hold."""


def read_capped(response: httpx.Response, limit: int) -> bytes:
    """Read a *streamed* response body, refusing more than ``limit`` bytes.

    ``response.content`` on a non-streamed request buffers whatever the server chooses to send, and
    every URL these callers use is one an operator typed in. The count is taken after transport
    decoding, so a gzip-encoded response that inflates past the limit is refused too.
    """
    declared = response.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise TooLarge(f"response of {int(declared)} bytes exceeds the {limit}-byte limit")
    body = bytearray()
    for chunk in response.iter_bytes():
        body += chunk
        if len(body) > limit:
            raise TooLarge(f"response exceeds the {limit}-byte limit")
    return bytes(body)
