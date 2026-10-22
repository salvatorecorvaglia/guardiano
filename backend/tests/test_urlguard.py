"""Outbound requests must not reach the network Guardiano itself sits in."""

import pytest

from app.core import urlguard
from app.core.urlguard import BlockedURL, check_url

BLOCKED = [
    "http://169.254.169.254/latest/meta-data/",  # cloud metadata
    "http://127.0.0.1:8000/api/v1/assets",
    "http://localhost/admin",
    "http://10.0.0.5/",
    "http://192.168.1.1/",
    "http://172.16.0.1/",
    "http://[::1]/",
    "http://[::ffff:169.254.169.254]/",  # the same address wrapped in IPv6
    "http://0.0.0.0/",
]


@pytest.mark.parametrize("url", BLOCKED)
def test_internal_targets_are_refused(url):
    with pytest.raises(BlockedURL):
        check_url(url)


@pytest.mark.parametrize("url", ["ftp://example.test/x", "file:///etc/passwd", "gopher://x/", "//x/y"])
def test_only_http_and_https_are_allowed(url):
    with pytest.raises(BlockedURL):
        check_url(url)


def test_a_public_address_is_allowed():
    assert check_url("https://93.184.216.34/hook") == "https://93.184.216.34/hook"


def test_a_name_that_does_not_resolve_is_left_to_the_request(monkeypatch):
    """Private DNS the container cannot see, or a tracker that is simply down, is not an attack."""
    monkeypatch.setattr(urlguard, "_addresses", lambda host: None)
    assert check_url("https://jira.internal.example/x")


def test_a_name_resolving_to_both_public_and_private_is_refused(monkeypatch):
    """Every address is checked, not just the first."""
    import ipaddress

    monkeypatch.setattr(
        urlguard,
        "_addresses",
        lambda host: [ipaddress.ip_address("93.184.216.34"), ipaddress.ip_address("169.254.169.254")],
    )
    with pytest.raises(BlockedURL):
        check_url("https://rebind.example/x")


def test_an_allow_listed_host_may_be_internal(monkeypatch):
    import ipaddress

    # Both names resolve to the same private address; only the listed one is allowed through.
    monkeypatch.setattr(urlguard, "_addresses", lambda host: [ipaddress.ip_address("10.0.0.5")])
    monkeypatch.setattr(urlguard.settings, "outbound_allow_hosts", ["jira.internal"])
    assert check_url("https://jira.internal/rest/api/2/issue")
    with pytest.raises(BlockedURL):
        check_url("https://other.internal/x")  # the allowance is per host, not a switch
