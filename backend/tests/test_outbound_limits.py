"""Responses from third parties are read within limits.

Every URL here is one an operator typed in, so the other end is not trusted to be well behaved: an
endless body, a gzip file that inflates to gigabytes, or an empty "catalogue" must not take the worker
down or wipe data. These drive the real functions through httpx.MockTransport rather than stubbing
the functions out, which is how the tracker tests never exercised request() itself.
"""

import gzip
import json

import httpx
import pytest

from app.core import urlguard
from app.core.urlguard import TooLarge, read_capped
from app.services import intel, webhooks
from app.services.trackers import base as trackers_base


@pytest.fixture
def serve(monkeypatch):
    """Route every httpx.stream call to ``handler`` instead of the network."""
    monkeypatch.setattr(urlguard, "_addresses", lambda host: None)  # no DNS in tests

    def install(handler):
        def fake_stream(method, url, **kwargs):
            kwargs.pop("timeout", None)
            kwargs.pop("follow_redirects", None)
            return httpx.Client(transport=httpx.MockTransport(handler)).stream(method, url, **kwargs)

        monkeypatch.setattr(trackers_base, "guarded_stream", fake_stream)
        monkeypatch.setattr(webhooks, "guarded_stream", fake_stream)

    return install


def _endless():
    while True:
        yield b"x" * 65536


# ---- read_capped ----------------------------------------------------------------------------------


def test_a_body_over_the_limit_is_refused_while_streaming():
    transport = httpx.MockTransport(lambda r: httpx.Response(200, content=_endless()))
    with (
        httpx.Client(transport=transport) as client,
        client.stream("GET", "https://x.test") as response,
        pytest.raises(TooLarge),
    ):
        read_capped(response, 1024 * 1024)


def test_a_declared_length_over_the_limit_is_refused_before_reading():
    transport = httpx.MockTransport(
        lambda r: httpx.Response(200, headers={"content-length": "999999999"}, content=b"")
    )
    with (
        httpx.Client(transport=transport) as client,
        client.stream("GET", "https://x.test") as response,
        pytest.raises(TooLarge),
    ):
        read_capped(response, 1024)


def test_a_body_within_the_limit_is_returned():
    transport = httpx.MockTransport(lambda r: httpx.Response(200, content=b"hello"))
    with httpx.Client(transport=transport) as client, client.stream("GET", "https://x.test") as response:
        assert read_capped(response, 1024) == b"hello"


# ---- issue trackers -------------------------------------------------------------------------------


def test_a_tracker_answering_with_an_enormous_body_is_an_error(serve):
    serve(lambda r: httpx.Response(200, content=_endless()))
    with pytest.raises(trackers_base.TrackerError, match="larger than"):
        trackers_base.request("GET", "https://tracker.test/api")


def test_a_tracker_error_body_is_not_passed_back(serve):
    serve(lambda r: httpx.Response(500, content=b"internal: aws_secret=abc123"))
    with pytest.raises(trackers_base.TrackerError) as caught:
        trackers_base.request("GET", "https://tracker.test/api")
    assert "500" in str(caught.value) and "abc123" not in str(caught.value)


def test_a_tracker_response_that_is_not_json_is_an_error(serve):
    serve(lambda r: httpx.Response(200, content=b"<html>login</html>"))
    with pytest.raises(trackers_base.TrackerError, match="not JSON"):
        trackers_base.request("GET", "https://tracker.test/api")


def test_a_tracker_list_is_wrapped_and_an_empty_body_is_empty(serve):
    serve(lambda r: httpx.Response(200, json=[{"number": 1}]))
    assert trackers_base.request("GET", "https://tracker.test/api") == {"items": [{"number": 1}]}
    serve(lambda r: httpx.Response(204))
    assert trackers_base.request("DELETE", "https://tracker.test/api") == {}


def test_a_json_body_is_sent_as_json(serve):
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return httpx.Response(201, json={"ok": True})

    serve(handler)
    assert trackers_base.request("POST", "https://tracker.test/api", json={"a": 1}) == {"ok": True}
    assert seen["body"] == {"a": 1}


# ---- webhooks -------------------------------------------------------------------------------------


def test_a_webhook_receiver_body_is_never_read(serve):
    """Only the status matters. A body that raises when read proves it is never consumed."""

    def unreadable():
        raise AssertionError("the webhook response body was read")
        yield b""  # pragma: no cover

    serve(lambda r: httpx.Response(200, content=unreadable()))
    assert webhooks._post("https://receiver.test/hook", b"{}", {}) == (200, None)


# ---- exploitability feeds -------------------------------------------------------------------------


def test_a_gzip_bomb_in_the_epss_feed_is_refused(monkeypatch):
    monkeypatch.setattr(intel, "_MAX_INFLATED", 1024 * 1024)
    bomb = gzip.compress(b"0" * (4 * 1024 * 1024))  # a few KB that inflate to 4 MB
    assert len(bomb) < 64 * 1024
    with pytest.raises(TooLarge):
        intel.parse_epss(bomb, {"CVE-1"})


def test_the_epss_feed_still_parses_line_by_line():
    feed = gzip.compress(
        b"#model_version:v2025,score_date:2026-09-21\ncve,epss,percentile\n"
        b"CVE-1,0.5,0.9\nCVE-2,0.1,0.2\nCVE-3,0.9,0.99\n"
    )
    rows = intel.parse_epss(feed, {"CVE-1", "CVE-3"})
    assert [r["cve_id"] for r in rows] == ["CVE-1", "CVE-3"]


def test_an_empty_kev_catalogue_does_not_clear_the_flags(db):
    """A broken download or mirror must not unflag every exploited CVE in the installation."""
    from app.models import VulnIntel

    intel.sync_kev(db, json.dumps({"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}).encode())
    db.commit()
    with pytest.raises(ValueError, match="empty"):
        intel.sync_kev(db, json.dumps({"vulnerabilities": []}).encode())
    db.rollback()
    assert db.get(VulnIntel, "CVE-2021-44228").in_kev is True
