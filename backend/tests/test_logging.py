"""The JSON log formatter: fixed fields, request id, and every ``extra`` a caller passes."""

import json
import logging

from app.core.logging import JsonFormatter, request_id_ctx


def _format(msg="hello", extra=None, exc_info=None):
    logger = logging.getLogger("test")
    record = logger.makeRecord("test", logging.WARNING, __file__, 1, msg, (), exc_info, extra=extra)
    return json.loads(JsonFormatter().format(record))


def test_the_fixed_fields_are_present():
    out = _format()
    assert out["level"] == "WARNING" and out["logger"] == "test" and out["msg"] == "hello"
    assert "ts" in out


def test_every_extra_is_kept():
    """A tracker's error body used to be dropped because "body" was not on a fixed list."""
    out = _format(extra={"status": 502, "body": "upstream said no", "method": "GET", "duration_ms": 3.5})
    assert (out["status"], out["body"]) == (502, "upstream said no")
    assert (out["method"], out["duration_ms"]) == ("GET", 3.5)


def test_record_internals_are_not_output():
    out = _format()
    for internal in ("args", "levelno", "pathname", "lineno", "funcName", "created", "msecs", "thread"):
        assert internal not in out


def test_an_extra_cannot_overwrite_the_request_id():
    token = request_id_ctx.set("req-1")
    try:
        out = _format(extra={"request_id": "forged"})
    finally:
        request_id_ctx.reset(token)
    assert out["request_id"] == "req-1"


def test_values_that_are_not_json_are_stringified():
    out = _format(extra={"thing": object()})
    assert out["thing"].startswith("<object object")


def test_exceptions_are_included():
    try:
        raise ValueError("boom")
    except ValueError:
        import sys

        out = _format(exc_info=sys.exc_info())
    assert "ValueError: boom" in out["exc"]
