"""Phase 3 tests — JSON logging."""

from __future__ import annotations

import json
import logging

from certwatch.logging_setup import JsonFormatter, configure_logging


def _record(msg, level=logging.INFO, name="certwatch"):
    return logging.LogRecord(
        name=name, level=level, pathname="", lineno=0,
        msg=msg, args=None, exc_info=None,
    )


def test_dict_message_becomes_json_payload():
    out = JsonFormatter().format(_record({"event": "cycle_start", "host_count": 5}))
    p = json.loads(out)
    assert p["event"] == "cycle_start"
    assert p["host_count"] == 5
    assert p["level"] == "INFO"
    assert p["logger"] == "certwatch"
    assert p["ts"].endswith("Z")


def test_string_message_is_wrapped_under_message_key():
    out = JsonFormatter().format(_record("hello world", level=logging.WARNING))
    p = json.loads(out)
    assert p["message"] == "hello world"
    assert p["level"] == "WARNING"


def test_dict_can_override_top_level_keys():
    # Caller can pin their own ts/level/logger if they want.
    out = JsonFormatter().format(
        _record({"event": "x", "ts": "2030-01-01T00:00:00Z", "logger": "custom"})
    )
    p = json.loads(out)
    assert p["ts"] == "2030-01-01T00:00:00Z"
    assert p["logger"] == "custom"


def test_configure_logging_emits_to_stdout(capsys):
    configure_logging("INFO")
    logging.getLogger("certwatch.testing").info({"event": "hello", "n": 1})
    out = capsys.readouterr().out
    p = json.loads(out.strip())
    assert p["event"] == "hello"
    assert p["n"] == 1


def test_configure_logging_is_idempotent(capsys):
    configure_logging("INFO")
    configure_logging("INFO")  # second call should not duplicate output
    logging.getLogger("certwatch.testing").info({"event": "once"})
    out_lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    assert len(out_lines) == 1


def test_configure_logging_respects_level(capsys):
    configure_logging("WARNING")
    log = logging.getLogger("certwatch.levels")
    log.info({"event": "should-be-suppressed"})
    log.warning({"event": "should-appear"})
    lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
    assert len(lines) == 1
    assert json.loads(lines[0])["event"] == "should-appear"
