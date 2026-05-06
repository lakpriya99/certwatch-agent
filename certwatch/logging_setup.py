"""Structured JSON logging to stdout — one JSON object per line.

Call sites pass dicts to logger.info/etc.; `JsonFormatter` extracts the dict
as the JSON payload and adds `ts` / `level` / `logger`. String messages are
wrapped as `{"message": "..."}`. Dicts produced by the agent should always
include an `event` key naming the log type (cycle_start, cert_check_result,
cycle_summary, etc.) so log consumers can filter cleanly.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import sys
from typing import Any


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        if isinstance(record.msg, dict):
            payload: dict[str, Any] = dict(record.msg)
        else:
            payload = {"message": record.getMessage()}

        payload.setdefault(
            "ts",
            dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        payload.setdefault("level", record.levelname)
        payload.setdefault("logger", record.name)
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    """Install JSON-to-stdout on the root logger. Idempotent — clears any
    handlers we previously attached so reconfiguration during tests or on
    config reload doesn't double-up output."""
    root = logging.getLogger()
    for h in list(root.handlers):
        if getattr(h, "_certwatch", False):
            root.removeHandler(h)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    handler._certwatch = True  # type: ignore[attr-defined]
    root.addHandler(handler)
    root.setLevel(level.upper())
