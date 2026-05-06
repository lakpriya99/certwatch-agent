"""Shared lifecycle for the mock Flask servers.

Uses werkzeug's `make_server` (rather than `app.run()`) so we get a
clean `shutdown()` method on the server object — testable, no
deprecation warnings.
"""

from __future__ import annotations

import logging
import threading

from werkzeug.serving import make_server

# Suppress per-request access logs from werkzeug; the e2e tests already
# capture the agent's structured log output, and Flask's default
# access-log line per request would just clutter pytest output.
logging.getLogger("werkzeug").setLevel(logging.ERROR)


class MockServer:
    """Wraps a Flask app in a background-thread werkzeug server.

    Binds to 127.0.0.1:0 so the OS picks a free port — multiple
    concurrent test runs don't collide. Read `.url` after `.start()`.
    """

    def __init__(self, app, *, host: str = "127.0.0.1") -> None:
        self._server = make_server(host, 0, app, threaded=True)
        self._port = self._server.server_port
        self._host = host
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name=f"mock-server-{self._port}",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._server.shutdown()
        self._thread.join(timeout=timeout)

    @property
    def url(self) -> str:
        return f"http://{self._host}:{self._port}"
