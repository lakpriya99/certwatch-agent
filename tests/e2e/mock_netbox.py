"""Mock NetBox for e2e tests.

Implements only what pynetbox's `api.dcim.devices.filter(...)` actually
hits: GET /api/dcim/devices/ with optional filter query params,
returning a paginated response.

The fixture devices live in a thread-safe dict; tests add/remove them
between assertions. `simulate_failure(mode)` lets tests force NetBox
into 500/401/timeout modes to exercise the safety contract.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from flask import Flask, jsonify, request

from tests.e2e.mock_server import MockServer


@dataclass
class _State:
    lock: threading.Lock = field(default_factory=threading.Lock)
    devices: dict = field(default_factory=dict)
    failure_mode: Optional[str] = None  # "500" | "401" | "timeout" | None


class MockNetBox:
    def __init__(self) -> None:
        self._state = _State()
        self._app = self._build_app()
        self._server = MockServer(self._app)

    # ---- lifecycle --------------------------------------------------

    def start(self) -> None:
        self._server.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._server.stop(timeout=timeout)

    @property
    def url(self) -> str:
        return self._server.url

    # ---- control surface --------------------------------------------

    def add_device(
        self,
        netbox_device_id: int,
        name: str,
        *,
        primary_ip4: Optional[str] = None,
        primary_ip6: Optional[str] = None,
        custom_fields: Optional[dict] = None,
        tags: Optional[list] = None,
    ) -> None:
        with self._state.lock:
            self._state.devices[netbox_device_id] = {
                "id": netbox_device_id,
                "name": name,
                "primary_ip4": (
                    {"address": primary_ip4} if primary_ip4 else None
                ),
                "primary_ip6": (
                    {"address": primary_ip6} if primary_ip6 else None
                ),
                "custom_fields": dict(custom_fields or {}),
                "tags": [{"name": t} for t in (tags or [])],
            }

    def remove_device(self, netbox_device_id: int) -> None:
        with self._state.lock:
            self._state.devices.pop(netbox_device_id, None)

    def simulate_failure(self, mode: Optional[str]) -> None:
        with self._state.lock:
            self._state.failure_mode = mode

    # ---- Flask app --------------------------------------------------

    def _build_app(self) -> Flask:
        state = self._state
        app = Flask("mock_netbox")

        @app.get("/api/dcim/devices/")
        def list_devices():
            with state.lock:
                mode = state.failure_mode
                devices = list(state.devices.values())
            if mode == "500":
                return jsonify({"detail": "Internal Server Error"}), 500
            if mode == "401":
                return jsonify({"detail": "Unauthorized"}), 401
            if mode == "timeout":
                # Sleep longer than the agent's default 30s NetBox timeout
                # so the agent's request times out cleanly.
                time.sleep(45)

            # Filter by query params (supports tag=... and name=...)
            filtered = devices
            args = request.args
            for key, values in args.lists():
                if key in ("limit", "offset"):
                    continue
                if key == "tag":
                    filtered = [
                        d for d in filtered
                        if any(t["name"] in values for t in (d.get("tags") or []))
                    ]
                elif key == "name":
                    filtered = [
                        d for d in filtered
                        if d.get("name") in values
                    ]
                # Other filters are ignored (just for test robustness)

            return jsonify({
                "count": len(filtered),
                "next": None,
                "previous": None,
                "results": filtered,
            })

        # Some pynetbox versions probe the status endpoint. Provide a
        # minimal stub so the probe doesn't 404 if it ever runs.
        @app.get("/api/status/")
        def status():
            return jsonify({"netbox-version": "3.7.0"})

        return app
