"""Mock CertWatch dashboard for e2e tests.

Implements all five contract endpoints with a thread-safe state object
that tests manipulate via the `MockDashboard` control surface. The
agent under test sees a real HTTP server with realistic responses;
tests inspect what was received and steer behavior (revoke, queue
actions, force errors).

Default config has aggressive intervals (1s heartbeat, 5s check,
5s netbox sync) so the e2e suite completes in under 2 minutes of
real time — the agent honors whatever intervals the dashboard hands
back, so this is the speed knob for the whole suite.
"""

from __future__ import annotations

import datetime as dt
import threading
import uuid
from dataclasses import dataclass, field
from typing import Optional

from flask import Flask, jsonify, request

from tests.e2e.mock_server import MockServer


def _utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _expires_at_iso(seconds_from_now: int = 300) -> str:
    return (dt.datetime.now(dt.timezone.utc)
            + dt.timedelta(seconds=seconds_from_now)).strftime("%Y-%m-%dT%H:%M:%SZ")


def _default_config() -> dict:
    """Aggressive intervals for fast e2e tests. The agent reads these
    from the dashboard's responses, so this is the cadence everyone
    in this suite operates on."""
    return {
        "config_version": 1,
        "fetched_at": _utc_now_iso(),
        "intervals": {
            "heartbeat_seconds": 1,
            "check_seconds": 5,
            "netbox_sync_seconds": 5,
        },
        "timeouts": {
            "tcp_connect_seconds": 1,
            "tls_handshake_seconds": 1,
        },
        "concurrency": {"max_parallel_checks": 4},
        "alert_thresholds_days": [30, 7, 1],
        "manual_hosts": [],
    }


@dataclass
class _State:
    lock: threading.Lock = field(default_factory=threading.Lock)

    # Registration
    valid_registration_tokens: set = field(default_factory=set)
    consumed_registration_tokens: set = field(default_factory=set)
    agent_id: str = "00000000-1111-4222-8333-444444444444"
    agent_secret: str = "agtkey_e2e_test_secret"
    registered_at: str = field(default_factory=_utc_now_iso)

    # Auth state
    is_revoked: bool = False

    # Config
    config: dict = field(default_factory=_default_config)

    # Action queue (heartbeat hands these to the agent once each)
    pending_actions: list = field(default_factory=list)

    # Recorded requests for test inspection
    received_register_calls: list = field(default_factory=list)
    received_heartbeats: list = field(default_factory=list)
    received_reports: list = field(default_factory=list)
    received_discovered_hosts: list = field(default_factory=list)
    received_get_config_calls: int = 0

    # Force-failure modes for test scenarios
    force_report_status: Optional[int] = None  # e.g. 503
    force_report_status_count: int = 0
    force_heartbeat_status: Optional[int] = None
    force_heartbeat_status_count: int = 0

    # Idempotency tracking for reports (so duplicate report_ids 409)
    seen_report_ids: set = field(default_factory=set)


class MockDashboard:
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

    @property
    def agent_id(self) -> str:
        return self._state.agent_id

    @property
    def agent_secret(self) -> str:
        return self._state.agent_secret

    # ---- control surface --------------------------------------------

    def add_valid_registration_token(self, token: str) -> None:
        with self._state.lock:
            self._state.valid_registration_tokens.add(token)

    def revoke_agent(self) -> None:
        """Subsequent heartbeat / config / report calls return 401."""
        with self._state.lock:
            self._state.is_revoked = True

    def queue_action(
        self,
        action_type: str,
        payload: Optional[dict] = None,
        *,
        expires_in_seconds: int = 300,
    ) -> str:
        """Queue an action to be delivered on the next heartbeat.
        Returns the action_id (for the test to assert later)."""
        action_id = str(uuid.uuid4())
        with self._state.lock:
            self._state.pending_actions.append({
                "action_id": action_id,
                "action_type": action_type,
                "payload": payload or {},
                "queued_at": _utc_now_iso(),
                "expires_at": _expires_at_iso(expires_in_seconds),
            })
        return action_id

    def update_config_manual_hosts(self, hosts: list) -> None:
        """Replace manual_hosts and bump config_version so the next
        heartbeat signals config_refresh_required."""
        with self._state.lock:
            self._state.config["manual_hosts"] = list(hosts)
            self._state.config["config_version"] += 1
            self._state.config["fetched_at"] = _utc_now_iso()

    def force_next_reports(self, status: int, count: int) -> None:
        """Cause the next `count` /reports calls to return `status`."""
        with self._state.lock:
            self._state.force_report_status = status
            self._state.force_report_status_count = count

    def clear_forced_failures(self) -> None:
        with self._state.lock:
            self._state.force_report_status = None
            self._state.force_report_status_count = 0
            self._state.force_heartbeat_status = None
            self._state.force_heartbeat_status_count = 0

    def received_register_calls(self) -> list:
        with self._state.lock:
            return list(self._state.received_register_calls)

    def received_heartbeats(self) -> list:
        with self._state.lock:
            return list(self._state.received_heartbeats)

    def received_reports(self) -> list:
        with self._state.lock:
            return list(self._state.received_reports)

    def received_discovered_hosts(self) -> list:
        with self._state.lock:
            return list(self._state.received_discovered_hosts)

    def received_get_config_count(self) -> int:
        with self._state.lock:
            return self._state.received_get_config_calls

    # ---- Flask app --------------------------------------------------

    def _build_app(self) -> Flask:
        state = self._state
        app = Flask("mock_dashboard")

        def _envelope(code: str, message: str, status: int):
            return jsonify({"error": {
                "code": code, "message": message,
                "request_id": f"req_{uuid.uuid4().hex[:8]}",
            }}), status

        def _check_auth(agent_id: str) -> Optional[tuple]:
            """Returns None on success, or an (envelope, status) tuple."""
            with state.lock:
                if state.is_revoked:
                    return _envelope("agent_revoked",
                                      "agent has been revoked", 401)
                if agent_id != state.agent_id:
                    return _envelope("agent_not_found",
                                      "no such agent", 404)
                auth = request.headers.get("Authorization", "")
                if auth != f"Bearer {state.agent_secret}":
                    return _envelope("invalid_token",
                                      "secret rejected", 401)
            return None

        @app.post("/api/public/v1/agents/register")
        def register():
            token = request.headers.get("X-Registration-Token", "")
            body = request.get_json(silent=True) or {}
            with state.lock:
                state.received_register_calls.append({
                    "token": token, "body": body,
                })
                if token in state.consumed_registration_tokens:
                    return _envelope("invalid_registration_token",
                                      "token already used", 401)
                if token not in state.valid_registration_tokens:
                    return _envelope("invalid_registration_token",
                                      "token unknown", 401)
                state.consumed_registration_tokens.add(token)
                # Per Phase 4b spec, the register response's "config"
                # is a small FLAT bootstrap snapshot (matches the
                # dashboard's DB column names). Distinct from the
                # GET /config endpoint, which returns the NESTED
                # intervals/timeouts/concurrency shape. Real Lovable
                # implements this distinction; the mock has to too,
                # otherwise the e2e suite hides shape-handling bugs.
                intervals = state.config.get("intervals", {})
                flat_config_snapshot = {
                    "heartbeat_interval_seconds": intervals.get("heartbeat_seconds", 15),
                    "check_interval_seconds": intervals.get("check_seconds", 3600),
                    "config_version": state.config.get("config_version", 1),
                }
                return jsonify({
                    "agent_id": state.agent_id,
                    "agent_secret": state.agent_secret,
                    "registered_at": state.registered_at,
                    "config": flat_config_snapshot,
                }), 201

        @app.get("/api/public/v1/agents/<agent_id>/config")
        def get_config(agent_id):
            err = _check_auth(agent_id)
            if err is not None:
                return err
            with state.lock:
                state.received_get_config_calls += 1
                return jsonify(dict(state.config)), 200

        @app.post("/api/public/v1/agents/<agent_id>/heartbeat")
        def heartbeat(agent_id):
            err = _check_auth(agent_id)
            if err is not None:
                return err
            body = request.get_json(silent=True) or {}
            with state.lock:
                state.received_heartbeats.append(body)
                if state.force_heartbeat_status_count > 0 and state.force_heartbeat_status:
                    state.force_heartbeat_status_count -= 1
                    return _envelope("internal_error", "forced",
                                      state.force_heartbeat_status)
                current_version = state.config.get("config_version", 0)
                agent_version = int(body.get("current_config_version", 0))
                # Drain pending actions on each heartbeat — single-delivery
                # contract per Phase 5c's answer to Q1.
                actions = list(state.pending_actions)
                state.pending_actions.clear()
                return jsonify({
                    "received_at": _utc_now_iso(),
                    "config_version": current_version,
                    "config_refresh_required": agent_version < current_version,
                    "pending_actions": actions,
                }), 200

        @app.post("/api/public/v1/agents/<agent_id>/reports")
        def reports(agent_id):
            err = _check_auth(agent_id)
            if err is not None:
                return err
            body = request.get_json(silent=True) or {}
            with state.lock:
                if state.force_report_status_count > 0 and state.force_report_status:
                    state.force_report_status_count -= 1
                    return _envelope("internal_error", "forced",
                                      state.force_report_status)
                report_id = body.get("report_id", "")
                if report_id in state.seen_report_ids:
                    return jsonify({
                        "error": {
                            "code": "report_already_received",
                            "message": "duplicate report_id",
                            "request_id": f"req_{uuid.uuid4().hex[:8]}",
                        },
                        "original_received_at": _utc_now_iso(),
                        "original_summary": {"total_checks": 0, "success": 0,
                                              "connection_failed": 0,
                                              "tls_failed": 0,
                                              "alerts_triggered": 0,
                                              "ignored_unknown_hosts": 0},
                    }), 409
                state.seen_report_ids.add(report_id)
                state.received_reports.append(body)
                checks = body.get("checks", []) or []
                summary = {
                    "total_checks": len(checks),
                    "success": sum(1 for c in checks if c.get("status") == "success"),
                    "connection_failed": sum(1 for c in checks if c.get("status") == "connection_failed"),
                    "tls_failed": sum(1 for c in checks if c.get("status") == "tls_failed"),
                    "alerts_triggered": 0,
                    "ignored_unknown_hosts": 0,
                }
                return jsonify({
                    "received_at": _utc_now_iso(),
                    "report_id": report_id,
                    "summary": summary,
                    "action_completed": body.get("action_id"),
                }), 200

        @app.post("/api/public/v1/agents/<agent_id>/discovered-hosts")
        def discovered_hosts(agent_id):
            err = _check_auth(agent_id)
            if err is not None:
                return err
            body = request.get_json(silent=True) or {}
            with state.lock:
                state.received_discovered_hosts.append(body)
                hosts = body.get("hosts", []) or []
                return jsonify({
                    "received_at": _utc_now_iso(),
                    "summary": {
                        "total_received": len(hosts),
                        "created": len(hosts),
                        "updated": 0,
                        "removed": 0,
                        "unchanged": 0,
                    },
                    "config_version": state.config["config_version"],
                    "action_completed": body.get("action_id"),
                }), 200

        return app
