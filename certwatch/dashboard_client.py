"""Dashboard API client — Phase 4a shared HTTP client + exception hierarchy.

Endpoint-specific methods (register, get_config, submit_reports,
report_discovered_hosts, heartbeat) land in Phase 4b-4f and use `_request`
below. The exception hierarchy mirrors the dashboard's standard error
envelope:

  { "error": { "code": "<snake_case>", "message": "...",
               "request_id": "req_..." } }

`code`, `message`, and `request_id` are preserved on every raised exception
when the server provided them. Tolerant readers: a missing or absent
envelope (e.g. CDN HTML 502 page, empty body) does NOT crash parsing — the
exception is still raised, just with `code=None` etc.

Retry policy: catch `DashboardRetriableError` (covers 5xx server errors,
network timeouts, connection failures, 429 rate limits) at the call site.
Non-retriable failures bubble out as their concrete subclass.
"""

from __future__ import annotations

import json
from typing import Any, Optional

import requests


# ---- exception hierarchy ----------------------------------------------


class DashboardError(Exception):
    """Base for all dashboard client errors. Preserves the standard error
    envelope fields when the server provided them."""

    def __init__(
        self,
        message: str,
        *,
        code: Optional[str] = None,
        request_id: Optional[str] = None,
        status_code: Optional[int] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.request_id = request_id
        self.status_code = status_code

    def __str__(self) -> str:
        parts = [self.message]
        if self.code:
            parts.append(f"code={self.code}")
        if self.status_code is not None:
            parts.append(f"status={self.status_code}")
        if self.request_id:
            parts.append(f"request_id={self.request_id}")
        return " ".join(parts)


class DashboardAuthError(DashboardError):
    """401 — invalid_registration_token, invalid_token, agent_revoked."""


class DashboardNotFoundError(DashboardError):
    """404 — agent_not_found."""


class DashboardValidationError(DashboardError):
    """400 — validation_failed (or other 4xx malformed-request responses)."""


class DashboardConflictError(DashboardError):
    """409 — registration_conflict, report_already_received.

    Preserves the full parsed response body on `.body` so callers can read
    additional context the server included alongside the error envelope
    (e.g. `existing_report_id` on report dedup)."""

    def __init__(
        self,
        message: str,
        *,
        code: Optional[str] = None,
        request_id: Optional[str] = None,
        status_code: Optional[int] = None,
        body: Optional[Any] = None,
    ) -> None:
        super().__init__(
            message,
            code=code,
            request_id=request_id,
            status_code=status_code,
        )
        self.body = body


class DashboardPayloadTooLargeError(DashboardError):
    """413 — payload_too_large. Caller should reduce batch size and retry."""


class DashboardRetriableError(DashboardError):
    """Marker base for errors the agent should retry with backoff: 5xx,
    timeouts, connection errors, 429. Catch this base in retry loops to
    keep retry policy in one place."""


class DashboardServerError(DashboardRetriableError):
    """5xx — internal_error or any other server-side failure."""


class DashboardNetworkError(DashboardRetriableError):
    """Connection error or timeout reaching the dashboard."""


class DashboardRateLimitError(DashboardRetriableError):
    """429 — rate_limited (reserved for v2 in the API contract)."""


# ---- client ----------------------------------------------------------


class DashboardClient:
    """Wraps the dashboard REST API. Endpoint methods land in 4b-4f.

    `agent_id` and `agent_secret` are optional because the register
    endpoint runs before we have credentials; endpoint methods that
    require auth assert these are set. Pass a custom `session` to inject
    transport behavior (timeouts, retries via urllib3) or for testing."""

    def __init__(
        self,
        dashboard_url: str,
        agent_id: Optional[str] = None,
        agent_secret: Optional[str] = None,
        *,
        session: Optional[requests.Session] = None,
        default_timeout: float = 10.0,
    ) -> None:
        self.dashboard_url = dashboard_url.rstrip("/")
        self.agent_id = agent_id
        self.agent_secret = agent_secret
        self._session = session or requests.Session()
        self._default_timeout = default_timeout

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Optional[Any] = None,
        headers: Optional[dict[str, str]] = None,
        timeout: Optional[float] = None,
        authenticated: bool = True,
    ) -> Any:
        """Issue a JSON-over-HTTP request to the dashboard.

        Headers added automatically:
          - `Accept: application/json` (always)
          - `Content-Type: application/json` (only if `body` is not None)
          - `Authorization: Bearer <agent_secret>` (only when `authenticated`
            is True and `agent_secret` is set on the client)

        `headers` overrides any of the above (e.g. the register endpoint
        passes `X-Registration-Token` here). The `authenticated=False`
        escape hatch exists so the register endpoint can guarantee NO
        Authorization header is sent even if the client was somehow
        constructed with a stale `agent_secret`.

        Returns parsed JSON on 2xx; raises a `DashboardError` subclass
        otherwise. Network failures and 5xx are surfaced as
        `DashboardRetriableError` subclasses.
        """
        url = self.dashboard_url + path

        send_headers: dict[str, str] = {"Accept": "application/json"}
        if body is not None:
            send_headers["Content-Type"] = "application/json"
        if authenticated and self.agent_secret is not None:
            send_headers["Authorization"] = f"Bearer {self.agent_secret}"
        if headers:
            send_headers.update(headers)

        data = json.dumps(body) if body is not None else None

        try:
            resp = self._session.request(
                method,
                url,
                data=data,
                headers=send_headers,
                timeout=timeout if timeout is not None else self._default_timeout,
            )
        except requests.Timeout as e:
            raise DashboardNetworkError(
                f"timeout calling {method} {path}: {e}"
            ) from e
        except requests.ConnectionError as e:
            raise DashboardNetworkError(
                f"connection error calling {method} {path}: {e}"
            ) from e
        except requests.RequestException as e:
            raise DashboardNetworkError(
                f"request error calling {method} {path}: {e}"
            ) from e

        return self._handle_response(method, path, resp)

    def _handle_response(
        self, method: str, path: str, resp: requests.Response
    ) -> Any:
        status = resp.status_code

        if 200 <= status < 300:
            try:
                return resp.json()
            except ValueError as e:
                raise DashboardError(
                    f"non-JSON 2xx response from {method} {path}: {e}",
                    status_code=status,
                ) from e

        code, message, request_id, body = self._parse_error_envelope(resp)
        msg = message or f"{method} {path} -> HTTP {status}"

        if status == 400:
            raise DashboardValidationError(
                msg, code=code, request_id=request_id, status_code=status
            )
        if status == 401:
            raise DashboardAuthError(
                msg, code=code, request_id=request_id, status_code=status
            )
        if status == 404:
            raise DashboardNotFoundError(
                msg, code=code, request_id=request_id, status_code=status
            )
        if status == 409:
            raise DashboardConflictError(
                msg,
                code=code,
                request_id=request_id,
                status_code=status,
                body=body,
            )
        if status == 413:
            raise DashboardPayloadTooLargeError(
                msg, code=code, request_id=request_id, status_code=status
            )
        if status == 429:
            raise DashboardRateLimitError(
                msg, code=code, request_id=request_id, status_code=status
            )
        if 500 <= status < 600:
            raise DashboardServerError(
                msg, code=code, request_id=request_id, status_code=status
            )

        raise DashboardError(
            msg, code=code, request_id=request_id, status_code=status
        )

    # ---- endpoints --------------------------------------------------

    def register(
        self,
        registration_token: str,
        agent_version: str,
        hostname: str,
        platform: Optional[str],
        started_at: str,
    ) -> dict:
        """POST /api/v1/agents/register — first-run-only credential exchange.

        Sends the one-time `registration_token` via `X-Registration-Token`
        header (NOT `Authorization`, per the API contract). On 201, returns
        the parsed response dict containing `agent_id`, `agent_secret`,
        `registered_at`, and the initial `config` block.

        Errors map to:
          - 401 invalid_registration_token → DashboardAuthError (do not retry)
          - 400 validation_failed         → DashboardValidationError (code bug)
          - 409 registration_conflict     → DashboardConflictError (treat as 401)
          - 5xx / network                 → DashboardRetriableError subclass
        """
        body: dict[str, Any] = {
            "agent_version": agent_version,
            "hostname": hostname,
            "started_at": started_at,
        }
        if platform is not None:
            body["platform"] = platform
        return self._request(
            "POST",
            "/api/v1/agents/register",
            body=body,
            headers={"X-Registration-Token": registration_token},
            authenticated=False,
        )

    def submit_report(
        self,
        report_id: str,
        report_type: str,
        started_at: str,
        completed_at: str,
        action_id: Optional[str],
        checks: list[dict],
    ) -> dict:
        """POST /api/v1/agents/{agent_id}/reports — submit batched cert results.

        Stateless wire-format method. The caller owns the report_id (and
        retries with the SAME report_id on transport failures, per the
        idempotency contract). The caller also owns batching to <=1000
        checks; if the dashboard returns 413, this method raises
        DashboardPayloadTooLargeError without trying to split.

        Body shape (always — none of these are conditionally omitted):
          - report_id, report_type, started_at, completed_at, checks
          - action_id (sent as null when None — the contract distinguishes
            missing from null; null explicitly means "not in response to an
            action queue item", which is the normal case for scheduled and
            startup reports)

        The `checks` list is passed through verbatim. Caller is responsible
        for shaping each entry per contract (host_ref discriminated union,
        status, conditional cert/error_reason). No client-side validation —
        the dashboard validates and returns 400 validation_failed if the
        shape is wrong.

        On 200: returns the parsed response (received_at, report_id echo,
        summary, action_completed).

        On 409 report_already_received: DashboardConflictError propagates.
        Do NOT swallow into a synthetic success — the runner treats 409 as
        success but wants visibility, and the exception's `.body` attribute
        carries the dashboard's response (including any original_summary
        fields the dashboard chose to include) for logging.
        """
        self._require_credentials()
        body = {
            "report_id": report_id,
            "report_type": report_type,
            "started_at": started_at,
            "completed_at": completed_at,
            "action_id": action_id,
            "checks": checks,
        }
        return self._request(
            "POST",
            f"/api/v1/agents/{self.agent_id}/reports",
            body=body,
        )

    def submit_discovered_hosts(
        self,
        action_id: Optional[str],
        synced_at: str,
        netbox_url: str,
        netbox_filter: str,
        hosts: list[dict],
    ) -> dict:
        """POST /api/v1/agents/{agent_id}/discovered-hosts — REPLACE-semantics
        sync of NetBox-discovered hosts.

        The dashboard derives removals server-side: any host with
        (agent_id matches, source=netbox, netbox_device_id NOT in this
        request) is removed. Manual hosts are unaffected.

        Safety contract — owned by the CALLER (Phase 6 NetBox sync):
        do NOT call this method when NetBox sync fails. An empty `hosts`
        list explicitly means "NetBox matched nothing this cycle"; failure
        means "preserve dashboard state, don't call". This client method
        cannot tell the difference and trusts what's passed in.

        Body shape — all five fields always included:
          - action_id (sent as null when None — distinguishes scheduled
            syncs from action-triggered syncs, mirroring submit_report's
            handling of the same field)
          - synced_at, netbox_url, netbox_filter, hosts

        `hosts` is passed through verbatim. Caller shapes each entry per
        contract: required `netbox_device_id` (integer) and `hostname`
        (string), optional `port` / `display_name` / `tags`.

        Returns parsed response (received_at, summary with create/update/
        remove/unchanged counts, config_version, action_completed).
        """
        self._require_credentials()
        body = {
            "action_id": action_id,
            "synced_at": synced_at,
            "netbox_url": netbox_url,
            "netbox_filter": netbox_filter,
            "hosts": hosts,
        }
        return self._request(
            "POST",
            f"/api/v1/agents/{self.agent_id}/discovered-hosts",
            body=body,
        )

    def heartbeat(
        self,
        sent_at: str,
        agent_version: str,
        uptime_seconds: int,
        current_config_version: int,
        stats: Optional[dict] = None,
    ) -> dict:
        """POST /api/v1/agents/{agent_id}/heartbeat — 15s liveness signal.

        Body shape:
          - sent_at, agent_version, uptime_seconds, current_config_version:
            always present
          - stats: OMITTED entirely when None (NOT sent as null). The
            heartbeat contract treats absence as the natural form of
            "no telemetry to report this tick". Contrast with submit_report
            and submit_discovered_hosts, where action_id IS sent as null
            when None — different fields follow different missing/null
            contracts; both are correct for their respective endpoints.

        No client-side validation of stats sub-fields. The dashboard's
        lenient-validation contract: dropping a heartbeat is more harmful
        than accepting a slightly-malformed one (a missed heartbeat moves
        the agent toward "stale"; a malformed-but-accepted one just loses
        some telemetry).

        Returns the parsed response (received_at, config_version,
        config_refresh_required, pending_actions). pending_actions is
        passed through verbatim — including action_types the agent
        doesn't recognize, since blocking known actions on the same
        response over an unknown sibling would be a self-inflicted DOS.
        Action routing, expiration filtering, and the
        config_refresh_required→get_config() sequencing are all the
        runner's job (Phase 5).
        """
        self._require_credentials()
        body: dict[str, Any] = {
            "sent_at": sent_at,
            "agent_version": agent_version,
            "uptime_seconds": uptime_seconds,
            "current_config_version": current_config_version,
        }
        if stats is not None:
            body["stats"] = stats
        return self._request(
            "POST",
            f"/api/v1/agents/{self.agent_id}/heartbeat",
            body=body,
        )

    def get_config(self) -> dict:
        """GET /api/v1/agents/{agent_id}/config — fetch current operating config.

        Returns the full nested response (intervals, timeouts, concurrency,
        alert_thresholds_days, manual_hosts, plus any future fields). Does
        NOT cache or fall back to a previous config on failure — the runner
        owns those concerns. This method is stateless.

        Per the contract, NetBox-discovered hosts are NEVER in this
        response; the agent merges manual_hosts (here) with its locally
        synced netbox_hosts to form the effective host list.
        """
        self._require_credentials()
        return self._request(
            "GET", f"/api/v1/agents/{self.agent_id}/config"
        )

    # ---- internal helpers ------------------------------------------

    def _require_credentials(self) -> None:
        """Guard for endpoint methods that need a registered agent.

        Raises ValueError (not DashboardError) because missing credentials
        is a programming-error condition — registration was skipped, or
        credentials weren't loaded from /data/agent.json before constructing
        the client. Surfacing it as ValueError keeps it distinct from
        runtime/transport errors that the retry loop catches."""
        if self.agent_id is None or self.agent_secret is None:
            raise ValueError(
                "operation requires both agent_id and agent_secret on the client; "
                "register first or load credentials from /data/agent.json"
            )

    @staticmethod
    def _parse_error_envelope(
        resp: requests.Response,
    ) -> tuple[Optional[str], Optional[str], Optional[str], Optional[Any]]:
        try:
            body = resp.json()
        except (ValueError, TypeError):
            return None, None, None, None
        if not isinstance(body, dict):
            return None, None, None, body
        err = body.get("error")
        if not isinstance(err, dict):
            return None, None, None, body
        return err.get("code"), err.get("message"), err.get("request_id"), body
