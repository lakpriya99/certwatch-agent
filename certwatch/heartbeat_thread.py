"""Phase 5c — heartbeat thread + shared state.

Three thread-safe components:

  - ConfigState: heartbeat-owned in-memory config holder. Snapshot/replace
    pattern. Many readers (heartbeat, cert check thread, action workers),
    one writer (heartbeat thread when config_refresh_required is signaled).
    The dict is treated as immutable by convention; readers don't deep-copy.

  - StatsState: telemetry holder. Many writers (cert check thread, NetBox
    sync), one reader (heartbeat thread building the stats payload).
    snapshot_for_heartbeat() returns None when nothing has been recorded
    yet, and a fresh dict copy when there's data — so a slow heartbeat
    that holds the snapshot during JSON serialization doesn't block writers.

  - HeartbeatThread: the 15s-cadence loop. No-catch-up: the wait between
    heartbeats happens AFTER each heartbeat completes, not on a fixed
    wall-clock schedule. A slow 8s heartbeat means the next fires at
    t=23s, not t=15s — preventing back-to-back firing right after a
    network blip.

The heartbeat is the one thread allowed to set shutdown_event on its
own (when an auth error proves the agent_secret is no longer valid).
The runner observes the event and brings down the rest of the threads.
"""

from __future__ import annotations

import logging
import queue
import threading
from typing import Optional

from certwatch.clock import Clock, utc_now_iso
from certwatch.dashboard_client import (
    DashboardAuthError,
    DashboardClient,
    DashboardError,
    DashboardRetriableError,
    DashboardValidationError,
)

log = logging.getLogger("certwatch")


class ConfigState:
    """Thread-safe in-memory config holder.

    The held dict is treated as immutable by convention: readers grab a
    reference via snapshot() and use it freely; the next snapshot() call
    returns whatever's current. Writers atomically swap the WHOLE dict
    via replace(); they don't mutate fields in place.
    """

    def __init__(self, initial: dict) -> None:
        self._lock = threading.Lock()
        self._config = initial

    def snapshot(self) -> dict:
        """Return a reference to the current config dict.

        Cheap (no copy). The caller is responsible for not mutating the
        returned dict. If a config refresh happens while the caller is
        using a snapshot, the caller continues to see the old config —
        natural "stable view per cycle" semantics for the cert check
        thread (each cycle uses one snapshot).
        """
        with self._lock:
            return self._config

    def replace(self, new_config: dict) -> None:
        with self._lock:
            self._config = new_config


class StatsState:
    """Thread-safe operational telemetry holder.

    Writers (cert check thread, NetBox sync) update fields independently;
    the heartbeat thread snapshots all of them at once for the heartbeat
    body. Snapshot returns a COPY so writers can update fields the moment
    the snapshot is taken without blocking on the caller's serialization.
    """

    def __init__(self, clock: Clock) -> None:
        self._lock = threading.Lock()
        self._clock = clock  # held for future telemetry that needs monotonic time
        self._hosts_monitored: Optional[int] = None
        self._last_check_completed_at: Optional[str] = None
        self._last_check_duration_seconds: Optional[int] = None
        self._last_netbox_sync_at: Optional[str] = None
        self._checks_succeeded_last_cycle: Optional[int] = None
        self._checks_failed_last_cycle: Optional[int] = None

    def record_check_cycle(
        self,
        *,
        hosts_monitored: int,
        completed_at: str,
        duration_seconds: int,
        succeeded: int,
        failed: int,
    ) -> None:
        """Called by the cert check thread (5e) at the end of every cycle."""
        with self._lock:
            self._hosts_monitored = hosts_monitored
            self._last_check_completed_at = completed_at
            self._last_check_duration_seconds = duration_seconds
            self._checks_succeeded_last_cycle = succeeded
            self._checks_failed_last_cycle = failed

    def record_netbox_sync(self, *, completed_at: str) -> None:
        """Called by the NetBox sync (Phase 6) after a successful sync."""
        with self._lock:
            self._last_netbox_sync_at = completed_at

    def snapshot_for_heartbeat(self) -> Optional[dict]:
        """Build the heartbeat body's `stats` field.

        Returns None when nothing has been recorded yet — sending an
        all-None stats dict is pointless noise (and the contract treats
        the field as optional). Returns a fresh dict otherwise.
        """
        with self._lock:
            populated = {
                k: v
                for k, v in (
                    ("hosts_monitored", self._hosts_monitored),
                    ("last_check_completed_at", self._last_check_completed_at),
                    ("last_check_duration_seconds", self._last_check_duration_seconds),
                    ("last_netbox_sync_at", self._last_netbox_sync_at),
                    ("checks_succeeded_last_cycle", self._checks_succeeded_last_cycle),
                    ("checks_failed_last_cycle", self._checks_failed_last_cycle),
                )
                if v is not None
            }
        return populated or None


class _ShutdownRequested(Exception):
    """Internal signal: heartbeat detected an auth error and requested
    global shutdown. Caught at the top of the run loop to break out
    cleanly."""


class HeartbeatThread(threading.Thread):
    """Heartbeat loop: 15s cadence, no catch-up, auth-error stops the world.

    The first heartbeat fires immediately on .start() — there's no
    initial wait. Subsequent heartbeats fire `interval` seconds AFTER
    each previous one completes (no-catch-up: a slow 8s heartbeat means
    the next is at t=23s, not t=15s).

    The loop reads the heartbeat interval from ConfigState on each
    iteration, so dashboard-driven changes (`intervals.heartbeat_seconds`)
    take effect on the next tick after a config refresh.
    """

    def __init__(
        self,
        *,
        client: DashboardClient,
        config_state: ConfigState,
        stats_state: StatsState,
        action_queue: "queue.Queue[dict]",
        shutdown_event: threading.Event,
        clock: Clock,
        process_started_at: float,
        agent_version: str,
        auth_error_event: Optional[threading.Event] = None,
        name: str = "certwatch-heartbeat",
    ) -> None:
        super().__init__(name=name, daemon=False)
        self._client = client
        self._config_state = config_state
        self._stats_state = stats_state
        self._action_queue = action_queue
        self._shutdown_event = shutdown_event
        # Optional: when provided, this is set IN ADDITION to shutdown_event
        # whenever the thread detects an auth error. The runner uses it to
        # distinguish "shutdown due to revocation" (exit 2) from "shutdown
        # due to SIGTERM" (exit 0) at the integration layer.
        self._auth_error_event = auth_error_event
        self._clock = clock
        self._process_started_at = process_started_at
        self._agent_version = agent_version

    def run(self) -> None:
        log.info({"event": "heartbeat_thread_starting"})
        try:
            while not self._shutdown_event.is_set():
                try:
                    self._do_heartbeat()
                except _ShutdownRequested:
                    break

                interval = self._heartbeat_interval()
                # wait_for returns True if the event was set (now or during
                # the wait), False on normal timeout. Either way, exit on True.
                if self._clock.wait_for(interval, self._shutdown_event):
                    break
        except Exception as e:
            # Catch-all so an unexpected exception in the loop signals
            # global shutdown rather than silently killing the thread
            # (and leaving the rest of the agent running headless).
            # Don't re-raise — the threading framework has no recovery
            # path, so propagation just flags the exception out-of-band
            # without changing what we want (set shutdown, exit thread).
            log.error(
                {
                    "event": "heartbeat_thread_unhandled_exception",
                    "error_class": type(e).__name__,
                    "error_message": str(e),
                }
            )
            self._shutdown_event.set()
        finally:
            log.info({"event": "heartbeat_thread_exiting"})

    # ---- heartbeat call ----------------------------------------------

    def _do_heartbeat(self) -> None:
        body_args = self._build_heartbeat_args()

        try:
            response = self._client.heartbeat(**body_args)
        except DashboardAuthError as e:
            # Revoked or invalid token. Stop the world: signal shutdown
            # so other threads notice, then break the heartbeat loop.
            log.error(
                {
                    "event": "heartbeat_auth_error_shutting_down",
                    "error_code": e.code,
                    "error_message": e.message,
                    "request_id": e.request_id,
                }
            )
            if self._auth_error_event is not None:
                self._auth_error_event.set()
            self._shutdown_event.set()
            raise _ShutdownRequested() from e
        except DashboardValidationError as e:
            # Rare per the lenient-validation contract; log and continue.
            # The dashboard accepts the liveness signal even on bad bodies,
            # so this is genuinely surprising — but not fatal.
            log.warning(
                {
                    "event": "heartbeat_validation_error",
                    "error_code": e.code,
                    "error_message": e.message,
                    "request_id": e.request_id,
                }
            )
            return
        except DashboardRetriableError as e:
            # 5xx, network, etc. Don't backoff — heartbeat cadence IS the
            # point. Just continue at the next 15s tick.
            log.warning(
                {
                    "event": "heartbeat_retriable_error",
                    "error_class": type(e).__name__,
                    "error_code": e.code,
                    "error_message": e.message,
                }
            )
            return
        except DashboardError as e:
            # Other DashboardError subclass (NotFound, base, etc.).
            # Treat like retriable (log + continue) since none of these
            # should happen to a registered agent under normal operation.
            log.warning(
                {
                    "event": "heartbeat_unexpected_dashboard_error",
                    "error_class": type(e).__name__,
                    "error_code": e.code,
                    "error_message": e.message,
                    "status_code": e.status_code,
                }
            )
            return

        self._process_response(response)

    def _build_heartbeat_args(self) -> dict:
        config = self._config_state.snapshot()
        stats = self._stats_state.snapshot_for_heartbeat()
        uptime_seconds = max(0, int(self._clock.now() - self._process_started_at))
        return {
            "sent_at": utc_now_iso(),
            "agent_version": self._agent_version,
            "uptime_seconds": uptime_seconds,
            "current_config_version": int(config["config_version"]),
            "stats": stats,
        }

    # ---- response handling -------------------------------------------

    def _process_response(self, response: dict) -> None:
        # Config refresh first (per the contract: refresh, THEN process
        # actions on the new state). If the get_config call raises, the
        # action processing for this response is still executed against
        # the OLD config — that's intentional (we don't drop pending
        # actions just because one config refresh transiently failed).
        if response.get("config_refresh_required"):
            self._refresh_config()

        actions = response.get("pending_actions") or []
        if actions:
            self._enqueue_actions(actions)

    def _enqueue_actions(self, actions: list) -> None:
        now_iso = utc_now_iso()
        enqueued = 0
        skipped_expired = 0
        for action in actions:
            expires_at = action.get("expires_at")
            if expires_at and expires_at < now_iso:
                # Filter expired here — keeps the queue meaningful (every
                # entry is actionable). 5d's worker will re-check on
                # pickup, but that's a defense-in-depth check, not the
                # primary filter.
                log.info(
                    {
                        "event": "action_received_but_expired",
                        "action_id": action.get("action_id"),
                        "action_type": action.get("action_type"),
                        "expires_at": expires_at,
                        "now": now_iso,
                    }
                )
                skipped_expired += 1
                continue
            self._action_queue.put(action)
            enqueued += 1

        log.info(
            {
                "event": "heartbeat_actions_enqueued",
                "enqueued": enqueued,
                "skipped_expired": skipped_expired,
            }
        )

    def _refresh_config(self) -> None:
        try:
            new_config = self._client.get_config()
        except DashboardAuthError as e:
            log.error(
                {
                    "event": "config_refresh_auth_error_shutting_down",
                    "error_code": e.code,
                    "error_message": e.message,
                }
            )
            if self._auth_error_event is not None:
                self._auth_error_event.set()
            self._shutdown_event.set()
            raise _ShutdownRequested() from e
        except DashboardError as e:
            # Retriable, validation, not-found — keep using the current
            # config. The heartbeat will signal again on the next tick;
            # the dashboard will retry the refresh request via its
            # config_refresh_required signal.
            log.warning(
                {
                    "event": "config_refresh_failed_keeping_old",
                    "error_class": type(e).__name__,
                    "error_code": e.code,
                    "error_message": e.message,
                }
            )
            return

        old_config = self._config_state.snapshot()
        old_version = old_config.get("config_version")
        new_version = new_config.get("config_version")
        self._config_state.replace(new_config)
        log.info(
            {
                "event": "config_refreshed",
                "old_version": old_version,
                "new_version": new_version,
                "manual_hosts_count": len(new_config.get("manual_hosts", []) or []),
            }
        )

    # ---- helpers ------------------------------------------------------

    def _heartbeat_interval(self) -> float:
        config = self._config_state.snapshot()
        return float(config["intervals"]["heartbeat_seconds"])
