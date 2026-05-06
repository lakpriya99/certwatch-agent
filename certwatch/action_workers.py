"""Phase 5d — action worker pool + handlers.

The pool is the consumer side of the action queue that HeartbeatThread
fills. Workers block on the queue, dispatch each action by action_type
to the registered handler, and respect shutdown signals at task pickup.

Defense-in-depth: HeartbeatThread filters expired actions at enqueue,
but workers re-check at pickup (an action queued at t=0 may expire
before the worker dequeues it).

The pool is generic — handlers are passed in by the runner. For 5d:
  - check_host: resolves host_ref, runs cert_check, submits an on_demand
    report echoing the action_id
  - sync_netbox: placeholder logging "not yet implemented" (Phase 6
    replaces this)
  - unknown action_type: log warning, skip (forward-compat for v2
    dashboards that introduce new action types)

Auth errors during a handler signal global shutdown via the
shutdown_event. Other handler exceptions are swallowed by the worker
loop so one bad action doesn't kill the worker.
"""

from __future__ import annotations

import dataclasses
import logging
import queue
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from certwatch.cert_check import CertResult, cert_check as default_cert_check
from certwatch.check_payload import (
    build_check_payload as _build_check_payload,
    cert_dict_from_result as _cert_dict_from_result,
)
from certwatch.clock import Clock, utc_now_iso
from certwatch.dashboard_client import DashboardAuthError, DashboardClient
from certwatch.heartbeat_thread import ConfigState
from certwatch.report_submission import (
    ReportSubmissionResult,
    submit_report_with_retry as default_submit,
)

log = logging.getLogger("certwatch")


@dataclass(frozen=True)
class ActionContext:
    """The shape passed to action handlers. The worker has already verified
    expires_at > now; handlers can trust the action is still actionable
    at the moment they receive the context (though network failures
    during processing are still possible)."""

    action_id: str
    action_type: str
    payload: dict
    queued_at: str
    expires_at: str


ActionHandler = Callable[[ActionContext], None]


class ActionWorkerPool:
    """Bounded thread pool for processing dashboard-queued actions.

    Workers are daemon threads so a forgotten join() doesn't prevent
    process exit, but the runner is expected to call join() explicitly
    so shutdown latency is observable.

    Shutdown contract: on shutdown_event, workers finish their currently
    in-flight handler (don't interrupt cert_check mid-handshake) and
    exit at the top of their next loop iteration. Worst-case shutdown
    latency = max handler duration. submit_report_with_retry already
    respects shutdown_event during its backoff sleeps, so retries don't
    extend shutdown indefinitely; the only true cap is cert_check's
    10s connect+handshake budget.
    """

    def __init__(
        self,
        *,
        action_queue: "queue.Queue[dict]",
        handlers: dict[str, ActionHandler],
        shutdown_event: threading.Event,
        clock: Clock,
        num_workers: int = 4,
        auth_error_event: Optional[threading.Event] = None,
    ) -> None:
        self._queue = action_queue
        self._handlers = handlers
        self._shutdown_event = shutdown_event
        # Optional companion event the runner uses to detect auth-driven
        # shutdown for exit-code purposes.
        self._auth_error_event = auth_error_event
        self._clock = clock
        self._num_workers = num_workers
        self._threads: list[threading.Thread] = []

    def start(self) -> None:
        if self._threads:
            raise RuntimeError("ActionWorkerPool already started")
        for i in range(self._num_workers):
            t = threading.Thread(
                target=self._worker_loop,
                args=(i,),
                name=f"certwatch-action-worker-{i}",
                daemon=True,
            )
            self._threads.append(t)
            t.start()
        log.info(
            {
                "event": "action_worker_pool_started",
                "num_workers": self._num_workers,
            }
        )

    def join(self, timeout: Optional[float] = None) -> bool:
        """Wait for all workers to exit. Returns True if all exited
        within the timeout, False if any are still alive."""
        if timeout is None:
            for t in self._threads:
                t.join()
            return True
        # Distribute the timeout: each worker gets a slice. Simple and
        # sufficient — workers wake at most every 0.5s on the queue.get
        # poll, so 1s+ usually clears all of them.
        per_thread = max(0.05, timeout / max(1, len(self._threads)))
        for t in self._threads:
            t.join(timeout=per_thread)
        return all(not t.is_alive() for t in self._threads)

    # ---- worker loop -------------------------------------------------

    def _worker_loop(self, worker_id: int) -> None:
        log.info({"event": "action_worker_starting", "worker_id": worker_id})
        try:
            while not self._shutdown_event.is_set():
                try:
                    # 0.5s timeout balances "wake fast on shutdown" vs
                    # "don't burn CPU when idle." Phase 5c's heartbeat
                    # cadence is 15s, so this is plenty fast.
                    action = self._queue.get(timeout=0.5)
                except queue.Empty:
                    continue

                try:
                    self._dispatch(action, worker_id)
                except DashboardAuthError as e:
                    # Auth error is the one handler exception that means
                    # "stop the world." Set the global shutdown signal
                    # so the runner brings down everything else.
                    log.error(
                        {
                            "event": "action_handler_auth_error_shutdown_signaled",
                            "worker_id": worker_id,
                            "action_id": action.get("action_id"),
                            "action_type": action.get("action_type"),
                            "error_code": e.code,
                            "error_message": e.message,
                        }
                    )
                    if self._auth_error_event is not None:
                        self._auth_error_event.set()
                    self._shutdown_event.set()
                    # Don't re-raise: the next iteration's is_set() check
                    # exits cleanly, and re-raising would bypass task_done.
                except Exception as e:
                    # Other handler errors must NOT crash the worker.
                    # One bad action shouldn't take down the pool.
                    log.error(
                        {
                            "event": "action_handler_unexpected_error",
                            "worker_id": worker_id,
                            "action_id": action.get("action_id"),
                            "action_type": action.get("action_type"),
                            "error_class": type(e).__name__,
                            "error_message": str(e),
                        }
                    )
                finally:
                    self._queue.task_done()
        finally:
            log.info({"event": "action_worker_exiting", "worker_id": worker_id})

    # ---- dispatch -----------------------------------------------------

    def _dispatch(self, action: dict, worker_id: int) -> None:
        action_id = action.get("action_id", "<missing>")
        action_type = action.get("action_type", "<missing>")
        expires_at = action.get("expires_at", "")

        # Defense-in-depth: re-check expiration at pickup. HeartbeatThread
        # filters at enqueue, but actions can sit in the queue if workers
        # are slow — by the time a worker dequeues, the action may have
        # expired.
        now = utc_now_iso()
        if expires_at and expires_at < now:
            log.info(
                {
                    "event": "action_skipped_expired_at_pickup",
                    "worker_id": worker_id,
                    "action_id": action_id,
                    "action_type": action_type,
                    "expires_at": expires_at,
                    "now": now,
                }
            )
            return

        # Don't start new work after shutdown signaled — same pattern as
        # Phase 3's check_loop.
        if self._shutdown_event.is_set():
            log.info(
                {
                    "event": "action_skipped_shutdown_signaled",
                    "worker_id": worker_id,
                    "action_id": action_id,
                }
            )
            return

        handler = self._handlers.get(action_type)
        if handler is None:
            # Forward-compat: a v2 dashboard may deliver action types
            # this v1 agent doesn't recognize. Log + skip; don't crash.
            log.warning(
                {
                    "event": "action_unknown_type_skipped",
                    "worker_id": worker_id,
                    "action_id": action_id,
                    "action_type": action_type,
                }
            )
            return

        ctx = ActionContext(
            action_id=action_id,
            action_type=action_type,
            payload=action.get("payload", {}) or {},
            queued_at=action.get("queued_at", ""),
            expires_at=expires_at,
        )

        log.info(
            {
                "event": "action_handler_starting",
                "worker_id": worker_id,
                "action_id": action_id,
                "action_type": action_type,
            }
        )
        handler(ctx)
        log.info(
            {
                "event": "action_handler_completed",
                "worker_id": worker_id,
                "action_id": action_id,
                "action_type": action_type,
            }
        )


# ---- check_host handler ----------------------------------------------


def make_check_host_handler(
    *,
    client: DashboardClient,
    data_dir: str | Path,
    config_state: ConfigState,
    clock: Clock,
    shutdown_event: threading.Event,
    check_fn: Callable = default_cert_check,
    submit_fn: Callable = default_submit,
) -> ActionHandler:
    """Returns the check_host action handler.

    The factory takes everything the handler needs; the resulting closure
    has the right shape for ActionWorkerPool's handlers map.

    `check_fn` and `submit_fn` are injectable for unit testing — same
    pattern Phase 3's check_loop established. Production code uses the
    defaults.
    """

    def handle(ctx: ActionContext) -> None:
        host_ref = ctx.payload.get("host_ref") or {}
        ref_type = host_ref.get("type")

        config = config_state.snapshot()

        if ref_type == "manual":
            host_id = host_ref.get("host_id")
            resolved = _resolve_manual_host(host_id, config)
            if resolved is None:
                log.info(
                    {
                        "event": "action_check_host_skipped_host_not_found",
                        "action_id": ctx.action_id,
                        "host_id": host_id,
                        "current_config_version": config.get("config_version"),
                        "manual_hosts_count": len(config.get("manual_hosts", []) or []),
                    }
                )
                return
            hostname, port = resolved
        elif ref_type == "netbox":
            # Phase 6 will replace this branch with real NetBox state lookup.
            log.warning(
                {
                    "event": "action_check_host_netbox_not_yet_supported",
                    "action_id": ctx.action_id,
                    "netbox_device_id": host_ref.get("netbox_device_id"),
                }
            )
            return
        else:
            log.warning(
                {
                    "event": "action_check_host_unknown_host_ref_type",
                    "action_id": ctx.action_id,
                    "host_ref_type": ref_type,
                }
            )
            return

        # Capture started_at BEFORE cert_check; completed_at AFTER. The
        # ordering is intentional and tested explicitly.
        started_at = utc_now_iso()
        timeouts = config.get("timeouts", {}) or {}
        result = check_fn(
            hostname,
            port,
            connect_timeout=float(timeouts.get("tcp_connect_seconds", 5)),
            handshake_timeout=float(timeouts.get("tls_handshake_seconds", 5)),
        )
        completed_at = utc_now_iso()

        check_payload = _build_check_payload(host_ref, result)
        report_id = str(uuid.uuid4())  # fresh; NOT the action_id
        submit_fn(
            client=client,
            data_dir=data_dir,
            report_id=report_id,
            report_type="on_demand",
            started_at=started_at,
            completed_at=completed_at,
            action_id=ctx.action_id,  # echo so dashboard marks action complete
            checks=[check_payload],
            clock=clock,
            shutdown_event=shutdown_event,
        )

    return handle


def make_sync_netbox_handler(
    *,
    netbox_client,  # NetBoxClient | None
    dashboard_client: DashboardClient,
    stats_state,  # StatsState
    clock: Clock,
    shutdown_event: threading.Event,
) -> ActionHandler:
    """Phase 6: real sync_netbox handler.

    When NetBox is configured (netbox_client is not None), runs a sync
    via run_netbox_sync, echoing the action's action_id so the dashboard
    marks the action complete. When NetBox is NOT configured, logs and
    skips — the action expires unfulfilled, which is the truthful outcome
    for an agent that can't fulfill it.

    Auth errors from the dashboard during submission propagate up via
    DashboardAuthError; the action worker pool's dispatcher catches and
    triggers global shutdown (existing 5d behavior).
    """
    # Local import to avoid a top-level circular dependency between
    # action_workers and netbox_sync.
    from certwatch.netbox_sync import run_netbox_sync

    def handle(ctx: ActionContext) -> None:
        if netbox_client is None:
            log.info(
                {
                    "event": "netbox_sync_action_received_but_not_configured",
                    "action_id": ctx.action_id,
                    "note": "set NETBOX_URL/NETBOX_TOKEN/NETBOX_FILTER to enable",
                }
            )
            return

        run_netbox_sync(
            netbox_client=netbox_client,
            dashboard_client=dashboard_client,
            action_id=ctx.action_id,
            stats_state=stats_state,
            clock=clock,
            shutdown_event=shutdown_event,
        )

    return handle


def make_sync_netbox_placeholder_handler() -> ActionHandler:
    """Deprecated alias for the not-configured sync_netbox handler.

    Kept for backward compatibility with Phase 5d tests; new code should
    call `make_sync_netbox_handler(netbox_client=None, ...)` directly,
    which produces the same log+skip behavior with the additional
    configurability of the rest of the parameters."""

    def handle(ctx: ActionContext) -> None:
        log.info(
            {
                "event": "netbox_sync_action_received_but_not_configured",
                "action_id": ctx.action_id,
                "note": "set NETBOX_URL/NETBOX_TOKEN/NETBOX_FILTER to enable",
            }
        )

    return handle


# ---- internal helpers ------------------------------------------------


def _resolve_manual_host(
    host_id: Optional[str], config: dict
) -> Optional[tuple[str, int]]:
    """Look up a manual host by host_id in the current config snapshot.
    Returns (hostname, port) or None if not found."""
    if not host_id:
        return None
    for host in config.get("manual_hosts", []) or []:
        if host.get("host_id") == host_id:
            return (
                host.get("hostname", ""),
                int(host.get("port", 443)),
            )
    return None


# _build_check_payload and _cert_dict_from_result moved to check_payload.py
# (Phase 5e refactor) so 5e's cycle thread shares the same builder.
