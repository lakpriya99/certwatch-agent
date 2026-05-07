"""Phase 6 — NetBox sync orchestration + scheduled-sync thread.

`run_netbox_sync` is the orchestration primitive used by both:
  - the action handler (5d's sync_netbox handler, replacement)
  - the scheduled NetBoxSyncThread (this module)

Safety contract — owned at this layer: if NetBox sync fails (raises
NetBoxSyncError), do NOT call submit_discovered_hosts. The dashboard's
last known state is preserved. An empty hosts list from a SUCCESSFUL
NetBox sync ("filter matches nothing") IS submitted — that's a
legitimate state distinct from "NetBox unreachable".
"""

from __future__ import annotations

import dataclasses
import logging
import threading
from dataclasses import dataclass, field
from typing import Optional, Sequence

from certwatch.clock import Clock, RealClock, utc_now_iso
from certwatch.dashboard_client import (
    DashboardAuthError,
    DashboardClient,
    DashboardError,
    DashboardPayloadTooLargeError,
    DashboardRetriableError,
    DashboardValidationError,
)
from certwatch.heartbeat_thread import ConfigState, StatsState
from certwatch.netbox_client import (
    DiscoveredHost,
    NetBoxClient,
    NetBoxSyncError,
)


class NetBoxHostsState:
    """Thread-safe holder for the agent's local view of NetBox-discovered
    hosts.

    Written by NetBoxSyncThread after every SUCCESSFUL NetBox fetch
    (regardless of whether the subsequent /discovered-hosts submission
    to the dashboard succeeds — the agent's cert-check loop should
    always see the freshest set NetBox returned, even when the
    dashboard temporarily can't be told about it).

    Read by:
      - CertCheckThread (every cycle, to merge with manual_hosts)
      - the check_host action handler (on-demand, to resolve a netbox
        host_ref's netbox_device_id to (hostname, port))

    snapshot() returns a fresh list copy — different from ConfigState's
    return-by-reference. Callers iterate this list while holding no
    lock; defensive copy prevents a concurrent replace() from
    invalidating iteration.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hosts: list[DiscoveredHost] = []

    def replace(self, hosts: Sequence[DiscoveredHost]) -> None:
        with self._lock:
            self._hosts = list(hosts)

    def snapshot(self) -> list[DiscoveredHost]:
        with self._lock:
            return list(self._hosts)

log = logging.getLogger("certwatch")


# Backoff for retriable submission failures during NetBox sync. Same
# values as bootstrap/report_submission; pinned independently so v2
# can let them drift without coupling.
BACKOFF_SCHEDULE = (5.0, 15.0, 30.0, 60.0, 120.0)


@dataclass
class NetBoxSyncResult:
    status: str  # "success" | "netbox_error" | "submission_error" | "shutdown"
    hosts_count: int = 0
    submission_summary: Optional[dict] = None


def run_netbox_sync(
    *,
    netbox_client: NetBoxClient,
    dashboard_client: DashboardClient,
    action_id: Optional[str],
    stats_state: StatsState,
    clock: Optional[Clock] = None,
    shutdown_event: Optional[threading.Event] = None,
    netbox_hosts_state: Optional[NetBoxHostsState] = None,
) -> NetBoxSyncResult:
    """Run one sync: fetch from NetBox → update agent-local state →
    submit to dashboard.

    Local-state update happens IMMEDIATELY after a successful fetch and
    BEFORE the dashboard submission. The cycle thread reads the state
    on its own cadence, so even if the /discovered-hosts submission
    fails (or shutdown signals mid-retry), the agent still cert-checks
    whatever NetBox most-recently reported. The dashboard's view may
    lag temporarily; it converges on the next successful submission.

    Auth errors during submission are RE-RAISED — the caller (action
    pool dispatcher or NetBoxSyncThread) is responsible for triggering
    global shutdown. All other failures are returned as a
    NetBoxSyncResult status string."""
    if clock is None:
        clock = RealClock()

    synced_at = utc_now_iso()

    try:
        hosts = netbox_client.fetch_hosts()
    except NetBoxSyncError as e:
        # Safety contract: NetBox failure → do NOT call /discovered-hosts.
        # Local state stays at last-known (no replace call), so cycle
        # thread continues cert-checking the previous host set rather
        # than silently going dark on every NetBox blip.
        log.error(
            {
                "event": "netbox_sync_netbox_error_preserving_state",
                "error_class": type(e.original_error).__name__ if e.original_error else "NetBoxSyncError",
                "error_message": e.message,
            }
        )
        return NetBoxSyncResult(status="netbox_error", hosts_count=0)

    # Update local state on EVERY successful fetch — even if the
    # subsequent submission to the dashboard fails. The cycle thread
    # cares about cert-checking the freshest set; the dashboard's
    # discovered-hosts table is a separate concern that converges
    # later.
    if netbox_hosts_state is not None:
        netbox_hosts_state.replace(hosts)

    payload_hosts = [_host_to_payload(h) for h in hosts]

    return _submit_with_retry(
        dashboard_client=dashboard_client,
        action_id=action_id,
        synced_at=synced_at,
        netbox_client=netbox_client,
        hosts=payload_hosts,
        stats_state=stats_state,
        clock=clock,
        shutdown_event=shutdown_event,
    )


def _submit_with_retry(
    *,
    dashboard_client: DashboardClient,
    action_id: Optional[str],
    synced_at: str,
    netbox_client: NetBoxClient,
    hosts: list[dict],
    stats_state: StatsState,
    clock: Clock,
    shutdown_event: Optional[threading.Event],
) -> NetBoxSyncResult:
    attempts = 0
    while True:
        if shutdown_event is not None and shutdown_event.is_set():
            return NetBoxSyncResult(status="shutdown", hosts_count=len(hosts))

        attempts += 1
        try:
            response = dashboard_client.submit_discovered_hosts(
                action_id=action_id,
                synced_at=synced_at,
                netbox_url=netbox_client.url,
                netbox_filter=netbox_client.filter_expr,
                hosts=hosts,
            )
        except DashboardAuthError:
            # Re-raise — runner / action dispatcher signals global shutdown.
            raise
        except DashboardValidationError as e:
            log.error(
                {
                    "event": "netbox_sync_submission_validation_failed",
                    "error_code": e.code,
                    "error_message": e.message,
                    "request_id": e.request_id,
                    "hosts_count": len(hosts),
                }
            )
            return NetBoxSyncResult(
                status="submission_error", hosts_count=len(hosts)
            )
        except DashboardPayloadTooLargeError as e:
            log.error(
                {
                    "event": "netbox_sync_submission_too_large",
                    "error_code": e.code,
                    "error_message": e.message,
                    "hosts_count": len(hosts),
                    "note": "operator should refine NETBOX_FILTER",
                }
            )
            return NetBoxSyncResult(
                status="submission_error", hosts_count=len(hosts)
            )
        except DashboardRetriableError as e:
            delay = _backoff_delay(attempts)
            log.warning(
                {
                    "event": "netbox_sync_submission_retry",
                    "attempts": attempts,
                    "delay_seconds": delay,
                    "error_class": type(e).__name__,
                    "error_code": e.code,
                    "error_message": e.message,
                }
            )
            if shutdown_event is not None:
                if clock.wait_for(delay, shutdown_event):
                    return NetBoxSyncResult(
                        status="shutdown", hosts_count=len(hosts)
                    )
            else:
                clock.sleep(delay)
            continue
        except DashboardError as e:
            # Other DashboardError (NotFound, etc.) — fatal for THIS sync,
            # not for the agent.
            log.error(
                {
                    "event": "netbox_sync_submission_unexpected_error",
                    "error_class": type(e).__name__,
                    "error_code": e.code,
                    "error_message": e.message,
                    "status_code": e.status_code,
                }
            )
            return NetBoxSyncResult(
                status="submission_error", hosts_count=len(hosts)
            )

        # Success
        summary = response.get("summary") or {}
        log.info(
            {
                "event": "netbox_sync_complete",
                "synced_at": synced_at,
                "hosts_count": len(hosts),
                "attempts": attempts,
                "summary": summary,
            }
        )
        stats_state.record_netbox_sync(completed_at=synced_at)
        return NetBoxSyncResult(
            status="success",
            hosts_count=len(hosts),
            submission_summary=response,
        )


def _backoff_delay(attempts: int) -> float:
    idx = max(0, min(attempts - 1, len(BACKOFF_SCHEDULE) - 1))
    return BACKOFF_SCHEDULE[idx]


def _host_to_payload(host: DiscoveredHost) -> dict:
    """Map DiscoveredHost → /discovered-hosts payload entry. Optional
    fields (display_name, tags) are OMITTED when their natural empty
    value applies — matches Phase 4e's contract for optional fields
    that mean "use dashboard default" when absent. Tags=[] IS included
    as an empty list since the contract allows that distinction."""
    out: dict = {
        "netbox_device_id": host.netbox_device_id,
        "hostname": host.hostname,
        "port": host.port,
    }
    if host.display_name is not None:
        out["display_name"] = host.display_name
    # tags=[] is meaningful per the 4e contract (operator removed all tags
    # vs operator never set any). Always include — keeps the wire shape
    # consistent and the dashboard can treat both equivalently if it
    # chooses.
    out["tags"] = list(host.tags)
    return out


# ---- NetBoxSyncThread -------------------------------------------------


class NetBoxSyncThread(threading.Thread):
    """Scheduled background sync. First sync runs immediately on
    .start() (same first-cycle-immediate pattern as CertCheckThread);
    subsequent syncs wait `intervals.netbox_sync_seconds` AFTER each
    completes. The interval is read from the current config snapshot
    each iteration so dashboard-driven changes take effect on the next
    cycle.

    Auth errors trigger global shutdown via auth_error_event. NetBox
    errors don't stop the thread — the next sync attempts again on the
    normal cadence.
    """

    def __init__(
        self,
        *,
        netbox_client: NetBoxClient,
        dashboard_client: DashboardClient,
        config_state: ConfigState,
        stats_state: StatsState,
        shutdown_event: threading.Event,
        clock: Clock,
        netbox_hosts_state: Optional[NetBoxHostsState] = None,
        auth_error_event: Optional[threading.Event] = None,
        name: str = "certwatch-netbox-sync",
    ) -> None:
        super().__init__(name=name, daemon=False)
        self._netbox_client = netbox_client
        self._dashboard_client = dashboard_client
        self._config_state = config_state
        self._stats_state = stats_state
        self._netbox_hosts_state = netbox_hosts_state
        self._shutdown_event = shutdown_event
        self._auth_error_event = auth_error_event
        self._clock = clock

    def run(self) -> None:
        log.info({"event": "netbox_sync_thread_starting"})
        try:
            while not self._shutdown_event.is_set():
                try:
                    run_netbox_sync(
                        netbox_client=self._netbox_client,
                        dashboard_client=self._dashboard_client,
                        action_id=None,  # scheduled sync
                        stats_state=self._stats_state,
                        clock=self._clock,
                        shutdown_event=self._shutdown_event,
                        netbox_hosts_state=self._netbox_hosts_state,
                    )
                except DashboardAuthError as e:
                    log.error(
                        {
                            "event": "netbox_sync_auth_error_shutting_down",
                            "error_code": e.code,
                            "error_message": e.message,
                            "request_id": e.request_id,
                        }
                    )
                    if self._auth_error_event is not None:
                        self._auth_error_event.set()
                    self._shutdown_event.set()
                    break
                except Exception as e:
                    # Catch-all: NetBox query errors are returned as
                    # status="netbox_error" already (not raised); this
                    # path is for truly unexpected exceptions.
                    log.error(
                        {
                            "event": "netbox_sync_thread_unexpected_error",
                            "error_class": type(e).__name__,
                            "error_message": str(e),
                        }
                    )

                interval = self._sync_interval()
                if self._clock.wait_for(interval, self._shutdown_event):
                    break
        except Exception as e:
            log.error(
                {
                    "event": "netbox_sync_thread_unhandled_exception",
                    "error_class": type(e).__name__,
                    "error_message": str(e),
                }
            )
            self._shutdown_event.set()
        finally:
            log.info({"event": "netbox_sync_thread_exiting"})

    def _sync_interval(self) -> float:
        config = self._config_state.snapshot()
        return float(config["intervals"]["netbox_sync_seconds"])
