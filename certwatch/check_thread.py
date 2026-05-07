"""Phase 5e — cert check thread.

Wraps cycle cadence + parallel checks + report submission + StatsState
update into a single threaded loop.

  - First cycle runs immediately on .start() with report_type="startup".
  - Subsequent cycles wait `intervals.check_seconds` AFTER each previous
    cycle completes (no-catch-up). The interval is read from the current
    config snapshot each iteration, so config refresh changes the cadence
    on the next cycle.
  - Each cycle reads manual_hosts from the current config, runs all hosts
    in parallel (capped at config.concurrency.max_parallel_checks), submits
    a single batched /reports request via Phase 5b's at-least-once
    delivery, and records the cycle's outcome to StatsState for the next
    heartbeat to pick up.
  - DashboardAuthError during submission triggers global shutdown via
    shutdown_event (same escalation pattern as 5d's action workers); other
    cycle exceptions are logged and the next cycle proceeds.

Phase 9c cutover: per-source dispatch in the cert-check pipeline.
Manual hosts call the original `cert_check` (the operator typed an
FQDN with intent — verify against THAT name). NetBox hosts call
`cert_check_with_discovery`, which connects by IP and discovers the
cert-presented hostname (see cert_check_with_discovery's module
docstring for the why).
"""

from __future__ import annotations

import logging
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, Union

from certwatch.cert_check import CertResult, cert_check as default_cert_check
from certwatch.cert_check_with_discovery import (
    CertCheckResult,
    cert_check_with_discovery as default_discovery_check,
)
from certwatch.check_payload import (
    build_check_payload,
    build_check_payload_from_discovery,
)
from certwatch.clock import Clock, utc_now_iso
from certwatch.dashboard_client import DashboardAuthError, DashboardClient
from certwatch.heartbeat_thread import ConfigState, StatsState
from certwatch.netbox_client import DiscoveredHost
from certwatch.netbox_sync import NetBoxHostsState
from certwatch.report_submission import (
    submit_report_with_retry as default_submit,
)

log = logging.getLogger("certwatch")


@dataclass
class CycleResult:
    started_at: str  # wire format ISO 8601 UTC
    completed_at: str
    checks: list[dict] = field(default_factory=list)
    duration_seconds: float = 0.0
    submission_status: str = ""  # from ReportSubmissionResult


class CertCheckThread(threading.Thread):
    """Cycle loop. Started by the runner (5f); pulls hosts from
    ConfigState, checks them in parallel, submits the batched report,
    updates StatsState.
    """

    # Maximum time the cycle thread will wait for the first NetBox sync
    # to complete before running its first cycle. Bounds the worst-case
    # startup gap when NetBox is misconfigured/unreachable: after this
    # wait, the cycle proceeds without netbox hosts (manual hosts still
    # get checked).
    _FIRST_NETBOX_SYNC_WAIT_SECONDS = 30.0

    def __init__(
        self,
        *,
        client: DashboardClient,
        data_dir: str | Path,
        config_state: ConfigState,
        stats_state: StatsState,
        shutdown_event: threading.Event,
        clock: Clock,
        check_fn: Callable = default_cert_check,
        discovery_check_fn: Callable = default_discovery_check,
        submit_fn: Callable = default_submit,
        netbox_hosts_state: Optional[NetBoxHostsState] = None,
        auth_error_event: Optional[threading.Event] = None,
        first_netbox_sync_done_event: Optional[threading.Event] = None,
        name: str = "certwatch-check-thread",
    ) -> None:
        super().__init__(name=name, daemon=False)
        self._client = client
        self._data_dir = data_dir
        self._config_state = config_state
        self._stats_state = stats_state
        self._netbox_hosts_state = netbox_hosts_state
        self._shutdown_event = shutdown_event
        # Optional companion event for the runner to distinguish auth-driven
        # shutdown (exit 2) from signal-driven shutdown (exit 0).
        self._auth_error_event = auth_error_event
        # Set by NetBoxSyncThread after its first sync attempt (success
        # or failure). When None or already set, the thread skips the
        # gate and runs its first cycle immediately. Runner pre-sets it
        # when NetBox isn't configured.
        self._first_netbox_sync_done_event = first_netbox_sync_done_event
        self._clock = clock
        self._check_fn = check_fn
        self._discovery_check_fn = discovery_check_fn
        self._submit_fn = submit_fn

    def run(self) -> None:
        log.info({"event": "check_thread_starting"})

        # Gate the first cycle on NetBox sync. Without this, the startup
        # cycle reports netbox_hosts_count=0 because NetBoxSyncThread
        # hasn't populated state yet — operators see "Last check: never"
        # on every NetBox host until the next scheduled cycle (potentially
        # an hour later).
        self._wait_for_first_netbox_sync()

        is_first_cycle = True

        try:
            while not self._shutdown_event.is_set():
                report_type = "startup" if is_first_cycle else "scheduled"

                try:
                    # Snapshot netbox hosts ONCE per cycle. Subsequent
                    # NetBox syncs that complete during a long cycle
                    # don't change what this cycle is checking — same
                    # "stable view per cycle" pattern as ConfigState.
                    netbox_hosts = (
                        self._netbox_hosts_state.snapshot()
                        if self._netbox_hosts_state is not None
                        else []
                    )
                    cycle_result = _run_one_cycle(
                        client=self._client,
                        data_dir=self._data_dir,
                        config=self._config_state.snapshot(),
                        netbox_hosts=netbox_hosts,
                        report_type=report_type,
                        clock=self._clock,
                        shutdown_event=self._shutdown_event,
                        check_fn=self._check_fn,
                        discovery_check_fn=self._discovery_check_fn,
                        submit_fn=self._submit_fn,
                    )
                    # Stats update + is_first_cycle flip are part of the
                    # cycle pipeline — fold them inside the try so an
                    # exception here is logged as a cycle-level error
                    # (continue) not a thread-level catastrophe (exit).
                    self._stats_state.record_check_cycle(
                        hosts_monitored=len(cycle_result.checks),
                        completed_at=cycle_result.completed_at,
                        duration_seconds=int(cycle_result.duration_seconds),
                        succeeded=sum(
                            1 for c in cycle_result.checks
                            if c["status"] == "success"
                        ),
                        failed=sum(
                            1 for c in cycle_result.checks
                            if c["status"] != "success"
                        ),
                    )
                    # Per the answer to Question 3: flip is_first_cycle=False
                    # only when the cycle's data has been or will not be
                    # delivered (delivered/duplicate/rejected). On shutdown,
                    # the next start is still semantically a startup since
                    # the dashboard never saw this attempt.
                    if cycle_result.submission_status != "shutdown":
                        is_first_cycle = False
                except DashboardAuthError as e:
                    # Auth error during submission — stop the world.
                    # Don't update stats (we never got to that point).
                    log.error(
                        {
                            "event": "check_cycle_auth_error_shutting_down",
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
                    # Catch-all so one cycle's exception doesn't kill the
                    # thread. The next cycle gets a fresh chance.
                    log.error(
                        {
                            "event": "check_cycle_unexpected_error",
                            "error_class": type(e).__name__,
                            "error_message": str(e),
                        }
                    )

                # Wait until next cycle, or break early on shutdown.
                interval = self._check_interval()
                if self._clock.wait_for(interval, self._shutdown_event):
                    break
        except Exception as e:
            # Truly unexpected — catch-all to set shutdown so the rest of
            # the runner brings everything down rather than running headless.
            log.error(
                {
                    "event": "check_thread_unhandled_exception",
                    "error_class": type(e).__name__,
                    "error_message": str(e),
                }
            )
            self._shutdown_event.set()
        finally:
            log.info({"event": "check_thread_exiting"})

    def _check_interval(self) -> float:
        config = self._config_state.snapshot()
        return float(config["intervals"]["check_seconds"])

    def _wait_for_first_netbox_sync(self) -> None:
        """Block until the first NetBox sync completes (or the bounded
        wait elapses, or shutdown is signaled). No-op when the event
        wasn't wired in (NetBox not configured) or has already fired.

        Runner pre-sets the event for NetBox-disabled deployments so
        manual-only setups don't pay the startup cost."""
        ev = self._first_netbox_sync_done_event
        if ev is None or ev.is_set():
            return

        log.info({"event": "check_thread_waiting_for_first_netbox_sync"})
        # Bound the wait so a misconfigured/down NetBox doesn't block
        # cert checks indefinitely. Manual hosts will still be checked
        # if we time out.
        ev.wait(timeout=self._FIRST_NETBOX_SYNC_WAIT_SECONDS)
        if ev.is_set():
            log.info({"event": "check_thread_first_netbox_sync_done_proceeding"})
        else:
            log.warning(
                {
                    "event": "check_thread_first_netbox_sync_timeout_proceeding",
                    "wait_seconds": self._FIRST_NETBOX_SYNC_WAIT_SECONDS,
                    "note": (
                        "first NetBox sync did not complete within the "
                        "startup window; first cycle runs without NetBox "
                        "hosts. Subsequent cycles pick them up once sync "
                        "succeeds."
                    ),
                }
            )


def _run_one_cycle(
    *,
    client: DashboardClient,
    data_dir: str | Path,
    config: dict,
    report_type: str,
    clock: Clock,
    shutdown_event: threading.Event,
    netbox_hosts: Optional[list[DiscoveredHost]] = None,
    check_fn: Callable = default_cert_check,
    discovery_check_fn: Callable = default_discovery_check,
    submit_fn: Callable = default_submit,
) -> CycleResult:
    """One cycle: merge manual + netbox hosts → run checks in parallel
    → build payloads → submit batched /reports.

    Cutover (Phase 9c): manual hosts and netbox hosts go through
    different cert-check functions. Manual hosts use the original
    `cert_check` (verify against the FQDN the operator typed). NetBox
    hosts use `cert_check_with_discovery` (connect by IP, learn the
    cert-presented hostname, verify against THAT). The host_ref in
    the report distinguishes the source for the dashboard.

    Empty hosts (manual_hosts=[] AND netbox_hosts=[]) is a legitimate
    state. A report still goes out with checks=[]; the dashboard
    records the cycle happened.

    Auth errors during submission propagate to the caller so the
    thread's escalation path can trigger global shutdown.
    """
    cycle_start_monotonic = clock.now()
    started_at = utc_now_iso()

    manual_hosts = list(config.get("manual_hosts", []) or [])
    netbox_hosts = list(netbox_hosts or [])

    # Build a unified to-check list. Manual hosts come first (preserving
    # config order), netbox hosts second. Each entry carries `source`
    # so _run_parallel_checks dispatches the right cert-check function
    # and the payload-builder dispatch picks the right serializer.
    to_check: list[dict] = []
    for h in manual_hosts:
        host_id = h.get("host_id")
        to_check.append({
            "identity_key": f"manual:{host_id}",
            "host_ref": {"type": "manual", "host_id": host_id},
            "source": "manual",
            "connect_target": h.get("hostname", ""),
            "port": int(h.get("port", 443)),
        })
    for nh in netbox_hosts:
        # Connect by IP when NetBox knows it; fall back to hostname
        # (device.name FQDN) only when ip_address is missing — the
        # cert_check_with_discovery function accepts either string,
        # but IP-first matches Phase 9's design (the cert tells us
        # the truth about the hostname, not the operator-supplied
        # name).
        connect_target = nh.ip_address or nh.hostname
        to_check.append({
            "identity_key": f"netbox:{nh.netbox_device_id}",
            "host_ref": {
                "type": "netbox",
                "netbox_device_id": nh.netbox_device_id,
            },
            "source": "netbox",
            "connect_target": connect_target,
            "port": nh.port,
        })

    log.info(
        {
            "event": "check_cycle_starting",
            "report_type": report_type,
            "manual_hosts_count": len(manual_hosts),
            "netbox_hosts_count": len(netbox_hosts),
            "total_hosts_count": len(to_check),
        }
    )

    # max(alert_thresholds_days) so the cert_expiring_soon status fires
    # at the most permissive threshold; finer-grained thresholding is
    # done downstream by the dashboard.
    alert_thresholds = config.get("alert_thresholds_days", [30]) or [30]
    expiring_soon_threshold = max(int(t) for t in alert_thresholds)

    if to_check:
        results_by_key = _run_parallel_checks(
            hosts=to_check,
            check_fn=check_fn,
            discovery_check_fn=discovery_check_fn,
            tcp_connect_seconds=float(
                config.get("timeouts", {}).get("tcp_connect_seconds", 5)
            ),
            tls_handshake_seconds=float(
                config.get("timeouts", {}).get("tls_handshake_seconds", 5)
            ),
            expiring_soon_threshold_days=expiring_soon_threshold,
            max_concurrency=int(
                config.get("concurrency", {}).get("max_parallel_checks", 20)
            ),
            shutdown_event=shutdown_event,
        )
        # Preserve original input order (manual first, then netbox).
        checks: list[dict] = []
        for entry in to_check:
            key = entry["identity_key"]
            if key not in results_by_key:
                # Skipped due to shutdown signaled before this host's
                # worker started. Don't include in the report.
                continue
            checks.append(_build_payload_for_entry(entry, results_by_key[key]))
    else:
        checks = []

    completed_at = utc_now_iso()
    duration_seconds = clock.now() - cycle_start_monotonic

    summary_counts = {"success": 0, "connection_failed": 0, "tls_failed": 0}
    for c in checks:
        s = c.get("status")
        if s in summary_counts:
            summary_counts[s] += 1

    log.info(
        {
            "event": "check_cycle_summary",
            "report_type": report_type,
            "manual_hosts_count": len(manual_hosts),
            "netbox_hosts_count": len(netbox_hosts),
            "total_hosts_count": len(to_check),
            "checks_completed": len(checks),
            "checks_skipped": len(to_check) - len(checks),
            "duration_seconds": round(duration_seconds, 3),
            **summary_counts,
        }
    )

    # Submit the report. submit_report_with_retry persists to disk
    # BEFORE the network call, so even mid-cycle shutdown leaves the
    # data on disk for the next start's replay.
    report_id = str(uuid.uuid4())
    submission_result = submit_fn(
        client=client,
        data_dir=data_dir,
        report_id=report_id,
        report_type=report_type,
        started_at=started_at,
        completed_at=completed_at,
        action_id=None,  # scheduled / startup — not in response to an action
        checks=checks,
        clock=clock,
        shutdown_event=shutdown_event,
    )

    return CycleResult(
        started_at=started_at,
        completed_at=completed_at,
        checks=checks,
        duration_seconds=duration_seconds,
        submission_status=submission_result.status,
    )


def _build_payload_for_entry(
    entry: dict, result: Union[CertResult, CertCheckResult],
) -> dict:
    """Per-source payload-builder dispatch. Manual entries always
    produce a CertResult (old check_fn) → old builder. NetBox entries
    always produce a CertCheckResult (new discovery_check_fn) → new
    compat-envelope builder."""
    if entry["source"] == "netbox":
        return build_check_payload_from_discovery(
            host_ref=entry["host_ref"], result=result,
        )
    return build_check_payload(
        host_ref=entry["host_ref"], result=result,
    )


def _run_parallel_checks(
    *,
    hosts: list[dict],
    check_fn: Callable,
    discovery_check_fn: Callable,
    tcp_connect_seconds: float,
    tls_handshake_seconds: float,
    expiring_soon_threshold_days: int,
    max_concurrency: int,
    shutdown_event: threading.Event,
) -> dict[str, Union[CertResult, CertCheckResult]]:
    """Run a cert-check function (per-entry dispatched on `source`)
    in parallel across `hosts`. Returns a {identity_key: result} dict,
    omitting hosts skipped due to shutdown.

    Each entry in `hosts` is a dict with:
      - identity_key: unique key per host across both sources (e.g.
        "manual:<uuid>" or "netbox:<int>"). Used as the result-dict key
        so the caller can match back to the input entry regardless of
        host source.
      - host_ref: the report's host_ref dict (used here only for log
        context on errors).
      - source: "manual" or "netbox" — selects which check function
        to invoke.
      - connect_target: the string passed to the chosen check function
        as its first positional arg. For manual hosts this is the
        operator-supplied FQDN (cert_check verifies against it). For
        netbox hosts this is ip_address (or hostname fallback) — the
        cert-discovery function learns the canonical hostname from
        the cert itself.
      - port: TCP port.

    Mirrors Phase 3's run_cycle skip-at-pickup pattern: a worker
    short-circuits without calling the check if shutdown is set when
    the worker picks up the task. In-flight checks run to completion
    (no interruption mid-handshake).
    """
    results: dict[str, Union[CertResult, CertCheckResult]] = {}

    def task(entry: dict):
        identity_key = entry["identity_key"]
        if shutdown_event.is_set():
            return None
        target = entry.get("connect_target", "")
        port = int(entry.get("port", 443))
        try:
            if entry["source"] == "netbox":
                result = discovery_check_fn(
                    target, port,
                    connect_timeout=tcp_connect_seconds,
                    handshake_timeout=tls_handshake_seconds,
                    expiring_soon_threshold_days=expiring_soon_threshold_days,
                )
            else:
                result = check_fn(
                    target, port,
                    connect_timeout=tcp_connect_seconds,
                    handshake_timeout=tls_handshake_seconds,
                )
        except Exception as e:
            log.error(
                {
                    "event": "cert_check_unhandled_error",
                    "host_ref": entry.get("host_ref"),
                    "source": entry.get("source"),
                    "connect_target": target,
                    "error_class": type(e).__name__,
                    "error_message": str(e),
                }
            )
            return None
        return identity_key, result

    with ThreadPoolExecutor(max_workers=max_concurrency) as pool:
        futures = [pool.submit(task, h) for h in hosts]
        for fut in as_completed(futures):
            outcome = fut.result()
            if outcome is None:
                continue
            identity_key, result = outcome
            results[identity_key] = result

    return results
