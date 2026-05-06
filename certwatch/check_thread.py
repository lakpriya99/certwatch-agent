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

NetBox-discovered hosts are NOT handled here — Phase 6 will extend the
host list construction to merge manual_hosts + netbox_hosts.
"""

from __future__ import annotations

import logging
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from certwatch.cert_check import CertResult, cert_check as default_cert_check
from certwatch.check_payload import build_check_payload
from certwatch.clock import Clock, utc_now_iso
from certwatch.dashboard_client import DashboardAuthError, DashboardClient
from certwatch.heartbeat_thread import ConfigState, StatsState
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
        submit_fn: Callable = default_submit,
        auth_error_event: Optional[threading.Event] = None,
        name: str = "certwatch-check-thread",
    ) -> None:
        super().__init__(name=name, daemon=False)
        self._client = client
        self._data_dir = data_dir
        self._config_state = config_state
        self._stats_state = stats_state
        self._shutdown_event = shutdown_event
        # Optional companion event for the runner to distinguish auth-driven
        # shutdown (exit 2) from signal-driven shutdown (exit 0).
        self._auth_error_event = auth_error_event
        self._clock = clock
        self._check_fn = check_fn
        self._submit_fn = submit_fn

    def run(self) -> None:
        log.info({"event": "check_thread_starting"})
        is_first_cycle = True

        try:
            while not self._shutdown_event.is_set():
                report_type = "startup" if is_first_cycle else "scheduled"

                try:
                    cycle_result = _run_one_cycle(
                        client=self._client,
                        data_dir=self._data_dir,
                        config=self._config_state.snapshot(),
                        report_type=report_type,
                        clock=self._clock,
                        shutdown_event=self._shutdown_event,
                        check_fn=self._check_fn,
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


def _run_one_cycle(
    *,
    client: DashboardClient,
    data_dir: str | Path,
    config: dict,
    report_type: str,
    clock: Clock,
    shutdown_event: threading.Event,
    check_fn: Callable = default_cert_check,
    submit_fn: Callable = default_submit,
) -> CycleResult:
    """One cycle: build host list → run checks in parallel → build
    payloads → submit batched /reports.

    Empty manual_hosts is a legitimate state (agent has no hosts assigned).
    A report still goes out with checks=[]; the dashboard records the
    cycle happened.

    Auth errors during submission propagate to the caller so the thread's
    escalation path can trigger global shutdown.
    """
    cycle_start_monotonic = clock.now()
    started_at = utc_now_iso()

    manual_hosts = list(config.get("manual_hosts", []) or [])

    log.info(
        {
            "event": "check_cycle_starting",
            "report_type": report_type,
            "manual_hosts_count": len(manual_hosts),
        }
    )

    if manual_hosts:
        results_by_id = _run_parallel_checks(
            hosts=manual_hosts,
            check_fn=check_fn,
            tcp_connect_seconds=float(
                config.get("timeouts", {}).get("tcp_connect_seconds", 5)
            ),
            tls_handshake_seconds=float(
                config.get("timeouts", {}).get("tls_handshake_seconds", 5)
            ),
            max_concurrency=int(
                config.get("concurrency", {}).get("max_parallel_checks", 20)
            ),
            shutdown_event=shutdown_event,
        )
        # Preserve original host order — the iteration of manual_hosts
        # is the canonical order regardless of completion timing.
        checks: list[dict] = []
        for host in manual_hosts:
            host_id = host.get("host_id")
            if host_id not in results_by_id:
                # Skipped due to shutdown signaled before this host's
                # worker started. Don't include in the report.
                continue
            checks.append(
                build_check_payload(
                    host_ref={"type": "manual", "host_id": host_id},
                    result=results_by_id[host_id],
                )
            )
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
            "checks_completed": len(checks),
            "checks_skipped": len(manual_hosts) - len(checks),
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


def _run_parallel_checks(
    *,
    hosts: list[dict],
    check_fn: Callable,
    tcp_connect_seconds: float,
    tls_handshake_seconds: float,
    max_concurrency: int,
    shutdown_event: threading.Event,
) -> dict[str, CertResult]:
    """Run cert_check in parallel across `hosts`. Returns a {host_id:
    CertResult} dict, omitting hosts skipped due to shutdown.

    Mirrors Phase 3's run_cycle skip-at-pickup pattern: a worker
    short-circuits without calling cert_check if shutdown is set when
    the worker picks up the task. In-flight cert_check calls run to
    completion (no interruption mid-handshake).
    """
    results: dict[str, CertResult] = {}

    def task(host: dict) -> Optional[tuple[str, CertResult]]:
        host_id = host.get("host_id")
        if shutdown_event.is_set():
            return None
        try:
            result = check_fn(
                host.get("hostname", ""),
                int(host.get("port", 443)),
                connect_timeout=tcp_connect_seconds,
                handshake_timeout=tls_handshake_seconds,
            )
        except Exception as e:
            log.error(
                {
                    "event": "cert_check_unhandled_error",
                    "host_id": host_id,
                    "hostname": host.get("hostname"),
                    "error_class": type(e).__name__,
                    "error_message": str(e),
                }
            )
            return None
        return host_id, result

    with ThreadPoolExecutor(max_workers=max_concurrency) as pool:
        futures = [pool.submit(task, h) for h in hosts]
        for fut in as_completed(futures):
            outcome = fut.result()
            if outcome is None:
                continue
            host_id, result = outcome
            if host_id is not None:
                results[host_id] = result

    return results
