"""Local check loop — sweeps the configured hosts in parallel, logs results,
and supports graceful SIGTERM/SIGINT shutdown.

Graceful-shutdown contract: on signal, do NOT cancel cert checks already in
flight (they finish naturally). Do NOT start any new checks. Implementation:
each task checks the StopSignal at the moment a worker thread picks it up;
if set, the task short-circuits without calling cert_check. This avoids the
edge cases of Future.cancel() racing with worker thread scheduling.
"""

from __future__ import annotations

import dataclasses
import logging
import signal
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Optional

from certwatch.cert_check import CertResult, cert_check
from certwatch.config import AgentConfig, HostConfig

log = logging.getLogger("certwatch")


CheckFn = Callable[..., CertResult]


class StopSignal:
    """Thread-safe stop flag. `request_stop()` from any thread (including a
    signal handler); `wait()` from the loop thread."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def request_stop(self) -> None:
        self._event.set()

    def wait(self, timeout: float) -> bool:
        """Sleep up to `timeout` seconds; return True if stop was requested
        during the wait, False if the timeout elapsed normally."""
        return self._event.wait(timeout)

    @property
    def is_set(self) -> bool:
        return self._event.is_set()


def install_signal_handlers(stop: StopSignal) -> None:
    """Wire SIGTERM/SIGINT to set the stop flag. Must be called from the
    main thread (Python signal restriction)."""

    def handler(signum, _frame):
        log.info({"event": "shutdown_signal", "signal": int(signum)})
        stop.request_stop()

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, handler)


def run_cycle(
    config: AgentConfig,
    *,
    check_fn: CheckFn = cert_check,
    stop: Optional[StopSignal] = None,
) -> list[CertResult]:
    """One sweep across all hosts. Returns the completed CertResult list.
    Skipped hosts (because stop arrived before their worker started) are
    omitted from the return value but counted in the cycle_aborted log
    event."""
    started = time.monotonic()
    log.info({"event": "cycle_start", "host_count": len(config.hosts)})

    results: list[CertResult] = []
    skipped = 0

    def task(host: HostConfig) -> Optional[tuple[HostConfig, CertResult]]:
        if stop is not None and stop.is_set:
            return None
        try:
            r = check_fn(
                host.hostname,
                host.port,
                connect_timeout=config.tcp_connect_seconds,
                handshake_timeout=config.tls_handshake_seconds,
            )
        except Exception as e:
            log.error(
                {
                    "event": "cert_check_unhandled_error",
                    "hostname": host.hostname,
                    "port": host.port,
                    "error": repr(e),
                }
            )
            return None
        return host, r

    with ThreadPoolExecutor(max_workers=config.max_concurrency) as pool:
        futures = [pool.submit(task, host) for host in config.hosts]
        for fut in as_completed(futures):
            outcome = fut.result()
            if outcome is None:
                skipped += 1
                continue
            host, r = outcome
            results.append(r)
            log.info(_result_log_payload(r, host, include_sans=log.isEnabledFor(logging.DEBUG)))

    duration_s = round(time.monotonic() - started, 3)
    if skipped:
        log.info(
            {
                "event": "cycle_aborted",
                "skipped_hosts": skipped,
                "completed_hosts": len(results),
            }
        )
    counts = _summary_counts(results)
    log.info(
        {
            "event": "cycle_summary",
            "total": len(results),
            "success": counts["success"],
            "connection_failed": counts["connection_failed"],
            "tls_failed": counts["tls_failed"],
            "duration_seconds": duration_s,
        }
    )
    return results


def run_loop(
    config: AgentConfig,
    *,
    check_fn: CheckFn = cert_check,
    stop: Optional[StopSignal] = None,
) -> None:
    """Run cycles forever, separated by `sweep_interval_seconds`, until
    `stop` is set. Wakes immediately on stop rather than finishing the sleep."""
    if stop is None:
        stop = StopSignal()
    log.info(
        {
            "event": "loop_starting",
            "host_count": len(config.hosts),
            "sweep_interval_seconds": config.sweep_interval_seconds,
            "max_concurrency": config.max_concurrency,
        }
    )
    while not stop.is_set:
        run_cycle(config, check_fn=check_fn, stop=stop)
        if stop.is_set:
            break
        if stop.wait(config.sweep_interval_seconds):
            break
    log.info({"event": "loop_stopped"})


def _result_log_payload(
    r: CertResult, host: HostConfig, *, include_sans: bool
) -> dict:
    """Build the cert_check_result log payload.

    `subject_san_count` is always present. The full `subject_sans` array is
    only emitted when `include_sans=True` — call sites pass
    `log.isEnabledFor(logging.DEBUG)` so DEBUG runs see the array but INFO
    runs don't pay the stdout-flooding tax for cert SAN lists with hundreds
    of entries (e.g. google.com)."""
    payload: dict = {
        "event": "cert_check_result",
        "display_name": host.display_name or host.hostname,
        "tags": list(host.tags),
    }
    payload.update(dataclasses.asdict(r))
    sans = payload.get("subject_sans") or []
    payload["subject_san_count"] = len(sans)
    if not include_sans:
        payload.pop("subject_sans", None)
    return payload


def _summary_counts(results: list[CertResult]) -> dict[str, int]:
    counts = {"success": 0, "connection_failed": 0, "tls_failed": 0}
    for r in results:
        if r.state in counts:
            counts[r.state] += 1
    return counts
