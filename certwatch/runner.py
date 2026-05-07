"""Phase 5f — agent runner integration.

Glues bootstrap (5a), pending-report replay (5b), heartbeat thread (5c),
action worker pool (5d), and cert check thread (5e) into a single
running service.

Lifecycle:
  1. Bootstrap — load or register credentials, fetch initial config.
     BootstrapError → exit 1; revoked-during-bootstrap → exit 2.
  2. Replay pending reports — synchronously, BEFORE any thread starts,
     so old reports land before new cycles begin.
     Auth error here → exit 2; other failures → log and continue.
  3. Construct shared state: ConfigState, StatsState, action_queue,
     shutdown_event, auth_error_event.
  4. Start three threads: HeartbeatThread, ActionWorkerPool, CertCheckThread.
  5. Install SIGTERM/SIGINT handlers (main-thread only; tests skip).
  6. Wait on shutdown_event.
  7. Join everything with bounded timeouts. Exit code:
       - 0: clean shutdown via signal
       - 2: any thread observed an auth error (revocation)
       - 1 / 3: not reachable from this layer (bootstrap layer handles)

Exit codes:
  0  Clean shutdown (SIGTERM/SIGINT)
  1  Bootstrap failure (config error, code bug)
  2  Auth-driven shutdown (registration rejected, secret revoked, etc.)
  3  Reserved (unexpected fatal in run() itself)
"""

from __future__ import annotations

import logging
import queue
import signal
import threading
from pathlib import Path
from typing import Mapping, Optional

from certwatch._version import __version__
from certwatch.action_workers import (
    ActionWorkerPool,
    make_check_host_handler,
    make_sync_netbox_handler,
)
from certwatch.bootstrap import BootstrapError, bootstrap
from certwatch.check_thread import CertCheckThread
from certwatch.clock import Clock, RealClock
from certwatch.dashboard_client import DashboardAuthError
from certwatch.heartbeat_thread import ConfigState, HeartbeatThread, StatsState
from certwatch.netbox_client import NetBoxClient, _parse_netbox_verify_ssl_env
from certwatch.netbox_sync import NetBoxHostsState, NetBoxSyncThread
from certwatch.report_submission import replay_pending_reports

log = logging.getLogger("certwatch")


# Per-component join timeouts during shutdown. The runner is the integration
# layer; literal-value pin (same defensive pattern as BACKOFF_SCHEDULE).
HEARTBEAT_JOIN_TIMEOUT_SECONDS = 10.0
ACTION_POOL_JOIN_TIMEOUT_SECONDS = 15.0
CHECK_THREAD_JOIN_TIMEOUT_SECONDS = 15.0
NETBOX_SYNC_JOIN_TIMEOUT_SECONDS = 15.0
ACTION_WORKER_COUNT = 4


# Exit codes — the runner's contract with the OS. Pinned by tests.
EXIT_CLEAN = 0
EXIT_BOOTSTRAP_FAILURE = 1
EXIT_AUTH_ERROR = 2
EXIT_UNEXPECTED = 3


class AgentRunner:
    """Orchestrates the agent's lifecycle. One instance per process."""

    def __init__(
        self,
        *,
        env: Mapping[str, str],
        data_dir: str | Path,
        clock: Optional[Clock] = None,
    ) -> None:
        self.env = env
        self.data_dir = Path(data_dir)
        self.clock = clock if clock is not None else RealClock()
        # Internal state — populated during run().
        self._shutdown_event = threading.Event()
        self._auth_error_event = threading.Event()

    def run(self) -> int:
        process_started_at = self.clock.now()
        log.info(
            {
                "event": "agent_starting",
                "agent_version": __version__,
                "data_dir": str(self.data_dir),
            }
        )

        # 1. Bootstrap — fatal failures exit 1; revoked-at-startup exit 2.
        try:
            bootstrap_result = bootstrap(
                env=self.env, data_dir=self.data_dir, clock=self.clock
            )
        except BootstrapError as e:
            log.error({"event": "bootstrap_failed", "error": str(e)})
            return EXIT_BOOTSTRAP_FAILURE
        except Exception as e:
            log.error(
                {
                    "event": "bootstrap_unexpected_error",
                    "error_class": type(e).__name__,
                    "error_message": str(e),
                }
            )
            return EXIT_BOOTSTRAP_FAILURE

        log.info(
            {
                "event": "bootstrap_complete",
                "agent_id": bootstrap_result.agent_id,
                "dashboard_url": bootstrap_result.dashboard_url,
                "config_version": bootstrap_result.initial_config.get("config_version"),
            }
        )

        # 2. Replay pending reports BEFORE starting any thread. If shutdown
        # arrives during replay, we exit cleanly without spinning up loops.
        # Auth error during replay → exit 2.
        try:
            replay_result = replay_pending_reports(
                client=bootstrap_result.client,
                data_dir=self.data_dir,
                credentials_registered_at=bootstrap_result.registered_at,
                clock=self.clock,
                shutdown_event=self._shutdown_event,
            )
            log.info(
                {
                    "event": "replay_phase_complete",
                    "replayed_count": replay_result.replayed_count,
                    "skipped_corrupt": replay_result.skipped_corrupt,
                    "skipped_orphan": replay_result.skipped_orphan,
                    "shutdown_during": replay_result.shutdown_during,
                }
            )
        except DashboardAuthError as e:
            log.error(
                {
                    "event": "replay_auth_error_shutting_down",
                    "error_code": e.code,
                    "error_message": e.message,
                }
            )
            return EXIT_AUTH_ERROR
        except Exception as e:
            # Non-auth replay failures are non-fatal: log and continue.
            # Pending files remain on disk for the next start.
            log.error(
                {
                    "event": "replay_unexpected_error_continuing",
                    "error_class": type(e).__name__,
                    "error_message": str(e),
                }
            )

        # If the shutdown event was set during replay (e.g., SIGTERM during
        # a long-running replay), don't bother starting threads.
        if self._shutdown_event.is_set():
            log.info({"event": "shutdown_signaled_during_replay_skipping_threads"})
            return self._final_exit_code()

        # 3. Build shared state.
        config_state = ConfigState(initial=bootstrap_result.initial_config)
        stats_state = StatsState(clock=self.clock)
        action_queue: "queue.Queue[dict]" = queue.Queue()
        # Always construct NetBoxHostsState — when NetBox is not
        # configured, snapshot() returns [] and the cycle iterates only
        # manual_hosts. Always-present state simplifies wiring (no
        # conditional None passing) and the empty-list path is harmless.
        netbox_hosts_state = NetBoxHostsState()

        # 3a. Construct NetBoxClient if configured (Phase 6).
        netbox_client = self._build_netbox_client_if_configured()

        # 4. Build handlers + threads + pool.
        check_host_handler = make_check_host_handler(
            client=bootstrap_result.client,
            data_dir=self.data_dir,
            config_state=config_state,
            clock=self.clock,
            shutdown_event=self._shutdown_event,
            netbox_hosts_state=netbox_hosts_state,
        )
        sync_netbox_handler = make_sync_netbox_handler(
            netbox_client=netbox_client,
            dashboard_client=bootstrap_result.client,
            stats_state=stats_state,
            clock=self.clock,
            shutdown_event=self._shutdown_event,
        )

        heartbeat_thread = HeartbeatThread(
            client=bootstrap_result.client,
            config_state=config_state,
            stats_state=stats_state,
            action_queue=action_queue,
            shutdown_event=self._shutdown_event,
            auth_error_event=self._auth_error_event,
            clock=self.clock,
            process_started_at=process_started_at,
            agent_version=__version__,
        )
        action_pool = ActionWorkerPool(
            action_queue=action_queue,
            handlers={
                "check_host": check_host_handler,
                "sync_netbox": sync_netbox_handler,
            },
            shutdown_event=self._shutdown_event,
            auth_error_event=self._auth_error_event,
            clock=self.clock,
            num_workers=ACTION_WORKER_COUNT,
        )
        check_thread = CertCheckThread(
            client=bootstrap_result.client,
            data_dir=self.data_dir,
            config_state=config_state,
            stats_state=stats_state,
            shutdown_event=self._shutdown_event,
            auth_error_event=self._auth_error_event,
            clock=self.clock,
            netbox_hosts_state=netbox_hosts_state,
        )

        netbox_thread: Optional[NetBoxSyncThread] = None
        if netbox_client is not None:
            netbox_thread = NetBoxSyncThread(
                netbox_client=netbox_client,
                dashboard_client=bootstrap_result.client,
                config_state=config_state,
                stats_state=stats_state,
                shutdown_event=self._shutdown_event,
                auth_error_event=self._auth_error_event,
                clock=self.clock,
                netbox_hosts_state=netbox_hosts_state,
            )

        # 5. Install signal handlers. Main-thread only; in tests we run
        # the runner from a background thread and trigger shutdown via
        # the event directly.
        self._install_signal_handlers()

        # 6. Start everything.
        log.info(
            {
                "event": "agent_starting_threads",
                "netbox_sync_enabled": netbox_thread is not None,
            }
        )
        heartbeat_thread.start()
        action_pool.start()
        check_thread.start()
        if netbox_thread is not None:
            netbox_thread.start()

        # 7. Wait for shutdown signal (signal handler, auth error, or test).
        log.info({"event": "agent_running"})
        self._shutdown_event.wait()
        log.info({"event": "agent_shutdown_signaled"})

        # 8. Join threads with bounded timeouts.
        return self._shutdown(heartbeat_thread, action_pool, check_thread, netbox_thread)

    # ---- shutdown ---------------------------------------------------

    def _shutdown(
        self,
        heartbeat: HeartbeatThread,
        action_pool: ActionWorkerPool,
        check: CertCheckThread,
        netbox: Optional[NetBoxSyncThread] = None,
    ) -> int:
        shutdown_start = self.clock.now()

        heartbeat.join(timeout=HEARTBEAT_JOIN_TIMEOUT_SECONDS)
        if heartbeat.is_alive():
            log.warning(
                {
                    "event": "heartbeat_thread_did_not_exit_within_timeout",
                    "timeout_seconds": HEARTBEAT_JOIN_TIMEOUT_SECONDS,
                }
            )

        all_workers_exited = action_pool.join(
            timeout=ACTION_POOL_JOIN_TIMEOUT_SECONDS
        )
        if not all_workers_exited:
            log.warning(
                {
                    "event": "action_pool_did_not_fully_exit_within_timeout",
                    "timeout_seconds": ACTION_POOL_JOIN_TIMEOUT_SECONDS,
                }
            )

        check.join(timeout=CHECK_THREAD_JOIN_TIMEOUT_SECONDS)
        if check.is_alive():
            log.warning(
                {
                    "event": "check_thread_did_not_exit_within_timeout",
                    "timeout_seconds": CHECK_THREAD_JOIN_TIMEOUT_SECONDS,
                }
            )

        if netbox is not None:
            netbox.join(timeout=NETBOX_SYNC_JOIN_TIMEOUT_SECONDS)
            if netbox.is_alive():
                log.warning(
                    {
                        "event": "netbox_sync_thread_did_not_exit_within_timeout",
                        "timeout_seconds": NETBOX_SYNC_JOIN_TIMEOUT_SECONDS,
                    }
                )

        duration = self.clock.now() - shutdown_start
        log.info(
            {
                "event": "shutdown_complete",
                "duration_seconds": round(duration, 3),
            }
        )
        return self._final_exit_code()

    def _final_exit_code(self) -> int:
        """Determine the process exit code from the runner's flags."""
        if self._auth_error_event.is_set():
            return EXIT_AUTH_ERROR
        return EXIT_CLEAN

    # ---- signal handling --------------------------------------------

    def _install_signal_handlers(self) -> None:
        def handler(signum, _frame):
            log.info({"event": "signal_received", "signum": int(signum)})
            self._shutdown_event.set()

        try:
            signal.signal(signal.SIGTERM, handler)
            signal.signal(signal.SIGINT, handler)
        except ValueError:
            # `signal.signal()` only works on the main thread. Tests and
            # non-main-thread integrations skip handler install — they
            # set shutdown_event directly.
            log.warning(
                {"event": "signal_handlers_not_installed_not_main_thread"}
            )

    # ---- internal helpers --------------------------------------------

    def _build_netbox_client_if_configured(self) -> Optional[NetBoxClient]:
        """Construct a NetBoxClient when NETBOX_URL is set; otherwise
        return None and let the sync_netbox handler / sync thread no-op.

        The bootstrap-time validate_netbox_env() guarantees that if URL
        is set, TOKEN and FILTER are too — so we don't re-check here."""
        url = self.env.get("NETBOX_URL", "").strip()
        if not url:
            log.info({"event": "netbox_not_configured"})
            return None
        token = self.env["NETBOX_TOKEN"].strip()
        filter_expr = self.env["NETBOX_FILTER"].strip()
        # Read NETBOX_VERIFY_SSL from the runner's env Mapping (not
        # os.environ) so tests with synthetic envs see the right value.
        # NetBoxClient logs the security warning on its own when False.
        verify_ssl = _parse_netbox_verify_ssl_env(self.env)
        log.info(
            {
                "event": "netbox_configured",
                "url": url,
                "filter": filter_expr,
                "verify_ssl": verify_ssl,
            }
        )
        return NetBoxClient(
            url=url, token=token, filter_expr=filter_expr,
            verify_ssl=verify_ssl,
        )

    # ---- test hooks --------------------------------------------------

    @property
    def shutdown_event(self) -> threading.Event:
        """Exposed for integration tests that simulate signals by setting
        the event directly. Production code uses the SIGTERM/SIGINT
        handlers."""
        return self._shutdown_event

    @property
    def auth_error_event(self) -> threading.Event:
        """Exposed for tests."""
        return self._auth_error_event


def main(*, env: Mapping[str, str], data_dir: str | Path) -> int:
    """Convenience entry point for `python -m certwatch agent`. Constructs
    a RealClock-backed runner from the provided env and data dir."""
    runner = AgentRunner(env=env, data_dir=data_dir)
    return runner.run()
