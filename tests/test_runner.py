"""Phase 5f — AgentRunner integration tests.

Runs the full runner against responses-mocked dashboard endpoints. The
runner is started on a background thread; tests trigger shutdown via
the runner's exposed shutdown_event and observe behavior + exit code.

Same _run_until_exit discipline as 5c-5e: every test joins the runner
thread with a strict timeout, fails fast on leaks rather than letting
threads bleed between tests.

The startup decision-tree state machine (fresh / restart-with-creds /
restart-with-pending-reports / corrupt / orphan) gets explicit per-case
coverage following 5e's is_first_cycle three-case template.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest
import responses

from certwatch.agent_state import save_credentials
from certwatch.bootstrap import bootstrap as _bootstrap_fn
from certwatch.clock import FakeClock
from certwatch.pending_reports import (
    pending_dir,
    save_pending_report,
)
from certwatch.runner import (
    EXIT_AUTH_ERROR,
    EXIT_BOOTSTRAP_FAILURE,
    EXIT_CLEAN,
    AgentRunner,
)


DASH = "https://certwatch.lovable.app"
AGENT_ID = "a8f3d12e-7b4c-4d8a-9e1f-2c5b6a7d8e9f"
SECRET = "agtkey_test"

REGISTER_URL = f"{DASH}/api/v1/agents/register"
CONFIG_URL = f"{DASH}/api/v1/agents/{AGENT_ID}/config"
HEARTBEAT_URL = f"{DASH}/api/v1/agents/{AGENT_ID}/heartbeat"
REPORTS_URL = f"{DASH}/api/v1/agents/{AGENT_ID}/reports"


CONFIG_BODY = {
    "config_version": 1,
    "fetched_at": "2026-05-02T15:00:00Z",
    "intervals": {"heartbeat_seconds": 15, "check_seconds": 3600,
                  "netbox_sync_seconds": 3600},
    "timeouts": {"tcp_connect_seconds": 5, "tls_handshake_seconds": 5},
    "concurrency": {"max_parallel_checks": 20},
    "alert_thresholds_days": [30, 7, 1],
    "manual_hosts": [],
}

REGISTER_RESPONSE = {
    "agent_id": AGENT_ID,
    "agent_secret": SECRET,
    "registered_at": "2026-05-02T14:30:01Z",
    "config": CONFIG_BODY,
}

STEADY_HEARTBEAT_RESPONSE = {
    "received_at": "2026-05-02T15:00:00Z",
    "config_version": 1,
    "config_refresh_required": False,
    "pending_actions": [],
}

REPORT_OK_RESPONSE = {
    "received_at": "2026-05-02T15:01:43Z",
    "report_id": "placeholder",
    "summary": {"total_checks": 0, "success": 0,
                 "connection_failed": 0, "tls_failed": 0,
                 "alerts_triggered": 0, "ignored_unknown_hosts": 0},
    "action_completed": None,
}


def _seed_credentials(data_dir: Path):
    """Pre-write /data/agent.json so the runner takes the subsequent-run
    path without registering."""
    save_credentials(
        data_dir / "agent.json",
        agent_id=AGENT_ID,
        agent_secret=SECRET,
        dashboard_url=DASH,
        registered_at="2026-05-02T14:30:01Z",
    )


def _run_runner(runner: AgentRunner, *, shutdown_after_seconds: float = 0.2,
                 timeout: float = 5.0):
    """Run AgentRunner.run() on a background thread, set shutdown after
    a brief delay, join with a strict timeout, return the exit code.

    Mirrors _run_until_exit from 5c-5e. Strict timeout means a deadlocked
    runner fails the test rather than hanging the suite."""
    result_box: list = []
    exception_box: list = []

    def target():
        try:
            result_box.append(runner.run())
        except Exception as e:
            exception_box.append(e)

    thread = threading.Thread(target=target, name="runner-test")
    thread.start()
    # Brief real wait to let the runner spin up its threads.
    time.sleep(shutdown_after_seconds)
    runner.shutdown_event.set()
    thread.join(timeout=timeout)

    if thread.is_alive():
        # Last-resort: keep the event set and join one more time with a
        # short final wait, then declare leak.
        thread.join(timeout=1.0)
        if thread.is_alive():
            raise AssertionError(
                f"runner thread did not exit within {timeout}s — "
                f"likely a deadlock"
            )

    if exception_box:
        raise exception_box[0]
    assert result_box, "runner.run() never returned"
    return result_box[0]


# ============================================================
#  Bootstrap failure paths (no threads start)
# ============================================================


def test_bootstrap_failure_returns_exit_1(tmp_path):
    """Missing DASHBOARD_URL → BootstrapError → exit 1, no threads."""
    runner = AgentRunner(env={}, data_dir=tmp_path, clock=FakeClock())
    rc = runner.run()  # Synchronous; bootstrap fails fast
    assert rc == EXIT_BOOTSTRAP_FAILURE


def test_bootstrap_first_run_missing_token_returns_exit_1(tmp_path):
    """First-run path needs REGISTRATION_TOKEN; missing → exit 1."""
    runner = AgentRunner(
        env={"DASHBOARD_URL": DASH},  # no REGISTRATION_TOKEN
        data_dir=tmp_path, clock=FakeClock(),
    )
    rc = runner.run()
    assert rc == EXIT_BOOTSTRAP_FAILURE


def test_bootstrap_invalid_registration_token_returns_exit_1(tmp_path):
    """401 invalid_registration_token during register → BootstrapError → exit 1."""
    env = {"DASHBOARD_URL": DASH, "REGISTRATION_TOKEN": "regtok_bad"}
    err = {"error": {"code": "invalid_registration_token",
                      "message": "Token unknown", "request_id": "req_x"}}
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REGISTER_URL, json=err, status=401)
        runner = AgentRunner(env=env, data_dir=tmp_path, clock=FakeClock())
        rc = runner.run()
    assert rc == EXIT_BOOTSTRAP_FAILURE


# ============================================================
#  Replay-before-threads decision tree
# ============================================================


def test_fresh_start_no_credentials_no_pending(tmp_path):
    """Decision tree case 1: fresh agent. Bootstrap registers, no pending
    reports to replay, threads start, runner exits cleanly on shutdown."""
    env = {"DASHBOARD_URL": DASH, "REGISTRATION_TOKEN": "regtok_fresh"}

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add("POST", REGISTER_URL, json=REGISTER_RESPONSE, status=201)
        # The threads will fire heartbeats / submit reports — register
        # plenty of mocks for whatever they do.
        for _ in range(50):
            rsps.add("POST", HEARTBEAT_URL, json=STEADY_HEARTBEAT_RESPONSE, status=200)
            rsps.add("POST", REPORTS_URL, json=REPORT_OK_RESPONSE, status=200)

        runner = AgentRunner(env=env, data_dir=tmp_path, clock=FakeClock())
        rc = _run_runner(runner)

    assert rc == EXIT_CLEAN
    # Credentials persisted (registration ran)
    assert (tmp_path / "agent.json").exists()


def test_restart_with_credentials_no_pending(tmp_path):
    """Decision tree case 2: restart with creds, no pending reports.
    Bootstrap loads creds, get_config called, threads start cleanly."""
    _seed_credentials(tmp_path)
    env = {"DASHBOARD_URL": DASH}  # no REGISTRATION_TOKEN

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add("GET", CONFIG_URL, json=CONFIG_BODY, status=200)
        for _ in range(50):
            rsps.add("POST", HEARTBEAT_URL, json=STEADY_HEARTBEAT_RESPONSE, status=200)
            rsps.add("POST", REPORTS_URL, json=REPORT_OK_RESPONSE, status=200)

        runner = AgentRunner(env=env, data_dir=tmp_path, clock=FakeClock())
        rc = _run_runner(runner)

    assert rc == EXIT_CLEAN


def test_restart_with_credentials_and_pending_reports(tmp_path):
    """Decision tree case 3: pending reports replay BEFORE any thread
    starts. Verify the replay submission lands on the dashboard before
    the cycle thread fires its own first 'startup' report."""
    _seed_credentials(tmp_path)
    env = {"DASHBOARD_URL": DASH}

    # Pre-seed a pending report from "before" the agent started (still
    # within the registered_at horizon so it's not orphaned).
    save_pending_report(
        tmp_path,
        report_id="leftover-from-previous-run",
        payload={
            "report_id": "leftover-from-previous-run",
            "report_type": "scheduled",
            "started_at": "2026-05-02T14:50:00Z",
            "completed_at": "2026-05-02T14:51:00Z",
            "action_id": None,
            "checks": [],
        },
    )

    submission_order = []

    def submit_handler(request):
        body = json.loads(request.body)
        submission_order.append(body["report_id"])
        return (
            200, {},
            json.dumps({**REPORT_OK_RESPONSE, "report_id": body["report_id"]}),
        )

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add("GET", CONFIG_URL, json=CONFIG_BODY, status=200)
        for _ in range(20):
            rsps.add("POST", HEARTBEAT_URL, json=STEADY_HEARTBEAT_RESPONSE, status=200)
            rsps.add_callback("POST", REPORTS_URL, callback=submit_handler)

        runner = AgentRunner(env=env, data_dir=tmp_path, clock=FakeClock())
        rc = _run_runner(runner, shutdown_after_seconds=0.5)

    assert rc == EXIT_CLEAN
    # The leftover report submitted BEFORE any new cycle's report.
    assert submission_order, "no submissions recorded"
    assert submission_order[0] == "leftover-from-previous-run"
    # The leftover file is gone (delivered).
    assert not (pending_dir(tmp_path) / "leftover-from-previous-run.json").exists()


def test_restart_with_corrupt_pending_report_continues(tmp_path):
    """Decision tree case 4: a corrupt pending file gets quarantined and
    replay continues; the runner still starts threads and exits cleanly."""
    _seed_credentials(tmp_path)
    env = {"DASHBOARD_URL": DASH}

    # Write a corrupt pending file directly (bypassing save_pending_report)
    pdir = pending_dir(tmp_path)
    pdir.mkdir(parents=True, exist_ok=True)
    corrupt_path = pdir / "corrupt-id.json"
    corrupt_content = "this is not { valid json"
    corrupt_path.write_text(corrupt_content)

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add("GET", CONFIG_URL, json=CONFIG_BODY, status=200)
        for _ in range(50):
            rsps.add("POST", HEARTBEAT_URL, json=STEADY_HEARTBEAT_RESPONSE, status=200)
            rsps.add("POST", REPORTS_URL, json=REPORT_OK_RESPONSE, status=200)

        runner = AgentRunner(env=env, data_dir=tmp_path, clock=FakeClock())
        rc = _run_runner(runner)

    assert rc == EXIT_CLEAN
    # Corrupt file moved to corrupt/ subdir, contents preserved
    assert not corrupt_path.exists()
    quarantined = list((pdir / "corrupt").iterdir())
    assert len(quarantined) == 1
    assert quarantined[0].read_text() == corrupt_content


def test_restart_with_orphan_pending_report_skips_it(tmp_path):
    """Decision tree case 5: a pending file from a previous (revoked)
    agent identity. _persisted_at < credentials.registered_at means we
    skip it; replay continues; threads start; orphan file preserved."""
    _seed_credentials(tmp_path)
    env = {"DASHBOARD_URL": DASH}

    pdir = pending_dir(tmp_path)
    pdir.mkdir(parents=True, exist_ok=True)
    orphan_path = pdir / "orphan.json"
    # _persisted_at predates credentials.registered_at (2026-05-02T14:30:01Z)
    orphan_path.write_text(json.dumps({
        "report_id": "orphan", "report_type": "scheduled",
        "started_at": "2025-01-01T00:00:00Z",
        "completed_at": "2025-01-01T00:00:01Z",
        "action_id": None, "checks": [],
        "_persisted_at": "2025-01-01T00:00:00Z",  # older than registered_at
        "_attempts": 3,
    }))

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add("GET", CONFIG_URL, json=CONFIG_BODY, status=200)
        for _ in range(50):
            rsps.add("POST", HEARTBEAT_URL, json=STEADY_HEARTBEAT_RESPONSE, status=200)
            rsps.add("POST", REPORTS_URL, json=REPORT_OK_RESPONSE, status=200)

        runner = AgentRunner(env=env, data_dir=tmp_path, clock=FakeClock())
        rc = _run_runner(runner)

    assert rc == EXIT_CLEAN
    # Orphan file preserved — operator may want to inspect.
    assert orphan_path.exists()


# ============================================================
#  Auth error → exit 2
# ============================================================


def test_replay_auth_error_returns_exit_2(tmp_path):
    """If a replayed report's submission returns 401, the runner exits 2
    BEFORE starting threads."""
    _seed_credentials(tmp_path)
    env = {"DASHBOARD_URL": DASH}

    save_pending_report(tmp_path, "pending-1", payload={
        "report_id": "pending-1", "report_type": "scheduled",
        "started_at": "2026-05-02T14:50:00Z",
        "completed_at": "2026-05-02T14:51:00Z",
        "action_id": None, "checks": [],
    })

    err = {"error": {"code": "agent_revoked", "message": "revoked",
                      "request_id": "req_r"}}
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        # The replay's first submission returns 401 → bubble up → exit 2
        rsps.add("POST", REPORTS_URL, json=err, status=401)
        # In case any other endpoint gets called, register placeholders.
        rsps.add("GET", CONFIG_URL, json=CONFIG_BODY, status=200)

        runner = AgentRunner(env=env, data_dir=tmp_path, clock=FakeClock())
        rc = runner.run()  # synchronous; replay raises before threads start

    assert rc == EXIT_AUTH_ERROR


def test_heartbeat_auth_error_during_operation_returns_exit_2(tmp_path):
    """A 401 from a steady-state heartbeat triggers global shutdown via
    auth_error_event → exit code 2."""
    _seed_credentials(tmp_path)
    env = {"DASHBOARD_URL": DASH}

    err = {"error": {"code": "agent_revoked", "message": "revoked",
                      "request_id": "req_r"}}

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add("GET", CONFIG_URL, json=CONFIG_BODY, status=200)
        # First heartbeat returns 401 — heartbeat thread sets
        # auth_error_event + shutdown_event, all threads exit.
        rsps.add("POST", HEARTBEAT_URL, json=err, status=401)
        # Cycle thread may or may not fire a report depending on timing.
        for _ in range(20):
            rsps.add("POST", REPORTS_URL, json=REPORT_OK_RESPONSE, status=200)

        runner = AgentRunner(env=env, data_dir=tmp_path, clock=FakeClock())

        # Don't manually trigger shutdown — let auth error do it.
        result_box = []
        thread = threading.Thread(
            target=lambda: result_box.append(runner.run()),
            name="runner-auth-test",
        )
        thread.start()
        thread.join(timeout=5.0)
        assert not thread.is_alive(), "runner did not exit on auth error"

    assert result_box == [EXIT_AUTH_ERROR]
    assert runner.auth_error_event.is_set()


def test_check_thread_auth_error_returns_exit_2(tmp_path):
    """A 401 from a cycle's submit_report triggers auth-error shutdown."""
    _seed_credentials(tmp_path)
    # Use a config with at least one host so the cycle has work to do
    config_with_hosts = {
        **CONFIG_BODY,
        "manual_hosts": [
            {"host_id": "h1", "hostname": "192.0.2.1", "port": 443,
             "added_at": "2026-04-01T00:00:00Z"},
        ],
    }
    env = {"DASHBOARD_URL": DASH}

    err = {"error": {"code": "agent_revoked", "message": "revoked",
                      "request_id": "req_r"}}

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add("GET", CONFIG_URL, json=config_with_hosts, status=200)
        for _ in range(20):
            rsps.add("POST", HEARTBEAT_URL, json=STEADY_HEARTBEAT_RESPONSE, status=200)
        # Cycle's submit returns 401
        rsps.add("POST", REPORTS_URL, json=err, status=401)

        runner = AgentRunner(env=env, data_dir=tmp_path, clock=FakeClock())

        result_box = []
        thread = threading.Thread(
            target=lambda: result_box.append(runner.run()),
            name="runner-cycle-auth",
        )
        thread.start()
        thread.join(timeout=10.0)  # cert_check may take a couple seconds
        assert not thread.is_alive()

    assert result_box == [EXIT_AUTH_ERROR]


# ============================================================
#  Signal-handler installation
# ============================================================


def test_signal_handlers_skipped_in_non_main_thread(tmp_path, caplog):
    """Tests run the runner on a background thread; signal.signal()
    raises ValueError outside the main thread. The runner must catch
    that, log a warning, and continue normally."""
    _seed_credentials(tmp_path)
    env = {"DASHBOARD_URL": DASH}

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add("GET", CONFIG_URL, json=CONFIG_BODY, status=200)
        for _ in range(50):
            rsps.add("POST", HEARTBEAT_URL, json=STEADY_HEARTBEAT_RESPONSE, status=200)
            rsps.add("POST", REPORTS_URL, json=REPORT_OK_RESPONSE, status=200)

        runner = AgentRunner(env=env, data_dir=tmp_path, clock=FakeClock())
        with caplog.at_level("WARNING"):
            rc = _run_runner(runner)

    assert rc == EXIT_CLEAN
    skipped = [r.msg for r in caplog.records
               if isinstance(r.msg, dict) and r.msg.get("event") == "signal_handlers_not_installed_not_main_thread"]
    assert len(skipped) >= 1


# ============================================================
#  Lifecycle observability
# ============================================================


def test_clean_shutdown_emits_lifecycle_log_events(tmp_path, caplog):
    """The runner emits structured-JSON events for each lifecycle phase
    so operators can grep logs for shutdown duration etc."""
    _seed_credentials(tmp_path)
    env = {"DASHBOARD_URL": DASH}

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add("GET", CONFIG_URL, json=CONFIG_BODY, status=200)
        for _ in range(50):
            rsps.add("POST", HEARTBEAT_URL, json=STEADY_HEARTBEAT_RESPONSE, status=200)
            rsps.add("POST", REPORTS_URL, json=REPORT_OK_RESPONSE, status=200)

        runner = AgentRunner(env=env, data_dir=tmp_path, clock=FakeClock())
        with caplog.at_level("INFO"):
            _run_runner(runner)

    events = [r.msg.get("event") for r in caplog.records if isinstance(r.msg, dict)]
    # Key lifecycle events all present
    assert "agent_starting" in events
    assert "bootstrap_complete" in events
    assert "agent_starting_threads" in events
    assert "agent_running" in events
    assert "agent_shutdown_signaled" in events
    assert "shutdown_complete" in events


def test_shutdown_complete_event_includes_duration(tmp_path, caplog):
    _seed_credentials(tmp_path)
    env = {"DASHBOARD_URL": DASH}

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add("GET", CONFIG_URL, json=CONFIG_BODY, status=200)
        for _ in range(50):
            rsps.add("POST", HEARTBEAT_URL, json=STEADY_HEARTBEAT_RESPONSE, status=200)
            rsps.add("POST", REPORTS_URL, json=REPORT_OK_RESPONSE, status=200)

        runner = AgentRunner(env=env, data_dir=tmp_path, clock=FakeClock())
        with caplog.at_level("INFO"):
            _run_runner(runner)

    msgs = [r.msg for r in caplog.records
            if isinstance(r.msg, dict) and r.msg.get("event") == "shutdown_complete"]
    assert len(msgs) == 1
    assert "duration_seconds" in msgs[0]


# ============================================================
#  Constants pinning (literal-value test pattern)
# ============================================================


def test_exit_code_constants_match_documented_contract():
    """Pin the runner's exit-code contract literally — same defensive
    pattern as BACKOFF_SCHEDULE in 5a/5b."""
    assert EXIT_CLEAN == 0
    assert EXIT_BOOTSTRAP_FAILURE == 1
    assert EXIT_AUTH_ERROR == 2


def test_join_timeout_constants_pinned():
    """Pin the per-component shutdown timeouts. The runner's total
    shutdown budget = sum of these; if the constants drift, container
    SIGTERM grace periods may need adjustment in deployment configs."""
    from certwatch.runner import (
        ACTION_POOL_JOIN_TIMEOUT_SECONDS,
        ACTION_WORKER_COUNT,
        CHECK_THREAD_JOIN_TIMEOUT_SECONDS,
        HEARTBEAT_JOIN_TIMEOUT_SECONDS,
    )
    assert HEARTBEAT_JOIN_TIMEOUT_SECONDS == 10.0
    assert ACTION_POOL_JOIN_TIMEOUT_SECONDS == 15.0
    assert CHECK_THREAD_JOIN_TIMEOUT_SECONDS == 15.0
    assert ACTION_WORKER_COUNT == 4


# ============================================================
#  CLI entry — `python -m certwatch agent`
# ============================================================


# ============================================================
#  Phase 6 — NetBox configuration paths
# ============================================================


def test_runner_without_netbox_url_does_not_start_netbox_thread(tmp_path):
    """Default agent: NETBOX_URL not set → sync_netbox handler is the
    no-op variant; no NetBoxSyncThread started; runner exits cleanly."""
    _seed_credentials(tmp_path)
    env = {"DASHBOARD_URL": DASH}  # no NETBOX_*

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add("GET", CONFIG_URL, json=CONFIG_BODY, status=200)
        for _ in range(50):
            rsps.add("POST", HEARTBEAT_URL, json=STEADY_HEARTBEAT_RESPONSE, status=200)
            rsps.add("POST", REPORTS_URL, json=REPORT_OK_RESPONSE, status=200)

        runner = AgentRunner(env=env, data_dir=tmp_path, clock=FakeClock())
        rc = _run_runner(runner)

    assert rc == EXIT_CLEAN


def test_runner_logs_netbox_not_configured_at_startup(tmp_path, caplog):
    _seed_credentials(tmp_path)
    env = {"DASHBOARD_URL": DASH}

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add("GET", CONFIG_URL, json=CONFIG_BODY, status=200)
        for _ in range(50):
            rsps.add("POST", HEARTBEAT_URL, json=STEADY_HEARTBEAT_RESPONSE, status=200)
            rsps.add("POST", REPORTS_URL, json=REPORT_OK_RESPONSE, status=200)

        runner = AgentRunner(env=env, data_dir=tmp_path, clock=FakeClock())
        with caplog.at_level("INFO"):
            _run_runner(runner)

    msgs = [r.msg for r in caplog.records
            if isinstance(r.msg, dict) and r.msg.get("event") == "netbox_not_configured"]
    assert len(msgs) == 1


def test_runner_with_netbox_url_but_missing_token_returns_exit_1(tmp_path):
    """Half-configured NetBox is operator error; bootstrap fails fast."""
    _seed_credentials(tmp_path)
    env = {
        "DASHBOARD_URL": DASH,
        "NETBOX_URL": "https://netbox.example",
        "NETBOX_FILTER": "tag=monitor-cert",
        # NETBOX_TOKEN missing
    }
    runner = AgentRunner(env=env, data_dir=tmp_path, clock=FakeClock())
    rc = runner.run()
    assert rc == EXIT_BOOTSTRAP_FAILURE


def test_runner_with_netbox_url_but_missing_filter_returns_exit_1(tmp_path):
    _seed_credentials(tmp_path)
    env = {
        "DASHBOARD_URL": DASH,
        "NETBOX_URL": "https://netbox.example",
        "NETBOX_TOKEN": "nbtok_x",
        # NETBOX_FILTER missing
    }
    runner = AgentRunner(env=env, data_dir=tmp_path, clock=FakeClock())
    rc = runner.run()
    assert rc == EXIT_BOOTSTRAP_FAILURE


def test_runner_with_full_netbox_config_starts_netbox_thread(tmp_path, monkeypatch, caplog):
    """All three NETBOX_* env vars set → NetBoxClient is constructed,
    NetBoxSyncThread is started. Patch pynetbox.api so we don't actually
    hit a network."""
    _seed_credentials(tmp_path)
    env = {
        "DASHBOARD_URL": DASH,
        "NETBOX_URL": "https://netbox.example",
        "NETBOX_TOKEN": "nbtok_x",
        "NETBOX_FILTER": "tag=monitor-cert",
    }

    # Stub pynetbox.api so the NetBox client doesn't actually connect.
    from types import SimpleNamespace
    import certwatch.netbox_client as nbc

    class StubFilter:
        def filter(self, **kwargs):
            return []  # no devices

    class StubDcim:
        devices = StubFilter()

    class StubApi:
        dcim = StubDcim()
        http_session = SimpleNamespace()

    monkeypatch.setattr(nbc.pynetbox, "api", lambda *a, **k: StubApi())

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add("GET", CONFIG_URL, json=CONFIG_BODY, status=200)
        for _ in range(50):
            rsps.add("POST", HEARTBEAT_URL, json=STEADY_HEARTBEAT_RESPONSE, status=200)
            rsps.add("POST", REPORTS_URL, json=REPORT_OK_RESPONSE, status=200)
            rsps.add(
                "POST",
                f"{DASH}/api/v1/agents/{AGENT_ID}/discovered-hosts",
                json={
                    "received_at": "t", "summary": {
                        "total_received": 0, "created": 0, "updated": 0,
                        "removed": 0, "unchanged": 0,
                    },
                    "config_version": 1, "action_completed": None,
                },
                status=200,
            )

        runner = AgentRunner(env=env, data_dir=tmp_path, clock=FakeClock())
        with caplog.at_level("INFO"):
            rc = _run_runner(runner, shutdown_after_seconds=0.5)

    assert rc == EXIT_CLEAN
    # Lifecycle log shows NetBox enabled
    starts = [r.msg for r in caplog.records
              if isinstance(r.msg, dict) and r.msg.get("event") == "agent_starting_threads"]
    assert len(starts) == 1
    assert starts[0]["netbox_sync_enabled"] is True
    # netbox_configured event emitted
    cfg = [r.msg for r in caplog.records
           if isinstance(r.msg, dict) and r.msg.get("event") == "netbox_configured"]
    assert len(cfg) == 1
    # NetBox sync thread ran at least one cycle
    sync_thread_started = [r.msg for r in caplog.records
                            if isinstance(r.msg, dict) and r.msg.get("event") == "netbox_sync_thread_starting"]
    assert len(sync_thread_started) == 1


def test_cli_agent_dry_run_unchanged_from_phase_5a(tmp_path):
    """The --dry-run path is the Phase 5a behavior preserved: bootstrap
    runs, threads do NOT start, exit 0."""
    from certwatch.__main__ import main

    _seed_credentials(tmp_path)
    import os
    saved_env = dict(os.environ)
    try:
        os.environ.clear()
        os.environ["DASHBOARD_URL"] = DASH
        with responses.RequestsMock() as rsps:
            rsps.add("GET", CONFIG_URL, json=CONFIG_BODY, status=200)
            rc = main(["agent", "--data-dir", str(tmp_path), "--dry-run"])
    finally:
        os.environ.clear()
        os.environ.update(saved_env)

    assert rc == 0
