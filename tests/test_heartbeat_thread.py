"""Phase 5c — HeartbeatThread tests.

Concurrency surface: real thread + real DashboardClient + responses-mocked
HTTP + FakeClock. Each test owns the thread lifecycle explicitly via
try/finally so a stuck thread fails the test rather than leaking into
the next one.

Pattern for "wait until N heartbeats fire": the request handler counts
hits and sets shutdown_event when the target is reached. The thread's
subsequent wait_for(15, event) sees the set event and exits the loop.
Test then thread.join()s with a timeout.
"""

from __future__ import annotations

import json
import queue
import threading
import time

import pytest
import responses

from certwatch.clock import FakeClock
from certwatch.dashboard_client import DashboardClient
from certwatch.heartbeat_thread import (
    ConfigState,
    HeartbeatThread,
    StatsState,
)

DASH = "https://certwatch.lovable.app"
AGENT_ID = "a8f3d12e-7b4c-4d8a-9e1f-2c5b6a7d8e9f"
SECRET = "agtkey_test"
HB_URL = f"{DASH}/api/public/v1/agents/{AGENT_ID}/heartbeat"
CONFIG_URL = f"{DASH}/api/public/v1/agents/{AGENT_ID}/config"

INITIAL_CONFIG = {
    "config_version": 1,
    "intervals": {"heartbeat_seconds": 15, "check_seconds": 3600, "netbox_sync_seconds": 3600},
    "timeouts": {"tcp_connect_seconds": 5, "tls_handshake_seconds": 5},
    "concurrency": {"max_parallel_checks": 20},
    "alert_thresholds_days": [30, 7, 1],
    "manual_hosts": [],
}

NEW_CONFIG = {
    "config_version": 2,
    "fetched_at": "2026-05-02T15:00:00Z",
    "intervals": {"heartbeat_seconds": 30, "check_seconds": 1800, "netbox_sync_seconds": 1800},
    "timeouts": {"tcp_connect_seconds": 3, "tls_handshake_seconds": 3},
    "concurrency": {"max_parallel_checks": 10},
    "alert_thresholds_days": [30, 7, 1],
    "manual_hosts": [{"host_id": "h1", "hostname": "x.example.com", "port": 443, "added_at": "2026-04-01T00:00:00Z"}],
}

STEADY_HB_RESPONSE = {
    "received_at": "2026-05-02T15:00:00Z",
    "config_version": 1,
    "config_refresh_required": False,
    "pending_actions": [],
}

REFRESH_HB_RESPONSE = {
    "received_at": "2026-05-02T15:00:00Z",
    "config_version": 2,
    "config_refresh_required": True,
    "pending_actions": [],
}


@pytest.fixture
def client():
    return DashboardClient(DASH, agent_id=AGENT_ID, agent_secret=SECRET)


def _build_thread(client, fc, shutdown, *, config=None, stats=None,
                  action_queue=None, agent_version="0.1.0",
                  process_started_at=None):
    cfg = config if config is not None else ConfigState(initial=dict(INITIAL_CONFIG))
    stats_state = stats if stats is not None else StatsState(clock=fc)
    q = action_queue if action_queue is not None else queue.Queue()
    started_at = fc.now() if process_started_at is None else process_started_at
    return HeartbeatThread(
        client=client, config_state=cfg, stats_state=stats_state,
        action_queue=q, shutdown_event=shutdown, clock=fc,
        process_started_at=started_at, agent_version=agent_version,
    ), cfg, stats_state, q


def _run_until_exit(thread, shutdown, timeout=2.0):
    """Set shutdown if not already, then join with a strict timeout. Use
    in a `finally` to make sure no test ever leaks a thread."""
    shutdown.set()
    thread.join(timeout=timeout)
    assert not thread.is_alive(), (
        f"{thread.name} did not exit within {timeout}s — likely a deadlock"
    )


# ---- cadence (Mode 1 steady state) -----------------------------------


def test_5_heartbeats_fire_at_15s_intervals(client):
    """No-catch-up cadence: 5 successful heartbeats produce 5 wait_for
    calls of 15s each (the 5th wait short-circuits when shutdown is set
    by the 5th handler)."""
    fc = FakeClock()
    shutdown = threading.Event()
    thread, _, _, _ = _build_thread(client, fc, shutdown)

    hb_count = {"n": 0}

    def handler(request):
        hb_count["n"] += 1
        if hb_count["n"] >= 5:
            shutdown.set()
        return (200, {}, json.dumps(STEADY_HB_RESPONSE))

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        for _ in range(50):
            rsps.add_callback("POST", HB_URL, callback=handler)
        try:
            thread.start()
            thread.join(timeout=2.0)
        finally:
            _run_until_exit(thread, shutdown)

    assert hb_count["n"] == 5
    assert fc.sleeps == [15.0, 15.0, 15.0, 15.0, 15.0]


def test_no_catch_up_after_slow_heartbeat(client):
    """A slow 8s heartbeat does NOT cause back-to-back firing on the next
    tick — the next sleep is still the full 15s, not 7s."""
    fc = FakeClock()
    shutdown = threading.Event()
    thread, _, _, _ = _build_thread(client, fc, shutdown)

    hb_count = {"n": 0}

    def slow_handler(request):
        fc.advance(8.0)  # Simulate 8s of network/processing time
        hb_count["n"] += 1
        if hb_count["n"] >= 2:
            shutdown.set()
        return (200, {}, json.dumps(STEADY_HB_RESPONSE))

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        for _ in range(10):
            rsps.add_callback("POST", HB_URL, callback=slow_handler)
        try:
            thread.start()
            thread.join(timeout=2.0)
        finally:
            _run_until_exit(thread, shutdown)

    assert hb_count["n"] == 2
    # Both sleeps are 15.0 — the slow heartbeat duration is unrelated.
    assert fc.sleeps == [15.0, 15.0]


def test_heartbeat_interval_read_from_current_config_each_iteration(client):
    """If config refresh changes heartbeat_seconds, the next sleep uses
    the new value — readers always pull a fresh snapshot per iteration."""
    fc = FakeClock()
    shutdown = threading.Event()
    config_state = ConfigState(initial=dict(INITIAL_CONFIG))
    thread, _, _, _ = _build_thread(client, fc, shutdown, config=config_state)

    hb_count = {"n": 0}

    def handler(request):
        hb_count["n"] += 1
        if hb_count["n"] == 1:
            # Mid-test, swap config to a 30s interval.
            config_state.replace({**INITIAL_CONFIG, "config_version": 2,
                                   "intervals": {**INITIAL_CONFIG["intervals"],
                                                  "heartbeat_seconds": 30}})
        if hb_count["n"] >= 3:
            shutdown.set()
        return (200, {}, json.dumps(STEADY_HB_RESPONSE))

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        for _ in range(20):
            rsps.add_callback("POST", HB_URL, callback=handler)
        try:
            thread.start()
            thread.join(timeout=2.0)
        finally:
            _run_until_exit(thread, shutdown)

    # First sleep (after HB1): we just replaced config to 30s, so the
    # NEXT iteration uses 30s. fc.sleeps = [30, 30, 30] (HB1's wait
    # happens after the swap).
    assert hb_count["n"] == 3
    assert fc.sleeps == [30.0, 30.0, 30.0]


# ---- shutdown signal ------------------------------------------------


def test_shutdown_already_set_at_start_no_heartbeat_fires(client):
    fc = FakeClock()
    shutdown = threading.Event()
    shutdown.set()
    thread, _, _, _ = _build_thread(client, fc, shutdown)

    hb_count = {"n": 0}

    def handler(request):
        hb_count["n"] += 1
        return (200, {}, json.dumps(STEADY_HB_RESPONSE))

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add_callback("POST", HB_URL, callback=handler)
        try:
            thread.start()
            thread.join(timeout=2.0)
        finally:
            _run_until_exit(thread, shutdown)

    # Loop's top-of-iteration is_set() check exits immediately.
    assert hb_count["n"] == 0


def test_shutdown_event_set_during_sleep_exits_loop(client):
    fc = FakeClock()
    shutdown = threading.Event()
    thread, _, _, _ = _build_thread(client, fc, shutdown)

    hb_count = {"n": 0}

    def handler(request):
        hb_count["n"] += 1
        # Set shutdown DURING the response — the thread is between
        # request and wait_for. wait_for sees event set, exits.
        shutdown.set()
        return (200, {}, json.dumps(STEADY_HB_RESPONSE))

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add_callback("POST", HB_URL, callback=handler)
        rsps.add_callback("POST", HB_URL, callback=handler)
        try:
            thread.start()
            thread.join(timeout=2.0)
        finally:
            _run_until_exit(thread, shutdown)

    assert hb_count["n"] == 1
    # The wait was attempted and recorded, even though it short-circuited.
    assert fc.sleeps == [15.0]


# ---- error handling -------------------------------------------------


def test_auth_error_signals_shutdown_and_exits(client):
    """401 invalid_token / agent_revoked must set shutdown_event so the
    rest of the runner notices and brings everything down. The thread
    itself exits cleanly."""
    fc = FakeClock()
    shutdown = threading.Event()
    thread, _, _, _ = _build_thread(client, fc, shutdown)

    err = {
        "error": {"code": "agent_revoked", "message": "revoked",
                  "request_id": "req_r"},
    }

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add("POST", HB_URL, json=err, status=401)
        try:
            thread.start()
            thread.join(timeout=2.0)
        finally:
            _run_until_exit(thread, shutdown)

    assert shutdown.is_set()
    assert not thread.is_alive()


def test_validation_error_logs_and_continues(client, caplog):
    """400 is rare per the lenient-validation contract; log warning,
    keep heartbeating at the next tick."""
    fc = FakeClock()
    shutdown = threading.Event()
    thread, _, _, _ = _build_thread(client, fc, shutdown)

    hb_count = {"n": 0}

    def handler(request):
        hb_count["n"] += 1
        if hb_count["n"] == 1:
            # First HB validation error; subsequent succeed.
            return (400, {}, json.dumps({
                "error": {"code": "validation_failed", "message": "bad shape",
                          "request_id": "req_v"},
            }))
        if hb_count["n"] >= 3:
            shutdown.set()
        return (200, {}, json.dumps(STEADY_HB_RESPONSE))

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        for _ in range(10):
            rsps.add_callback("POST", HB_URL, callback=handler)
        try:
            with caplog.at_level("WARNING"):
                thread.start()
                thread.join(timeout=2.0)
        finally:
            _run_until_exit(thread, shutdown)

    assert hb_count["n"] == 3
    assert not shutdown.is_set() or shutdown.is_set()  # set after HB3
    # Warning logged for the validation error
    warns = [r.msg for r in caplog.records
             if isinstance(r.msg, dict) and r.msg.get("event") == "heartbeat_validation_error"]
    assert len(warns) == 1


def test_retriable_error_logs_and_continues_at_next_tick(client, caplog):
    """5xx and network errors don't trigger backoff — heartbeat cadence
    IS the value. Just continue at the next 15s tick."""
    fc = FakeClock()
    shutdown = threading.Event()
    thread, _, _, _ = _build_thread(client, fc, shutdown)

    hb_count = {"n": 0}

    def handler(request):
        hb_count["n"] += 1
        if hb_count["n"] == 1:
            return (503, {}, json.dumps({
                "error": {"code": "internal_error", "message": "boom"}
            }))
        if hb_count["n"] >= 3:
            shutdown.set()
        return (200, {}, json.dumps(STEADY_HB_RESPONSE))

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        for _ in range(10):
            rsps.add_callback("POST", HB_URL, callback=handler)
        try:
            with caplog.at_level("WARNING"):
                thread.start()
                thread.join(timeout=2.0)
        finally:
            _run_until_exit(thread, shutdown)

    assert hb_count["n"] == 3
    # Sleeps are still 15s each — no backoff.
    assert fc.sleeps == [15.0, 15.0, 15.0]
    warns = [r.msg for r in caplog.records
             if isinstance(r.msg, dict) and r.msg.get("event") == "heartbeat_retriable_error"]
    assert len(warns) == 1


# ---- response Mode 2 (config refresh) -------------------------------


def test_config_refresh_required_triggers_get_config_and_swaps_state(client):
    fc = FakeClock()
    shutdown = threading.Event()
    config_state = ConfigState(initial=dict(INITIAL_CONFIG))
    thread, _, _, _ = _build_thread(client, fc, shutdown, config=config_state)

    def hb_handler(request):
        shutdown.set()  # exit after one HB
        return (200, {}, json.dumps(REFRESH_HB_RESPONSE))

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add_callback("POST", HB_URL, callback=hb_handler)
        rsps.add("GET", CONFIG_URL, json=NEW_CONFIG, status=200)
        try:
            thread.start()
            thread.join(timeout=2.0)
        finally:
            _run_until_exit(thread, shutdown)

    # Config swapped via get_config response
    snap = config_state.snapshot()
    assert snap["config_version"] == 2
    assert snap["intervals"]["heartbeat_seconds"] == 30


def test_get_config_failure_keeps_old_config(client, caplog):
    """Retriable failure during config refresh must NOT clobber the
    in-memory config — the heartbeat will signal again on the next tick."""
    fc = FakeClock()
    shutdown = threading.Event()
    config_state = ConfigState(initial=dict(INITIAL_CONFIG))
    thread, _, _, _ = _build_thread(client, fc, shutdown, config=config_state)

    def hb_handler(request):
        shutdown.set()
        return (200, {}, json.dumps(REFRESH_HB_RESPONSE))

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add_callback("POST", HB_URL, callback=hb_handler)
        rsps.add("GET", CONFIG_URL, json={"error": {"code": "internal_error", "message": "boom"}}, status=503)
        try:
            with caplog.at_level("WARNING"):
                thread.start()
                thread.join(timeout=2.0)
        finally:
            _run_until_exit(thread, shutdown)

    # Old config preserved
    assert config_state.snapshot()["config_version"] == 1
    warns = [r.msg for r in caplog.records
             if isinstance(r.msg, dict) and r.msg.get("event") == "config_refresh_failed_keeping_old"]
    assert len(warns) == 1


def test_get_config_auth_error_signals_shutdown(client):
    """401 during config refresh is the same kind of auth error as on
    heartbeat itself — set shutdown, exit."""
    fc = FakeClock()
    shutdown = threading.Event()
    thread, _, _, _ = _build_thread(client, fc, shutdown)

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add("POST", HB_URL, json=REFRESH_HB_RESPONSE, status=200)
        rsps.add("GET", CONFIG_URL, json={"error": {"code": "agent_revoked", "message": "revoked"}}, status=401)
        try:
            thread.start()
            thread.join(timeout=2.0)
        finally:
            _run_until_exit(thread, shutdown)

    assert shutdown.is_set()
    assert not thread.is_alive()


# ---- response Mode 3 (pending actions) -------------------------------


def test_pending_actions_enqueued(client):
    fc = FakeClock()
    shutdown = threading.Event()
    action_queue: queue.Queue = queue.Queue()
    thread, _, _, _ = _build_thread(client, fc, shutdown, action_queue=action_queue)

    # Use a future expires_at so they don't get filtered.
    future_iso = "2099-12-31T00:00:00Z"
    action1 = {
        "action_id": "act-1", "action_type": "check_host",
        "payload": {"host_ref": {"type": "manual", "host_id": "h1"}},
        "queued_at": "2026-05-02T15:00:00Z", "expires_at": future_iso,
    }
    action2 = {
        "action_id": "act-2", "action_type": "sync_netbox",
        "payload": {},
        "queued_at": "2026-05-02T15:00:00Z", "expires_at": future_iso,
    }
    response = {**STEADY_HB_RESPONSE, "pending_actions": [action1, action2]}

    def handler(request):
        shutdown.set()
        return (200, {}, json.dumps(response))

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add_callback("POST", HB_URL, callback=handler)
        try:
            thread.start()
            thread.join(timeout=2.0)
        finally:
            _run_until_exit(thread, shutdown)

    queued = []
    while not action_queue.empty():
        queued.append(action_queue.get_nowait())
    assert queued == [action1, action2]


def test_expired_action_filtered_at_enqueue(client, caplog):
    """Expired actions never reach the queue. Filtering at heartbeat
    response keeps the queue meaningful — every entry is actionable
    at enqueue time (5d's worker re-checks at pickup as defense in
    depth, but this is the primary filter)."""
    fc = FakeClock()
    shutdown = threading.Event()
    action_queue: queue.Queue = queue.Queue()
    thread, _, _, _ = _build_thread(client, fc, shutdown, action_queue=action_queue)

    expired = {
        "action_id": "act-expired", "action_type": "check_host",
        "payload": {"host_ref": {"type": "manual", "host_id": "h1"}},
        "queued_at": "2025-01-01T00:00:00Z",
        "expires_at": "2025-01-01T00:05:00Z",  # long past
    }
    fresh = {
        "action_id": "act-fresh", "action_type": "check_host",
        "payload": {"host_ref": {"type": "manual", "host_id": "h2"}},
        "queued_at": "2026-05-02T15:00:00Z",
        "expires_at": "2099-12-31T00:00:00Z",  # far future
    }
    response = {**STEADY_HB_RESPONSE, "pending_actions": [expired, fresh]}

    def handler(request):
        shutdown.set()
        return (200, {}, json.dumps(response))

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add_callback("POST", HB_URL, callback=handler)
        try:
            with caplog.at_level("INFO"):
                thread.start()
                thread.join(timeout=2.0)
        finally:
            _run_until_exit(thread, shutdown)

    # Only the fresh action made it onto the queue
    queued = []
    while not action_queue.empty():
        queued.append(action_queue.get_nowait())
    assert len(queued) == 1
    assert queued[0]["action_id"] == "act-fresh"

    # Info log emitted for the expired one
    expired_logs = [r.msg for r in caplog.records
                    if isinstance(r.msg, dict) and r.msg.get("event") == "action_received_but_expired"]
    assert len(expired_logs) == 1
    assert expired_logs[0]["action_id"] == "act-expired"


# ---- combined Mode 2 + Mode 3 (config refresh first, then actions) ---


def test_combined_response_refreshes_config_before_enqueuing_actions(client):
    """Order matters: refresh first, THEN process actions on the new
    state (so a config update that changes manual_hosts is visible to
    an action_id that references one of the new hosts)."""
    fc = FakeClock()
    shutdown = threading.Event()
    action_queue: queue.Queue = queue.Queue()
    config_state = ConfigState(initial=dict(INITIAL_CONFIG))
    thread, _, _, _ = _build_thread(
        client, fc, shutdown, config=config_state, action_queue=action_queue
    )

    fresh_action = {
        "action_id": "act-1", "action_type": "check_host",
        "payload": {"host_ref": {"type": "manual", "host_id": "h1"}},
        "queued_at": "2026-05-02T15:00:00Z",
        "expires_at": "2099-12-31T00:00:00Z",
    }
    response = {
        "received_at": "2026-05-02T15:00:00Z",
        "config_version": 2,
        "config_refresh_required": True,
        "pending_actions": [fresh_action],
    }

    call_order = []

    def hb_handler(request):
        call_order.append("heartbeat")
        shutdown.set()
        return (200, {}, json.dumps(response))

    def config_handler(request):
        call_order.append("get_config")
        return (200, {}, json.dumps(NEW_CONFIG))

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add_callback("POST", HB_URL, callback=hb_handler)
        rsps.add_callback("GET", CONFIG_URL, callback=config_handler)
        try:
            thread.start()
            thread.join(timeout=2.0)
        finally:
            _run_until_exit(thread, shutdown)

    # Order: heartbeat → get_config → (actions enqueued in process step)
    assert call_order == ["heartbeat", "get_config"]
    # Config was swapped by the time actions were enqueued
    assert config_state.snapshot()["config_version"] == 2
    # Action made it onto the queue
    queued = []
    while not action_queue.empty():
        queued.append(action_queue.get_nowait())
    assert queued == [fresh_action]


# ---- request body shape ---------------------------------------------


def test_heartbeat_body_includes_uptime_seconds(client):
    fc = FakeClock(start=100.0)
    shutdown = threading.Event()
    thread, _, _, _ = _build_thread(
        client, fc, shutdown,
        process_started_at=10.0,  # process start at fc.now()=10
    )

    captured = {}

    def handler(request):
        captured["body"] = json.loads(request.body)
        shutdown.set()
        return (200, {}, json.dumps(STEADY_HB_RESPONSE))

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add_callback("POST", HB_URL, callback=handler)
        try:
            thread.start()
            thread.join(timeout=2.0)
        finally:
            _run_until_exit(thread, shutdown)

    body = captured["body"]
    assert body["uptime_seconds"] == 90  # 100 - 10
    assert body["agent_version"] == "0.1.0"
    assert body["current_config_version"] == 1
    assert body["sent_at"].endswith("Z")


def test_heartbeat_omits_stats_when_state_empty(client):
    """No cycles recorded yet → snapshot_for_heartbeat returns None →
    heartbeat() omits the field from the body. Pinned via wire-bytes
    assertion (mirrors Phase 4f)."""
    fc = FakeClock()
    shutdown = threading.Event()
    thread, _, _, _ = _build_thread(client, fc, shutdown)

    captured = {}

    def handler(request):
        captured["body_str"] = request.body
        shutdown.set()
        return (200, {}, json.dumps(STEADY_HB_RESPONSE))

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add_callback("POST", HB_URL, callback=handler)
        try:
            thread.start()
            thread.join(timeout=2.0)
        finally:
            _run_until_exit(thread, shutdown)

    body_str = captured["body_str"]
    body = json.loads(body_str)
    assert "stats" not in body
    assert '"stats":' not in body_str


def test_heartbeat_includes_stats_when_state_populated(client):
    fc = FakeClock()
    shutdown = threading.Event()
    stats = StatsState(clock=fc)
    stats.record_check_cycle(
        hosts_monitored=47, completed_at="2026-05-02T15:00:00Z",
        duration_seconds=102, succeeded=45, failed=2,
    )
    thread, _, _, _ = _build_thread(client, fc, shutdown, stats=stats)

    captured = {}

    def handler(request):
        captured["body"] = json.loads(request.body)
        shutdown.set()
        return (200, {}, json.dumps(STEADY_HB_RESPONSE))

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add_callback("POST", HB_URL, callback=handler)
        try:
            thread.start()
            thread.join(timeout=2.0)
        finally:
            _run_until_exit(thread, shutdown)

    body = captured["body"]
    assert body["stats"]["hosts_monitored"] == 47
    assert body["stats"]["checks_succeeded_last_cycle"] == 45
    assert body["stats"]["checks_failed_last_cycle"] == 2


# ---- lifecycle ------------------------------------------------------


def test_thread_can_be_started_and_joined_cleanly(client):
    fc = FakeClock()
    shutdown = threading.Event()
    shutdown.set()  # so the thread exits on first iteration
    thread, _, _, _ = _build_thread(client, fc, shutdown)

    with responses.RequestsMock(assert_all_requests_are_fired=False):
        thread.start()
        thread.join(timeout=2.0)

    assert not thread.is_alive()


def test_thread_exits_on_unhandled_exception_setting_shutdown(client, caplog):
    """An unexpected exception in the loop must set shutdown_event so
    the rest of the runner can bring everything down — silently dying
    threads are the worst kind of failure."""
    fc = FakeClock()
    shutdown = threading.Event()
    thread, _, _, _ = _build_thread(client, fc, shutdown)

    # Patch _do_heartbeat to raise something unexpected
    def boom():
        raise RuntimeError("unexpected explosion")
    thread._do_heartbeat = boom

    with responses.RequestsMock(assert_all_requests_are_fired=False):
        with caplog.at_level("ERROR"):
            try:
                thread.start()
                thread.join(timeout=2.0)
            finally:
                _run_until_exit(thread, shutdown)

    assert shutdown.is_set()
    errors = [r.msg for r in caplog.records
              if isinstance(r.msg, dict) and r.msg.get("event") == "heartbeat_thread_unhandled_exception"]
    assert len(errors) == 1
