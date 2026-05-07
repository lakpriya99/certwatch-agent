"""Phase 5d — ActionWorkerPool + check_host handler tests.

Same threading-test discipline as Phase 5c: every test owns the pool
lifecycle explicitly via try/finally with a strict 2s join timeout. A
leaked worker between tests fails immediately rather than producing
weird intermittent failures elsewhere.
"""

from __future__ import annotations

import json
import queue
import threading
import time
import uuid

import pytest
import responses

from certwatch.cert_check import CertResult
from certwatch.clock import FakeClock
from certwatch.dashboard_client import DashboardClient
from certwatch.heartbeat_thread import ConfigState
from certwatch.action_workers import (
    ActionContext,
    ActionWorkerPool,
    _build_check_payload,
    _cert_dict_from_result,
    _resolve_manual_host,
    make_check_host_handler,
    make_sync_netbox_placeholder_handler,
)

DASH = "https://certwatch.lovable.app"
AGENT_ID = "a8f3d12e-7b4c-4d8a-9e1f-2c5b6a7d8e9f"
SECRET = "agtkey_test"
REPORTS_URL = f"{DASH}/api/public/v1/agents/{AGENT_ID}/reports"

INITIAL_CONFIG = {
    "config_version": 1,
    "intervals": {"heartbeat_seconds": 15, "check_seconds": 3600, "netbox_sync_seconds": 3600},
    "timeouts": {"tcp_connect_seconds": 5, "tls_handshake_seconds": 5},
    "concurrency": {"max_parallel_checks": 20},
    "alert_thresholds_days": [30, 7, 1],
    "manual_hosts": [
        {
            "host_id": "h1",
            "hostname": "app01.example.com",
            "port": 443,
            "added_at": "2026-04-01T00:00:00Z",
        },
        {
            "host_id": "h2",
            "hostname": "192.168.1.50",
            "port": 8443,
            "added_at": "2026-04-02T00:00:00Z",
        },
    ],
}


@pytest.fixture
def client():
    return DashboardClient(DASH, agent_id=AGENT_ID, agent_secret=SECRET)


def _action(
    *,
    action_type: str = "check_host",
    payload: dict | None = None,
    expires_at: str = "2099-12-31T00:00:00Z",
    action_id: str | None = None,
) -> dict:
    return {
        "action_id": action_id or str(uuid.uuid4()),
        "action_type": action_type,
        "payload": payload or {"host_ref": {"type": "manual", "host_id": "h1"}},
        "queued_at": "2026-05-02T15:00:00Z",
        "expires_at": expires_at,
    }


def _stop_pool(pool: ActionWorkerPool, shutdown: threading.Event, *, timeout: float = 2.0):
    """Set shutdown and join with a strict timeout. Mirror of
    _run_until_exit from Phase 5c — same discipline applied to the
    worker pool."""
    shutdown.set()
    if not pool.join(timeout=timeout):
        alive = [t.name for t in pool._threads if t.is_alive()]
        raise AssertionError(
            f"workers did not exit within {timeout}s: {alive}"
        )


def _success_cert_result(hostname: str, port: int = 443) -> CertResult:
    return CertResult(
        state="success",
        hostname=hostname,
        port=port,
        checked_at="2026-05-02T15:00:03Z",
        subject_cn=hostname,
        subject_sans=[hostname],
        issuer_cn="DigiCert TLS RSA SHA256 2020 CA1",
        issuer_o="DigiCert Inc",
        issuer_full_dn="CN=DigiCert TLS RSA SHA256 2020 CA1,O=DigiCert Inc,C=US",
        ca_category="well_known_public",
        is_self_signed=False,
        not_before="2025-01-01T00:00:00Z",
        not_after="2026-12-31T23:59:59Z",
        days_until_expiry=240,
        signature_algorithm="SHA256withRSA",
        key_size=2048,
        hostname_matches=True,
        chain_trusted_by_system=True,
        chain_error_reason=None,
        error_message=None,
    )


# ============================================================
#  ActionWorkerPool — dispatch + lifecycle
# ============================================================


def test_pool_routes_action_to_correct_handler():
    received = {"check_host": [], "sync_netbox": []}

    def check_host_h(ctx: ActionContext):
        received["check_host"].append(ctx.action_id)

    def sync_netbox_h(ctx: ActionContext):
        received["sync_netbox"].append(ctx.action_id)

    q = queue.Queue()
    shutdown = threading.Event()
    pool = ActionWorkerPool(
        action_queue=q,
        handlers={"check_host": check_host_h, "sync_netbox": sync_netbox_h},
        shutdown_event=shutdown,
        clock=FakeClock(),
        num_workers=2,
    )
    a1 = _action(action_type="check_host", action_id="a1")
    a2 = _action(action_type="sync_netbox", action_id="a2")
    a3 = _action(action_type="check_host", action_id="a3")
    q.put(a1)
    q.put(a2)
    q.put(a3)

    try:
        pool.start()
        # Wait for queue to drain
        q.join()
    finally:
        _stop_pool(pool, shutdown)

    assert sorted(received["check_host"]) == ["a1", "a3"]
    assert received["sync_netbox"] == ["a2"]


def test_unknown_action_type_logs_warning_and_skips(caplog):
    """Forward-compat: a v2 dashboard may queue actions this v1 agent
    doesn't recognize. Don't crash, don't dispatch — just log."""
    handler_called = {"n": 0}

    def known_h(ctx):
        handler_called["n"] += 1

    q = queue.Queue()
    shutdown = threading.Event()
    pool = ActionWorkerPool(
        action_queue=q,
        handlers={"check_host": known_h},
        shutdown_event=shutdown,
        clock=FakeClock(),
        num_workers=1,
    )
    q.put(_action(action_type="check_all_hosts_v2_hint", action_id="unk-1"))
    q.put(_action(action_type="check_host", action_id="known-1"))

    try:
        with caplog.at_level("WARNING"):
            pool.start()
            q.join()
    finally:
        _stop_pool(pool, shutdown)

    # The known one ran; the unknown one was skipped
    assert handler_called["n"] == 1
    skipped = [r.msg for r in caplog.records
               if isinstance(r.msg, dict) and r.msg.get("event") == "action_unknown_type_skipped"]
    assert len(skipped) == 1
    assert skipped[0]["action_id"] == "unk-1"
    assert skipped[0]["action_type"] == "check_all_hosts_v2_hint"


def test_expired_action_skipped_at_pickup(caplog):
    """Defense-in-depth: HeartbeatThread filters at enqueue; workers
    re-check at pickup in case an action sat long enough to expire."""
    handler_called = {"n": 0}

    def h(ctx):
        handler_called["n"] += 1

    q = queue.Queue()
    shutdown = threading.Event()
    pool = ActionWorkerPool(
        action_queue=q,
        handlers={"check_host": h},
        shutdown_event=shutdown,
        clock=FakeClock(),
        num_workers=1,
    )
    q.put(_action(expires_at="2025-01-01T00:00:00Z", action_id="expired"))
    q.put(_action(expires_at="2099-12-31T00:00:00Z", action_id="fresh"))

    try:
        with caplog.at_level("INFO"):
            pool.start()
            q.join()
    finally:
        _stop_pool(pool, shutdown)

    assert handler_called["n"] == 1
    skipped = [r.msg for r in caplog.records
               if isinstance(r.msg, dict) and r.msg.get("event") == "action_skipped_expired_at_pickup"]
    assert len(skipped) == 1
    assert skipped[0]["action_id"] == "expired"


def test_action_skipped_when_shutdown_already_signaled():
    """Same skip-at-pickup pattern as Phase 3: don't start new work
    after shutdown signaled."""
    handler_called = {"n": 0}

    def slow(ctx):
        time.sleep(0.01)
        handler_called["n"] += 1

    q = queue.Queue()
    shutdown = threading.Event()
    pool = ActionWorkerPool(
        action_queue=q,
        handlers={"check_host": slow},
        shutdown_event=shutdown,
        clock=FakeClock(),
        num_workers=1,
    )
    # Pre-shutdown: enqueue several actions, signal shutdown, start pool.
    for i in range(5):
        q.put(_action(action_id=f"a{i}"))
    shutdown.set()

    try:
        pool.start()
        # Workers should exit within their queue.get timeout (0.5s) without
        # picking up any actions — the top-of-loop is_set check exits.
        # Give them a moment.
        for t in pool._threads:
            t.join(timeout=2.0)
        assert all(not t.is_alive() for t in pool._threads)
    finally:
        _stop_pool(pool, shutdown)

    assert handler_called["n"] == 0


def test_handler_exception_does_not_crash_worker(caplog):
    """One bad handler must NOT take down the worker. Subsequent actions
    on the same worker should still be processed."""
    processed = []

    def boom_then_good(ctx):
        processed.append(ctx.action_id)
        if ctx.action_id == "boom":
            raise RuntimeError("kaboom")

    q = queue.Queue()
    shutdown = threading.Event()
    pool = ActionWorkerPool(
        action_queue=q,
        handlers={"check_host": boom_then_good},
        shutdown_event=shutdown,
        clock=FakeClock(),
        num_workers=1,  # one worker, so order is deterministic
    )
    q.put(_action(action_id="before"))
    q.put(_action(action_id="boom"))
    q.put(_action(action_id="after"))

    try:
        with caplog.at_level("ERROR"):
            pool.start()
            q.join()
    finally:
        _stop_pool(pool, shutdown)

    assert processed == ["before", "boom", "after"]
    errors = [r.msg for r in caplog.records
              if isinstance(r.msg, dict) and r.msg.get("event") == "action_handler_unexpected_error"]
    assert len(errors) == 1
    assert errors[0]["action_id"] == "boom"


def test_workers_run_in_parallel_when_pool_has_capacity():
    """4 workers, 4 slow concurrent actions — verify all run concurrently
    via a barrier that forces all to enter their handlers before any
    proceed."""
    barrier = threading.Barrier(4, timeout=2.0)
    finished = []
    finished_lock = threading.Lock()

    def parallel(ctx):
        barrier.wait()  # blocks until 4 threads converge
        with finished_lock:
            finished.append(ctx.action_id)

    q = queue.Queue()
    shutdown = threading.Event()
    pool = ActionWorkerPool(
        action_queue=q,
        handlers={"check_host": parallel},
        shutdown_event=shutdown,
        clock=FakeClock(),
        num_workers=4,
    )
    for i in range(4):
        q.put(_action(action_id=f"a{i}"))

    try:
        pool.start()
        q.join()
    finally:
        _stop_pool(pool, shutdown)

    assert sorted(finished) == [f"a{i}" for i in range(4)]


def test_single_worker_processes_serially():
    in_flight = 0
    max_seen = 0
    lock = threading.Lock()

    def slow(ctx):
        nonlocal in_flight, max_seen
        with lock:
            in_flight += 1
            max_seen = max(max_seen, in_flight)
        time.sleep(0.02)
        with lock:
            in_flight -= 1

    q = queue.Queue()
    shutdown = threading.Event()
    pool = ActionWorkerPool(
        action_queue=q,
        handlers={"check_host": slow},
        shutdown_event=shutdown,
        clock=FakeClock(),
        num_workers=1,
    )
    for i in range(3):
        q.put(_action(action_id=f"a{i}"))

    try:
        pool.start()
        q.join()
    finally:
        _stop_pool(pool, shutdown)

    assert max_seen == 1


def test_task_done_called_for_each_action_even_on_handler_error():
    """queue.join() must return after all actions processed, including
    ones whose handlers raised."""
    def boom(ctx):
        raise RuntimeError("kaboom")

    q = queue.Queue()
    shutdown = threading.Event()
    pool = ActionWorkerPool(
        action_queue=q,
        handlers={"check_host": boom},
        shutdown_event=shutdown,
        clock=FakeClock(),
        num_workers=2,
    )
    for i in range(5):
        q.put(_action(action_id=f"a{i}"))

    try:
        pool.start()
        # If task_done isn't called for failed handlers, this hangs.
        q.join()
    finally:
        _stop_pool(pool, shutdown)


def test_workers_are_daemon_threads():
    """daemon=True so a forgotten join() doesn't prevent process exit.
    Belt-and-braces — the runner is still expected to join explicitly."""
    q = queue.Queue()
    shutdown = threading.Event()
    pool = ActionWorkerPool(
        action_queue=q,
        handlers={},
        shutdown_event=shutdown,
        clock=FakeClock(),
        num_workers=2,
    )
    try:
        pool.start()
        for t in pool._threads:
            assert t.daemon is True
    finally:
        _stop_pool(pool, shutdown)


def test_pool_start_twice_raises():
    pool = ActionWorkerPool(
        action_queue=queue.Queue(),
        handlers={},
        shutdown_event=threading.Event(),
        clock=FakeClock(),
        num_workers=1,
    )
    pool.start()
    try:
        with pytest.raises(RuntimeError, match="already started"):
            pool.start()
    finally:
        _stop_pool(pool, pool._shutdown_event)


# ============================================================
#  check_host handler — host_ref resolution
# ============================================================


def test_check_host_resolves_manual_host_id_to_hostname_and_port(client):
    """Manual host_id present in current config → cert_check called
    with the matching hostname/port."""
    captured = {}

    def fake_check(host, port, *, connect_timeout, handshake_timeout):
        captured["host"] = host
        captured["port"] = port
        captured["connect_timeout"] = connect_timeout
        captured["handshake_timeout"] = handshake_timeout
        return _success_cert_result(host, port)

    config_state = ConfigState(initial=dict(INITIAL_CONFIG))
    handler = make_check_host_handler(
        client=client,
        data_dir="/tmp",  # not used because submit is mocked
        config_state=config_state,
        clock=FakeClock(),
        shutdown_event=threading.Event(),
        check_fn=fake_check,
        submit_fn=lambda **k: None,
    )
    ctx = ActionContext(
        action_id="a1", action_type="check_host",
        payload={"host_ref": {"type": "manual", "host_id": "h2"}},
        queued_at="t0", expires_at="2099-01-01T00:00:00Z",
    )
    handler(ctx)
    assert captured["host"] == "192.168.1.50"
    assert captured["port"] == 8443


def test_check_host_uses_current_config_for_resolution(client):
    """If config is swapped between enqueue and pickup, resolution uses
    the CURRENT config (snapshot)."""
    captured = {}

    def fake_check(host, port, **k):
        captured["host"] = host
        return _success_cert_result(host, port)

    config_state = ConfigState(initial=dict(INITIAL_CONFIG))
    handler = make_check_host_handler(
        client=client, data_dir="/tmp", config_state=config_state,
        clock=FakeClock(), shutdown_event=threading.Event(),
        check_fn=fake_check, submit_fn=lambda **k: None,
    )

    # Replace config: change h1's hostname
    new_config = {
        **INITIAL_CONFIG,
        "config_version": 2,
        "manual_hosts": [
            {"host_id": "h1", "hostname": "renamed.example.com", "port": 443,
             "added_at": "2026-04-01T00:00:00Z"},
        ],
    }
    config_state.replace(new_config)

    ctx = ActionContext(
        action_id="a1", action_type="check_host",
        payload={"host_ref": {"type": "manual", "host_id": "h1"}},
        queued_at="t0", expires_at="2099-01-01T00:00:00Z",
    )
    handler(ctx)
    assert captured["host"] == "renamed.example.com"


def test_check_host_skips_when_host_id_not_in_config(client, caplog):
    """Per the agreed answer to Question 2: log + skip, no synthetic
    failure report. The action expires unfulfilled."""
    check_called = {"n": 0}
    submit_called = {"n": 0}

    def fake_check(*a, **k):
        check_called["n"] += 1
        return _success_cert_result("x", 443)

    def fake_submit(**k):
        submit_called["n"] += 1

    config_state = ConfigState(initial=dict(INITIAL_CONFIG))
    handler = make_check_host_handler(
        client=client, data_dir="/tmp", config_state=config_state,
        clock=FakeClock(), shutdown_event=threading.Event(),
        check_fn=fake_check, submit_fn=fake_submit,
    )
    ctx = ActionContext(
        action_id="a1", action_type="check_host",
        payload={"host_ref": {"type": "manual", "host_id": "missing-id"}},
        queued_at="t0", expires_at="2099-01-01T00:00:00Z",
    )
    with caplog.at_level("INFO"):
        handler(ctx)

    assert check_called["n"] == 0
    assert submit_called["n"] == 0
    skip_logs = [r.msg for r in caplog.records
                 if isinstance(r.msg, dict) and r.msg.get("event") == "action_check_host_skipped_host_not_found"]
    assert len(skip_logs) == 1
    log_data = skip_logs[0]
    # Diagnostic fields present per the spec
    assert log_data["action_id"] == "a1"
    assert log_data["host_id"] == "missing-id"
    assert log_data["current_config_version"] == 1
    assert log_data["manual_hosts_count"] == 2


def test_check_host_netbox_ref_resolves_via_netbox_hosts_state(client):
    """The netbox host_ref now goes through the same cert-check pipeline
    as manual hosts. The handler resolves netbox_device_id to (hostname,
    port) via NetBoxHostsState, then calls check_fn + submit_fn just
    like the manual path."""
    from certwatch.netbox_client import DiscoveredHost
    from certwatch.netbox_sync import NetBoxHostsState

    captured = {}

    def fake_check(host, port, **k):
        captured["host"] = host
        captured["port"] = port
        return _success_cert_result(host, port)

    def fake_submit(*, checks, action_id, **k):
        captured["checks"] = checks
        captured["action_id"] = action_id

    netbox_state = NetBoxHostsState()
    netbox_state.replace([
        DiscoveredHost(
            netbox_device_id=1247,
            hostname="esxi02.collabtips.net",
            port=443,
            display_name="esxi02",
            tags=["vmware"],
        ),
    ])

    handler = make_check_host_handler(
        client=client, data_dir="/tmp",
        config_state=ConfigState(initial=dict(INITIAL_CONFIG)),
        clock=FakeClock(), shutdown_event=threading.Event(),
        check_fn=fake_check, submit_fn=fake_submit,
        netbox_hosts_state=netbox_state,
    )
    ctx = ActionContext(
        action_id="act-uuid-1", action_type="check_host",
        payload={"host_ref": {"type": "netbox", "netbox_device_id": 1247}},
        queued_at="t0", expires_at="2099-01-01T00:00:00Z",
    )
    handler(ctx)

    # cert_check called with NetBox-derived hostname/port
    assert captured["host"] == "esxi02.collabtips.net"
    assert captured["port"] == 443
    # Report submitted with the netbox host_ref echoed and action_id set
    assert captured["action_id"] == "act-uuid-1"
    assert len(captured["checks"]) == 1
    assert captured["checks"][0]["host_ref"] == {
        "type": "netbox", "netbox_device_id": 1247,
    }


def test_check_host_netbox_ref_skips_when_id_not_found(client, caplog):
    """If the netbox_device_id isn't in our state snapshot (sync hasn't
    happened or the host was removed from NetBox), log+skip with rich
    diagnostic context. Don't synthesize a fake report — that would
    pollute the host's history with a phantom failure."""
    from certwatch.netbox_sync import NetBoxHostsState

    check_called = {"n": 0}
    submit_called = {"n": 0}

    def fake_check(*a, **k):
        check_called["n"] += 1

    def fake_submit(**k):
        submit_called["n"] += 1

    netbox_state = NetBoxHostsState()  # empty — no sync has happened

    handler = make_check_host_handler(
        client=client, data_dir="/tmp",
        config_state=ConfigState(initial=dict(INITIAL_CONFIG)),
        clock=FakeClock(), shutdown_event=threading.Event(),
        check_fn=fake_check, submit_fn=fake_submit,
        netbox_hosts_state=netbox_state,
    )
    ctx = ActionContext(
        action_id="a1", action_type="check_host",
        payload={"host_ref": {"type": "netbox", "netbox_device_id": 9999}},
        queued_at="t0", expires_at="2099-01-01T00:00:00Z",
    )
    with caplog.at_level("INFO"):
        handler(ctx)

    assert check_called["n"] == 0
    assert submit_called["n"] == 0
    skip_logs = [r.msg for r in caplog.records
                 if isinstance(r.msg, dict) and r.msg.get("event") == "action_check_host_netbox_id_not_found"]
    assert len(skip_logs) == 1
    assert skip_logs[0]["netbox_device_id"] == 9999
    assert skip_logs[0]["current_netbox_hosts_count"] == 0


def test_check_host_netbox_ref_skips_when_state_is_none(client, caplog):
    """If NetBox isn't configured at all (state is None — possible in
    older runner code paths or test setups), the handler still skips
    cleanly via the same not-found log event with count=0."""
    check_called = {"n": 0}

    def fake_check(*a, **k):
        check_called["n"] += 1

    handler = make_check_host_handler(
        client=client, data_dir="/tmp",
        config_state=ConfigState(initial=dict(INITIAL_CONFIG)),
        clock=FakeClock(), shutdown_event=threading.Event(),
        check_fn=fake_check, submit_fn=lambda **k: None,
        netbox_hosts_state=None,
    )
    ctx = ActionContext(
        action_id="a1", action_type="check_host",
        payload={"host_ref": {"type": "netbox", "netbox_device_id": 1247}},
        queued_at="t0", expires_at="2099-01-01T00:00:00Z",
    )
    with caplog.at_level("INFO"):
        handler(ctx)

    assert check_called["n"] == 0
    skip_logs = [r.msg for r in caplog.records
                 if isinstance(r.msg, dict) and r.msg.get("event") == "action_check_host_netbox_id_not_found"]
    assert len(skip_logs) == 1
    assert skip_logs[0]["current_netbox_hosts_count"] == 0


# ============================================================
#  check_host handler — report submission integration
# ============================================================


def test_check_host_submits_on_demand_report_with_action_id_echoed(client, tmp_path):
    """End-to-end: cert_check returns a CertResult, handler builds the
    on_demand report, submit_report_with_retry sends it. Verify the
    wire payload has report_type='on_demand', action_id matches the
    inbound action, and report_id is FRESH (not the action_id)."""
    sent = {}

    def handler_response(request):
        sent["body"] = json.loads(request.body)
        return (200, {}, json.dumps({
            "received_at": "2026-05-02T15:00:00Z",
            "report_id": json.loads(request.body)["report_id"],
            "summary": {"total_checks": 1, "success": 1,
                         "connection_failed": 0, "tls_failed": 0,
                         "alerts_triggered": 0, "ignored_unknown_hosts": 0},
            "action_completed": json.loads(request.body)["action_id"],
        }))

    def fake_check(host, port, **k):
        return _success_cert_result(host, port)

    config_state = ConfigState(initial=dict(INITIAL_CONFIG))
    handler = make_check_host_handler(
        client=client, data_dir=tmp_path, config_state=config_state,
        clock=FakeClock(), shutdown_event=threading.Event(),
        check_fn=fake_check,
    )
    action_id = "act-uuid-12345"
    ctx = ActionContext(
        action_id=action_id, action_type="check_host",
        payload={"host_ref": {"type": "manual", "host_id": "h1"}},
        queued_at="t0", expires_at="2099-01-01T00:00:00Z",
    )
    with responses.RequestsMock() as rsps:
        rsps.add_callback("POST", REPORTS_URL, callback=handler_response)
        handler(ctx)

    body = sent["body"]
    assert body["report_type"] == "on_demand"
    assert body["action_id"] == action_id
    # report_id is fresh — not the action_id
    assert body["report_id"] != action_id
    # And it's a UUID
    uuid.UUID(body["report_id"])  # raises if not a valid UUID
    # Single check in the batch
    assert len(body["checks"]) == 1
    check = body["checks"][0]
    assert check["host_ref"] == {"type": "manual", "host_id": "h1"}
    assert check["status"] == "success"
    assert check["cert"]["subject_cn"] == "app01.example.com"


def test_check_host_passes_timeouts_from_config_to_cert_check(client, tmp_path):
    """Per-check timeouts come from config['timeouts'], not hardcoded."""
    captured = {}

    def fake_check(host, port, *, connect_timeout, handshake_timeout):
        captured["connect"] = connect_timeout
        captured["handshake"] = handshake_timeout
        return _success_cert_result(host, port)

    custom_config = {
        **INITIAL_CONFIG,
        "timeouts": {"tcp_connect_seconds": 3, "tls_handshake_seconds": 7},
    }
    handler = make_check_host_handler(
        client=client, data_dir=tmp_path,
        config_state=ConfigState(initial=custom_config),
        clock=FakeClock(), shutdown_event=threading.Event(),
        check_fn=fake_check,
        submit_fn=lambda **k: None,
    )
    ctx = ActionContext(
        action_id="a1", action_type="check_host",
        payload={"host_ref": {"type": "manual", "host_id": "h1"}},
        queued_at="t0", expires_at="2099-01-01T00:00:00Z",
    )
    handler(ctx)
    assert captured["connect"] == 3.0
    assert captured["handshake"] == 7.0


def test_check_host_order_cert_check_before_submit(client, tmp_path):
    """Order-of-operations test, mirroring the Phase 5c pattern. cert_check
    must run BEFORE submit_report — not in parallel, not the other way
    around. Pin via call_order list."""
    call_order = []

    def fake_check(host, port, **k):
        call_order.append("cert_check")
        return _success_cert_result(host, port)

    def fake_submit(**k):
        call_order.append("submit_report")

    handler = make_check_host_handler(
        client=client, data_dir=tmp_path,
        config_state=ConfigState(initial=dict(INITIAL_CONFIG)),
        clock=FakeClock(), shutdown_event=threading.Event(),
        check_fn=fake_check, submit_fn=fake_submit,
    )
    ctx = ActionContext(
        action_id="a1", action_type="check_host",
        payload={"host_ref": {"type": "manual", "host_id": "h1"}},
        queued_at="t0", expires_at="2099-01-01T00:00:00Z",
    )
    handler(ctx)
    assert call_order == ["cert_check", "submit_report"]


def test_check_host_started_at_before_completed_at(client, tmp_path):
    """started_at captured BEFORE cert_check, completed_at AFTER —
    the report's timing reflects the actual check."""
    timestamps = {}

    def fake_check(host, port, **k):
        time.sleep(0.01)  # nudge wall-clock so timestamps differ
        return _success_cert_result(host, port)

    def fake_submit(*, started_at, completed_at, **k):
        timestamps["started_at"] = started_at
        timestamps["completed_at"] = completed_at

    handler = make_check_host_handler(
        client=client, data_dir=tmp_path,
        config_state=ConfigState(initial=dict(INITIAL_CONFIG)),
        clock=FakeClock(), shutdown_event=threading.Event(),
        check_fn=fake_check, submit_fn=fake_submit,
    )
    ctx = ActionContext(
        action_id="a1", action_type="check_host",
        payload={"host_ref": {"type": "manual", "host_id": "h1"}},
        queued_at="t0", expires_at="2099-01-01T00:00:00Z",
    )
    handler(ctx)
    # ISO 8601 strings sort lexicographically as time
    assert timestamps["started_at"] <= timestamps["completed_at"]


def test_check_host_with_connection_failed_result_sends_cert_null(client, tmp_path):
    sent = {}

    def fake_check(host, port, **k):
        return CertResult(
            state="connection_failed", hostname=host, port=port,
            checked_at="2026-05-02T15:00:00Z",
            error_message="TimeoutError: timed out",
        )

    def fake_submit(*, checks, **k):
        sent["check"] = checks[0]

    handler = make_check_host_handler(
        client=client, data_dir=tmp_path,
        config_state=ConfigState(initial=dict(INITIAL_CONFIG)),
        clock=FakeClock(), shutdown_event=threading.Event(),
        check_fn=fake_check, submit_fn=fake_submit,
    )
    ctx = ActionContext(
        action_id="a1", action_type="check_host",
        payload={"host_ref": {"type": "manual", "host_id": "h1"}},
        queued_at="t0", expires_at="2099-01-01T00:00:00Z",
    )
    handler(ctx)
    check = sent["check"]
    assert check["status"] == "connection_failed"
    assert check["cert"] is None
    assert check["error_reason"] == "TimeoutError: timed out"


def test_check_host_with_tls_failed_with_cert_includes_cert_dict(client, tmp_path):
    """tls_failed but cert was recovered (the badssl/expired pattern):
    the report includes cert details so the dashboard can show
    'Certificate expired on date X'."""
    sent = {}

    def fake_check(host, port, **k):
        return CertResult(
            state="tls_failed", hostname=host, port=port,
            checked_at="2026-05-02T15:00:00Z",
            error_message="certificate has expired",
            subject_cn="app.example.com",
            subject_sans=["app.example.com"],
            issuer_cn="DigiCert",
            issuer_o="DigiCert Inc",
            issuer_full_dn="CN=DigiCert,O=DigiCert Inc",
            ca_category="well_known_public",
            is_self_signed=False,
            not_before="2025-01-01T00:00:00Z",
            not_after="2025-06-01T00:00:00Z",
            days_until_expiry=-30,
            signature_algorithm="SHA256withRSA",
            key_size=2048,
            hostname_matches=True,
            chain_trusted_by_system=False,
            chain_error_reason="certificate has expired",
        )

    def fake_submit(*, checks, **k):
        sent["check"] = checks[0]

    handler = make_check_host_handler(
        client=client, data_dir=tmp_path,
        config_state=ConfigState(initial=dict(INITIAL_CONFIG)),
        clock=FakeClock(), shutdown_event=threading.Event(),
        check_fn=fake_check, submit_fn=fake_submit,
    )
    ctx = ActionContext(
        action_id="a1", action_type="check_host",
        payload={"host_ref": {"type": "manual", "host_id": "h1"}},
        queued_at="t0", expires_at="2099-01-01T00:00:00Z",
    )
    handler(ctx)
    check = sent["check"]
    assert check["status"] == "tls_failed"
    assert check["error_reason"] == "certificate has expired"
    assert check["cert"] is not None
    assert check["cert"]["days_until_expiry"] == -30
    assert check["cert"]["chain_trusted_by_system"] is False
    assert check["cert"]["ca_category"] == "well_known_public"


# ============================================================
#  check_host handler — auth-error propagation through pool
# ============================================================


def test_check_host_auth_error_signals_global_shutdown(client, tmp_path):
    """When submit_report_with_retry raises DashboardAuthError, the pool's
    dispatcher catches it, sets shutdown_event, and the worker exits."""

    def fake_check(host, port, **k):
        return _success_cert_result(host, port)

    err = {"error": {"code": "agent_revoked", "message": "revoked",
                     "request_id": "req_r"}}

    config_state = ConfigState(initial=dict(INITIAL_CONFIG))
    shutdown = threading.Event()
    handler = make_check_host_handler(
        client=client, data_dir=tmp_path, config_state=config_state,
        clock=FakeClock(), shutdown_event=shutdown,
        check_fn=fake_check,
    )
    q = queue.Queue()
    pool = ActionWorkerPool(
        action_queue=q,
        handlers={"check_host": handler},
        shutdown_event=shutdown,
        clock=FakeClock(),
        num_workers=1,
    )
    q.put(_action(payload={"host_ref": {"type": "manual", "host_id": "h1"}}))

    try:
        with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
            rsps.add("POST", REPORTS_URL, json=err, status=401)
            pool.start()
            # Wait for worker to process the auth error and exit
            for t in pool._threads:
                t.join(timeout=2.0)
            assert all(not t.is_alive() for t in pool._threads)
    finally:
        _stop_pool(pool, shutdown)

    assert shutdown.is_set()


# ============================================================
#  sync_netbox placeholder
# ============================================================


def test_sync_netbox_placeholder_logs_and_returns(caplog):
    """The deprecated placeholder remains as a thin alias for the
    not-configured behavior of the real handler. Same event name across
    both code paths so log-grepping for "NetBox sync configured?" gives
    one consistent answer."""
    handler = make_sync_netbox_placeholder_handler()
    ctx = ActionContext(
        action_id="a1", action_type="sync_netbox",
        payload={}, queued_at="t0", expires_at="2099-01-01T00:00:00Z",
    )
    with caplog.at_level("INFO"):
        handler(ctx)  # must not raise
    msgs = [r.msg for r in caplog.records
            if isinstance(r.msg, dict) and r.msg.get("event") == "netbox_sync_action_received_but_not_configured"]
    assert len(msgs) == 1


# ============================================================
#  internal helpers
# ============================================================


def test_resolve_manual_host_returns_hostname_and_port():
    config = {"manual_hosts": [
        {"host_id": "h1", "hostname": "x.example", "port": 443,
         "added_at": "t"},
        {"host_id": "h2", "hostname": "y.example", "port": 8443,
         "added_at": "t"},
    ]}
    assert _resolve_manual_host("h1", config) == ("x.example", 443)
    assert _resolve_manual_host("h2", config) == ("y.example", 8443)


def test_resolve_manual_host_returns_none_when_not_found():
    config = {"manual_hosts": [{"host_id": "h1", "hostname": "x", "port": 443}]}
    assert _resolve_manual_host("missing", config) is None


def test_resolve_manual_host_returns_none_when_empty_id():
    config = {"manual_hosts": [{"host_id": "h1", "hostname": "x", "port": 443}]}
    assert _resolve_manual_host(None, config) is None
    assert _resolve_manual_host("", config) is None


def test_resolve_manual_host_returns_none_when_no_manual_hosts():
    """The natural-empty pattern: missing key should not crash."""
    assert _resolve_manual_host("any", {}) is None
    assert _resolve_manual_host("any", {"manual_hosts": []}) is None
    assert _resolve_manual_host("any", {"manual_hosts": None}) is None


def test_resolve_manual_host_defaults_port_to_443():
    config = {"manual_hosts": [{"host_id": "h1", "hostname": "x"}]}  # no port
    assert _resolve_manual_host("h1", config) == ("x", 443)


def test_cert_dict_from_result_returns_none_for_connection_failed():
    r = CertResult(
        state="connection_failed", hostname="x", port=443,
        checked_at="t", error_message="timeout",
    )
    assert _cert_dict_from_result(r) is None


def test_cert_dict_from_result_returns_none_for_tls_failed_without_cert():
    """TLS failed before cert exchange (handshake protocol error) — no
    cert data to include."""
    r = CertResult(
        state="tls_failed", hostname="x", port=443,
        checked_at="t", error_message="protocol violation",
        # All cert fields default to None
    )
    assert _cert_dict_from_result(r) is None


def test_cert_dict_from_result_returns_dict_for_success():
    r = _success_cert_result("x.example.com")
    d = _cert_dict_from_result(r)
    assert d is not None
    # All 15 fields present
    expected = {
        "subject_cn", "subject_sans", "issuer_cn", "issuer_o",
        "issuer_full_dn", "ca_category", "is_self_signed",
        "not_before", "not_after", "days_until_expiry",
        "signature_algorithm", "key_size", "hostname_matches",
        "chain_trusted_by_system", "chain_error_reason",
    }
    assert set(d.keys()) == expected


def test_build_check_payload_includes_host_ref_unchanged():
    """The host_ref the agent received goes back to the dashboard
    unchanged — the dashboard resolves netbox refs to internal UUIDs
    via (agent_id, netbox_device_id) lookup; the agent doesn't translate."""
    netbox_ref = {"type": "netbox", "netbox_device_id": 1247}
    r = _success_cert_result("app01.example.com")
    payload = _build_check_payload(netbox_ref, r)
    assert payload["host_ref"] == netbox_ref
    assert payload["host_ref"]["netbox_device_id"] == 1247
