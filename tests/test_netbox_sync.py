"""Phase 6 — run_netbox_sync orchestration + NetBoxSyncThread tests.

NetBoxClient.fetch_hosts is mocked at the instance level so tests
control NetBox behavior directly without re-doing the pynetbox
fakery from test_netbox_client.py. The dashboard side uses real
DashboardClient with `responses`-mocked HTTP, so the wire format is
exercised end-to-end.
"""

from __future__ import annotations

import json
import threading
import time
from unittest.mock import MagicMock

import pytest
import requests
import responses

from certwatch.clock import FakeClock
from certwatch.dashboard_client import DashboardAuthError, DashboardClient
from certwatch.heartbeat_thread import ConfigState, StatsState
from certwatch.netbox_client import (
    DiscoveredHost,
    NetBoxClient,
    NetBoxSyncError,
)
from certwatch.netbox_sync import (
    BACKOFF_SCHEDULE,
    NetBoxSyncResult,
    NetBoxSyncThread,
    _backoff_delay,
    _host_to_payload,
    run_netbox_sync,
)


DASH = "https://certwatch.lovable.app"
AGENT_ID = "a8f3d12e-7b4c-4d8a-9e1f-2c5b6a7d8e9f"
SECRET = "agtkey_test"
DISCOVERED_URL = f"{DASH}/api/public/v1/agents/{AGENT_ID}/discovered-hosts"

NETBOX_URL = "https://netbox.kurmi-lab-paris.local"
NETBOX_FILTER = "tag=monitor-cert"

OK_RESPONSE = {
    "received_at": "2026-05-02T14:40:01Z",
    "summary": {
        "total_received": 0,
        "created": 0,
        "updated": 0,
        "removed": 0,
        "unchanged": 0,
    },
    "config_version": 12,
    "action_completed": None,
}


@pytest.fixture
def dashboard_client():
    return DashboardClient(DASH, agent_id=AGENT_ID, agent_secret=SECRET)


@pytest.fixture
def stats():
    return StatsState(clock=FakeClock())


def _fake_netbox_client(hosts=None, *, raise_on_fetch=None):
    nb = MagicMock(spec=NetBoxClient)
    nb.url = NETBOX_URL
    nb.filter_expr = NETBOX_FILTER
    if raise_on_fetch is not None:
        nb.fetch_hosts.side_effect = raise_on_fetch
    else:
        nb.fetch_hosts.return_value = hosts or []
    return nb


def _hosts(*items: tuple[int, str, int]) -> list[DiscoveredHost]:
    return [
        DiscoveredHost(
            netbox_device_id=did, hostname=hn, port=port,
            display_name=f"d{did}", tags=["monitor-cert"],
        )
        for did, hn, port in items
    ]


# ============================================================
#  Successful sync end-to-end
# ============================================================


def test_successful_sync_returns_status_and_updates_stats(dashboard_client, stats):
    nb = _fake_netbox_client(_hosts((1, "10.0.0.1", 443), (2, "10.0.0.2", 8443)))

    with responses.RequestsMock() as rsps:
        rsps.add("POST", DISCOVERED_URL,
                 json={**OK_RESPONSE,
                       "summary": {**OK_RESPONSE["summary"],
                                    "total_received": 2, "created": 2}},
                 status=200)
        result = run_netbox_sync(
            netbox_client=nb, dashboard_client=dashboard_client,
            action_id=None, stats_state=stats, clock=FakeClock(),
        )

    assert result.status == "success"
    assert result.hosts_count == 2
    assert result.submission_summary["summary"]["total_received"] == 2
    # Stats updated
    snap = stats.snapshot_for_heartbeat()
    assert snap is not None
    assert "last_netbox_sync_at" in snap


def test_empty_hosts_from_netbox_still_submits(dashboard_client, stats):
    """The 'NetBox filter matched nothing' case is legitimate — submit
    [] explicitly so the dashboard's replace semantics remove any
    previously-NetBox-sourced hosts."""
    nb = _fake_netbox_client([])

    sent_payload = {}

    def handler(request):
        sent_payload.update(json.loads(request.body))
        return (200, {},
                json.dumps({**OK_RESPONSE,
                            "summary": {**OK_RESPONSE["summary"], "removed": 5}}))

    with responses.RequestsMock() as rsps:
        rsps.add_callback("POST", DISCOVERED_URL, callback=handler)
        result = run_netbox_sync(
            netbox_client=nb, dashboard_client=dashboard_client,
            action_id=None, stats_state=stats, clock=FakeClock(),
        )

    assert result.status == "success"
    assert sent_payload["hosts"] == []
    assert result.submission_summary["summary"]["removed"] == 5


def test_payload_format_matches_contract(dashboard_client, stats):
    nb = _fake_netbox_client([
        DiscoveredHost(
            netbox_device_id=1247, hostname="app01.example.com", port=443,
            display_name="App 01", tags=["monitor-cert", "web"],
        ),
    ])
    sent = {}

    def handler(request):
        sent.update(json.loads(request.body))
        return (200, {}, json.dumps(OK_RESPONSE))

    with responses.RequestsMock() as rsps:
        rsps.add_callback("POST", DISCOVERED_URL, callback=handler)
        run_netbox_sync(
            netbox_client=nb, dashboard_client=dashboard_client,
            action_id=None, stats_state=stats, clock=FakeClock(),
        )

    assert sent["netbox_url"] == NETBOX_URL
    assert sent["netbox_filter"] == NETBOX_FILTER
    assert sent["synced_at"].endswith("Z")
    assert sent["hosts"] == [{
        "netbox_device_id": 1247,
        "hostname": "app01.example.com",
        "port": 443,
        "display_name": "App 01",
        "tags": ["monitor-cert", "web"],
    }]


# ============================================================
#  action_id null vs string (wire-bytes assertion)
# ============================================================


def test_action_id_null_when_none_wire_bytes(dashboard_client, stats):
    """Same defensive pattern as Phase 4d/4e: scheduled syncs send
    action_id explicitly as `null` in the body, not omitted."""
    nb = _fake_netbox_client([])
    captured = {}

    def handler(request):
        captured["body_str"] = request.body
        return (200, {}, json.dumps(OK_RESPONSE))

    with responses.RequestsMock() as rsps:
        rsps.add_callback("POST", DISCOVERED_URL, callback=handler)
        run_netbox_sync(
            netbox_client=nb, dashboard_client=dashboard_client,
            action_id=None, stats_state=stats, clock=FakeClock(),
        )

    body_str = captured["body_str"]
    assert '"action_id": null' in body_str
    body = json.loads(body_str)
    assert body["action_id"] is None


def test_action_id_string_passed_through(dashboard_client, stats):
    nb = _fake_netbox_client([])
    captured = {}

    def handler(request):
        captured["body"] = json.loads(request.body)
        return (200, {}, json.dumps(OK_RESPONSE))

    with responses.RequestsMock() as rsps:
        rsps.add_callback("POST", DISCOVERED_URL, callback=handler)
        run_netbox_sync(
            netbox_client=nb, dashboard_client=dashboard_client,
            action_id="action-uuid-abc", stats_state=stats, clock=FakeClock(),
        )

    assert captured["body"]["action_id"] == "action-uuid-abc"


# ============================================================
#  Safety contract: NetBox failure → no submission
# ============================================================


def test_netbox_error_does_not_call_submit(dashboard_client, stats):
    """The defining safety contract of this phase: NetBox failure must
    NEVER trigger an empty hosts submission (which would wipe every
    NetBox-sourced host on the dashboard)."""
    nb = _fake_netbox_client(
        raise_on_fetch=NetBoxSyncError(
            "connection refused",
            original_error=requests.ConnectionError("ECONNREFUSED"),
        ),
    )

    # No responses mock registered — if submit is called, it'll raise
    # ConnectionError and the test sees it.
    with responses.RequestsMock():
        result = run_netbox_sync(
            netbox_client=nb, dashboard_client=dashboard_client,
            action_id=None, stats_state=stats, clock=FakeClock(),
        )

    assert result.status == "netbox_error"
    assert result.hosts_count == 0
    # Stats NOT updated (no successful sync)
    assert stats.snapshot_for_heartbeat() is None


# ============================================================
#  Submission error mapping
# ============================================================


def test_413_payload_too_large_returns_submission_error_no_retry(dashboard_client, stats):
    """Caller (operator) needs to refine NETBOX_FILTER; retrying same
    payload would just fail the same way."""
    nb = _fake_netbox_client(_hosts((1, "10.0.0.1", 443)))
    fc = FakeClock()

    err = {"error": {"code": "payload_too_large",
                      "message": "max 1000 hosts", "request_id": "req_p"}}
    with responses.RequestsMock() as rsps:
        rsps.add("POST", DISCOVERED_URL, json=err, status=413)
        result = run_netbox_sync(
            netbox_client=nb, dashboard_client=dashboard_client,
            action_id=None, stats_state=stats, clock=fc,
        )

    assert result.status == "submission_error"
    assert fc.sleeps == []  # no retries


def test_400_validation_failed_returns_submission_error(dashboard_client, stats):
    nb = _fake_netbox_client(_hosts((1, "10.0.0.1", 443)))
    fc = FakeClock()
    err = {"error": {"code": "validation_failed",
                      "message": "duplicate netbox_device_id", "request_id": "req_v"}}
    with responses.RequestsMock() as rsps:
        rsps.add("POST", DISCOVERED_URL, json=err, status=400)
        result = run_netbox_sync(
            netbox_client=nb, dashboard_client=dashboard_client,
            action_id=None, stats_state=stats, clock=fc,
        )

    assert result.status == "submission_error"
    assert fc.sleeps == []


def test_5xx_retried_with_backoff_then_succeeds(dashboard_client, stats):
    """Same backoff schedule as bootstrap/report_submission. Pin both
    the retry behavior AND the schedule values."""
    nb = _fake_netbox_client(_hosts((1, "10.0.0.1", 443)))
    fc = FakeClock()

    err = {"error": {"code": "internal_error", "message": "boom"}}
    with responses.RequestsMock() as rsps:
        rsps.add("POST", DISCOVERED_URL, json=err, status=503)
        rsps.add("POST", DISCOVERED_URL, json=err, status=503)
        rsps.add("POST", DISCOVERED_URL, json=OK_RESPONSE, status=200)
        result = run_netbox_sync(
            netbox_client=nb, dashboard_client=dashboard_client,
            action_id=None, stats_state=stats, clock=fc,
        )

    assert result.status == "success"
    assert fc.sleeps == [5.0, 15.0]


def test_network_error_treated_as_retriable(dashboard_client, stats, monkeypatch):
    nb = _fake_netbox_client(_hosts((1, "10.0.0.1", 443)))
    fc = FakeClock()

    real_request = requests.Session.request
    call_count = {"n": 0}

    def flaky(self, method, url, **kw):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise requests.Timeout("read timeout")
        return real_request(self, method, url, **kw)

    monkeypatch.setattr(requests.Session, "request", flaky)

    with responses.RequestsMock() as rsps:
        rsps.add("POST", DISCOVERED_URL, json=OK_RESPONSE, status=200)
        result = run_netbox_sync(
            netbox_client=nb, dashboard_client=dashboard_client,
            action_id=None, stats_state=stats, clock=fc,
        )

    assert result.status == "success"
    assert fc.sleeps == [5.0]


def test_401_auth_error_re_raises(dashboard_client, stats):
    """Auth errors must propagate so the caller (action dispatcher or
    NetBoxSyncThread) triggers global shutdown — same pattern as
    submit_report_with_retry."""
    nb = _fake_netbox_client(_hosts((1, "10.0.0.1", 443)))
    err = {"error": {"code": "agent_revoked", "message": "revoked",
                      "request_id": "req_r"}}
    with responses.RequestsMock() as rsps:
        rsps.add("POST", DISCOVERED_URL, json=err, status=401)
        with pytest.raises(DashboardAuthError) as exc:
            run_netbox_sync(
                netbox_client=nb, dashboard_client=dashboard_client,
                action_id=None, stats_state=stats, clock=FakeClock(),
            )
    assert exc.value.code == "agent_revoked"


def test_shutdown_during_retries_returns_shutdown(dashboard_client, stats):
    nb = _fake_netbox_client(_hosts((1, "10.0.0.1", 443)))
    fc = FakeClock()
    shutdown = threading.Event()

    err = {"error": {"code": "internal_error", "message": "boom"}}

    def handler(request):
        shutdown.set()  # set during the request; next backoff returns shutdown
        return (503, {}, json.dumps(err))

    with responses.RequestsMock() as rsps:
        rsps.add_callback("POST", DISCOVERED_URL, callback=handler)
        result = run_netbox_sync(
            netbox_client=nb, dashboard_client=dashboard_client,
            action_id=None, stats_state=stats, clock=fc,
            shutdown_event=shutdown,
        )

    assert result.status == "shutdown"


# ============================================================
#  Constants and helpers
# ============================================================


def test_backoff_schedule_pinned_to_contract_values():
    """Same defensive pattern as bootstrap/report_submission. NetBox
    sync's schedule is independent so v2 can drift it without
    coupling — but for v1 they all match the documented sequence."""
    assert BACKOFF_SCHEDULE == (5.0, 15.0, 30.0, 60.0, 120.0)


def test_backoff_delay_follows_schedule():
    assert [_backoff_delay(n) for n in (1, 2, 3, 4, 5)] == [5.0, 15.0, 30.0, 60.0, 120.0]


def test_backoff_delay_caps_at_steady_state():
    assert _backoff_delay(50) == 120.0


def test_host_to_payload_includes_required_fields():
    h = DiscoveredHost(
        netbox_device_id=1, hostname="x", port=443,
        display_name=None, tags=[],
    )
    p = _host_to_payload(h)
    assert p["netbox_device_id"] == 1
    assert p["hostname"] == "x"
    assert p["port"] == 443
    assert p["tags"] == []
    # display_name omitted when None (optional field)
    assert "display_name" not in p
    # ip_address omitted when None (no primary_ip on the device)
    assert "ip_address" not in p


def test_host_to_payload_includes_display_name_when_set():
    h = DiscoveredHost(
        netbox_device_id=1, hostname="x", port=443,
        display_name="App 01", tags=["a"],
    )
    p = _host_to_payload(h)
    assert p["display_name"] == "App 01"


def test_host_to_payload_includes_ip_address_when_set():
    """ip_address rides alongside hostname so the dashboard can render
    both — title typically shows IP, subtitle shows FQDN. Tolerant
    readers that don't yet know about ip_address simply ignore it."""
    h = DiscoveredHost(
        netbox_device_id=1247, hostname="esxi02.collabtips.net",
        port=443, display_name="esxi02", tags=["vmware"],
        ip_address="10.10.2.22",
    )
    p = _host_to_payload(h)
    assert p["hostname"] == "esxi02.collabtips.net"
    assert p["ip_address"] == "10.10.2.22"


# ============================================================
#  NetBoxSyncThread
# ============================================================


def _stop_thread(thread, shutdown, timeout=2.0):
    shutdown.set()
    thread.join(timeout=timeout)
    assert not thread.is_alive(), (
        f"{thread.name} did not exit within {timeout}s — likely a deadlock"
    )


INITIAL_CONFIG = {
    "config_version": 1,
    "intervals": {"heartbeat_seconds": 15, "check_seconds": 3600,
                  "netbox_sync_seconds": 3600},
    "timeouts": {"tcp_connect_seconds": 5, "tls_handshake_seconds": 5},
    "concurrency": {"max_parallel_checks": 20},
    "alert_thresholds_days": [30, 7, 1],
    "manual_hosts": [],
}


def test_netbox_sync_thread_first_sync_immediate(dashboard_client, stats):
    fc = FakeClock()
    nb = _fake_netbox_client(_hosts((1, "10.0.0.1", 443)))
    shutdown = threading.Event()
    config = ConfigState(initial=dict(INITIAL_CONFIG))

    sync_count = {"n": 0}

    def handler(request):
        sync_count["n"] += 1
        if sync_count["n"] >= 1:
            shutdown.set()
        return (200, {}, json.dumps(OK_RESPONSE))

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add_callback("POST", DISCOVERED_URL, callback=handler)
        thread = NetBoxSyncThread(
            netbox_client=nb, dashboard_client=dashboard_client,
            config_state=config, stats_state=stats,
            shutdown_event=shutdown, clock=fc,
        )
        try:
            thread.start()
            thread.join(timeout=2.0)
        finally:
            _stop_thread(thread, shutdown)

    assert sync_count["n"] == 1


def test_netbox_sync_thread_subsequent_syncs_wait_netbox_sync_seconds(dashboard_client, stats):
    fc = FakeClock()
    nb = _fake_netbox_client([])
    shutdown = threading.Event()
    config = ConfigState(initial=dict(INITIAL_CONFIG))

    sync_count = {"n": 0}

    def handler(request):
        sync_count["n"] += 1
        if sync_count["n"] >= 3:
            shutdown.set()
        return (200, {}, json.dumps(OK_RESPONSE))

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add_callback("POST", DISCOVERED_URL, callback=handler)
        rsps.add_callback("POST", DISCOVERED_URL, callback=handler)
        rsps.add_callback("POST", DISCOVERED_URL, callback=handler)
        thread = NetBoxSyncThread(
            netbox_client=nb, dashboard_client=dashboard_client,
            config_state=config, stats_state=stats,
            shutdown_event=shutdown, clock=fc,
        )
        try:
            thread.start()
            thread.join(timeout=2.0)
        finally:
            _stop_thread(thread, shutdown)

    # 3 syncs → 3 waits of 3600s (the third short-circuits via shutdown)
    assert sync_count["n"] == 3
    assert fc.sleeps == [3600.0, 3600.0, 3600.0]


def test_netbox_sync_thread_interval_read_from_current_config(dashboard_client, stats):
    """If config refresh changes netbox_sync_seconds, the next sleep
    uses the new value."""
    fc = FakeClock()
    nb = _fake_netbox_client([])
    shutdown = threading.Event()
    config = ConfigState(initial=dict(INITIAL_CONFIG))

    sync_count = {"n": 0}

    def handler(request):
        sync_count["n"] += 1
        if sync_count["n"] == 1:
            new = {**INITIAL_CONFIG,
                   "intervals": {**INITIAL_CONFIG["intervals"],
                                 "netbox_sync_seconds": 1800}}
            config.replace(new)
        if sync_count["n"] >= 2:
            shutdown.set()
        return (200, {}, json.dumps(OK_RESPONSE))

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add_callback("POST", DISCOVERED_URL, callback=handler)
        rsps.add_callback("POST", DISCOVERED_URL, callback=handler)
        thread = NetBoxSyncThread(
            netbox_client=nb, dashboard_client=dashboard_client,
            config_state=config, stats_state=stats,
            shutdown_event=shutdown, clock=fc,
        )
        try:
            thread.start()
            thread.join(timeout=2.0)
        finally:
            _stop_thread(thread, shutdown)

    # First wait happens AFTER the config swap; both waits are 1800s.
    assert fc.sleeps == [1800.0, 1800.0]


def test_netbox_sync_thread_auth_error_signals_shutdown_and_auth_error_event(
    dashboard_client, stats
):
    fc = FakeClock()
    nb = _fake_netbox_client(_hosts((1, "10.0.0.1", 443)))
    shutdown = threading.Event()
    auth_error = threading.Event()
    config = ConfigState(initial=dict(INITIAL_CONFIG))

    err = {"error": {"code": "agent_revoked", "message": "revoked",
                      "request_id": "req_r"}}

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add("POST", DISCOVERED_URL, json=err, status=401)
        thread = NetBoxSyncThread(
            netbox_client=nb, dashboard_client=dashboard_client,
            config_state=config, stats_state=stats,
            shutdown_event=shutdown, clock=fc,
            auth_error_event=auth_error,
        )
        try:
            thread.start()
            thread.join(timeout=2.0)
        finally:
            _stop_thread(thread, shutdown)

    assert shutdown.is_set()
    assert auth_error.is_set()


def test_netbox_sync_thread_netbox_error_does_not_stop_thread(dashboard_client, stats, caplog):
    """A NetBox query failure is logged + the next sync attempts again
    on the normal cadence. Thread keeps running."""
    fc = FakeClock()
    shutdown = threading.Event()
    config = ConfigState(initial=dict(INITIAL_CONFIG))

    fetch_call_count = {"n": 0}

    def fetch_hosts():
        fetch_call_count["n"] += 1
        if fetch_call_count["n"] == 1:
            raise NetBoxSyncError("connection refused")
        # Second sync succeeds
        return _hosts((1, "10.0.0.1", 443))

    nb = MagicMock(spec=NetBoxClient)
    nb.url = NETBOX_URL
    nb.filter_expr = NETBOX_FILTER
    nb.fetch_hosts = fetch_hosts

    sync_count = {"n": 0}

    def handler(request):
        sync_count["n"] += 1
        if sync_count["n"] >= 1:
            shutdown.set()
        return (200, {}, json.dumps(OK_RESPONSE))

    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        rsps.add_callback("POST", DISCOVERED_URL, callback=handler)
        thread = NetBoxSyncThread(
            netbox_client=nb, dashboard_client=dashboard_client,
            config_state=config, stats_state=stats,
            shutdown_event=shutdown, clock=fc,
        )
        try:
            with caplog.at_level("ERROR"):
                thread.start()
                thread.join(timeout=2.0)
        finally:
            _stop_thread(thread, shutdown)

    # First sync: NetBox error logged, no submission. Second sync: succeeds.
    assert fetch_call_count["n"] == 2
    assert sync_count["n"] == 1
    netbox_errors = [r.msg for r in caplog.records
                      if isinstance(r.msg, dict) and r.msg.get("event") == "netbox_sync_netbox_error_preserving_state"]
    assert len(netbox_errors) == 1


# ============================================================
#  NetBoxHostsState (in-memory state for cycle + action consumers)
# ============================================================


def test_netbox_hosts_state_starts_empty():
    from certwatch.netbox_sync import NetBoxHostsState
    state = NetBoxHostsState()
    assert state.snapshot() == []


def test_netbox_hosts_state_replace_swaps_full_list():
    from certwatch.netbox_sync import NetBoxHostsState
    state = NetBoxHostsState()
    state.replace([
        DiscoveredHost(netbox_device_id=1, hostname="a", port=443, display_name="A", tags=[]),
        DiscoveredHost(netbox_device_id=2, hostname="b", port=8443, display_name="B", tags=["x"]),
    ])
    snap = state.snapshot()
    assert len(snap) == 2
    assert snap[0].netbox_device_id == 1
    assert snap[1].port == 8443


def test_netbox_hosts_state_snapshot_returns_independent_list():
    """Different from ConfigState (which returns by reference). Callers
    iterate netbox_hosts in the cycle thread; we don't want a concurrent
    replace() to invalidate iteration."""
    from certwatch.netbox_sync import NetBoxHostsState
    state = NetBoxHostsState()
    state.replace([
        DiscoveredHost(netbox_device_id=1, hostname="a", port=443, display_name=None, tags=[]),
    ])
    snap1 = state.snapshot()
    state.replace([])  # concurrent writer would drop everything
    # snap1 must still have its original contents
    assert len(snap1) == 1
    assert snap1[0].hostname == "a"


def test_run_netbox_sync_updates_local_state_on_successful_fetch(dashboard_client, stats):
    """The cycle thread reads NetBoxHostsState; it must be updated with
    fresh data on every successful fetch so the next cycle cert-checks
    the latest set."""
    from certwatch.netbox_sync import NetBoxHostsState

    nb = _fake_netbox_client(_hosts((1, "10.0.0.1", 443), (2, "10.0.0.2", 8443)))
    state = NetBoxHostsState()
    assert state.snapshot() == []  # initial empty

    with responses.RequestsMock() as rsps:
        rsps.add("POST", DISCOVERED_URL, json=OK_RESPONSE, status=200)
        run_netbox_sync(
            netbox_client=nb, dashboard_client=dashboard_client,
            action_id=None, stats_state=stats, clock=FakeClock(),
            netbox_hosts_state=state,
        )

    snap = state.snapshot()
    assert len(snap) == 2
    assert snap[0].hostname == "10.0.0.1"
    assert snap[1].port == 8443


def test_run_netbox_sync_does_not_update_state_on_netbox_error(dashboard_client, stats):
    """Safety contract: NetBox failure preserves last-known state. The
    cycle thread keeps cert-checking what it had rather than going dark."""
    from certwatch.netbox_sync import NetBoxHostsState

    state = NetBoxHostsState()
    # Pre-populate with a previous-sync result.
    previous_hosts = _hosts((1, "10.0.0.1", 443))
    state.replace(previous_hosts)

    nb = _fake_netbox_client(
        raise_on_fetch=NetBoxSyncError(
            "connection refused",
            original_error=requests.ConnectionError("ECONNREFUSED"),
        ),
    )

    with responses.RequestsMock():
        result = run_netbox_sync(
            netbox_client=nb, dashboard_client=dashboard_client,
            action_id=None, stats_state=stats, clock=FakeClock(),
            netbox_hosts_state=state,
        )

    assert result.status == "netbox_error"
    # State unchanged — cycle thread continues with the previous host list
    snap = state.snapshot()
    assert len(snap) == 1
    assert snap[0] == previous_hosts[0]


def test_run_netbox_sync_updates_state_even_when_dashboard_submission_fails(
    dashboard_client, stats
):
    """Local state and dashboard state are independent purposes. NetBox
    fetch succeeded → cycle thread should cert-check the fresh set
    immediately, regardless of whether /discovered-hosts submission
    landed. Dashboard view may temporarily lag; it converges later."""
    from certwatch.netbox_sync import NetBoxHostsState

    nb = _fake_netbox_client(_hosts((1, "10.0.0.1", 443), (2, "10.0.0.2", 8443)))
    state = NetBoxHostsState()
    fc = FakeClock()

    err = {"error": {"code": "validation_failed",
                      "message": "duplicate", "request_id": "req_v"}}

    with responses.RequestsMock() as rsps:
        rsps.add("POST", DISCOVERED_URL, json=err, status=400)
        result = run_netbox_sync(
            netbox_client=nb, dashboard_client=dashboard_client,
            action_id=None, stats_state=stats, clock=fc,
            netbox_hosts_state=state,
        )

    # Submission failed but local state still got the fresh set.
    assert result.status == "submission_error"
    snap = state.snapshot()
    assert len(snap) == 2
    assert {h.netbox_device_id for h in snap} == {1, 2}
