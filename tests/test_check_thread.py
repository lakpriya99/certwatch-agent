"""Phase 5e — CertCheckThread tests.

Same threading-test discipline as 5c/5d: every test owns the thread
lifecycle explicitly via try/finally with a strict 2s join timeout.
FakeClock controls cadence; mocked check_fn / submit_fn drive cycle
behavior; real ConfigState/StatsState verify integration.
"""

from __future__ import annotations

import json
import threading
import time
import uuid

import pytest

from certwatch.cert_check import CertResult
from certwatch.cert_check_with_discovery import CertCheckResult
from certwatch.check_thread import CertCheckThread, CycleResult, _run_one_cycle
from certwatch.clock import FakeClock
from certwatch.dashboard_client import DashboardAuthError, DashboardClient
from certwatch.heartbeat_thread import ConfigState, StatsState
from certwatch.report_submission import ReportSubmissionResult


DASH = "https://certwatch.lovable.app"
AGENT_ID = "a8f3d12e-7b4c-4d8a-9e1f-2c5b6a7d8e9f"
SECRET = "agtkey_test"

INITIAL_CONFIG = {
    "config_version": 1,
    "intervals": {"heartbeat_seconds": 15, "check_seconds": 3600,
                  "netbox_sync_seconds": 3600},
    "timeouts": {"tcp_connect_seconds": 5, "tls_handshake_seconds": 5},
    "concurrency": {"max_parallel_checks": 20},
    "alert_thresholds_days": [30, 7, 1],
    "manual_hosts": [
        {"host_id": "h1", "hostname": "app01.example.com", "port": 443,
         "added_at": "2026-04-01T00:00:00Z"},
        {"host_id": "h2", "hostname": "192.168.1.50", "port": 8443,
         "added_at": "2026-04-02T00:00:00Z"},
    ],
}


@pytest.fixture
def client():
    return DashboardClient(DASH, agent_id=AGENT_ID, agent_secret=SECRET)


def _success_result(hostname: str, port: int = 443) -> CertResult:
    return CertResult(
        state="success", hostname=hostname, port=port,
        checked_at="2026-05-02T15:00:03Z",
        subject_cn=hostname, subject_sans=[hostname],
        issuer_cn="DigiCert", issuer_o="DigiCert Inc",
        issuer_full_dn="CN=DigiCert,O=DigiCert Inc",
        ca_category="well_known_public", is_self_signed=False,
        not_before="2025-01-01T00:00:00Z", not_after="2026-12-31T23:59:59Z",
        days_until_expiry=240, signature_algorithm="SHA256withRSA",
        key_size=2048, hostname_matches=True,
        chain_trusted_by_system=True, chain_error_reason=None,
    )


def _delivered(report_id: str = "abc") -> ReportSubmissionResult:
    return ReportSubmissionResult(
        status="delivered", attempts=1, elapsed=0.1,
        dashboard_summary={"total_checks": 0, "success": 0,
                            "connection_failed": 0, "tls_failed": 0,
                            "alerts_triggered": 0,
                            "ignored_unknown_hosts": 0},
    )


def _success_discovery_result(target: str, port: int = 443) -> CertCheckResult:
    """Discovery-builder counterpart to `_success_result`. Used by the
    netbox path after Phase 9c's per-source dispatch."""
    return CertCheckResult(
        status="success", ip_address=target, port=port,
        checked_at="2026-05-02T15:00:03Z",
        canonical_hostname=target,
        subject_cn=target, subject_sans=[target],
        issuer_cn="DigiCert", issuer_o="DigiCert Inc",
        issuer_full_dn="CN=DigiCert,O=DigiCert Inc",
        is_self_signed=False,
        not_before="2025-01-01T00:00:00Z", not_after="2026-12-31T23:59:59Z",
        days_until_expiry=240, signature_algorithm="SHA256withRSA",
        key_size=2048, hostname_matches=True,
        chain_trusted_by_system=True, chain_trust_reason=None,
    )


def _build_thread(client, *, fc=None, config=None, stats=None, netbox=None,
                   shutdown=None, check_fn=None, discovery_check_fn=None,
                   submit_fn=None):
    fc = fc or FakeClock()
    config_state = config or ConfigState(initial=dict(INITIAL_CONFIG))
    stats_state = stats or StatsState(clock=fc)
    shutdown_event = shutdown or threading.Event()
    check_fn = check_fn or (lambda h, p, **k: _success_result(h, p))
    discovery_check_fn = discovery_check_fn or (
        lambda t, p, **k: _success_discovery_result(t, p)
    )
    submit_fn = submit_fn or (lambda **k: _delivered())
    thread = CertCheckThread(
        client=client, data_dir="/tmp",
        config_state=config_state, stats_state=stats_state,
        shutdown_event=shutdown_event, clock=fc,
        check_fn=check_fn, discovery_check_fn=discovery_check_fn,
        submit_fn=submit_fn,
        netbox_hosts_state=netbox,
    )
    return thread, config_state, stats_state, shutdown_event


def _stop_thread(thread, shutdown, timeout=2.0):
    """Mirror of _run_until_exit from 5c/5d — set shutdown, join with
    a strict timeout, fail if the thread leaks."""
    shutdown.set()
    thread.join(timeout=timeout)
    assert not thread.is_alive(), (
        f"{thread.name} did not exit within {timeout}s — likely a deadlock"
    )


# ============================================================
#  Cycle execution — first cycle immediate, subsequent cycles wait
# ============================================================


def test_first_cycle_runs_immediately_on_thread_start(client):
    """No initial 60-min wait — the first cycle fires as soon as the
    thread starts."""
    fc = FakeClock()
    cycle_count = {"n": 0}

    def fake_submit(**k):
        cycle_count["n"] += 1
        # Stop after first cycle so the test exits promptly.
        k["shutdown_event"].set()
        return _delivered()

    thread, _, _, shutdown = _build_thread(client, fc=fc, submit_fn=fake_submit)
    try:
        thread.start()
        thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    assert cycle_count["n"] == 1


def test_subsequent_cycles_wait_check_seconds_after_previous_completes(client):
    """After the first cycle, the thread waits config['intervals']['check_seconds']
    before the next one."""
    fc = FakeClock()
    cycle_count = {"n": 0}

    def fake_submit(**k):
        cycle_count["n"] += 1
        if cycle_count["n"] >= 3:
            k["shutdown_event"].set()
        return _delivered()

    thread, _, _, shutdown = _build_thread(client, fc=fc, submit_fn=fake_submit)
    try:
        thread.start()
        thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    assert cycle_count["n"] == 3
    # Three cycles → three waits of 3600s each (the third short-circuits
    # because shutdown is set, but the wait is still recorded).
    assert fc.sleeps == [3600.0, 3600.0, 3600.0]


def test_check_seconds_read_from_current_config_each_iteration(client):
    """Config refresh (changing check_seconds) takes effect on the next
    wait, not at process restart."""
    fc = FakeClock()
    cycle_count = {"n": 0}
    config_state = ConfigState(initial=dict(INITIAL_CONFIG))

    def fake_submit(**k):
        cycle_count["n"] += 1
        if cycle_count["n"] == 1:
            # Mid-test: change check_seconds to 1800 for subsequent cycles
            new_config = {**INITIAL_CONFIG, "config_version": 2,
                          "intervals": {**INITIAL_CONFIG["intervals"],
                                         "check_seconds": 1800}}
            config_state.replace(new_config)
        if cycle_count["n"] >= 3:
            k["shutdown_event"].set()
        return _delivered()

    thread, _, _, shutdown = _build_thread(
        client, fc=fc, config=config_state, submit_fn=fake_submit
    )
    try:
        thread.start()
        thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    # First wait: config swap happened at cycle 1, so the wait AFTER cycle 1
    # uses the NEW config (1800s). Subsequent waits also 1800s.
    assert fc.sleeps == [1800.0, 1800.0, 1800.0]


def test_no_catch_up_after_slow_cycle(client):
    """A 15-minute cycle (advance fc inside cert_check) does not compress
    the next sleep — it's still the full check_seconds."""
    fc = FakeClock()
    cycle_count = {"n": 0}

    def slow_check(host, port, **k):
        fc.advance(900)  # 15 fake minutes per check
        return _success_result(host, port)

    def fake_submit(**k):
        cycle_count["n"] += 1
        if cycle_count["n"] >= 2:
            k["shutdown_event"].set()
        return _delivered()

    thread, _, _, shutdown = _build_thread(
        client, fc=fc, check_fn=slow_check, submit_fn=fake_submit
    )
    try:
        thread.start()
        thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    # Both waits are full 3600s — no compression to "catch up".
    assert fc.sleeps == [3600.0, 3600.0]


# ============================================================
#  report_type — startup vs scheduled
# ============================================================


def test_first_cycle_uses_report_type_startup(client):
    captured = {"types": []}

    def fake_submit(**k):
        captured["types"].append(k["report_type"])
        if len(captured["types"]) >= 1:
            k["shutdown_event"].set()
        return _delivered()

    thread, _, _, shutdown = _build_thread(client, submit_fn=fake_submit)
    try:
        thread.start()
        thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    assert captured["types"] == ["startup"]


def test_subsequent_cycles_use_report_type_scheduled(client):
    captured = {"types": []}

    def fake_submit(**k):
        captured["types"].append(k["report_type"])
        if len(captured["types"]) >= 3:
            k["shutdown_event"].set()
        return _delivered()

    thread, _, _, shutdown = _build_thread(client, submit_fn=fake_submit)
    try:
        thread.start()
        thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    assert captured["types"] == ["startup", "scheduled", "scheduled"]


def test_is_first_cycle_stays_true_after_shutdown(client):
    """If submission returns 'shutdown', the next start is still
    semantically a startup (the dashboard never saw this attempt).
    Verify by running two cycles where the first returns shutdown."""
    captured = {"types": []}

    def fake_submit(**k):
        captured["types"].append(k["report_type"])
        if len(captured["types"]) == 1:
            return ReportSubmissionResult(
                status="shutdown", attempts=1, elapsed=0.1,
            )
        if len(captured["types"]) >= 2:
            k["shutdown_event"].set()
        return _delivered()

    thread, _, _, shutdown = _build_thread(client, submit_fn=fake_submit)
    try:
        thread.start()
        thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    # Both cycles report_type="startup" — the shutdown cycle didn't flip
    # the flag, so cycle 2 is still semantically the first.
    assert captured["types"] == ["startup", "startup"]


def test_is_first_cycle_flips_after_rejected_400(client):
    """A 400 rejection means data won't be redelivered (poison won't
    be retried). Future cycles are 'scheduled', not stuck on 'startup'."""
    captured = {"types": []}

    def fake_submit(**k):
        captured["types"].append(k["report_type"])
        if len(captured["types"]) == 1:
            return ReportSubmissionResult(
                status="rejected", attempts=1, elapsed=0.1,
            )
        if len(captured["types"]) >= 2:
            k["shutdown_event"].set()
        return _delivered()

    thread, _, _, shutdown = _build_thread(client, submit_fn=fake_submit)
    try:
        thread.start()
        thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    assert captured["types"] == ["startup", "scheduled"]


# ============================================================
#  Report payload contents
# ============================================================


def test_report_id_is_fresh_uuid_per_cycle(client):
    captured = {"ids": []}

    def fake_submit(**k):
        captured["ids"].append(k["report_id"])
        if len(captured["ids"]) >= 3:
            k["shutdown_event"].set()
        return _delivered()

    thread, _, _, shutdown = _build_thread(client, submit_fn=fake_submit)
    try:
        thread.start()
        thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    # Three cycles → three distinct UUIDs
    assert len(captured["ids"]) == 3
    assert len(set(captured["ids"])) == 3
    for rid in captured["ids"]:
        # Raises ValueError if not a valid UUID
        uuid.UUID(rid)


def test_action_id_is_none_on_scheduled_and_startup(client):
    captured = {"action_ids": []}

    def fake_submit(**k):
        captured["action_ids"].append(k["action_id"])
        if len(captured["action_ids"]) >= 2:
            k["shutdown_event"].set()
        return _delivered()

    thread, _, _, shutdown = _build_thread(client, submit_fn=fake_submit)
    try:
        thread.start()
        thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    # Both cycles (startup + scheduled) have action_id=None
    assert captured["action_ids"] == [None, None]


def test_checks_built_in_original_host_order(client):
    """Even when ThreadPoolExecutor's as_completed returns in a
    different order, the checks list must reflect the host order
    from manual_hosts in the config."""
    fc = FakeClock()
    captured = {"checks": None}

    config = {**INITIAL_CONFIG, "manual_hosts": [
        {"host_id": "first", "hostname": "a", "port": 443, "added_at": "t"},
        {"host_id": "second", "hostname": "b", "port": 443, "added_at": "t"},
        {"host_id": "third", "hostname": "c", "port": 443, "added_at": "t"},
    ]}
    config_state = ConfigState(initial=config)

    def variable_speed(host, port, **k):
        # First completes last; third completes first — completion order
        # is the inverse of submission order.
        if host == "a":
            time.sleep(0.03)
        elif host == "b":
            time.sleep(0.015)
        return _success_result(host, port)

    def fake_submit(**k):
        captured["checks"] = k["checks"]
        k["shutdown_event"].set()
        return _delivered()

    thread, _, _, shutdown = _build_thread(
        client, fc=fc, config=config_state,
        check_fn=variable_speed, submit_fn=fake_submit,
    )
    try:
        thread.start()
        thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    checks = captured["checks"]
    assert [c["host_ref"]["host_id"] for c in checks] == ["first", "second", "third"]


def test_checks_use_manual_host_ref_format(client):
    captured = {"checks": None}

    def fake_submit(**k):
        captured["checks"] = k["checks"]
        k["shutdown_event"].set()
        return _delivered()

    thread, _, _, shutdown = _build_thread(client, submit_fn=fake_submit)
    try:
        thread.start()
        thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    for c in captured["checks"]:
        assert c["host_ref"]["type"] == "manual"
        assert "host_id" in c["host_ref"]
        assert "netbox_device_id" not in c["host_ref"]


def test_check_includes_cert_dict_for_recovered_cert(client):
    """End-to-end: cert_check returns a CertResult with cert data, the
    check dict in the report has the cert object populated."""
    captured = {"checks": None}

    def fake_submit(**k):
        captured["checks"] = k["checks"]
        k["shutdown_event"].set()
        return _delivered()

    thread, _, _, shutdown = _build_thread(client, submit_fn=fake_submit)
    try:
        thread.start()
        thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    assert all(c["status"] == "success" for c in captured["checks"])
    assert all(c["cert"] is not None for c in captured["checks"])


# ============================================================
#  Empty hosts case
# ============================================================


def test_empty_manual_hosts_still_submits_report_with_empty_checks(client):
    """The natural-empty pattern: manual_hosts=[] is a legitimate state
    (agent has no hosts assigned). Still submit a report with checks=[]
    so the dashboard records the cycle happened."""
    captured = {"checks": "<unset>", "report_type": None}

    def fake_submit(**k):
        captured["checks"] = k["checks"]
        captured["report_type"] = k["report_type"]
        k["shutdown_event"].set()
        return _delivered()

    empty_config = {**INITIAL_CONFIG, "manual_hosts": []}
    thread, _, _, shutdown = _build_thread(
        client,
        config=ConfigState(initial=empty_config),
        submit_fn=fake_submit,
    )
    try:
        thread.start()
        thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    assert captured["checks"] == []
    assert captured["report_type"] == "startup"


def test_empty_manual_hosts_serializes_as_array_not_null():
    """Wire-bytes guard: empty checks becomes `"checks": []` in the
    serialized payload, not `null` or omitted. Pinned at the helper
    level so a future refactor that 'helpfully' substitutes None
    breaks here."""
    # _run_one_cycle directly so we can inspect the wire-shaped payload.
    captured = {}

    def capture_submit(**k):
        captured["body_str"] = json.dumps({
            "report_id": k["report_id"],
            "report_type": k["report_type"],
            "started_at": k["started_at"],
            "completed_at": k["completed_at"],
            "action_id": k["action_id"],
            "checks": k["checks"],
        }, sort_keys=True)
        return _delivered()

    fc = FakeClock()
    shutdown = threading.Event()
    config = {**INITIAL_CONFIG, "manual_hosts": []}

    _run_one_cycle(
        client=None, data_dir="/tmp", config=config,
        report_type="startup", clock=fc, shutdown_event=shutdown,
        check_fn=lambda *a, **k: _success_result("x"),
        submit_fn=capture_submit,
    )

    body_str = captured["body_str"]
    assert '"checks": []' in body_str
    assert '"checks": null' not in body_str


# ============================================================
#  StatsState integration
# ============================================================


def test_stats_recorded_after_successful_cycle(client):
    fc = FakeClock()
    config = {**INITIAL_CONFIG, "manual_hosts": [
        {"host_id": "h1", "hostname": "a", "port": 443, "added_at": "t"},
        {"host_id": "h2", "hostname": "b", "port": 443, "added_at": "t"},
    ]}
    config_state = ConfigState(initial=config)
    stats = StatsState(clock=fc)

    def fake_submit(**k):
        k["shutdown_event"].set()
        return _delivered()

    thread, _, _, shutdown = _build_thread(
        client, fc=fc, config=config_state, stats=stats,
        submit_fn=fake_submit,
    )
    try:
        thread.start()
        thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    snap = stats.snapshot_for_heartbeat()
    assert snap is not None
    assert snap["hosts_monitored"] == 2
    assert snap["checks_succeeded_last_cycle"] == 2
    assert snap["checks_failed_last_cycle"] == 0
    assert snap["last_check_completed_at"]


def test_stats_failed_count_reflects_non_success_results(client):
    fc = FakeClock()
    stats = StatsState(clock=fc)

    def mixed_check(host, port, **k):
        if host == "app01.example.com":
            return _success_result(host, port)
        return CertResult(state="connection_failed", hostname=host, port=port,
                          checked_at="t", error_message="timeout")

    def fake_submit(**k):
        k["shutdown_event"].set()
        return _delivered()

    thread, _, _, shutdown = _build_thread(
        client, fc=fc, stats=stats,
        check_fn=mixed_check, submit_fn=fake_submit,
    )
    try:
        thread.start()
        thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    snap = stats.snapshot_for_heartbeat()
    assert snap["checks_succeeded_last_cycle"] == 1
    assert snap["checks_failed_last_cycle"] == 1


def test_stats_not_updated_on_auth_error(client):
    """If submission raises DashboardAuthError, the cycle didn't complete
    successfully — stats remain unset for the heartbeat to omit."""
    stats = StatsState(clock=FakeClock())

    def fake_submit(**k):
        raise DashboardAuthError(
            "revoked", code="agent_revoked",
            request_id="req_r", status_code=401,
        )

    thread, _, _, shutdown = _build_thread(
        client, stats=stats, submit_fn=fake_submit
    )
    try:
        thread.start()
        thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    # Stats never updated → snapshot is None
    assert stats.snapshot_for_heartbeat() is None


# ============================================================
#  Auth error escalation (same pattern as 5d)
# ============================================================


def test_auth_error_during_submission_signals_global_shutdown(client):
    """DashboardAuthError → set shutdown_event, exit thread. Same
    escalation tier as 5d's action workers."""

    def fake_submit(**k):
        raise DashboardAuthError(
            "revoked", code="agent_revoked",
            request_id="req_r", status_code=401,
        )

    thread, _, _, shutdown = _build_thread(client, submit_fn=fake_submit)
    try:
        thread.start()
        thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    assert shutdown.is_set()
    assert not thread.is_alive()


def test_unexpected_cycle_exception_logged_and_continues(client, caplog):
    """One cycle's exception must NOT kill the thread — log and try
    again on the next cycle. (Auth errors are the special case that
    sets shutdown.)"""
    cycle_count = {"n": 0}

    def fake_submit(**k):
        cycle_count["n"] += 1
        if cycle_count["n"] == 1:
            raise RuntimeError("transient kaboom")
        # Second cycle succeeds
        k["shutdown_event"].set()
        return _delivered()

    thread, _, _, shutdown = _build_thread(client, submit_fn=fake_submit)
    try:
        with caplog.at_level("ERROR"):
            thread.start()
            thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    assert cycle_count["n"] == 2  # second cycle ran despite first's error
    errors = [r.msg for r in caplog.records
              if isinstance(r.msg, dict) and r.msg.get("event") == "check_cycle_unexpected_error"]
    assert len(errors) == 1


# ============================================================
#  Order of operations (the call_order pattern from 5c/5d)
# ============================================================


def test_cycle_sequence_is_check_then_submit_then_stats(client):
    """Pin the per-cycle order: cert_check (per host) → submit_report →
    stats update. Mirrors the order-of-operations tests in 5c (heartbeat
    response processing) and 5d (handler dispatch)."""
    call_order = []

    def fake_check(host, port, **k):
        call_order.append("cert_check")
        return _success_result(host, port)

    def fake_submit(**k):
        call_order.append("submit_report")
        k["shutdown_event"].set()
        return _delivered()

    class TracingStats(StatsState):
        def record_check_cycle(self, **k):
            call_order.append("update_stats")
            super().record_check_cycle(**k)

    fc = FakeClock()
    stats = TracingStats(clock=fc)
    config = {**INITIAL_CONFIG, "manual_hosts": [
        {"host_id": "h1", "hostname": "only-one", "port": 443, "added_at": "t"},
    ]}
    thread, _, _, shutdown = _build_thread(
        client, fc=fc, config=ConfigState(initial=config),
        stats=stats, check_fn=fake_check, submit_fn=fake_submit,
    )
    try:
        thread.start()
        thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    assert call_order == ["cert_check", "submit_report", "update_stats"]


def test_started_at_before_completed_at_in_submitted_report(client):
    """started_at captured BEFORE checks; completed_at captured AFTER.
    Verify via the wire payload (lexicographic comparison of ISO 8601
    strings yields the time ordering)."""
    captured = {}

    def slow_check(host, port, **k):
        time.sleep(0.01)
        return _success_result(host, port)

    def fake_submit(**k):
        captured["started_at"] = k["started_at"]
        captured["completed_at"] = k["completed_at"]
        k["shutdown_event"].set()
        return _delivered()

    thread, _, _, shutdown = _build_thread(
        client, check_fn=slow_check, submit_fn=fake_submit,
    )
    try:
        thread.start()
        thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    assert captured["started_at"] <= captured["completed_at"]


# ============================================================
#  Lifecycle / shutdown
# ============================================================


def test_shutdown_already_set_at_thread_start_no_cycle_runs(client):
    """Same fast-exit semantic as 5c: if shutdown is already set when
    the loop's top-of-iteration check runs, no cycle fires."""
    fc = FakeClock()
    shutdown = threading.Event()
    shutdown.set()

    cycle_count = {"n": 0}

    def fake_submit(**k):
        cycle_count["n"] += 1
        return _delivered()

    thread, _, _, _ = _build_thread(
        client, fc=fc, shutdown=shutdown, submit_fn=fake_submit
    )
    try:
        thread.start()
        thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    assert cycle_count["n"] == 0


def test_shutdown_during_inter_cycle_sleep_exits_loop(client):
    """Shutdown set during the wait_for between cycles → loop exits
    via the wait_for True return."""
    fc = FakeClock()
    cycle_count = {"n": 0}

    def fake_submit(**k):
        cycle_count["n"] += 1
        if cycle_count["n"] == 1:
            # After first cycle returns, signal shutdown — the wait_for
            # immediately following it will see the event and break.
            k["shutdown_event"].set()
        return _delivered()

    thread, _, _, shutdown = _build_thread(client, fc=fc, submit_fn=fake_submit)
    try:
        thread.start()
        thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    assert cycle_count["n"] == 1


def test_shutdown_during_cycle_partial_results_still_submitted(client):
    """If shutdown is signaled mid-cycle, in-flight checks complete and
    we still submit (with whatever results we got). The skip-at-pickup
    pattern in _run_parallel_checks handles 'don't start new checks
    after shutdown.'"""
    captured = {"checks": None}

    config = {**INITIAL_CONFIG, "manual_hosts": [
        {"host_id": "h1", "hostname": "a", "port": 443, "added_at": "t"},
        {"host_id": "h2", "hostname": "b", "port": 443, "added_at": "t"},
        {"host_id": "h3", "hostname": "c", "port": 443, "added_at": "t"},
    ]}
    fc = FakeClock()
    shutdown = threading.Event()

    def slow_check(host, port, **k):
        # Set shutdown after the first check starts so subsequent ones
        # see is_set() and short-circuit.
        if host == "a":
            shutdown.set()
            return _success_result(host, port)
        # Other hosts: workers see shutdown, return None, get filtered.
        if shutdown.is_set():
            time.sleep(0.001)  # let task() return None
        return _success_result(host, port)

    def fake_submit(**k):
        captured["checks"] = k["checks"]
        return _delivered()

    thread, _, _, _ = _build_thread(
        client, fc=fc, shutdown=shutdown,
        config=ConfigState(initial=config),
        check_fn=slow_check, submit_fn=fake_submit,
    )
    try:
        thread.start()
        thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    # At least the host that went first made it. The cycle still
    # submitted (we don't lose data on shutdown).
    assert captured["checks"] is not None
    host_ids = {c["host_ref"]["host_id"] for c in captured["checks"]}
    assert "h1" in host_ids


def test_thread_exits_on_unhandled_exception_setting_shutdown(client, caplog):
    """Unhandled exception OUTSIDE the cycle (e.g., in stats update) sets
    shutdown so the runner brings everything down — silently dying
    threads are the worst kind of failure."""
    fc = FakeClock()

    class BoomStats(StatsState):
        def record_check_cycle(self, **k):
            raise RuntimeError("stats exploded")

    stats = BoomStats(clock=fc)
    thread, _, _, shutdown = _build_thread(client, fc=fc, stats=stats)
    try:
        with caplog.at_level("ERROR"):
            thread.start()
            thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    # The catch-all in the cycle loop logged it; the thread continued
    # but the cycle is broken. (record_check_cycle is INSIDE the cycle
    # body's except clause, so it's caught as cycle_unexpected_error.)
    errors = [r.msg for r in caplog.records
              if isinstance(r.msg, dict) and r.msg.get("event") == "check_cycle_unexpected_error"]
    assert len(errors) >= 1


# ============================================================
#  NetBox-discovered hosts in the cycle (regression for the
#  "NetBox sync but no cert checks" production bug)
# ============================================================


def _netbox_host(device_id, hostname, port=443, tags=None):
    from certwatch.netbox_client import DiscoveredHost
    return DiscoveredHost(
        netbox_device_id=device_id, hostname=hostname, port=port,
        display_name=f"d{device_id}", tags=tags or [],
    )


def test_cycle_iterates_netbox_hosts_alongside_manual(client):
    """Regression test for the bug where the cycle iterated only
    manual_hosts and never cert-checked NetBox-discovered hosts.

    Phase 9c dispatch: manual hosts go through `check_fn` (old
    cert_check), netbox hosts go through `discovery_check_fn`
    (cert_check_with_discovery). Both end up in the same batched
    /reports payload."""
    from certwatch.netbox_sync import NetBoxHostsState

    fc = FakeClock()
    config = {**INITIAL_CONFIG, "manual_hosts": [
        {"host_id": "manual-1", "hostname": "manual.example", "port": 443,
         "added_at": "t"},
    ]}
    netbox_state = NetBoxHostsState()
    netbox_state.replace([
        _netbox_host(1247, "esxi02.lab"),
        _netbox_host(1248, "switch01.lab", port=8443),
    ])

    captured = {}
    manual_checked = []
    discovery_checked = []

    def fake_check(host, port, **k):
        manual_checked.append((host, port))
        return _success_result(host, port)

    def fake_discovery_check(target, port, **k):
        discovery_checked.append((target, port))
        return _success_discovery_result(target, port)

    def fake_submit(**k):
        captured["checks"] = k["checks"]
        k["shutdown_event"].set()
        return _delivered()

    thread, _, _, shutdown = _build_thread(
        client, fc=fc, config=ConfigState(initial=config),
        netbox=netbox_state,
        check_fn=fake_check, discovery_check_fn=fake_discovery_check,
        submit_fn=fake_submit,
    )
    try:
        thread.start()
        thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    # Manual host went through the old cert_check path
    assert manual_checked == [("manual.example", 443)]
    # NetBox hosts went through the new discovery path. _netbox_host
    # has no ip_address set, so connect_target falls back to hostname.
    assert ("esxi02.lab", 443) in discovery_checked
    assert ("switch01.lab", 8443) in discovery_checked
    assert len(discovery_checked) == 2

    # Report contains all three checks with correct host_ref types
    checks = captured["checks"]
    assert len(checks) == 3
    types = [(c["host_ref"]["type"], c["host_ref"]) for c in checks]
    assert ("manual", {"type": "manual", "host_id": "manual-1"}) in types
    assert ("netbox", {"type": "netbox", "netbox_device_id": 1247}) in types
    assert ("netbox", {"type": "netbox", "netbox_device_id": 1248}) in types
    # NetBox checks carry status_detail (compat envelope); manual ones
    # don't (old builder).
    netbox_checks = [c for c in checks if c["host_ref"]["type"] == "netbox"]
    manual_checks = [c for c in checks if c["host_ref"]["type"] == "manual"]
    assert all("status_detail" in c for c in netbox_checks)
    assert all("status_detail" not in c for c in manual_checks)


def test_cycle_with_only_netbox_hosts_no_manual(client):
    """A homelab agent with only NetBox-sourced hosts (no manual_hosts
    on the dashboard) should still cert-check everything from NetBox."""
    from certwatch.netbox_sync import NetBoxHostsState

    fc = FakeClock()
    config = {**INITIAL_CONFIG, "manual_hosts": []}
    netbox_state = NetBoxHostsState()
    netbox_state.replace([_netbox_host(1247, "esxi02.lab")])

    captured = {}

    def fake_submit(**k):
        captured["checks"] = k["checks"]
        k["shutdown_event"].set()
        return _delivered()

    thread, _, _, shutdown = _build_thread(
        client, fc=fc, config=ConfigState(initial=config),
        netbox=netbox_state, submit_fn=fake_submit,
    )
    try:
        thread.start()
        thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    checks = captured["checks"]
    assert len(checks) == 1
    assert checks[0]["host_ref"]["type"] == "netbox"
    assert checks[0]["host_ref"]["netbox_device_id"] == 1247


def test_cycle_summary_log_includes_separate_manual_and_netbox_counts(client, caplog):
    """check_cycle_summary log must distinguish the two sources so
    operators can tell at a glance what's being checked. This is also
    how we'd have spotted the original bug — with the count visible,
    the all-zero netbox count would have been a red flag."""
    from certwatch.netbox_sync import NetBoxHostsState

    fc = FakeClock()
    config = {**INITIAL_CONFIG, "manual_hosts": [
        {"host_id": "m1", "hostname": "m1", "port": 443, "added_at": "t"},
    ]}
    netbox_state = NetBoxHostsState()
    netbox_state.replace([
        _netbox_host(1247, "n1"),
        _netbox_host(1248, "n2"),
    ])

    def fake_submit(**k):
        k["shutdown_event"].set()
        return _delivered()

    thread, _, _, shutdown = _build_thread(
        client, fc=fc, config=ConfigState(initial=config),
        netbox=netbox_state, submit_fn=fake_submit,
    )
    try:
        with caplog.at_level("INFO"):
            thread.start()
            thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    summaries = [r.msg for r in caplog.records
                 if isinstance(r.msg, dict) and r.msg.get("event") == "check_cycle_summary"]
    assert len(summaries) >= 1
    s = summaries[0]
    assert s["manual_hosts_count"] == 1
    assert s["netbox_hosts_count"] == 2
    assert s["total_hosts_count"] == 3


def test_cycle_with_no_netbox_state_passed_works_unchanged(client):
    """Backward compat: existing callers that don't pass netbox_hosts_state
    (e.g., test fixtures from before this change) still work — the
    cycle just iterates manual_hosts only."""
    fc = FakeClock()
    captured = {}

    def fake_submit(**k):
        captured["checks"] = k["checks"]
        k["shutdown_event"].set()
        return _delivered()

    thread, _, _, shutdown = _build_thread(client, fc=fc, submit_fn=fake_submit)
    try:
        thread.start()
        thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    # Default INITIAL_CONFIG has 2 manual hosts
    assert len(captured["checks"]) == 2
    assert all(c["host_ref"]["type"] == "manual" for c in captured["checks"])


def test_cycle_preserves_manual_first_then_netbox_order(client):
    """Order in the report: manual hosts first (in config order), then
    netbox hosts (in state order). Important for the dashboard's UI
    to display per-cycle results in a stable way."""
    from certwatch.netbox_sync import NetBoxHostsState

    fc = FakeClock()
    config = {**INITIAL_CONFIG, "manual_hosts": [
        {"host_id": "ma", "hostname": "ma", "port": 443, "added_at": "t"},
        {"host_id": "mb", "hostname": "mb", "port": 443, "added_at": "t"},
    ]}
    netbox_state = NetBoxHostsState()
    netbox_state.replace([
        _netbox_host(100, "nx"),
        _netbox_host(200, "ny"),
    ])

    captured = {}

    def fake_submit(**k):
        captured["checks"] = k["checks"]
        k["shutdown_event"].set()
        return _delivered()

    thread, _, _, shutdown = _build_thread(
        client, fc=fc, config=ConfigState(initial=config),
        netbox=netbox_state, submit_fn=fake_submit,
    )
    try:
        thread.start()
        thread.join(timeout=2.0)
    finally:
        _stop_thread(thread, shutdown)

    refs = [c["host_ref"] for c in captured["checks"]]
    assert refs == [
        {"type": "manual", "host_id": "ma"},
        {"type": "manual", "host_id": "mb"},
        {"type": "netbox", "netbox_device_id": 100},
        {"type": "netbox", "netbox_device_id": 200},
    ]
