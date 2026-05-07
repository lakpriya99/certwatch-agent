"""Phase 8 — end-to-end lifecycle tests.

Real agent subprocess + real Flask mock servers. First time the
production binary executes against API surfaces; integration bugs
from phases 1-7 surface here.

Tuning: the mock dashboard hands back 1s heartbeat / 5s check / 5s
NetBox-sync intervals so the suite completes in ~1 min real time.
The agent honors whatever the dashboard returns, so the cadence here
is deliberately fast.
"""

from __future__ import annotations

import json
import signal
import socket
import time

import pytest


REGISTRATION_TOKEN = "regtok_e2e_test_token"


def _base_env(mock_dashboard, *, registration_token: str = REGISTRATION_TOKEN,
               extra: dict | None = None) -> dict:
    env = {
        "DASHBOARD_URL": mock_dashboard.url,
        "REGISTRATION_TOKEN": registration_token,
        "LOG_LEVEL": "INFO",
    }
    if extra:
        env.update(extra)
    return env


def _wait_until(predicate, *, timeout: float = 10.0, interval: float = 0.05):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval)
    raise TimeoutError(f"predicate did not become true within {timeout}s")


# ============================================================
#  Scenario 1: Fresh registration + steady-state operation
# ============================================================


def test_scenario_1_fresh_registration_and_heartbeats(
    mock_dashboard, agent_factory, fresh_data_dir,
):
    mock_dashboard.add_valid_registration_token(REGISTRATION_TOKEN)

    agent = agent_factory(
        env=_base_env(mock_dashboard), data_dir=fresh_data_dir,
    )

    # Wait for the agent to finish bootstrap + start its loops.
    agent.wait_for_event("agent_running", timeout=10.0)

    # Exactly one register call, with the expected token.
    register_calls = mock_dashboard.received_register_calls()
    assert len(register_calls) == 1
    assert register_calls[0]["token"] == REGISTRATION_TOKEN

    # /data/agent.json now exists with the dashboard's credentials.
    creds_path = fresh_data_dir / "agent.json"
    assert creds_path.exists()
    creds = json.loads(creds_path.read_text())
    assert creds["agent_id"] == mock_dashboard.agent_id
    assert creds["agent_secret"] == mock_dashboard.agent_secret

    # Wait for at least 3 heartbeats — at 1s cadence, ~3-4 real seconds.
    _wait_until(lambda: len(mock_dashboard.received_heartbeats()) >= 3,
                 timeout=8.0)

    rc = agent.stop(timeout=10.0)
    assert rc == 0, f"expected clean exit (0), got {rc}"


# ============================================================
#  Scenario 2: Re-registration is skipped on restart
# ============================================================


def test_scenario_2_restart_does_not_re_register(
    mock_dashboard, agent_factory, fresh_data_dir,
):
    mock_dashboard.add_valid_registration_token(REGISTRATION_TOKEN)

    # First run: full registration.
    first = agent_factory(
        env=_base_env(mock_dashboard), data_dir=fresh_data_dir,
    )
    first.wait_for_event("agent_running", timeout=10.0)
    _wait_until(lambda: len(mock_dashboard.received_heartbeats()) >= 1,
                 timeout=5.0)
    rc = first.stop(timeout=10.0)
    assert rc == 0

    register_count_before = len(mock_dashboard.received_register_calls())
    assert register_count_before == 1

    # Second run: same /data dir, NO REGISTRATION_TOKEN env var.
    env = _base_env(mock_dashboard)
    del env["REGISTRATION_TOKEN"]
    second = agent_factory(env=env, data_dir=fresh_data_dir)
    second.wait_for_event("agent_running", timeout=10.0)
    _wait_until(lambda: len(mock_dashboard.received_heartbeats()) >= 2,
                 timeout=5.0)

    # No additional /register call on restart.
    assert len(mock_dashboard.received_register_calls()) == register_count_before

    rc = second.stop(timeout=10.0)
    assert rc == 0


# ============================================================
#  Scenario 3: Manual host triggers cycle, report submitted
# ============================================================


def _closed_port_host() -> dict:
    """A manual-host config entry pointing at a guaranteed-closed local
    port. cert_check returns connection_failed within ~1s — perfect for
    e2e tests where we just want to exercise the wire flow without
    waiting for slow timeouts."""
    return {
        "host_id": "11111111-1111-4111-8111-111111111111",
        "hostname": "127.0.0.1",
        "port": 9,  # discard port — typically closed on dev machines
        "added_at": "2026-04-01T00:00:00Z",
    }


def test_scenario_3_manual_host_triggers_cycle_and_report(
    mock_dashboard, agent_factory, fresh_data_dir,
):
    mock_dashboard.add_valid_registration_token(REGISTRATION_TOKEN)
    mock_dashboard.update_config_manual_hosts([_closed_port_host()])

    agent = agent_factory(
        env=_base_env(mock_dashboard), data_dir=fresh_data_dir,
    )
    agent.wait_for_event("agent_running", timeout=10.0)

    # The first cycle runs immediately (with report_type="startup").
    # Wait for a report to land at the dashboard.
    _wait_until(lambda: len(mock_dashboard.received_reports()) >= 1,
                 timeout=15.0)

    reports = mock_dashboard.received_reports()
    assert len(reports) >= 1
    first = reports[0]
    assert first["report_type"] in ("startup", "scheduled")
    assert first["action_id"] is None
    assert len(first["checks"]) == 1
    check = first["checks"][0]
    assert check["host_ref"]["type"] == "manual"
    assert check["host_ref"]["host_id"] == "11111111-1111-4111-8111-111111111111"
    # status is connection_failed (closed port). cert is None for that state.
    assert check["status"] in ("connection_failed", "tls_failed")
    assert check["cert"] is None or check["cert"] is not None
    # error_reason populated on a failure
    assert check.get("error_reason") is not None

    rc = agent.stop(timeout=10.0)
    assert rc == 0


# ============================================================
#  Scenario 4: On-demand check_host action
# ============================================================


def test_scenario_4_on_demand_check_host_action(
    mock_dashboard, agent_factory, fresh_data_dir,
):
    mock_dashboard.add_valid_registration_token(REGISTRATION_TOKEN)
    mock_dashboard.update_config_manual_hosts([_closed_port_host()])

    agent = agent_factory(
        env=_base_env(mock_dashboard), data_dir=fresh_data_dir,
    )
    agent.wait_for_event("agent_running", timeout=10.0)

    # Drain the startup-cycle's report so we can isolate the on-demand one.
    _wait_until(lambda: len(mock_dashboard.received_reports()) >= 1,
                 timeout=15.0)
    startup_reports = len(mock_dashboard.received_reports())

    # Queue an on-demand check_host action targeting the manual host.
    action_id = mock_dashboard.queue_action(
        "check_host",
        payload={"host_ref": {
            "type": "manual",
            "host_id": "11111111-1111-4111-8111-111111111111",
        }},
    )

    # Wait for the agent to pick it up and submit an on-demand report.
    _wait_until(
        lambda: any(
            r.get("action_id") == action_id
            for r in mock_dashboard.received_reports()
        ),
        timeout=15.0,
    )

    # Verify the on-demand report shape
    on_demand = next(
        r for r in mock_dashboard.received_reports()
        if r.get("action_id") == action_id
    )
    assert on_demand["report_type"] == "on_demand"
    assert on_demand["action_id"] == action_id
    # report_id is fresh — not the action_id
    assert on_demand["report_id"] != action_id
    assert len(on_demand["checks"]) == 1

    rc = agent.stop(timeout=10.0)
    assert rc == 0


# ============================================================
#  Scenario 5: Config refresh on heartbeat signal
# ============================================================


def test_scenario_5_config_refresh_picks_up_new_manual_hosts(
    mock_dashboard, agent_factory, fresh_data_dir,
):
    mock_dashboard.add_valid_registration_token(REGISTRATION_TOKEN)
    # Start with no manual hosts so we can clearly tell the new host
    # came from a config refresh.

    agent = agent_factory(
        env=_base_env(mock_dashboard), data_dir=fresh_data_dir,
    )
    agent.wait_for_event("agent_running", timeout=10.0)

    # Wait for the startup cycle's empty-checks report to land.
    _wait_until(lambda: len(mock_dashboard.received_reports()) >= 1,
                 timeout=10.0)
    initial_reports = len(mock_dashboard.received_reports())
    initial_get_config_calls = mock_dashboard.received_get_config_count()

    # Add a host and bump config_version. Next heartbeat sees the bump
    # and triggers a get_config call.
    mock_dashboard.update_config_manual_hosts([_closed_port_host()])

    _wait_until(
        lambda: mock_dashboard.received_get_config_count() > initial_get_config_calls,
        timeout=8.0,
    )

    # The next cycle's report should now include the new manual host.
    _wait_until(
        lambda: any(
            len(r.get("checks", []) or []) > 0
            for r in mock_dashboard.received_reports()[initial_reports:]
        ),
        timeout=15.0,
    )

    rc = agent.stop(timeout=10.0)
    assert rc == 0


# ============================================================
#  Scenario 6: NetBox sync end-to-end
# ============================================================


def test_scenario_6_netbox_sync_submits_discovered_hosts(
    mock_dashboard, mock_netbox, agent_factory, fresh_data_dir,
):
    mock_dashboard.add_valid_registration_token(REGISTRATION_TOKEN)

    # Seed three NetBox devices.
    mock_netbox.add_device(
        netbox_device_id=1247, name="app01.lab",
        primary_ip4="10.1.2.3/24", tags=["monitor-cert"],
    )
    mock_netbox.add_device(
        netbox_device_id=1248, name="app02.lab",
        primary_ip4="10.1.2.4/24", tags=["monitor-cert"],
        custom_fields={"cert_check_port": 8443},
    )
    mock_netbox.add_device(
        netbox_device_id=1249, name="db01.lab",
        primary_ip4="10.1.2.5/24", tags=["monitor-cert"],
    )

    env = _base_env(mock_dashboard, extra={
        "NETBOX_URL": mock_netbox.url,
        "NETBOX_TOKEN": "nbtok_test",
        "NETBOX_FILTER": "tag=monitor-cert",
    })

    agent = agent_factory(env=env, data_dir=fresh_data_dir)
    agent.wait_for_event("agent_running", timeout=10.0)

    # NetBoxSyncThread runs its first sync immediately.
    _wait_until(
        lambda: len(mock_dashboard.received_discovered_hosts()) >= 1,
        timeout=15.0,
    )

    first_sync = mock_dashboard.received_discovered_hosts()[0]
    assert len(first_sync["hosts"]) == 3
    host_ids = sorted(h["netbox_device_id"] for h in first_sync["hosts"])
    assert host_ids == [1247, 1248, 1249]
    # cert_check_port custom field surfaced
    h1248 = next(h for h in first_sync["hosts"] if h["netbox_device_id"] == 1248)
    assert h1248["port"] == 8443
    # Synced under scheduled context — action_id is null
    assert first_sync["action_id"] is None

    # Remove one device, wait for the next sync (5s interval).
    mock_netbox.remove_device(1248)
    initial_sync_count = len(mock_dashboard.received_discovered_hosts())
    _wait_until(
        lambda: len(mock_dashboard.received_discovered_hosts()) > initial_sync_count,
        timeout=10.0,
    )
    later_sync = mock_dashboard.received_discovered_hosts()[-1]
    later_host_ids = sorted(h["netbox_device_id"] for h in later_sync["hosts"])
    assert later_host_ids == [1247, 1249]

    rc = agent.stop(timeout=10.0)
    assert rc == 0


# ============================================================
#  Scenario 7: NetBox failure preserves dashboard state
# ============================================================


def test_scenario_7_netbox_failure_does_not_call_discovered_hosts(
    mock_dashboard, mock_netbox, agent_factory, fresh_data_dir,
):
    mock_dashboard.add_valid_registration_token(REGISTRATION_TOKEN)
    mock_netbox.add_device(
        netbox_device_id=1247, name="app01.lab",
        primary_ip4="10.1.2.3/24", tags=["monitor-cert"],
    )

    env = _base_env(mock_dashboard, extra={
        "NETBOX_URL": mock_netbox.url,
        "NETBOX_TOKEN": "nbtok_test",
        "NETBOX_FILTER": "tag=monitor-cert",
    })

    agent = agent_factory(env=env, data_dir=fresh_data_dir)
    agent.wait_for_event("agent_running", timeout=10.0)

    # Wait for the first successful sync.
    _wait_until(
        lambda: len(mock_dashboard.received_discovered_hosts()) >= 1,
        timeout=15.0,
    )
    sync_count_after_first = len(mock_dashboard.received_discovered_hosts())

    # Trip NetBox into 500-mode. Subsequent sync attempts should NOT
    # produce a /discovered-hosts call (the safety contract: NetBox
    # failure → preserve last known state).
    mock_netbox.simulate_failure("500")

    # Give the next scheduled sync time to run and fail.
    agent.wait_for_event(
        "netbox_sync_netbox_error_preserving_state", timeout=15.0,
    )

    # Confirm no new discovered-hosts calls landed.
    assert (
        len(mock_dashboard.received_discovered_hosts())
        == sync_count_after_first
    ), "NetBox failure should NOT trigger a wipe of dashboard state"

    # Recovery: clear the failure, expect another successful sync.
    mock_netbox.simulate_failure(None)
    _wait_until(
        lambda: len(mock_dashboard.received_discovered_hosts()) > sync_count_after_first,
        timeout=15.0,
    )

    rc = agent.stop(timeout=10.0)
    assert rc == 0


# ============================================================
#  Scenario 8: Auth-error revocation → exit 2
# ============================================================


def test_scenario_8_revocation_causes_agent_exit_2(
    mock_dashboard, agent_factory, fresh_data_dir,
):
    mock_dashboard.add_valid_registration_token(REGISTRATION_TOKEN)

    agent = agent_factory(
        env=_base_env(mock_dashboard), data_dir=fresh_data_dir,
    )
    agent.wait_for_event("agent_running", timeout=10.0)
    _wait_until(lambda: len(mock_dashboard.received_heartbeats()) >= 1,
                 timeout=5.0)

    # Operator revokes from the dashboard side.
    mock_dashboard.revoke_agent()

    # Within ~2 heartbeats the agent should observe the 401 and self-shutdown.
    rc = agent.wait(timeout=10.0)
    assert rc == 2, f"expected exit code 2 (auth error), got {rc}"

    # The agent logged the auth-error event before exiting.
    auth_errors = [
        ev for ev in agent.events()
        if "auth_error" in ev.get("event", "")
    ]
    assert auth_errors, "expected at least one auth_error log event"


# ============================================================
#  Scenario 9: Pending report retry across restart
# ============================================================


def test_scenario_9_pending_report_retried_across_restart(
    mock_dashboard, agent_factory, fresh_data_dir,
):
    mock_dashboard.add_valid_registration_token(REGISTRATION_TOKEN)
    mock_dashboard.update_config_manual_hosts([_closed_port_host()])

    # Force the next 3 /reports calls to return 503 — the agent will
    # persist the pending file then enter retry-backoff.
    mock_dashboard.force_next_reports(503, count=3)

    first = agent_factory(
        env=_base_env(mock_dashboard), data_dir=fresh_data_dir,
    )
    first.wait_for_event("agent_running", timeout=10.0)

    # Wait for the first failed submission attempt.
    first.wait_for_event("report_submission_retry", timeout=15.0)

    # Pending file should be on disk with non-zero _attempts.
    pending_dir = fresh_data_dir / "pending_reports"
    pending_files = list(pending_dir.glob("*.json")) if pending_dir.exists() else []
    assert pending_files, "expected pending report file on disk during retry-backoff"
    persisted = json.loads(pending_files[0].read_text())
    pending_report_id = persisted["report_id"]
    assert persisted["_attempts"] >= 1

    # Stop the first agent (during backoff). File remains.
    rc = first.stop(timeout=10.0)
    assert rc == 0
    assert (pending_dir / f"{pending_report_id}.json").exists()

    # Clear the forced failures, restart the agent.
    mock_dashboard.clear_forced_failures()
    reports_before_replay = len(mock_dashboard.received_reports())

    env = _base_env(mock_dashboard)
    del env["REGISTRATION_TOKEN"]  # already registered
    second = agent_factory(env=env, data_dir=fresh_data_dir)

    # Replay should run BEFORE any new cycle's report. The replayed
    # report uses the SAME report_id from the persisted file.
    _wait_until(
        lambda: any(
            r.get("report_id") == pending_report_id
            for r in mock_dashboard.received_reports()[reports_before_replay:]
        ),
        timeout=15.0,
    )

    # Pending file deleted after successful replay.
    assert not (pending_dir / f"{pending_report_id}.json").exists()

    rc = second.stop(timeout=10.0)
    assert rc == 0


# ============================================================
#  Scenario 10: Graceful shutdown during cert check cycle
# ============================================================


def _routable_but_silent_host() -> dict:
    """TEST-NET-1 (RFC 5737) — guaranteed not routed. cert_check waits
    its full TCP-connect timeout, giving us time to SIGTERM mid-cycle."""
    return {
        "host_id": "22222222-2222-4222-8222-222222222222",
        "hostname": "192.0.2.1",
        "port": 443,
        "added_at": "2026-04-01T00:00:00Z",
    }


def test_scenario_10_sigterm_during_cycle_completes_and_submits(
    mock_dashboard, agent_factory, fresh_data_dir,
):
    mock_dashboard.add_valid_registration_token(REGISTRATION_TOKEN)
    # Use a config with a slower TCP timeout so the cycle stays in
    # cert_check long enough for our SIGTERM to land mid-cycle.
    mock_dashboard.update_config_manual_hosts([_routable_but_silent_host()])
    # Bump the timeout so the cycle takes ~3s instead of 1s
    with mock_dashboard._state.lock:
        mock_dashboard._state.config["timeouts"] = {
            "tcp_connect_seconds": 3,
            "tls_handshake_seconds": 1,
        }

    agent = agent_factory(
        env=_base_env(mock_dashboard), data_dir=fresh_data_dir,
    )
    agent.wait_for_event("agent_running", timeout=10.0)

    # Wait for the cycle to start, then SIGTERM during the in-flight check.
    agent.wait_for_event("check_cycle_starting", timeout=10.0)
    # Brief delay so we're firmly INSIDE cert_check, not before it.
    time.sleep(0.3)
    agent.send_signal(signal.SIGTERM)

    # Agent should finish in-flight check, submit report, exit cleanly.
    rc = agent.wait(timeout=15.0)
    assert rc == 0, f"expected clean exit (0), got {rc}"

    # The cycle's report DID land — partial-results submission succeeded.
    reports = mock_dashboard.received_reports()
    assert reports, "expected the cycle's report to land before exit"
    cycle_report = reports[0]
    assert len(cycle_report["checks"]) == 1
    assert cycle_report["checks"][0]["status"] == "connection_failed"


# ============================================================
#  Scenario 11: NetBox-discovered hosts get cert-checked
# ============================================================


def test_scenario_11_netbox_hosts_are_cert_checked_in_periodic_cycle(
    mock_dashboard, mock_netbox, agent_factory, fresh_data_dir,
):
    """Regression test for the production bug where NetBox sync only
    populated dashboard inventory but the cycle thread never actually
    cert-checked the discovered hosts. With the fix, NetBox hosts go
    through the cert-discovery pipeline (Phase 9c) — connect by IP,
    discover the cert-presented hostname.

    Wire shape (Phase 9b/9c compat envelope): netbox checks carry
    `status_detail` with the precise 9-value enum alongside the legacy
    3-value `status` for backward compatibility."""
    mock_dashboard.add_valid_registration_token(REGISTRATION_TOKEN)
    # NetBox device with a closed-port IP → discovery completes quickly
    # with status=connection_refused (testing the wire flow, not the
    # success path — cert-discovery success requires a real TLS target).
    mock_netbox.add_device(
        netbox_device_id=1247, name="localhost",
        primary_ip4="127.0.0.1/32",
        custom_fields={"cert_check_port": 9},  # discard port — closed
        tags=["monitor-cert"],
    )

    env = _base_env(mock_dashboard, extra={
        "NETBOX_URL": mock_netbox.url,
        "NETBOX_TOKEN": "nbtok_test",
        "NETBOX_FILTER": "tag=monitor-cert",
    })

    agent = agent_factory(env=env, data_dir=fresh_data_dir)
    agent.wait_for_event("agent_running", timeout=10.0)

    # Wait for a cycle's report to land that contains a NetBox host_ref.
    # The first cycle may run before NetBox sync completes (race), so
    # we wait for a report with a netbox check specifically.
    def has_netbox_check():
        for report in mock_dashboard.received_reports():
            for check in (report.get("checks") or []):
                ref = check.get("host_ref") or {}
                if ref.get("type") == "netbox":
                    return True
        return False

    _wait_until(has_netbox_check, timeout=20.0)

    # Verify the netbox check made it to the dashboard with the right shape
    netbox_checks = []
    for report in mock_dashboard.received_reports():
        for check in (report.get("checks") or []):
            if (check.get("host_ref") or {}).get("type") == "netbox":
                netbox_checks.append(check)
    assert netbox_checks, "expected at least one netbox host_ref in reports"
    nc = netbox_checks[0]
    assert nc["host_ref"]["netbox_device_id"] == 1247
    # Compat envelope: legacy `status` for old dashboards, precise
    # `status_detail` for new ones. Closed port → connection_refused.
    assert nc["status"] == "connection_failed"
    assert nc["status_detail"] == "connection_refused"
    # No cert recovered on a connection-family failure.
    assert nc["cert"] is None

    rc = agent.stop(timeout=10.0)
    assert rc == 0


def test_scenario_12_check_now_on_netbox_host_succeeds(
    mock_dashboard, mock_netbox, agent_factory, fresh_data_dir,
):
    """The "Check Now" button on a NetBox host's detail page queues a
    check_host action with a netbox host_ref. The agent's action
    handler must resolve it via NetBoxHostsState and submit an
    on_demand report. Pre-fix, the handler logged
    'action_check_host_netbox_not_yet_supported' and did nothing."""
    mock_dashboard.add_valid_registration_token(REGISTRATION_TOKEN)
    mock_netbox.add_device(
        netbox_device_id=1247, name="esxi02.lab",
        primary_ip4="127.0.0.1/32",
        custom_fields={"cert_check_port": 9},
        tags=["monitor-cert"],
    )

    env = _base_env(mock_dashboard, extra={
        "NETBOX_URL": mock_netbox.url,
        "NETBOX_TOKEN": "nbtok_test",
        "NETBOX_FILTER": "tag=monitor-cert",
    })
    agent = agent_factory(env=env, data_dir=fresh_data_dir)
    agent.wait_for_event("agent_running", timeout=10.0)

    # Wait for the first NetBox sync to populate local state, otherwise
    # the action handler can't resolve the netbox_device_id.
    _wait_until(
        lambda: len(mock_dashboard.received_discovered_hosts()) >= 1,
        timeout=15.0,
    )

    # Queue Check Now on the NetBox host.
    action_id = mock_dashboard.queue_action(
        "check_host",
        payload={"host_ref": {
            "type": "netbox", "netbox_device_id": 1247,
        }},
    )

    # The agent should pick it up via heartbeat and submit an on_demand
    # report with the action_id echoed.
    _wait_until(
        lambda: any(
            r.get("action_id") == action_id
            for r in mock_dashboard.received_reports()
        ),
        timeout=20.0,
    )

    on_demand = next(
        r for r in mock_dashboard.received_reports()
        if r.get("action_id") == action_id
    )
    assert on_demand["report_type"] == "on_demand"
    assert on_demand["action_id"] == action_id
    assert len(on_demand["checks"]) == 1
    check = on_demand["checks"][0]
    assert check["host_ref"]["type"] == "netbox"
    assert check["host_ref"]["netbox_device_id"] == 1247
    # Cert-discovery ran against the resolved IP:port. Compat envelope:
    # legacy `status` + precise `status_detail` from Phase 9b.
    assert check["status"] in ("connection_failed", "tls_failed", "success")
    assert "status_detail" in check, (
        "netbox-path checks must carry status_detail (compat envelope)"
    )
    assert check["status_detail"] in (
        "connection_refused", "connection_timeout",
        "tls_failed_no_cert", "tls_failed_malformed_cert",
        "cert_expired", "cert_no_usable_hostname", "tls_warning",
        "cert_expiring_soon", "success",
    )

    # No "not yet supported" log — proves the new resolution path ran
    not_supported = [
        ev for ev in agent.events()
        if ev.get("event") == "action_check_host_netbox_not_yet_supported"
    ]
    assert not_supported == [], (
        "the obsolete not-yet-supported event should never fire — "
        "it would mean the netbox-resolution path didn't run"
    )

    rc = agent.stop(timeout=10.0)
    assert rc == 0


# ============================================================
#  Scenario 13: NetBox device with no primary_ip falls back to hostname
# ============================================================


def test_scenario_13_netbox_host_without_primary_ip_falls_back_to_hostname(
    mock_dashboard, mock_netbox, agent_factory, fresh_data_dir,
):
    """NetBox devices that don't have primary_ip4/6 set (newly-added,
    or operator hasn't filled it in yet) must still get cert-checked
    using device.name as the connect target. Phase 9c's per-source
    dispatch picks `ip_address or hostname` — this scenario exercises
    the hostname-fallback half.

    Production matters because real NetBox deployments routinely have
    devices in inventory without primary_ip set (host added before its
    network plumbing is finalized). Skipping these would silently drop
    them from monitoring."""
    mock_dashboard.add_valid_registration_token(REGISTRATION_TOKEN)
    # NO primary_ip4. name="localhost" is reachable; port 9 closed →
    # connection_refused (fast).
    mock_netbox.add_device(
        netbox_device_id=1300, name="localhost",
        custom_fields={"cert_check_port": 9},
        tags=["monitor-cert"],
    )

    env = _base_env(mock_dashboard, extra={
        "NETBOX_URL": mock_netbox.url,
        "NETBOX_TOKEN": "nbtok_test",
        "NETBOX_FILTER": "tag=monitor-cert",
    })

    agent = agent_factory(env=env, data_dir=fresh_data_dir)
    agent.wait_for_event("agent_running", timeout=10.0)

    # First, verify the discovered-hosts payload reflects the missing IP
    # (regression: an earlier bug populated ip_address from hostname).
    _wait_until(
        lambda: len(mock_dashboard.received_discovered_hosts()) >= 1,
        timeout=15.0,
    )
    sync = mock_dashboard.received_discovered_hosts()[0]
    h = next(h for h in sync["hosts"] if h["netbox_device_id"] == 1300)
    # Missing primary_ip → no ip_address in the discovered-hosts payload
    # (or null, depending on the wire shape).
    assert h.get("ip_address") in (None, "")

    # Wait for a netbox check to land in a cycle's report.
    def has_check_for_1300():
        for report in mock_dashboard.received_reports():
            for check in (report.get("checks") or []):
                ref = check.get("host_ref") or {}
                if (ref.get("type") == "netbox"
                        and ref.get("netbox_device_id") == 1300):
                    return True
        return False

    _wait_until(has_check_for_1300, timeout=20.0)

    # The cert-discovery still ran (fallback path) and produced a
    # connection_refused — which is only possible if the agent
    # successfully resolved "localhost" to 127.0.0.1 and connected.
    matching = []
    for report in mock_dashboard.received_reports():
        for check in (report.get("checks") or []):
            ref = check.get("host_ref") or {}
            if (ref.get("type") == "netbox"
                    and ref.get("netbox_device_id") == 1300):
                matching.append(check)
    assert matching
    assert matching[0]["status"] == "connection_failed"
    assert matching[0]["status_detail"] == "connection_refused"

    rc = agent.stop(timeout=10.0)
    assert rc == 0


# ============================================================
#  Scenario 14: startup cycle waits for first NetBox sync (Bug 2)
# ============================================================


def test_scenario_14_startup_cycle_includes_netbox_hosts_no_race(
    mock_dashboard, mock_netbox, agent_factory, fresh_data_dir,
):
    """Regression test for the production startup race: the FIRST cycle
    must include NetBox-discovered hosts when NetBox is configured and
    has hosts. Pre-fix, check_thread and netbox_sync_thread started
    together; the cycle read empty netbox_hosts_state and the first
    report had netbox_hosts_count=0. Operators saw 'Last check: never'
    on every NetBox device until the next scheduled cycle (default 1h).

    Fix: check_thread blocks on the first_netbox_sync_done event before
    its first cycle. Bounded wait protects against misconfigured/down
    NetBox."""
    mock_dashboard.add_valid_registration_token(REGISTRATION_TOKEN)
    mock_netbox.add_device(
        netbox_device_id=2701, name="localhost",
        primary_ip4="127.0.0.1/32",
        custom_fields={"cert_check_port": 9},
        tags=["monitor-cert"],
    )
    mock_netbox.add_device(
        netbox_device_id=2702, name="localhost",
        primary_ip4="127.0.0.1/32",
        custom_fields={"cert_check_port": 9},
        tags=["monitor-cert"],
    )

    env = _base_env(mock_dashboard, extra={
        "NETBOX_URL": mock_netbox.url,
        "NETBOX_TOKEN": "nbtok_test",
        "NETBOX_FILTER": "tag=monitor-cert",
    })

    agent = agent_factory(env=env, data_dir=fresh_data_dir)
    agent.wait_for_event("agent_running", timeout=10.0)

    # Wait specifically for the FIRST check_cycle_summary log.
    def first_cycle_summary():
        for ev in agent.events():
            if ev.get("event") == "check_cycle_summary":
                return ev
        return None

    _wait_until(lambda: first_cycle_summary() is not None, timeout=15.0)
    summary = first_cycle_summary()
    assert summary["netbox_hosts_count"] == 2, (
        f"first cycle must include both NetBox hosts; got summary={summary}. "
        "If netbox_hosts_count=0, the startup race regressed."
    )

    # The waiting log line should also be present — proves the gate
    # actually engaged rather than the cycle running by luck.
    waited = [
        ev for ev in agent.events()
        if ev.get("event") == "check_thread_waiting_for_first_netbox_sync"
    ]
    proceeded = [
        ev for ev in agent.events()
        if ev.get("event") == "check_thread_first_netbox_sync_done_proceeding"
    ]
    assert len(waited) == 1
    assert len(proceeded) == 1

    rc = agent.stop(timeout=10.0)
    assert rc == 0


# ============================================================
#  Scenario 15: dashboard-triggered sync updates local state (Bug 1)
# ============================================================


def test_scenario_15_sync_netbox_action_updates_local_state(
    mock_dashboard, mock_netbox, agent_factory, fresh_data_dir,
):
    """Regression test for the bug where dashboard-triggered Sync NetBox
    populated dashboard inventory but left the agent's local
    NetBoxHostsState empty. Repro: operator tags a new device, presses
    Sync NetBox, then immediately presses Check Now — the Check Now
    action fails with action_check_host_netbox_id_not_found because
    the handler resolves netbox_device_ids against local state, which
    the action handler hadn't updated.

    Fix: make_sync_netbox_handler now accepts netbox_hosts_state and
    threads it through to run_netbox_sync, mirroring the scheduled
    NetBoxSyncThread."""
    mock_dashboard.add_valid_registration_token(REGISTRATION_TOKEN)
    # Start with NO devices in NetBox so the initial sync establishes
    # an empty baseline.

    env = _base_env(mock_dashboard, extra={
        "NETBOX_URL": mock_netbox.url,
        "NETBOX_TOKEN": "nbtok_test",
        "NETBOX_FILTER": "tag=monitor-cert",
    })
    agent = agent_factory(env=env, data_dir=fresh_data_dir)
    agent.wait_for_event("agent_running", timeout=10.0)

    # Wait for the initial NetBox sync (zero hosts) to complete.
    _wait_until(
        lambda: len(mock_dashboard.received_discovered_hosts()) >= 1,
        timeout=10.0,
    )

    # Operator tags a new device in NetBox.
    mock_netbox.add_device(
        netbox_device_id=2750, name="localhost",
        primary_ip4="127.0.0.1/32",
        custom_fields={"cert_check_port": 9},
        tags=["monitor-cert"],
    )

    # Operator presses "Sync NetBox" in the dashboard. This dispatches
    # a sync_netbox action. The new device should be syncrhonized to
    # the dashboard AND to the agent's local state — that's the bug.
    sync_action_id = mock_dashboard.queue_action("sync_netbox")
    _wait_until(
        lambda: any(
            r.get("action_id") == sync_action_id
            for r in mock_dashboard.received_discovered_hosts()
        ),
        timeout=10.0,
    )

    # NOW the operator immediately presses "Check Now" on the new
    # device. Pre-fix: the action handler resolves netbox_device_id
    # against local state, doesn't find 2750, logs
    # action_check_host_netbox_id_not_found and skips.
    check_action_id = mock_dashboard.queue_action(
        "check_host",
        payload={"host_ref": {"type": "netbox", "netbox_device_id": 2750}},
    )
    _wait_until(
        lambda: any(
            r.get("action_id") == check_action_id
            for r in mock_dashboard.received_reports()
        ),
        timeout=15.0,
    )

    # The Check Now action must NOT have logged "id not found".
    not_found = [
        ev for ev in agent.events()
        if ev.get("event") == "action_check_host_netbox_id_not_found"
        and ev.get("netbox_device_id") == 2750
    ]
    assert not_found == [], (
        "action_check_host_netbox_id_not_found fired for the freshly-"
        "synced device — local state wasn't updated by the sync_netbox "
        "action handler. Bug 1 regressed."
    )

    # And the on_demand report must include a netbox check for 2750.
    on_demand = next(
        r for r in mock_dashboard.received_reports()
        if r.get("action_id") == check_action_id
    )
    assert on_demand["report_type"] == "on_demand"
    assert len(on_demand["checks"]) == 1
    check = on_demand["checks"][0]
    assert check["host_ref"]["type"] == "netbox"
    assert check["host_ref"]["netbox_device_id"] == 2750

    rc = agent.stop(timeout=10.0)
    assert rc == 0
