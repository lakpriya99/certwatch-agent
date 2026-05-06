"""Phase 6 — sync_netbox action handler tests.

The handler factory has two modes: netbox_client=None (log+skip) and
netbox_client=set (real sync via run_netbox_sync). Both tested here.
"""

from __future__ import annotations

import json
import threading
from unittest.mock import MagicMock

import pytest
import responses

from certwatch.action_workers import (
    ActionContext,
    make_sync_netbox_handler,
    make_sync_netbox_placeholder_handler,
)
from certwatch.clock import FakeClock
from certwatch.dashboard_client import DashboardClient
from certwatch.heartbeat_thread import StatsState
from certwatch.netbox_client import DiscoveredHost, NetBoxClient

DASH = "https://certwatch.lovable.app"
AGENT_ID = "a8f3d12e-7b4c-4d8a-9e1f-2c5b6a7d8e9f"
SECRET = "agtkey_test"
DISCOVERED_URL = f"{DASH}/api/v1/agents/{AGENT_ID}/discovered-hosts"

OK_RESPONSE = {
    "received_at": "2026-05-02T14:40:01Z",
    "summary": {"total_received": 1, "created": 1, "updated": 0,
                 "removed": 0, "unchanged": 0},
    "config_version": 12,
    "action_completed": "act-uuid-1",
}


@pytest.fixture
def dashboard_client():
    return DashboardClient(DASH, agent_id=AGENT_ID, agent_secret=SECRET)


@pytest.fixture
def stats():
    return StatsState(clock=FakeClock())


def _action_ctx(action_id="act-uuid-1") -> ActionContext:
    return ActionContext(
        action_id=action_id, action_type="sync_netbox",
        payload={}, queued_at="t0", expires_at="2099-01-01T00:00:00Z",
    )


# ---- not configured: log + skip --------------------------------------


def test_handler_with_no_netbox_client_logs_and_skips(dashboard_client, stats, caplog):
    handler = make_sync_netbox_handler(
        netbox_client=None, dashboard_client=dashboard_client,
        stats_state=stats, clock=FakeClock(),
        shutdown_event=threading.Event(),
    )

    # No responses mock — if dashboard is called, the test sees an error.
    with caplog.at_level("INFO"):
        handler(_action_ctx())

    skip_logs = [r.msg for r in caplog.records
                 if isinstance(r.msg, dict) and r.msg.get("event") == "netbox_sync_action_received_but_not_configured"]
    assert len(skip_logs) == 1
    assert skip_logs[0]["action_id"] == "act-uuid-1"


def test_placeholder_handler_still_works_for_backward_compat(caplog):
    """The deprecated alias remains for any test that imports it directly."""
    handler = make_sync_netbox_placeholder_handler()
    with caplog.at_level("INFO"):
        handler(_action_ctx())
    msgs = [r.msg for r in caplog.records
            if isinstance(r.msg, dict) and r.msg.get("event") == "netbox_sync_action_received_but_not_configured"]
    assert len(msgs) == 1


# ---- configured: real sync ------------------------------------------


def test_handler_with_netbox_client_runs_sync_with_action_id_echoed(
    dashboard_client, stats
):
    nb = MagicMock(spec=NetBoxClient)
    nb.url = "https://netbox.example"
    nb.filter_expr = "tag=monitor-cert"
    nb.fetch_hosts.return_value = [
        DiscoveredHost(
            netbox_device_id=1, hostname="x", port=443,
            display_name="X", tags=["monitor-cert"],
        ),
    ]

    handler = make_sync_netbox_handler(
        netbox_client=nb, dashboard_client=dashboard_client,
        stats_state=stats, clock=FakeClock(),
        shutdown_event=threading.Event(),
    )

    captured = {}

    def submit_handler(request):
        captured["body"] = json.loads(request.body)
        return (200, {}, json.dumps(OK_RESPONSE))

    with responses.RequestsMock() as rsps:
        rsps.add_callback("POST", DISCOVERED_URL, callback=submit_handler)
        handler(_action_ctx(action_id="act-uuid-xyz"))

    # action_id from the action context is echoed in the body
    assert captured["body"]["action_id"] == "act-uuid-xyz"
    assert len(captured["body"]["hosts"]) == 1


def test_handler_with_netbox_client_doesnt_submit_on_netbox_error(
    dashboard_client, stats
):
    """Safety contract from this layer too: a NetBox error during the
    action handler must not cause a wipe of the dashboard's state."""
    from certwatch.netbox_client import NetBoxSyncError

    nb = MagicMock(spec=NetBoxClient)
    nb.url = "https://netbox.example"
    nb.filter_expr = "tag=monitor-cert"
    nb.fetch_hosts.side_effect = NetBoxSyncError("ECONNREFUSED")

    handler = make_sync_netbox_handler(
        netbox_client=nb, dashboard_client=dashboard_client,
        stats_state=stats, clock=FakeClock(),
        shutdown_event=threading.Event(),
    )

    # No responses mock — if submit is attempted, the test sees ConnectionError.
    with responses.RequestsMock():
        handler(_action_ctx())  # must not raise
