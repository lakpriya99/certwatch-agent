"""Phase 4f — DashboardClient.heartbeat() tests.

Three contract twists that shape the test design:
  1. stats=None OMITS the field (no `"stats":` key in body) — opposite of
     submit_report's action_id null-vs-missing pattern. Wire-bytes asserted.
  2. The dashboard is LENIENT about heartbeats (accepts malformed stats
     rather than dropping the liveness signal). The client doesn't
     validate stats sub-fields.
  3. pending_actions are passed through verbatim — including unknown
     action_types. Blocking known actions on an unknown sibling would be
     self-inflicted DOS for v2 forward-compat.
"""

from __future__ import annotations

import json

import pytest
import requests
import responses

from certwatch.dashboard_client import (
    DashboardAuthError,
    DashboardClient,
    DashboardNetworkError,
    DashboardRetriableError,
    DashboardServerError,
    DashboardValidationError,
)

DASH = "https://certwatch.lovable.app"
AGENT_ID = "a8f3d12e-7b4c-4d8a-9e1f-2c5b6a7d8e9f"
SECRET = "agtkey_test"
HB_URL = f"{DASH}/api/public/v1/agents/{AGENT_ID}/heartbeat"

SENT_AT = "2026-05-02T15:30:00Z"

STEADY_STATE_RESPONSE = {
    "received_at": "2026-05-02T15:30:00Z",
    "config_version": 12,
    "config_refresh_required": False,
    "pending_actions": [],
}

FULL_STATS = {
    "hosts_monitored": 47,
    "last_check_completed_at": "2026-05-02T15:00:00Z",
    "last_check_duration_seconds": 102,
    "last_netbox_sync_at": "2026-05-02T15:00:00Z",
    "checks_succeeded_last_cycle": 45,
    "checks_failed_last_cycle": 2,
}


@pytest.fixture
def client():
    return DashboardClient(DASH, agent_id=AGENT_ID, agent_secret=SECRET)


def _hb(client, **kwargs):
    """Helper with sane defaults so each test only sets what it cares about."""
    defaults = {
        "sent_at": SENT_AT,
        "agent_version": "0.1.0",
        "uptime_seconds": 86421,
        "current_config_version": 12,
        "stats": None,
    }
    defaults.update(kwargs)
    return client.heartbeat(**defaults)


# ---- 200 steady state (Mode 1) ---------------------------------------


def test_heartbeat_steady_state_returns_parsed_response(client):
    with responses.RequestsMock() as rsps:
        rsps.add("POST", HB_URL, json=STEADY_STATE_RESPONSE, status=200)
        result = _hb(client)
    assert result == STEADY_STATE_RESPONSE
    assert result["config_refresh_required"] is False
    assert result["pending_actions"] == []
    assert result["config_version"] == 12


# ---- stats: omit-when-None (the inverse pattern) ---------------------


def test_heartbeat_stats_none_omits_field_entirely(client):
    """Wire-bytes assertion of the omit-when-None contract. A future
    refactor that 'helpfully' sends stats=null would silently break the
    contract — opposite direction from the action_id assertions in
    submit_report. Both directions need explicit wire tests."""
    with responses.RequestsMock() as rsps:
        rsps.add("POST", HB_URL, json=STEADY_STATE_RESPONSE, status=200)
        _hb(client, stats=None)
        body_str = rsps.calls[0].request.body
        body = json.loads(body_str)
    # Dict-level: stats key absent
    assert "stats" not in body
    # Bytes-level: no `"stats":` substring anywhere in the payload
    assert '"stats":' not in body_str


def test_heartbeat_full_stats_passes_through_verbatim(client):
    with responses.RequestsMock() as rsps:
        rsps.add("POST", HB_URL, json=STEADY_STATE_RESPONSE, status=200)
        _hb(client, stats=FULL_STATS)
        sent = json.loads(rsps.calls[0].request.body)
    assert sent["stats"] == FULL_STATS
    # All six sub-fields preserved with original values
    assert sent["stats"]["hosts_monitored"] == 47
    assert sent["stats"]["checks_failed_last_cycle"] == 2


def test_heartbeat_partial_stats_does_not_fill_defaults(client):
    """Lenient-telemetry contract: send only what the agent has, don't
    gap-fill missing sub-fields with zeros or nulls. The dashboard
    handles partial telemetry."""
    partial = {"hosts_monitored": 47, "checks_failed_last_cycle": 2}
    with responses.RequestsMock() as rsps:
        rsps.add("POST", HB_URL, json=STEADY_STATE_RESPONSE, status=200)
        _hb(client, stats=partial)
        sent = json.loads(rsps.calls[0].request.body)
    assert sent["stats"] == partial
    # Specifically: other documented sub-fields are NOT auto-added
    for absent in (
        "last_check_completed_at",
        "last_check_duration_seconds",
        "last_netbox_sync_at",
        "checks_succeeded_last_cycle",
    ):
        assert absent not in sent["stats"]


def test_heartbeat_top_level_body_shape_without_stats(client):
    """When stats=None, exactly four top-level keys."""
    with responses.RequestsMock() as rsps:
        rsps.add("POST", HB_URL, json=STEADY_STATE_RESPONSE, status=200)
        _hb(client, stats=None)
        sent = json.loads(rsps.calls[0].request.body)
    assert set(sent.keys()) == {
        "sent_at",
        "agent_version",
        "uptime_seconds",
        "current_config_version",
    }


def test_heartbeat_top_level_body_shape_with_stats(client):
    """When stats is provided, exactly five top-level keys."""
    with responses.RequestsMock() as rsps:
        rsps.add("POST", HB_URL, json=STEADY_STATE_RESPONSE, status=200)
        _hb(client, stats=FULL_STATS)
        sent = json.loads(rsps.calls[0].request.body)
    assert set(sent.keys()) == {
        "sent_at",
        "agent_version",
        "uptime_seconds",
        "current_config_version",
        "stats",
    }


def test_heartbeat_does_not_validate_stats_subfield_types(client):
    """Lenient-validation contract: client passes whatever the caller
    provided. If the runner sends a string where an integer was expected,
    the dashboard logs and accepts; the client itself never rejects."""
    weird_stats = {
        "hosts_monitored": "not-an-integer",  # wrong type
        "future_metric": {"nested": [1, 2, 3]},  # unexpected shape
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", HB_URL, json=STEADY_STATE_RESPONSE, status=200)
        _hb(client, stats=weird_stats)
        sent = json.loads(rsps.calls[0].request.body)
    assert sent["stats"] == weird_stats


# ---- response Mode 2 (config changed) --------------------------------


def test_heartbeat_mode_2_config_refresh_required(client):
    response = {
        "received_at": "2026-05-02T15:30:00Z",
        "config_version": 14,
        "config_refresh_required": True,
        "pending_actions": [],
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", HB_URL, json=response, status=200)
        result = _hb(client, current_config_version=12)
    assert result["config_refresh_required"] is True
    assert result["config_version"] == 14
    assert result["pending_actions"] == []


# ---- response Mode 3 (pending actions) -------------------------------


def test_heartbeat_mode_3_check_host_action(client):
    """check_host action with full payload — verify all action fields
    survive the round-trip."""
    action = {
        "action_id": "e5f6a7b8-9c0d-1e2f-3a4b-5c6d7e8f9a0b",
        "action_type": "check_host",
        "payload": {
            "host_ref": {
                "type": "manual",
                "host_id": "b1c2d3e4-5f6a-7b8c-9d0e-1f2a3b4c5d6e",
            }
        },
        "queued_at": "2026-05-02T15:29:47Z",
        "expires_at": "2026-05-02T15:34:47Z",
    }
    response = {**STEADY_STATE_RESPONSE, "pending_actions": [action]}
    with responses.RequestsMock() as rsps:
        rsps.add("POST", HB_URL, json=response, status=200)
        result = _hb(client)
    assert result["pending_actions"] == [action]
    got = result["pending_actions"][0]
    assert got["action_type"] == "check_host"
    assert got["payload"]["host_ref"]["host_id"] == "b1c2d3e4-5f6a-7b8c-9d0e-1f2a3b4c5d6e"
    assert got["queued_at"] == "2026-05-02T15:29:47Z"
    assert got["expires_at"] == "2026-05-02T15:34:47Z"


def test_heartbeat_mode_3_sync_netbox_with_empty_payload(client):
    """payload: {} for sync_netbox must come through as an empty DICT,
    not None and not a missing key — the runner's action dispatcher
    expects to index into it."""
    action = {
        "action_id": "act-sync-1",
        "action_type": "sync_netbox",
        "payload": {},  # explicitly empty
        "queued_at": "2026-05-02T15:29:47Z",
        "expires_at": "2026-05-02T15:34:47Z",
    }
    response = {**STEADY_STATE_RESPONSE, "pending_actions": [action]}
    with responses.RequestsMock() as rsps:
        rsps.add("POST", HB_URL, json=response, status=200)
        result = _hb(client)
    got = result["pending_actions"][0]
    assert got["action_type"] == "sync_netbox"
    assert got["payload"] == {}
    assert isinstance(got["payload"], dict)


def test_heartbeat_mode_3_multiple_actions_preserves_order(client):
    actions = [
        {
            "action_id": "act-1",
            "action_type": "check_host",
            "payload": {"host_ref": {"type": "manual", "host_id": "h1"}},
            "queued_at": "2026-05-02T15:29:00Z",
            "expires_at": "2026-05-02T15:34:00Z",
        },
        {
            "action_id": "act-2",
            "action_type": "sync_netbox",
            "payload": {},
            "queued_at": "2026-05-02T15:29:30Z",
            "expires_at": "2026-05-02T15:34:30Z",
        },
        {
            "action_id": "act-3",
            "action_type": "check_host",
            "payload": {"host_ref": {"type": "netbox", "netbox_device_id": 42}},
            "queued_at": "2026-05-02T15:29:45Z",
            "expires_at": "2026-05-02T15:34:45Z",
        },
    ]
    response = {**STEADY_STATE_RESPONSE, "pending_actions": actions}
    with responses.RequestsMock() as rsps:
        rsps.add("POST", HB_URL, json=response, status=200)
        result = _hb(client)
    assert result["pending_actions"] == actions
    assert [a["action_id"] for a in result["pending_actions"]] == ["act-1", "act-2", "act-3"]


# ---- combined Mode 2 + Mode 3 (config + actions in same response) ----


def test_heartbeat_mode_2_plus_3_combined(client):
    """config_refresh_required=True AND non-empty pending_actions in the
    same response. The runner orchestrates 'refresh config first, then
    process actions on the new state' — but the client just returns
    both signals as-is."""
    response = {
        "received_at": "2026-05-02T15:30:00Z",
        "config_version": 14,
        "config_refresh_required": True,
        "pending_actions": [
            {
                "action_id": "act-1",
                "action_type": "check_host",
                "payload": {"host_ref": {"type": "manual", "host_id": "h1"}},
                "queued_at": "2026-05-02T15:29:00Z",
                "expires_at": "2026-05-02T15:34:00Z",
            }
        ],
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", HB_URL, json=response, status=200)
        result = _hb(client, current_config_version=12)
    assert result["config_refresh_required"] is True
    assert result["config_version"] == 14
    assert len(result["pending_actions"]) == 1


# ---- forward-compat: unknown action_type ------------------------------


def test_heartbeat_preserves_unknown_action_type_alongside_known(client):
    """v2 may add new action_types like check_all_hosts or reload_config.
    The agent must NOT crash on unknown action_types, AND must not drop
    them from the response — silently dropping would hide v2 behavior
    from the runner's logs. Equally important: unknown actions must not
    block delivery of KNOWN ones in the same response (a self-inflicted
    DOS for v1 agents on v2 dashboards)."""
    response = {
        **STEADY_STATE_RESPONSE,
        "pending_actions": [
            {
                "action_id": "act-known",
                "action_type": "check_host",  # v1 known
                "payload": {"host_ref": {"type": "manual", "host_id": "h1"}},
                "queued_at": "2026-05-02T15:29:00Z",
                "expires_at": "2026-05-02T15:34:00Z",
            },
            {
                "action_id": "act-unknown",
                "action_type": "check_all_hosts",  # v2 hint, unknown to v1
                "payload": {"some_v2_field": True},
                "queued_at": "2026-05-02T15:29:30Z",
                "expires_at": "2026-05-02T15:34:30Z",
            },
        ],
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", HB_URL, json=response, status=200)
        result = _hb(client)
    # Both actions present, in original order
    assert len(result["pending_actions"]) == 2
    assert result["pending_actions"][0]["action_type"] == "check_host"
    assert result["pending_actions"][1]["action_type"] == "check_all_hosts"
    # Unknown action's full structure preserved (so the runner's
    # log+skip path can record exactly what it didn't handle)
    assert result["pending_actions"][1]["payload"] == {"some_v2_field": True}


# ---- request shape ----------------------------------------------------


def test_heartbeat_url_uses_heartbeat_path(client):
    """One-character path-typo guard, same pattern as discovered-hosts."""
    with responses.RequestsMock() as rsps:
        rsps.add("POST", HB_URL, json=STEADY_STATE_RESPONSE, status=200)
        _hb(client)
        url = rsps.calls[0].request.url
        assert url == HB_URL
        assert "/heartbeat" in url


def test_heartbeat_sends_authorization_header(client):
    with responses.RequestsMock() as rsps:
        rsps.add("POST", HB_URL, json=STEADY_STATE_RESPONSE, status=200)
        _hb(client)
        sent = rsps.calls[0].request.headers
        assert sent.get("Authorization") == f"Bearer {SECRET}"


def test_heartbeat_sends_content_type_and_accept(client):
    with responses.RequestsMock() as rsps:
        rsps.add("POST", HB_URL, json=STEADY_STATE_RESPONSE, status=200)
        _hb(client)
        sent = rsps.calls[0].request.headers
        assert sent.get("Content-Type") == "application/json"
        assert sent.get("Accept") == "application/json"


# ---- error mapping ----------------------------------------------------


def test_heartbeat_401_invalid_token(client):
    body = {
        "error": {
            "code": "invalid_token",
            "message": "secret rejected",
            "request_id": "req_a",
        }
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", HB_URL, json=body, status=401)
        with pytest.raises(DashboardAuthError) as exc:
            _hb(client)
    assert exc.value.code == "invalid_token"


def test_heartbeat_401_agent_revoked_preserves_specific_code(client):
    """Operator-driven revocation must be distinguishable from
    invalid_token in logs. Same distinction-via-code pattern as
    get_config — assert the specific code on the exception."""
    body = {
        "error": {
            "code": "agent_revoked",
            "message": "revoked by operator",
            "request_id": "req_r",
        }
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", HB_URL, json=body, status=401)
        with pytest.raises(DashboardAuthError) as exc:
            _hb(client)
    assert exc.value.code == "agent_revoked"


def test_heartbeat_400_validation_failed(client):
    """Rare per the contract (dashboard is lenient about heartbeats),
    but the client doesn't apply any special treatment — it raises and
    lets the Phase 5 runner decide the log+continue policy."""
    body = {
        "error": {
            "code": "validation_failed",
            "message": "current_config_version must be integer",
            "request_id": "req_v",
        }
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", HB_URL, json=body, status=400)
        with pytest.raises(DashboardValidationError) as exc:
            _hb(client)
    assert exc.value.code == "validation_failed"


def test_heartbeat_500_is_retriable(client):
    body = {"error": {"code": "internal_error", "message": "boom"}}
    with responses.RequestsMock() as rsps:
        rsps.add("POST", HB_URL, json=body, status=500)
        with pytest.raises(DashboardServerError) as exc:
            _hb(client)
    assert isinstance(exc.value, DashboardRetriableError)


def test_heartbeat_network_timeout_is_retriable(client, monkeypatch):
    def boom(*a, **k):
        raise requests.Timeout("read timeout")
    monkeypatch.setattr(client._session, "request", boom)
    with pytest.raises(DashboardNetworkError) as exc:
        _hb(client)
    assert isinstance(exc.value, DashboardRetriableError)


def test_heartbeat_connection_error_is_retriable(client, monkeypatch):
    def boom(*a, **k):
        raise requests.ConnectionError("ECONNREFUSED")
    monkeypatch.setattr(client._session, "request", boom)
    with pytest.raises(DashboardNetworkError) as exc:
        _hb(client)
    assert isinstance(exc.value, DashboardRetriableError)


# ---- programming-error guards -----------------------------------------


def test_heartbeat_raises_value_error_when_no_agent_id():
    c = DashboardClient(DASH, agent_id=None, agent_secret=SECRET)
    with pytest.raises(ValueError, match="agent_id"):
        c.heartbeat(SENT_AT, "0.1.0", 0, 12)


def test_heartbeat_raises_value_error_when_no_secret():
    c = DashboardClient(DASH, agent_id=AGENT_ID, agent_secret=None)
    with pytest.raises(ValueError, match="agent_secret"):
        c.heartbeat(SENT_AT, "0.1.0", 0, 12)


def test_heartbeat_raises_value_error_when_unregistered():
    c = DashboardClient(DASH)
    with pytest.raises(ValueError):
        c.heartbeat(SENT_AT, "0.1.0", 0, 12)


# ---- forward-compat: unknown response fields -------------------------


def test_heartbeat_preserves_unknown_top_level_response_fields(client):
    body = {
        **STEADY_STATE_RESPONSE,
        "experimental_field": "future-value",
        "v2_thing": [1, 2, 3],
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", HB_URL, json=body, status=200)
        result = _hb(client)
    assert result["experimental_field"] == "future-value"
    assert result["v2_thing"] == [1, 2, 3]


def test_heartbeat_preserves_unknown_action_fields(client):
    """v2 may add fields inside an action object (priority,
    estimated_duration_seconds, etc.). The runner may use them, ignore
    them, or just log them — but they must SURVIVE through the client."""
    action = {
        "action_id": "act-1",
        "action_type": "check_host",
        "payload": {"host_ref": {"type": "manual", "host_id": "h1"}},
        "queued_at": "2026-05-02T15:29:00Z",
        "expires_at": "2026-05-02T15:34:00Z",
        "priority": "high",  # v2 hint
        "estimated_duration_seconds": 12,  # v2 hint
    }
    response = {**STEADY_STATE_RESPONSE, "pending_actions": [action]}
    with responses.RequestsMock() as rsps:
        rsps.add("POST", HB_URL, json=response, status=200)
        result = _hb(client)
    got = result["pending_actions"][0]
    assert got["priority"] == "high"
    assert got["estimated_duration_seconds"] == 12
