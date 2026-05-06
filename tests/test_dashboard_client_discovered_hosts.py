"""Phase 4e — DashboardClient.submit_discovered_hosts() tests.

The replace-semantics endpoint. Three traps to keep covered:
  1. Empty hosts=[] is a LEGITIMATE state ("NetBox matched nothing"),
     distinct from "sync failed" (which the caller handles by not calling
     this method at all).
  2. action_id explicit-null vs missing key — wire-bytes asserted.
  3. 413 must NOT be retriable (caller batching bug, retrying loops).

Test names deliberately avoid "with_removed_hosts" or similar — the client
just reports the current set; the dashboard derives removals.
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
    DashboardPayloadTooLargeError,
    DashboardRetriableError,
    DashboardServerError,
    DashboardValidationError,
)

DASH = "https://certwatch.lovable.app"
AGENT_ID = "a8f3d12e-7b4c-4d8a-9e1f-2c5b6a7d8e9f"
SECRET = "agtkey_test"
DISCOVERED_URL = f"{DASH}/api/public/v1/agents/{AGENT_ID}/discovered-hosts"

ACTION_ID = "f6a7b8c9-0d1e-2f3a-4b5c-6d7e8f9a0b1c"

SUCCESS_BODY = {
    "received_at": "2026-05-02T14:40:01Z",
    "summary": {
        "total_received": 3,
        "created": 1,
        "updated": 2,
        "removed": 5,
        "unchanged": 0,
    },
    "config_version": 12,
    "action_completed": None,
}


@pytest.fixture
def client():
    return DashboardClient(DASH, agent_id=AGENT_ID, agent_secret=SECRET)


def _call(client, **kwargs):
    """Helper with sane defaults so individual tests only set what they care about."""
    defaults = {
        "action_id": None,
        "synced_at": "2026-05-02T14:40:00Z",
        "netbox_url": "https://netbox.kurmi-lab-paris.local",
        "netbox_filter": "tag=monitor-cert",
        "hosts": [],
    }
    defaults.update(kwargs)
    return client.submit_discovered_hosts(**defaults)


# ---- 200 success ------------------------------------------------------


def test_submit_discovered_hosts_returns_parsed_response(client):
    with responses.RequestsMock() as rsps:
        rsps.add("POST", DISCOVERED_URL, json=SUCCESS_BODY, status=200)
        result = _call(
            client,
            hosts=[
                {
                    "netbox_device_id": 1247,
                    "hostname": "app01.kurmi-lab-paris.local",
                    "port": 443,
                    "display_name": "Lab Paris App Server 01",
                    "tags": ["monitor-cert", "production-mirror", "web"],
                }
            ],
        )
    assert result == SUCCESS_BODY
    assert result["summary"]["total_received"] == 3
    assert result["config_version"] == 12


def test_submit_discovered_hosts_passes_hosts_through_verbatim(client):
    """Mix of full-fields and required-only hosts — verify the wire body
    matches the caller's input bytes-for-bytes (no transformation, no
    field defaulting)."""
    hosts = [
        {
            "netbox_device_id": 1247,
            "hostname": "app01.kurmi-lab-paris.local",
            "port": 443,
            "display_name": "Lab Paris App Server 01",
            "tags": ["monitor-cert", "production-mirror", "web"],
        },
        {
            # Minimal: only required fields. Dashboard defaults port to 443.
            "netbox_device_id": 1248,
            "hostname": "app02.kurmi-lab-paris.local",
        },
        {
            "netbox_device_id": 1249,
            "hostname": "192.168.1.50",
            "port": 8443,
            "tags": [],  # Empty list — should pass through, not be filtered
        },
    ]
    with responses.RequestsMock() as rsps:
        rsps.add("POST", DISCOVERED_URL, json=SUCCESS_BODY, status=200)
        _call(client, hosts=hosts)
        sent = json.loads(rsps.calls[0].request.body)
    assert sent["hosts"] == hosts
    # Spot-check that minimal host did not gain phantom fields
    assert "port" not in sent["hosts"][1]
    assert "display_name" not in sent["hosts"][1]
    assert "tags" not in sent["hosts"][1]


def test_submit_discovered_hosts_empty_array_is_legitimate(client):
    """The 'NetBox matched nothing this cycle' case. The CALLER is
    responsible for never calling this when NetBox sync FAILED — that
    safety guard lives in Phase 6's NetBox client. But [] meaning 'we
    successfully synced and found zero matching devices' is a real
    legitimate state and the dashboard responds with replace-semantics
    removal counts in summary.removed."""
    response_body = {
        **SUCCESS_BODY,
        "summary": {
            "total_received": 0,
            "created": 0,
            "updated": 0,
            "removed": 5,  # 5 hosts were on dashboard, now wiped by replace
            "unchanged": 0,
        },
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", DISCOVERED_URL, json=response_body, status=200)
        result = _call(client, hosts=[])
        sent = json.loads(rsps.calls[0].request.body)
    assert sent["hosts"] == []
    assert result["summary"]["total_received"] == 0
    assert result["summary"]["removed"] == 5


# ---- action_id semantics (null vs string) ----------------------------


def test_submit_discovered_hosts_action_id_included_as_string_when_set(client):
    with responses.RequestsMock() as rsps:
        rsps.add("POST", DISCOVERED_URL, json={**SUCCESS_BODY, "action_completed": ACTION_ID}, status=200)
        result = _call(client, action_id=ACTION_ID)
        sent = json.loads(rsps.calls[0].request.body)
    assert sent["action_id"] == ACTION_ID
    assert result["action_completed"] == ACTION_ID


def test_submit_discovered_hosts_action_id_included_as_null_when_none(client):
    """Same wire-bytes assertion pattern as submit_report. The contract
    distinguishes 'missing' from 'null': null explicitly signals
    'this sync was scheduled, not action-triggered'. A future refactor
    that 'helpfully' strips None values from the body would silently
    break the contract — assert the bytes."""
    with responses.RequestsMock() as rsps:
        rsps.add("POST", DISCOVERED_URL, json=SUCCESS_BODY, status=200)
        _call(client, action_id=None)
        body_str = rsps.calls[0].request.body
        body = json.loads(body_str)
    assert "action_id" in body
    assert body["action_id"] is None
    assert '"action_id": null' in body_str


def test_submit_discovered_hosts_top_level_body_shape(client):
    """All five top-level fields always present, none stripped."""
    with responses.RequestsMock() as rsps:
        rsps.add("POST", DISCOVERED_URL, json=SUCCESS_BODY, status=200)
        _call(
            client,
            action_id=None,
            synced_at="2026-05-02T14:40:00Z",
            netbox_url="https://netbox.example",
            netbox_filter="tag=cert",
        )
        sent = json.loads(rsps.calls[0].request.body)
    assert set(sent.keys()) == {
        "action_id",
        "synced_at",
        "netbox_url",
        "netbox_filter",
        "hosts",
    }


# ---- request shape ----------------------------------------------------


def test_submit_discovered_hosts_url_uses_hyphenated_path(client):
    """Defensive: the path is `discovered-hosts` (hyphen), not
    `discovered_hosts` (underscore). Trivial to typo."""
    with responses.RequestsMock() as rsps:
        rsps.add("POST", DISCOVERED_URL, json=SUCCESS_BODY, status=200)
        _call(client)
        url = rsps.calls[0].request.url
        assert url == DISCOVERED_URL
        assert "/discovered-hosts" in url


def test_submit_discovered_hosts_sends_authorization_header(client):
    with responses.RequestsMock() as rsps:
        rsps.add("POST", DISCOVERED_URL, json=SUCCESS_BODY, status=200)
        _call(client)
        sent = rsps.calls[0].request.headers
        assert sent.get("Authorization") == f"Bearer {SECRET}"


def test_submit_discovered_hosts_sends_content_type_and_accept(client):
    with responses.RequestsMock() as rsps:
        rsps.add("POST", DISCOVERED_URL, json=SUCCESS_BODY, status=200)
        _call(client)
        sent = rsps.calls[0].request.headers
        assert sent.get("Content-Type") == "application/json"
        assert sent.get("Accept") == "application/json"


# ---- error mapping ----------------------------------------------------


def test_submit_discovered_hosts_400_validation_failed(client):
    """Server-side validation rejects e.g. duplicate netbox_device_id."""
    body = {
        "error": {
            "code": "validation_failed",
            "message": "duplicate netbox_device_id 1247 in hosts array",
            "request_id": "req_dup",
        }
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", DISCOVERED_URL, json=body, status=400)
        with pytest.raises(DashboardValidationError) as exc:
            _call(
                client,
                hosts=[
                    {"netbox_device_id": 1247, "hostname": "a.example.com"},
                    {"netbox_device_id": 1247, "hostname": "b.example.com"},
                ],
            )
    assert exc.value.code == "validation_failed"
    assert "duplicate" in exc.value.message.lower()
    # Code bug in caller — explicitly NOT retriable.
    assert not isinstance(exc.value, DashboardRetriableError)


def test_submit_discovered_hosts_413_payload_too_large_not_retriable(client):
    """Same 'must not loop' assertion as submit_report. Caller (Phase 6)
    must batch <=1000 hosts per request; if the dashboard rejects, that
    signals a batching bug and a retry would just fail the same way."""
    body = {
        "error": {
            "code": "payload_too_large",
            "message": "max 1000 hosts per request",
            "request_id": "req_p",
        }
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", DISCOVERED_URL, json=body, status=413)
        with pytest.raises(DashboardPayloadTooLargeError) as exc:
            _call(client)
    assert exc.value.code == "payload_too_large"
    assert not isinstance(exc.value, DashboardRetriableError)


def test_submit_discovered_hosts_401_invalid_token(client):
    body = {
        "error": {
            "code": "invalid_token",
            "message": "secret rejected",
            "request_id": "req_a",
        }
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", DISCOVERED_URL, json=body, status=401)
        with pytest.raises(DashboardAuthError) as exc:
            _call(client)
    assert exc.value.code == "invalid_token"


def test_submit_discovered_hosts_500_is_retriable(client):
    """Endpoint is naturally idempotent at the payload level, so retrying
    the same payload after 5xx is safe — assert the type the runner
    catches."""
    body = {"error": {"code": "internal_error", "message": "boom"}}
    with responses.RequestsMock() as rsps:
        rsps.add("POST", DISCOVERED_URL, json=body, status=500)
        with pytest.raises(DashboardServerError) as exc:
            _call(client)
    assert isinstance(exc.value, DashboardRetriableError)


def test_submit_discovered_hosts_network_timeout_is_retriable(client, monkeypatch):
    def boom(*a, **k):
        raise requests.Timeout("read timeout")
    monkeypatch.setattr(client._session, "request", boom)
    with pytest.raises(DashboardNetworkError) as exc:
        _call(client)
    assert isinstance(exc.value, DashboardRetriableError)


def test_submit_discovered_hosts_connection_error_is_retriable(client, monkeypatch):
    def boom(*a, **k):
        raise requests.ConnectionError("ECONNREFUSED")
    monkeypatch.setattr(client._session, "request", boom)
    with pytest.raises(DashboardNetworkError) as exc:
        _call(client)
    assert isinstance(exc.value, DashboardRetriableError)


# ---- programming-error guards -----------------------------------------


def test_submit_discovered_hosts_raises_value_error_when_no_agent_id():
    c = DashboardClient(DASH, agent_id=None, agent_secret=SECRET)
    with pytest.raises(ValueError, match="agent_id"):
        c.submit_discovered_hosts(None, "t0", "url", "filter", [])


def test_submit_discovered_hosts_raises_value_error_when_no_secret():
    c = DashboardClient(DASH, agent_id=AGENT_ID, agent_secret=None)
    with pytest.raises(ValueError, match="agent_secret"):
        c.submit_discovered_hosts(None, "t0", "url", "filter", [])


def test_submit_discovered_hosts_raises_value_error_when_unregistered():
    c = DashboardClient(DASH)
    with pytest.raises(ValueError):
        c.submit_discovered_hosts(None, "t0", "url", "filter", [])


# ---- forward-compat ---------------------------------------------------


def test_submit_discovered_hosts_preserves_unknown_top_level_fields(client):
    body = {
        **SUCCESS_BODY,
        "experimental_field": "future-value",
        "v2_thing": [1, 2],
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", DISCOVERED_URL, json=body, status=200)
        result = _call(client)
    assert result["experimental_field"] == "future-value"
    assert result["v2_thing"] == [1, 2]


def test_submit_discovered_hosts_preserves_unknown_summary_fields(client):
    """v2 may add soft_deleted to summary alongside the existing five
    counts. Don't filter."""
    body = {
        **SUCCESS_BODY,
        "summary": {**SUCCESS_BODY["summary"], "soft_deleted": 2, "retained": 0},
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", DISCOVERED_URL, json=body, status=200)
        result = _call(client)
    assert result["summary"]["soft_deleted"] == 2
    assert result["summary"]["retained"] == 0
    # Original summary fields still present
    assert result["summary"]["total_received"] == 3
    assert result["summary"]["removed"] == 5
