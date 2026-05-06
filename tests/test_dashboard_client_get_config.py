"""Phase 4c — DashboardClient.get_config() tests."""

from __future__ import annotations

import pytest
import requests
import responses

from certwatch.dashboard_client import (
    DashboardAuthError,
    DashboardClient,
    DashboardNetworkError,
    DashboardNotFoundError,
    DashboardRetriableError,
    DashboardServerError,
)

DASH = "https://certwatch.lovable.app"
AGENT_ID = "a8f3d12e-7b4c-4d8a-9e1f-2c5b6a7d8e9f"
SECRET = "agtkey_test"
CONFIG_URL = f"{DASH}/api/v1/agents/{AGENT_ID}/config"

SAMPLE_RESPONSE = {
    "config_version": 7,
    "fetched_at": "2026-05-02T14:35:00Z",
    "intervals": {
        "heartbeat_seconds": 15,
        "check_seconds": 3600,
        "netbox_sync_seconds": 3600,
    },
    "timeouts": {
        "tcp_connect_seconds": 5,
        "tls_handshake_seconds": 5,
    },
    "concurrency": {
        "max_parallel_checks": 20,
    },
    "alert_thresholds_days": [30, 7, 1],
    "manual_hosts": [
        {
            "host_id": "b1c2d3e4-5f6a-7b8c-9d0e-1f2a3b4c5d6e",
            "hostname": "app.kurmi-lab-paris.local",
            "port": 443,
            "added_at": "2026-04-28T10:00:00Z",
        }
    ],
}


@pytest.fixture
def client():
    return DashboardClient(DASH, agent_id=AGENT_ID, agent_secret=SECRET)


# ---- 200 success ------------------------------------------------------


def test_get_config_returns_parsed_response(client):
    with responses.RequestsMock() as rsps:
        rsps.add("GET", CONFIG_URL, json=SAMPLE_RESPONSE, status=200)
        result = client.get_config()
    assert result == SAMPLE_RESPONSE


def test_get_config_top_level_keys_present(client):
    with responses.RequestsMock() as rsps:
        rsps.add("GET", CONFIG_URL, json=SAMPLE_RESPONSE, status=200)
        result = client.get_config()
    for key in (
        "config_version",
        "fetched_at",
        "intervals",
        "timeouts",
        "concurrency",
        "alert_thresholds_days",
        "manual_hosts",
    ):
        assert key in result


def test_get_config_preserves_nested_structure(client):
    """intervals/timeouts/concurrency must come back as nested dicts, not
    flattened — Phase 5's runner will index into them as configured."""
    with responses.RequestsMock() as rsps:
        rsps.add("GET", CONFIG_URL, json=SAMPLE_RESPONSE, status=200)
        result = client.get_config()
    assert isinstance(result["intervals"], dict)
    assert result["intervals"]["heartbeat_seconds"] == 15
    assert result["intervals"]["check_seconds"] == 3600
    assert result["intervals"]["netbox_sync_seconds"] == 3600
    assert isinstance(result["timeouts"], dict)
    assert result["timeouts"]["tcp_connect_seconds"] == 5
    assert result["timeouts"]["tls_handshake_seconds"] == 5
    assert isinstance(result["concurrency"], dict)
    assert result["concurrency"]["max_parallel_checks"] == 20


def test_get_config_with_empty_manual_hosts(client):
    body = {**SAMPLE_RESPONSE, "manual_hosts": []}
    with responses.RequestsMock() as rsps:
        rsps.add("GET", CONFIG_URL, json=body, status=200)
        result = client.get_config()
    assert result["manual_hosts"] == []


def test_get_config_preserves_host_order_and_fields(client):
    hosts = [
        {
            "host_id": "11111111-1111-4111-8111-111111111111",
            "hostname": "h1.example.com",
            "port": 443,
            "added_at": "2026-04-01T00:00:00Z",
        },
        {
            "host_id": "22222222-2222-4222-8222-222222222222",
            "hostname": "h2.example.com",
            "port": 8443,
            "added_at": "2026-04-02T00:00:00Z",
        },
        {
            "host_id": "33333333-3333-4333-8333-333333333333",
            "hostname": "192.168.1.10",
            "port": 443,
            "added_at": "2026-04-03T00:00:00Z",
        },
    ]
    body = {**SAMPLE_RESPONSE, "manual_hosts": hosts}
    with responses.RequestsMock() as rsps:
        rsps.add("GET", CONFIG_URL, json=body, status=200)
        result = client.get_config()
    assert result["manual_hosts"] == hosts
    assert [h["host_id"] for h in result["manual_hosts"]] == [h["host_id"] for h in hosts]


# ---- request shape ----------------------------------------------------


def test_get_config_url_includes_agent_id(client):
    with responses.RequestsMock() as rsps:
        rsps.add("GET", CONFIG_URL, json=SAMPLE_RESPONSE, status=200)
        client.get_config()
        assert rsps.calls[0].request.url == CONFIG_URL


def test_get_config_sends_authorization_header(client):
    with responses.RequestsMock() as rsps:
        rsps.add("GET", CONFIG_URL, json=SAMPLE_RESPONSE, status=200)
        client.get_config()
        sent = rsps.calls[0].request.headers
        assert sent.get("Authorization") == f"Bearer {SECRET}"


def test_get_config_sends_no_body_or_content_type(client):
    with responses.RequestsMock() as rsps:
        rsps.add("GET", CONFIG_URL, json=SAMPLE_RESPONSE, status=200)
        client.get_config()
        sent = rsps.calls[0].request
        assert sent.body is None
        assert "Content-Type" not in sent.headers


def test_get_config_sends_accept_header(client):
    with responses.RequestsMock() as rsps:
        rsps.add("GET", CONFIG_URL, json=SAMPLE_RESPONSE, status=200)
        client.get_config()
        assert rsps.calls[0].request.headers.get("Accept") == "application/json"


# ---- error mapping ----------------------------------------------------


def test_get_config_401_invalid_token(client):
    body = {
        "error": {
            "code": "invalid_token",
            "message": "secret rejected",
            "request_id": "req_a",
        }
    }
    with responses.RequestsMock() as rsps:
        rsps.add("GET", CONFIG_URL, json=body, status=401)
        with pytest.raises(DashboardAuthError) as exc:
            client.get_config()
    assert exc.value.code == "invalid_token"
    assert exc.value.request_id == "req_a"


def test_get_config_401_agent_revoked_preserves_specific_code(client):
    """Both invalid_token and agent_revoked map to DashboardAuthError, but
    the specific code must be preserved on the exception so the runner
    can log them distinctly (revoked is operator-driven; invalid_token
    might be a corrupted /data/agent.json)."""
    body = {
        "error": {
            "code": "agent_revoked",
            "message": "revoked by operator",
            "request_id": "req_r",
        }
    }
    with responses.RequestsMock() as rsps:
        rsps.add("GET", CONFIG_URL, json=body, status=401)
        with pytest.raises(DashboardAuthError) as exc:
            client.get_config()
    assert exc.value.code == "agent_revoked"


def test_get_config_404_agent_not_found(client):
    body = {
        "error": {
            "code": "agent_not_found",
            "message": "no such agent",
            "request_id": "req_n",
        }
    }
    with responses.RequestsMock() as rsps:
        rsps.add("GET", CONFIG_URL, json=body, status=404)
        with pytest.raises(DashboardNotFoundError) as exc:
            client.get_config()
    assert exc.value.code == "agent_not_found"


def test_get_config_500_is_retriable(client):
    body = {"error": {"code": "internal_error", "message": "boom", "request_id": "req_e"}}
    with responses.RequestsMock() as rsps:
        rsps.add("GET", CONFIG_URL, json=body, status=500)
        with pytest.raises(DashboardServerError) as exc:
            client.get_config()
    assert isinstance(exc.value, DashboardRetriableError)


def test_get_config_network_timeout_is_retriable(client, monkeypatch):
    def boom(*a, **k):
        raise requests.Timeout("read timeout")
    monkeypatch.setattr(client._session, "request", boom)
    with pytest.raises(DashboardNetworkError) as exc:
        client.get_config()
    assert isinstance(exc.value, DashboardRetriableError)


# ---- programming-error guards -----------------------------------------


def test_get_config_raises_value_error_when_no_agent_id():
    c = DashboardClient(DASH, agent_id=None, agent_secret=SECRET)
    with pytest.raises(ValueError, match="agent_id"):
        c.get_config()


def test_get_config_raises_value_error_when_no_secret():
    c = DashboardClient(DASH, agent_id=AGENT_ID, agent_secret=None)
    with pytest.raises(ValueError, match="agent_secret"):
        c.get_config()


def test_get_config_raises_value_error_when_unregistered():
    c = DashboardClient(DASH)  # no creds at all
    with pytest.raises(ValueError):
        c.get_config()


# ---- forward-compat ---------------------------------------------------


def test_get_config_preserves_unknown_top_level_fields(client):
    """Tolerant reader: future config_versions may add fields. Pass them
    through unfiltered so consumers can opt in if they understand them."""
    body = {
        **SAMPLE_RESPONSE,
        "experimental_feature_x": True,
        "next_thing": [1, 2, 3],
    }
    with responses.RequestsMock() as rsps:
        rsps.add("GET", CONFIG_URL, json=body, status=200)
        result = client.get_config()
    assert result["experimental_feature_x"] is True
    assert result["next_thing"] == [1, 2, 3]


def test_get_config_preserves_unknown_nested_fields(client):
    body = {
        **SAMPLE_RESPONSE,
        "intervals": {**SAMPLE_RESPONSE["intervals"], "future_interval_seconds": 42},
        "timeouts": {**SAMPLE_RESPONSE["timeouts"], "future_timeout_seconds": 99},
    }
    with responses.RequestsMock() as rsps:
        rsps.add("GET", CONFIG_URL, json=body, status=200)
        result = client.get_config()
    assert result["intervals"]["future_interval_seconds"] == 42
    assert result["timeouts"]["future_timeout_seconds"] == 99


def test_get_config_preserves_unknown_host_fields(client):
    """A future API may add per-host fields like check_priority. Don't
    drop them."""
    hosts = [
        {
            "host_id": "11111111-1111-4111-8111-111111111111",
            "hostname": "h.example.com",
            "port": 443,
            "added_at": "2026-04-01T00:00:00Z",
            "check_priority": "high",
            "labels": {"env": "prod"},
        }
    ]
    body = {**SAMPLE_RESPONSE, "manual_hosts": hosts}
    with responses.RequestsMock() as rsps:
        rsps.add("GET", CONFIG_URL, json=body, status=200)
        result = client.get_config()
    assert result["manual_hosts"][0]["check_priority"] == "high"
    assert result["manual_hosts"][0]["labels"] == {"env": "prod"}
