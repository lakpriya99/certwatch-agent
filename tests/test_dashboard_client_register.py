"""Phase 4b — DashboardClient.register() tests.

Kept in its own file so each endpoint test module stays focused on one
endpoint as we add 4c-4f.
"""

from __future__ import annotations

import json

import pytest
import requests
import responses

from certwatch.dashboard_client import (
    DashboardAuthError,
    DashboardClient,
    DashboardConflictError,
    DashboardNetworkError,
    DashboardRetriableError,
    DashboardServerError,
    DashboardValidationError,
)

DASH = "https://certwatch.lovable.app"
REGISTER_URL = DASH + "/api/public/v1/agents/register"

SUCCESS_BODY = {
    "agent_id": "a8f3d12e-7b4c-4d8a-9e1f-2c5b6a7d8e9f",
    "agent_secret": "agtkey_8nP3qR7tY9jH3vB6cF4dG1aE0sZxK9mP2qL5nR7tY8jH3vB",
    "registered_at": "2026-05-02T14:30:01Z",
    "config": {
        "heartbeat_interval_seconds": 15,
        "check_interval_seconds": 3600,
        "config_version": 1,
    },
}


@pytest.fixture
def anon_client():
    return DashboardClient(DASH)


# ---- 201 success ------------------------------------------------------


def test_register_returns_parsed_response_on_201(anon_client):
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REGISTER_URL, json=SUCCESS_BODY, status=201)
        result = anon_client.register(
            registration_token="regtok_xyz",
            agent_version="0.1.0",
            hostname="cert-agent-paris-01",
            platform="linux/amd64",
            started_at="2026-05-02T14:30:00Z",
        )
    assert result == SUCCESS_BODY
    assert result["agent_id"].count("-") == 4  # UUID v4 lowercase hyphenated
    assert result["agent_secret"].startswith("agtkey_")
    assert result["config"]["heartbeat_interval_seconds"] == 15


def test_register_sends_x_registration_token_header(anon_client):
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REGISTER_URL, json=SUCCESS_BODY, status=201)
        anon_client.register(
            "regtok_xyz", "0.1.0", "host", "linux/amd64", "2026-05-02T14:30:00Z"
        )
        sent = rsps.calls[0].request.headers
        assert sent.get("X-Registration-Token") == "regtok_xyz"


def test_register_does_not_send_authorization_header_with_anon_client(anon_client):
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REGISTER_URL, json=SUCCESS_BODY, status=201)
        anon_client.register("regtok_xyz", "0.1.0", "host", None, "ts")
        sent = rsps.calls[0].request.headers
        assert "Authorization" not in sent


def test_register_does_not_send_authorization_even_when_secret_set():
    # Defensive: a misconfigured client with a stale secret must STILL not
    # leak it to the register endpoint.
    misconfigured = DashboardClient(DASH, agent_secret="agtkey_stale")
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REGISTER_URL, json=SUCCESS_BODY, status=201)
        misconfigured.register("regtok_xyz", "0.1.0", "host", None, "ts")
        sent = rsps.calls[0].request.headers
        assert "Authorization" not in sent


def test_register_omits_platform_when_none(anon_client):
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REGISTER_URL, json=SUCCESS_BODY, status=201)
        anon_client.register(
            "regtok_xyz", "0.1.0", "cert-agent-x", None, "2026-05-02T14:30:00Z"
        )
        body = json.loads(rsps.calls[0].request.body)
        assert "platform" not in body
        assert body == {
            "agent_version": "0.1.0",
            "hostname": "cert-agent-x",
            "started_at": "2026-05-02T14:30:00Z",
        }


def test_register_includes_platform_when_set(anon_client):
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REGISTER_URL, json=SUCCESS_BODY, status=201)
        anon_client.register(
            "regtok_xyz", "0.1.0", "host", "linux/amd64", "2026-05-02T14:30:00Z"
        )
        body = json.loads(rsps.calls[0].request.body)
        assert body["platform"] == "linux/amd64"


def test_register_sets_content_type_header(anon_client):
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REGISTER_URL, json=SUCCESS_BODY, status=201)
        anon_client.register("regtok_xyz", "0.1.0", "host", None, "ts")
        sent = rsps.calls[0].request.headers
        assert sent.get("Content-Type") == "application/json"
        assert sent.get("Accept") == "application/json"


# ---- error mapping ----------------------------------------------------


def test_register_401_invalid_registration_token(anon_client):
    body = {
        "error": {
            "code": "invalid_registration_token",
            "message": "Token unknown, expired, or already used",
            "request_id": "req_a",
        }
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REGISTER_URL, json=body, status=401)
        with pytest.raises(DashboardAuthError) as exc:
            anon_client.register("regtok_bad", "0.1.0", "host", None, "ts")
    assert exc.value.code == "invalid_registration_token"
    assert exc.value.request_id == "req_a"
    # NOT retriable — the runner must exit on this.
    assert not isinstance(exc.value, DashboardRetriableError)


def test_register_400_validation_failed(anon_client):
    body = {
        "error": {
            "code": "validation_failed",
            "message": "missing field 'hostname'",
            "request_id": "req_v",
        }
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REGISTER_URL, json=body, status=400)
        with pytest.raises(DashboardValidationError) as exc:
            anon_client.register("regtok_xyz", "0.1.0", "host", None, "ts")
    assert exc.value.code == "validation_failed"
    assert "hostname" in exc.value.message
    # NOT retriable — code bug, fix and redeploy.
    assert not isinstance(exc.value, DashboardRetriableError)


def test_register_409_registration_conflict(anon_client):
    body = {
        "error": {
            "code": "registration_conflict",
            "message": "agent_id already exists",
            "request_id": "req_c",
        }
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REGISTER_URL, json=body, status=409)
        with pytest.raises(DashboardConflictError) as exc:
            anon_client.register("regtok_xyz", "0.1.0", "host", None, "ts")
    assert exc.value.code == "registration_conflict"
    # NOT retriable — runner treats this same as 401.
    assert not isinstance(exc.value, DashboardRetriableError)


def test_register_500_is_retriable(anon_client):
    body = {"error": {"code": "internal_error", "message": "boom", "request_id": "req_e"}}
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REGISTER_URL, json=body, status=500)
        with pytest.raises(DashboardServerError) as exc:
            anon_client.register("regtok_xyz", "0.1.0", "host", None, "ts")
    assert isinstance(exc.value, DashboardRetriableError)


def test_register_503_is_retriable(anon_client):
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REGISTER_URL, json={}, status=503)
        with pytest.raises(DashboardServerError) as exc:
            anon_client.register("regtok_xyz", "0.1.0", "host", None, "ts")
    assert isinstance(exc.value, DashboardRetriableError)


def test_register_network_timeout_is_retriable(anon_client, monkeypatch):
    def boom(*a, **k):
        raise requests.Timeout("read timeout")
    monkeypatch.setattr(anon_client._session, "request", boom)
    with pytest.raises(DashboardNetworkError) as exc:
        anon_client.register("regtok_xyz", "0.1.0", "host", None, "ts")
    assert isinstance(exc.value, DashboardRetriableError)


def test_register_connection_error_is_retriable(anon_client, monkeypatch):
    def boom(*a, **k):
        raise requests.ConnectionError("ECONNREFUSED")
    monkeypatch.setattr(anon_client._session, "request", boom)
    with pytest.raises(DashboardNetworkError):
        anon_client.register("regtok_xyz", "0.1.0", "host", None, "ts")
