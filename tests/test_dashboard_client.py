"""Phase 4a tests — DashboardClient `_request` helper + exception hierarchy.

Uses the `responses` library to mock the HTTP layer end-to-end (so the same
`requests.Session` codepath runs in tests as in production).
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
    DashboardError,
    DashboardNetworkError,
    DashboardNotFoundError,
    DashboardPayloadTooLargeError,
    DashboardRateLimitError,
    DashboardRetriableError,
    DashboardServerError,
    DashboardValidationError,
)

DASH = "https://certwatch.lovable.app"
PATH = "/api/v1/whatever"
URL = DASH + PATH


@pytest.fixture
def client():
    return DashboardClient(DASH, agent_id="aid", agent_secret="agtkey_test")


@pytest.fixture
def anon_client():
    return DashboardClient(DASH)


# ---- 2xx ---------------------------------------------------------------


def test_2xx_returns_parsed_json(client):
    with responses.RequestsMock() as rsps:
        rsps.add("GET", URL, json={"hello": "world", "n": 7}, status=200)
        assert client._request("GET", PATH) == {"hello": "world", "n": 7}


def test_201_returns_parsed_json(client):
    with responses.RequestsMock() as rsps:
        rsps.add("POST", URL, json={"id": "abc"}, status=201)
        assert client._request("POST", PATH, body={"x": 1}) == {"id": "abc"}


def test_2xx_non_json_raises_dashboard_error(client):
    with responses.RequestsMock() as rsps:
        rsps.add("GET", URL, body="not json", status=200, content_type="text/plain")
        with pytest.raises(DashboardError) as exc:
            client._request("GET", PATH)
    assert "non-JSON" in str(exc.value)
    assert exc.value.status_code == 200


# ---- error status mapping ----------------------------------------------


def test_400_validation_error_preserves_code_and_message(client):
    body = {
        "error": {
            "code": "validation_failed",
            "message": "missing field 'foo'",
            "request_id": "req_v1",
        }
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", URL, json=body, status=400)
        with pytest.raises(DashboardValidationError) as exc:
            client._request("POST", PATH, body={})
    assert exc.value.code == "validation_failed"
    assert exc.value.message == "missing field 'foo'"
    assert exc.value.request_id == "req_v1"
    assert exc.value.status_code == 400


def test_401_auth_error_preserves_envelope(client):
    body = {
        "error": {
            "code": "invalid_token",
            "message": "Agent secret is invalid",
            "request_id": "req_abc123",
        }
    }
    with responses.RequestsMock() as rsps:
        rsps.add("GET", URL, json=body, status=401)
        with pytest.raises(DashboardAuthError) as exc:
            client._request("GET", PATH)
    e = exc.value
    assert e.code == "invalid_token"
    assert e.message == "Agent secret is invalid"
    assert e.request_id == "req_abc123"
    assert e.status_code == 401


def test_404_not_found_with_agent_not_found_code(client):
    body = {
        "error": {
            "code": "agent_not_found",
            "message": "no such agent",
            "request_id": "req_x",
        }
    }
    with responses.RequestsMock() as rsps:
        rsps.add("GET", URL, json=body, status=404)
        with pytest.raises(DashboardNotFoundError) as exc:
            client._request("GET", PATH)
    assert exc.value.code == "agent_not_found"
    assert exc.value.status_code == 404


def test_409_conflict_preserves_full_body(client):
    body = {
        "error": {
            "code": "report_already_received",
            "message": "duplicate report_id",
            "request_id": "req_y",
        },
        "existing_report_id": "abc-123-original",  # extra field beyond envelope
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", URL, json=body, status=409)
        with pytest.raises(DashboardConflictError) as exc:
            client._request("POST", PATH, body={"x": 1})
    e = exc.value
    assert e.code == "report_already_received"
    assert e.body == body
    assert e.body["existing_report_id"] == "abc-123-original"


def test_413_payload_too_large(client):
    with responses.RequestsMock() as rsps:
        rsps.add("POST", URL, json={"error": {"code": "payload_too_large", "message": "too big"}}, status=413)
        with pytest.raises(DashboardPayloadTooLargeError) as exc:
            client._request("POST", PATH, body={"x": 1})
    assert exc.value.code == "payload_too_large"


def test_429_rate_limit_is_retriable(client):
    with responses.RequestsMock() as rsps:
        rsps.add("GET", URL, json={"error": {"code": "rate_limited", "message": "slow down"}}, status=429)
        with pytest.raises(DashboardRateLimitError) as exc:
            client._request("GET", PATH)
    assert isinstance(exc.value, DashboardRetriableError)


def test_500_raises_server_error_retriable(client):
    body = {"error": {"code": "internal_error", "message": "boom", "request_id": "req_e"}}
    with responses.RequestsMock() as rsps:
        rsps.add("GET", URL, json=body, status=500)
        with pytest.raises(DashboardServerError) as exc:
            client._request("GET", PATH)
    assert isinstance(exc.value, DashboardRetriableError)
    assert exc.value.status_code == 500
    assert exc.value.code == "internal_error"


def test_503_also_raises_server_error(client):
    with responses.RequestsMock() as rsps:
        rsps.add("GET", URL, json={}, status=503)
        with pytest.raises(DashboardServerError) as exc:
            client._request("GET", PATH)
    assert exc.value.status_code == 503


def test_unhandled_4xx_raises_base_error(client):
    # 418 is not in the contract; should fall through to base DashboardError
    with responses.RequestsMock() as rsps:
        rsps.add("GET", URL, json={}, status=418)
        with pytest.raises(DashboardError) as exc:
            client._request("GET", PATH)
    # Specifically NOT one of the typed subclasses
    assert type(exc.value) is DashboardError
    assert exc.value.status_code == 418


# ---- network errors ----------------------------------------------------


def test_network_timeout_is_retriable(client, monkeypatch):
    def boom(*a, **k):
        raise requests.Timeout("read timeout")
    monkeypatch.setattr(client._session, "request", boom)
    with pytest.raises(DashboardNetworkError) as exc:
        client._request("GET", PATH)
    assert isinstance(exc.value, DashboardRetriableError)


def test_connection_error_is_retriable(client, monkeypatch):
    def boom(*a, **k):
        raise requests.ConnectionError("ECONNREFUSED")
    monkeypatch.setattr(client._session, "request", boom)
    with pytest.raises(DashboardNetworkError) as exc:
        client._request("GET", PATH)
    assert isinstance(exc.value, DashboardRetriableError)


def test_other_request_exception_is_retriable(client, monkeypatch):
    # Any RequestException subclass we didn't explicitly catch should also
    # surface as DashboardNetworkError so retry policy doesn't miss it.
    def boom(*a, **k):
        raise requests.exceptions.ChunkedEncodingError("partial body")
    monkeypatch.setattr(client._session, "request", boom)
    with pytest.raises(DashboardNetworkError):
        client._request("GET", PATH)


# ---- header behavior ---------------------------------------------------


def test_authorization_header_when_secret_set(client):
    with responses.RequestsMock() as rsps:
        rsps.add("GET", URL, json={}, status=200)
        client._request("GET", PATH)
        sent = rsps.calls[0].request.headers
    assert sent.get("Authorization") == "Bearer agtkey_test"


def test_no_authorization_header_when_no_secret(anon_client):
    with responses.RequestsMock() as rsps:
        rsps.add("GET", URL, json={}, status=200)
        anon_client._request("GET", PATH)
        sent = rsps.calls[0].request.headers
    assert "Authorization" not in sent


def test_accept_header_always_sent(client):
    with responses.RequestsMock() as rsps:
        rsps.add("GET", URL, json={}, status=200)
        client._request("GET", PATH)
        sent = rsps.calls[0].request.headers
    assert sent.get("Accept") == "application/json"


def test_content_type_only_when_body(client):
    with responses.RequestsMock() as rsps:
        rsps.add("GET", URL, json={}, status=200)
        client._request("GET", PATH)
        sent = rsps.calls[0].request.headers
    assert "Content-Type" not in sent


def test_content_type_set_when_body_provided(client):
    with responses.RequestsMock() as rsps:
        rsps.add("POST", URL, json={}, status=200)
        client._request("POST", PATH, body={"x": 1})
        sent = rsps.calls[0].request.headers
    assert sent.get("Content-Type") == "application/json"


def test_body_serialized_as_json(client):
    with responses.RequestsMock() as rsps:
        rsps.add("POST", URL, json={"ok": True}, status=200)
        client._request("POST", PATH, body={"a": [1, 2], "b": "c"})
        sent_body = json.loads(rsps.calls[0].request.body)
    assert sent_body == {"a": [1, 2], "b": "c"}


def test_caller_can_override_headers(client):
    # The register endpoint will use this to pass X-Registration-Token.
    with responses.RequestsMock() as rsps:
        rsps.add("POST", URL, json={}, status=200)
        client._request("POST", PATH, body={}, headers={"X-Registration-Token": "regtok_xyz"})
        sent = rsps.calls[0].request.headers
        assert sent.get("X-Registration-Token") == "regtok_xyz"
        # Default headers still set
        assert sent.get("Accept") == "application/json"


def test_authenticated_false_omits_authorization_header_even_with_secret(client):
    # Defensive: the register endpoint must never send Authorization, even
    # if a misconfigured client somehow has agent_secret set.
    with responses.RequestsMock() as rsps:
        rsps.add("POST", URL, json={}, status=200)
        client._request("POST", PATH, body={}, authenticated=False)
        sent = rsps.calls[0].request.headers
        assert "Authorization" not in sent


# ---- envelope tolerance ------------------------------------------------


def test_envelope_without_request_id(client):
    # Forward-compat: tolerate missing request_id without crashing.
    body = {"error": {"code": "invalid_token", "message": "no rid here"}}
    with responses.RequestsMock() as rsps:
        rsps.add("GET", URL, json=body, status=401)
        with pytest.raises(DashboardAuthError) as exc:
            client._request("GET", PATH)
    assert exc.value.request_id is None
    assert exc.value.code == "invalid_token"
    assert exc.value.message == "no rid here"


def test_envelope_with_extra_fields_is_tolerated(client):
    # Forward-compat: ignore unknown envelope fields.
    body = {
        "error": {
            "code": "invalid_token",
            "message": "x",
            "request_id": "req_a",
            "future_field": "ignored",
        },
        "another_top_level": True,
    }
    with responses.RequestsMock() as rsps:
        rsps.add("GET", URL, json=body, status=401)
        with pytest.raises(DashboardAuthError) as exc:
            client._request("GET", PATH)
    assert exc.value.code == "invalid_token"


def test_response_with_no_envelope_does_not_crash(client):
    # 401 with HTML body (e.g. CDN intercept) — must surface as DashboardAuthError
    # with code/message/request_id all None.
    with responses.RequestsMock() as rsps:
        rsps.add("GET", URL, body="<html>denied</html>", status=401, content_type="text/html")
        with pytest.raises(DashboardAuthError) as exc:
            client._request("GET", PATH)
    assert exc.value.code is None
    assert exc.value.request_id is None
    assert exc.value.status_code == 401


def test_empty_response_body_on_error_does_not_crash(client):
    with responses.RequestsMock() as rsps:
        rsps.add("GET", URL, body="", status=500)
        with pytest.raises(DashboardServerError) as exc:
            client._request("GET", PATH)
    assert exc.value.status_code == 500


def test_error_with_non_dict_envelope_tolerated(client):
    # If "error" key happens to be a string instead of an object, don't crash.
    body = {"error": "just a string"}
    with responses.RequestsMock() as rsps:
        rsps.add("GET", URL, json=body, status=400)
        with pytest.raises(DashboardValidationError) as exc:
            client._request("GET", PATH)
    assert exc.value.code is None


# ---- URL composition ---------------------------------------------------


def test_dashboard_url_trailing_slash_is_normalized():
    c = DashboardClient("https://certwatch.lovable.app/", agent_secret="agtkey_x")
    with responses.RequestsMock() as rsps:
        rsps.add("GET", URL, json={}, status=200)
        c._request("GET", PATH)
        assert rsps.calls[0].request.url == URL


# ---- timeout behavior --------------------------------------------------


def test_default_timeout_is_passed_to_session(monkeypatch):
    seen = {}

    def capture(method, url, *, data=None, headers=None, timeout=None):
        seen["timeout"] = timeout
        r = requests.Response()
        r.status_code = 200
        r._content = b"{}"
        return r

    c = DashboardClient(DASH, agent_secret="x", default_timeout=7.5)
    monkeypatch.setattr(c._session, "request", capture)
    c._request("GET", PATH)
    assert seen["timeout"] == 7.5


def test_per_call_timeout_overrides_default(monkeypatch):
    seen = {}

    def capture(method, url, *, data=None, headers=None, timeout=None):
        seen["timeout"] = timeout
        r = requests.Response()
        r.status_code = 200
        r._content = b"{}"
        return r

    c = DashboardClient(DASH, agent_secret="x", default_timeout=10.0)
    monkeypatch.setattr(c._session, "request", capture)
    c._request("GET", PATH, timeout=2.0)
    assert seen["timeout"] == 2.0
