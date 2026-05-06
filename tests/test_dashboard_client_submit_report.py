"""Phase 4d — DashboardClient.submit_report() tests.

Idempotency-heavy: focus on action_id null-vs-set semantics, 409
report_already_received exposing the full response body via
DashboardConflictError.body, and 413 mapping to the dedicated payload-too-
large exception type.
"""

from __future__ import annotations

import json

import pytest
import requests
import responses

from certwatch.dashboard_client import (
    DashboardClient,
    DashboardConflictError,
    DashboardNetworkError,
    DashboardPayloadTooLargeError,
    DashboardRetriableError,
    DashboardServerError,
    DashboardValidationError,
)

DASH = "https://certwatch.lovable.app"
AGENT_ID = "a8f3d12e-7b4c-4d8a-9e1f-2c5b6a7d8e9f"
SECRET = "agtkey_test"
REPORTS_URL = f"{DASH}/api/public/v1/agents/{AGENT_ID}/reports"

REPORT_ID = "d4e5f6a7-8b9c-0d1e-2f3a-4b5c6d7e8f9a"

SUCCESS_BODY = {
    "received_at": "2026-05-02T15:01:43Z",
    "report_id": REPORT_ID,
    "summary": {
        "total_checks": 1,
        "success": 1,
        "connection_failed": 0,
        "tls_failed": 0,
        "alerts_triggered": 0,
        "ignored_unknown_hosts": 0,
    },
    "action_completed": None,
}


def _cert_dict(**overrides) -> dict:
    base = {
        "subject_cn": "app.kurmi-lab-paris.local",
        "subject_sans": ["app.kurmi-lab-paris.local"],
        "issuer_cn": "Kurmi Internal Lab CA",
        "issuer_o": "Kurmi Software",
        "issuer_full_dn": "CN=Kurmi Internal Lab CA,O=Kurmi Software,C=FR",
        "ca_category": "internal_corporate",
        "is_self_signed": False,
        "not_before": "2025-08-15T00:00:00Z",
        "not_after": "2026-08-15T23:59:59Z",
        "days_until_expiry": 105,
        "signature_algorithm": "sha256WithRSAEncryption",
        "key_size": 2048,
        "hostname_matches": True,
        "chain_trusted_by_system": False,
        "chain_error_reason": "unknown issuer (internal CA not in system trust store)",
    }
    base.update(overrides)
    return base


def _check(host_ref: dict, status: str = "success", error_reason=None, cert=None) -> dict:
    return {
        "host_ref": host_ref,
        "checked_at": "2026-05-02T15:00:03Z",
        "status": status,
        "error_reason": error_reason,
        "cert": cert if cert is not None else (_cert_dict() if status == "success" else None),
    }


@pytest.fixture
def client():
    return DashboardClient(DASH, agent_id=AGENT_ID, agent_secret=SECRET)


def _call(client, **kwargs):
    """Helper with sane defaults so individual tests only set what they care about."""
    defaults = {
        "report_id": REPORT_ID,
        "report_type": "scheduled",
        "started_at": "2026-05-02T15:00:00Z",
        "completed_at": "2026-05-02T15:01:42Z",
        "action_id": None,
        "checks": [],
    }
    defaults.update(kwargs)
    return client.submit_report(**defaults)


# ---- 200 success ------------------------------------------------------


def test_submit_report_returns_parsed_response(client):
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json=SUCCESS_BODY, status=200)
        result = _call(
            client,
            checks=[_check({"type": "manual", "host_id": "host-1"})],
        )
    assert result == SUCCESS_BODY
    assert result["report_id"] == REPORT_ID
    assert result["received_at"] == "2026-05-02T15:01:43Z"
    assert result["summary"]["total_checks"] == 1
    assert result["action_completed"] is None


def test_submit_report_with_empty_checks_is_valid(client):
    """The contract explicitly allows checks=[] — agent ran a cycle and
    found nothing to check."""
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json={**SUCCESS_BODY, "summary": {**SUCCESS_BODY["summary"], "total_checks": 0, "success": 0}}, status=200)
        result = _call(client, checks=[])
        sent = json.loads(rsps.calls[0].request.body)
    assert sent["checks"] == []
    assert result["summary"]["total_checks"] == 0


def test_submit_report_passes_checks_through_verbatim(client):
    """Multi-host with mixed states — verify the wire body matches the
    caller's input bytes-for-bytes (no transformation, no field stripping,
    no reordering)."""
    checks = [
        _check(
            {"type": "manual", "host_id": "11111111-1111-4111-8111-111111111111"},
            status="success",
        ),
        _check(
            {"type": "netbox", "netbox_device_id": 42},
            status="connection_failed",
            error_reason="TimeoutError: timed out",
            cert=None,
        ),
        _check(
            {"type": "manual", "host_id": "22222222-2222-4222-8222-222222222222"},
            status="tls_failed",
            error_reason="certificate has expired",
            cert=_cert_dict(days_until_expiry=-30, chain_trusted_by_system=False),
        ),
    ]
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json=SUCCESS_BODY, status=200)
        _call(client, checks=checks)
        sent = json.loads(rsps.calls[0].request.body)
    assert sent["checks"] == checks
    # Both host_ref discriminator types preserved
    assert sent["checks"][0]["host_ref"]["type"] == "manual"
    assert sent["checks"][1]["host_ref"]["type"] == "netbox"
    assert sent["checks"][1]["host_ref"]["netbox_device_id"] == 42


# ---- action_id semantics (null vs string vs missing) -----------------


def test_submit_report_action_id_included_as_string_when_set(client):
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json=SUCCESS_BODY, status=200)
        _call(client, action_id="action-uuid-123", report_type="on_demand")
        sent = json.loads(rsps.calls[0].request.body)
    assert sent["action_id"] == "action-uuid-123"


def test_submit_report_action_id_included_as_null_when_none(client):
    """CRITICAL: action_id must be present in the body as `null`, NOT
    omitted. The contract distinguishes 'missing' from 'null' — null
    explicitly signals 'this report is not in response to a queued action'.
    Contrast with register's `platform`, which IS omitted when None."""
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json=SUCCESS_BODY, status=200)
        _call(client, action_id=None)
        body_str = rsps.calls[0].request.body
        body = json.loads(body_str)
    assert "action_id" in body
    assert body["action_id"] is None
    # Belt-and-braces: confirm the wire bytes contain "action_id": null
    assert '"action_id": null' in body_str


def test_submit_report_top_level_body_shape(client):
    """All five required top-level fields plus action_id always present."""
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json=SUCCESS_BODY, status=200)
        _call(client, report_type="startup", action_id=None)
        sent = json.loads(rsps.calls[0].request.body)
    assert set(sent.keys()) == {
        "report_id",
        "report_type",
        "started_at",
        "completed_at",
        "action_id",
        "checks",
    }
    assert sent["report_type"] == "startup"


# ---- request shape ----------------------------------------------------


def test_submit_report_url_includes_agent_id(client):
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json=SUCCESS_BODY, status=200)
        _call(client)
        assert rsps.calls[0].request.url == REPORTS_URL


def test_submit_report_sends_authorization_header(client):
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json=SUCCESS_BODY, status=200)
        _call(client)
        sent = rsps.calls[0].request.headers
        assert sent.get("Authorization") == f"Bearer {SECRET}"


def test_submit_report_sends_content_type_and_accept(client):
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json=SUCCESS_BODY, status=200)
        _call(client)
        sent = rsps.calls[0].request.headers
        assert sent.get("Content-Type") == "application/json"
        assert sent.get("Accept") == "application/json"


# ---- 409 idempotency: critical contract -----------------------------


def test_submit_report_409_raises_conflict_with_specific_code(client):
    body = {
        "error": {
            "code": "report_already_received",
            "message": "duplicate report_id",
            "request_id": "req_dup",
        }
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json=body, status=409)
        with pytest.raises(DashboardConflictError) as exc:
            _call(client)
    assert exc.value.code == "report_already_received"
    assert exc.value.request_id == "req_dup"


def test_submit_report_409_body_exposes_original_summary(client):
    """The 409 response MAY include the original received_at and summary
    so the runner can log what the dashboard already saw. .body must
    expose all of it."""
    error_body = {
        "error": {
            "code": "report_already_received",
            "message": "duplicate",
            "request_id": "req_dup",
        },
        "original_received_at": "2026-05-02T15:01:43Z",
        "original_summary": {
            "total_checks": 4,
            "success": 2,
            "connection_failed": 1,
            "tls_failed": 1,
            "alerts_triggered": 1,
            "ignored_unknown_hosts": 0,
        },
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json=error_body, status=409)
        with pytest.raises(DashboardConflictError) as exc:
            _call(client)
    e = exc.value
    assert e.code == "report_already_received"
    assert e.body == error_body
    assert e.body["original_received_at"] == "2026-05-02T15:01:43Z"
    assert e.body["original_summary"]["success"] == 2
    assert e.body["original_summary"]["alerts_triggered"] == 1


def test_submit_report_does_not_swallow_409_into_success(client):
    """Explicit assertion of the 'don't swallow' contract: 409 must raise,
    not return a synthetic success dict. The runner decides how to map
    409→success at its layer; the client never lies about what happened."""
    body = {
        "error": {
            "code": "report_already_received",
            "message": "dup",
            "request_id": "req_x",
        }
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json=body, status=409)
        with pytest.raises(DashboardConflictError):
            _call(client)


# ---- error mapping ----------------------------------------------------


def test_submit_report_400_validation_failed(client):
    body = {
        "error": {
            "code": "validation_failed",
            "message": "checks[0]: status='success' requires non-null cert",
            "request_id": "req_v",
        }
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json=body, status=400)
        with pytest.raises(DashboardValidationError) as exc:
            _call(client)
    assert exc.value.code == "validation_failed"
    assert "cert" in exc.value.message
    # Code bug — not retriable.
    assert not isinstance(exc.value, DashboardRetriableError)


def test_submit_report_413_payload_too_large(client):
    body = {
        "error": {
            "code": "payload_too_large",
            "message": "max 1000 checks per report",
            "request_id": "req_p",
        }
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json=body, status=413)
        with pytest.raises(DashboardPayloadTooLargeError) as exc:
            _call(client)
    assert exc.value.code == "payload_too_large"
    # Programming-error in caller (should batch); explicitly NOT retriable.
    assert not isinstance(exc.value, DashboardRetriableError)


def test_submit_report_500_is_retriable(client):
    body = {"error": {"code": "internal_error", "message": "boom"}}
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json=body, status=500)
        with pytest.raises(DashboardServerError) as exc:
            _call(client)
    assert isinstance(exc.value, DashboardRetriableError)


def test_submit_report_network_timeout_is_retriable(client, monkeypatch):
    def boom(*a, **k):
        raise requests.Timeout("read timeout")
    monkeypatch.setattr(client._session, "request", boom)
    with pytest.raises(DashboardNetworkError) as exc:
        _call(client)
    assert isinstance(exc.value, DashboardRetriableError)


def test_submit_report_connection_error_is_retriable(client, monkeypatch):
    def boom(*a, **k):
        raise requests.ConnectionError("ECONNREFUSED")
    monkeypatch.setattr(client._session, "request", boom)
    with pytest.raises(DashboardNetworkError) as exc:
        _call(client)
    assert isinstance(exc.value, DashboardRetriableError)


# ---- programming-error guards -----------------------------------------


def test_submit_report_raises_value_error_when_no_agent_id():
    c = DashboardClient(DASH, agent_id=None, agent_secret=SECRET)
    with pytest.raises(ValueError, match="agent_id"):
        c.submit_report(REPORT_ID, "scheduled", "t0", "t1", None, [])


def test_submit_report_raises_value_error_when_no_secret():
    c = DashboardClient(DASH, agent_id=AGENT_ID, agent_secret=None)
    with pytest.raises(ValueError, match="agent_secret"):
        c.submit_report(REPORT_ID, "scheduled", "t0", "t1", None, [])


def test_submit_report_raises_value_error_when_unregistered():
    c = DashboardClient(DASH)
    with pytest.raises(ValueError):
        c.submit_report(REPORT_ID, "scheduled", "t0", "t1", None, [])


# ---- forward-compat ---------------------------------------------------


def test_submit_report_preserves_unknown_response_fields(client):
    body = {
        **SUCCESS_BODY,
        "experimental_feature": True,
        "summary": {
            **SUCCESS_BODY["summary"],
            "future_metric": 42,
        },
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json=body, status=200)
        result = _call(client)
    assert result["experimental_feature"] is True
    assert result["summary"]["future_metric"] == 42


def test_submit_report_returns_action_completed_when_set(client):
    """When fulfilling an on_demand action, the dashboard echoes the
    action_id back as action_completed for the runner's bookkeeping."""
    action_id = "act-9999-uuid"
    body = {**SUCCESS_BODY, "action_completed": action_id}
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json=body, status=200)
        result = _call(client, action_id=action_id, report_type="on_demand")
    assert result["action_completed"] == action_id
