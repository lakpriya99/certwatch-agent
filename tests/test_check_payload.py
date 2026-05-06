"""Phase 5e — check_payload shared module tests.

Targets the extracted shared builder. The Phase 5d action_workers tests
also exercise this code path (they import the same functions via aliases),
so this file's job is to pin the module's contract directly: what does
build_check_payload accept, what does it produce, and what does
cert_dict_from_result do with each CertResult shape.
"""

from __future__ import annotations

from certwatch.cert_check import CertResult
from certwatch.check_payload import build_check_payload, cert_dict_from_result


def _success_result(hostname: str = "x.example.com") -> CertResult:
    return CertResult(
        state="success",
        hostname=hostname,
        port=443,
        checked_at="2026-05-02T15:00:03Z",
        subject_cn=hostname,
        subject_sans=[hostname],
        issuer_cn="DigiCert TLS RSA SHA256 2020 CA1",
        issuer_o="DigiCert Inc",
        issuer_full_dn="CN=DigiCert TLS RSA SHA256 2020 CA1,O=DigiCert Inc,C=US",
        ca_category="well_known_public",
        is_self_signed=False,
        not_before="2025-01-01T00:00:00Z",
        not_after="2026-12-31T23:59:59Z",
        days_until_expiry=240,
        signature_algorithm="SHA256withRSA",
        key_size=2048,
        hostname_matches=True,
        chain_trusted_by_system=True,
        chain_error_reason=None,
    )


def test_build_check_payload_passes_host_ref_through_unchanged():
    """Manual and netbox host_refs must round-trip verbatim — the
    dashboard owns the discriminated-union resolution."""
    manual = {"type": "manual", "host_id": "uuid-1"}
    netbox = {"type": "netbox", "netbox_device_id": 1247}

    p_manual = build_check_payload(manual, _success_result())
    p_netbox = build_check_payload(netbox, _success_result())

    assert p_manual["host_ref"] == manual
    assert p_netbox["host_ref"] == netbox


def test_build_check_payload_top_level_fields():
    p = build_check_payload({"type": "manual", "host_id": "h1"},
                             _success_result())
    assert set(p.keys()) == {"host_ref", "checked_at", "status",
                              "error_reason", "cert"}


def test_cert_dict_returns_none_for_connection_failed():
    r = CertResult(state="connection_failed", hostname="x", port=443,
                    checked_at="t", error_message="timeout")
    assert cert_dict_from_result(r) is None


def test_cert_dict_returns_none_for_tls_failed_without_cert():
    """TLS handshake failed before cert exchange — no cert recovered."""
    r = CertResult(state="tls_failed", hostname="x", port=443,
                    checked_at="t", error_message="protocol violation")
    assert cert_dict_from_result(r) is None


def test_cert_dict_returns_dict_for_tls_failed_with_recovered_cert():
    """The expired/wrong-host/self-signed pattern: validation failed but
    cert was recovered. Dashboard wants the cert details."""
    r = CertResult(
        state="tls_failed", hostname="expired.example.com", port=443,
        checked_at="t", error_message="certificate has expired",
        subject_cn="*.example.com", subject_sans=["*.example.com"],
        issuer_cn="ExpiredCA", issuer_o="Expired Inc",
        issuer_full_dn="CN=ExpiredCA,O=Expired Inc",
        ca_category="well_known_public",
        is_self_signed=False,
        not_before="2024-01-01T00:00:00Z",
        not_after="2025-01-01T00:00:00Z",
        days_until_expiry=-365,
        signature_algorithm="SHA256withRSA", key_size=2048,
        hostname_matches=True,
        chain_trusted_by_system=False,
        chain_error_reason="certificate has expired",
    )
    d = cert_dict_from_result(r)
    assert d is not None
    assert d["chain_trusted_by_system"] is False
    assert d["chain_error_reason"] == "certificate has expired"
    assert d["days_until_expiry"] == -365


def test_cert_dict_includes_all_fifteen_fields_for_success():
    d = cert_dict_from_result(_success_result())
    assert set(d.keys()) == {
        "subject_cn", "subject_sans", "issuer_cn", "issuer_o",
        "issuer_full_dn", "ca_category", "is_self_signed",
        "not_before", "not_after", "days_until_expiry",
        "signature_algorithm", "key_size", "hostname_matches",
        "chain_trusted_by_system", "chain_error_reason",
    }


def test_cert_dict_subject_sans_is_a_list_copy_not_reference():
    """Defensive: mutating the returned subject_sans must not affect
    the source CertResult (the source dataclass is shared across many
    callers — a per-cycle dict, dashboard summary, etc.)."""
    r = _success_result()
    d = cert_dict_from_result(r)
    d["subject_sans"].append("INJECTED")
    assert "INJECTED" not in r.subject_sans
