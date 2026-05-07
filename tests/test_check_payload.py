"""Phase 5e — check_payload shared module tests.

Targets the extracted shared builder. The Phase 5d action_workers tests
also exercise this code path (they import the same functions via aliases),
so this file's job is to pin the module's contract directly: what does
build_check_payload accept, what does it produce, and what does
cert_dict_from_result do with each CertResult shape.

Phase 9b additions: tests for the discovery-style builder
(build_check_payload_from_discovery / cert_dict_from_discovery_result),
including the exhaustive parametrized status-mapping table.
"""

from __future__ import annotations

import pytest

from certwatch.cert_check import CertResult
from certwatch.cert_check_with_discovery import (
    ALL_STATUSES,
    CertCheckResult,
)
from certwatch.check_payload import (
    build_check_payload,
    build_check_payload_from_discovery,
    cert_dict_from_discovery_result,
    cert_dict_from_result,
)


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


# ---- Phase 9b: discovery-style builder tests ------------------------


def _success_discovery_result(canonical: str = "x.example.com") -> CertCheckResult:
    """A CertCheckResult shaped like a clean handshake-3 success."""
    return CertCheckResult(
        status="success",
        ip_address="10.0.0.5",
        port=443,
        checked_at="2026-05-02T15:00:03Z",
        canonical_hostname=canonical,
        subject_cn=canonical,
        subject_sans=[canonical, "alt.example.com"],
        issuer_cn="DigiCert TLS RSA SHA256 2020 CA1",
        issuer_o="DigiCert Inc",
        issuer_full_dn="CN=DigiCert TLS RSA SHA256 2020 CA1,O=DigiCert Inc,C=US",
        not_before="2025-01-01T00:00:00Z",
        not_after="2026-12-31T23:59:59Z",
        days_until_expiry=240,
        signature_algorithm="SHA256withRSA",
        key_size=2048,
        hostname_matches=True,
        chain_trusted_by_system=True,
        chain_trust_reason=None,
        is_self_signed=False,
    )


# Authoritative table for the parametrized mapping test. Mirrors the
# table inside check_payload._DETAILED_TO_LEGACY_STATUS but is repeated
# here on purpose — we want a test that fails loudly if the production
# table is edited without intent.
_EXPECTED_STATUS_MAPPING = {
    "success":                    "success",
    "cert_expiring_soon":         "success",
    "tls_warning":                "success",
    "cert_expired":               "tls_failed",
    "cert_no_usable_hostname":    "tls_failed",
    "tls_failed_no_cert":         "tls_failed",
    "tls_failed_malformed_cert":  "tls_failed",
    "connection_refused":         "connection_failed",
    "connection_timeout":         "connection_failed",
}


def test_status_mapping_table_covers_every_status_constant():
    """Guardrail: if a new STATUS_* is added to cert_check_with_discovery,
    this test fails until both the production mapping table and the
    expected-mapping table here are updated."""
    assert set(_EXPECTED_STATUS_MAPPING.keys()) == set(ALL_STATUSES)


@pytest.mark.parametrize(
    "detailed_status, expected_legacy_status",
    list(_EXPECTED_STATUS_MAPPING.items()),
)
def test_discovery_builder_maps_status_to_legacy_bucket(
    detailed_status: str, expected_legacy_status: str,
):
    """Compat envelope: every one of the 9 detailed statuses is mapped
    to one of the 3 legacy values for top-level `status`, and the
    detailed value rides along on `status_detail`."""
    r = CertCheckResult(
        status=detailed_status,
        ip_address="10.0.0.5",
        port=443,
        checked_at="2026-05-02T15:00:03Z",
    )
    p = build_check_payload_from_discovery({"type": "manual",
                                             "host_id": "h1"}, r)
    assert p["status"] == expected_legacy_status
    assert p["status_detail"] == detailed_status


def test_discovery_builder_top_level_keys_are_additive():
    """The new builder adds `status_detail` to the original 5-key set —
    nothing else at the top level. Existing keys preserved verbatim."""
    p = build_check_payload_from_discovery(
        {"type": "manual", "host_id": "h1"},
        _success_discovery_result(),
    )
    assert set(p.keys()) == {"host_ref", "checked_at", "status",
                              "status_detail", "error_reason", "cert"}


def test_discovery_builder_passes_host_ref_through_unchanged():
    manual = {"type": "manual", "host_id": "uuid-1"}
    netbox = {"type": "netbox", "netbox_device_id": 1247}
    p_manual = build_check_payload_from_discovery(
        manual, _success_discovery_result())
    p_netbox = build_check_payload_from_discovery(
        netbox, _success_discovery_result())
    assert p_manual["host_ref"] == manual
    assert p_netbox["host_ref"] == netbox


def test_discovery_cert_dict_returns_none_for_connection_refused():
    r = CertCheckResult(
        status="connection_refused", ip_address="10.0.0.5", port=443,
        checked_at="2026-05-02T15:00:03Z",
        error_message="connection refused",
    )
    assert cert_dict_from_discovery_result(r) is None


def test_discovery_cert_dict_returns_none_for_connection_timeout():
    r = CertCheckResult(
        status="connection_timeout", ip_address="10.0.0.5", port=443,
        checked_at="2026-05-02T15:00:03Z",
        error_message="timeout",
    )
    assert cert_dict_from_discovery_result(r) is None


def test_discovery_cert_dict_returns_none_for_tls_failed_no_cert():
    r = CertCheckResult(
        status="tls_failed_no_cert", ip_address="10.0.0.5", port=443,
        checked_at="2026-05-02T15:00:03Z",
        error_message="server presented no certificate",
    )
    assert cert_dict_from_discovery_result(r) is None


def test_discovery_cert_dict_returns_none_for_malformed_cert():
    """Malformed cert can't be parsed, so issuer_full_dn is None and
    no cert sub-object is emitted."""
    r = CertCheckResult(
        status="tls_failed_malformed_cert", ip_address="10.0.0.5",
        port=443, checked_at="2026-05-02T15:00:03Z",
        error_message="cert won't parse",
    )
    assert cert_dict_from_discovery_result(r) is None


def test_discovery_cert_dict_returns_dict_for_expired_cert():
    """Expired cert: handshake 3 failed but the cert was recovered
    in handshake 1 — the cert sub-object must be populated for the
    dashboard to show issuer/expiry details."""
    r = CertCheckResult(
        status="cert_expired", ip_address="10.0.0.5", port=443,
        checked_at="2026-05-02T15:00:03Z",
        canonical_hostname="expired.badssl.com",
        subject_cn="*.badssl.com",
        subject_sans=["*.badssl.com", "badssl.com"],
        issuer_cn="ExpiredCA", issuer_o="Expired Inc",
        issuer_full_dn="CN=ExpiredCA,O=Expired Inc",
        is_self_signed=False,
        not_before="2024-01-01T00:00:00Z",
        not_after="2025-01-01T00:00:00Z",
        days_until_expiry=-365,
        signature_algorithm="SHA256withRSA", key_size=2048,
        hostname_matches=True,
        chain_trusted_by_system=False,
        chain_trust_reason=None,
        error_message="certificate has expired",
    )
    d = cert_dict_from_discovery_result(r)
    assert d is not None
    assert d["canonical_hostname"] == "expired.badssl.com"
    assert d["days_until_expiry"] == -365
    assert d["chain_trusted_by_system"] is False


def test_discovery_cert_dict_keys_are_superset_of_old_builder():
    """All 15 old-builder fields are preserved + 2 new fields
    (canonical_hostname, chain_trust_reason). Pinned so a future cert-
    schema change has to choose between the two builders intentionally."""
    d = cert_dict_from_discovery_result(_success_discovery_result())
    assert set(d.keys()) == {
        # old fields
        "subject_cn", "subject_sans", "issuer_cn", "issuer_o",
        "issuer_full_dn", "ca_category", "is_self_signed",
        "not_before", "not_after", "days_until_expiry",
        "signature_algorithm", "key_size", "hostname_matches",
        "chain_trusted_by_system", "chain_error_reason",
        # new fields
        "canonical_hostname", "chain_trust_reason",
    }


def test_discovery_cert_dict_chain_error_reason_aliased_to_chain_trust_reason():
    """Old `chain_error_reason` is populated from `chain_trust_reason`
    so the existing dashboard can keep displaying a reason string."""
    r = _success_discovery_result()
    r.chain_trusted_by_system = False
    r.chain_trust_reason = "self_signed"
    d = cert_dict_from_discovery_result(r)
    assert d["chain_trust_reason"] == "self_signed"
    assert d["chain_error_reason"] == "self_signed"


def test_discovery_cert_dict_ca_category_for_well_known_public():
    """Categorization is best-effort from is_self_signed +
    chain_trusted_by_system + issuer_full_dn (not the precise Phase 2
    inputs). Trusted public CA → well_known_public."""
    d = cert_dict_from_discovery_result(_success_discovery_result())
    assert d["ca_category"] == "well_known_public"


def test_discovery_cert_dict_ca_category_for_self_signed():
    r = _success_discovery_result()
    r.is_self_signed = True
    r.chain_trusted_by_system = False
    r.issuer_full_dn = r.subject_cn  # subject == issuer is the convention
    d = cert_dict_from_discovery_result(r)
    assert d["ca_category"] == "self_signed"


def test_discovery_cert_dict_subject_sans_is_a_list_copy_not_reference():
    """Defensive copy — same invariant as the old builder."""
    r = _success_discovery_result()
    d = cert_dict_from_discovery_result(r)
    d["subject_sans"].append("INJECTED")
    assert "INJECTED" not in r.subject_sans


def test_discovery_builder_preserves_error_message_in_top_level():
    """`error_reason` mirrors the source's error_message field."""
    r = CertCheckResult(
        status="connection_timeout", ip_address="10.0.0.5", port=443,
        checked_at="2026-05-02T15:00:03Z",
        error_message="timed out after 5.0s",
    )
    p = build_check_payload_from_discovery({"type": "manual",
                                             "host_id": "h1"}, r)
    assert p["error_reason"] == "timed out after 5.0s"
    assert p["cert"] is None
