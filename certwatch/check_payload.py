"""Shared check-payload builder.

Two functions live here:

  - `build_check_payload(host_ref, CertResult)`: the original (Phase 1)
    builder. Used by all production code paths today (cycle thread,
    action handler). Maps Phase 1's three-value state directly to the
    wire `status` field. Stays unchanged.

  - `build_check_payload_from_discovery(host_ref, CertCheckResult)`:
    Phase 9b — the new builder for cert_check_with_discovery's output.
    Carries the new 9-value enum on `status_detail` while mapping it
    to the legacy 3-value `status` for backward compatibility with the
    existing dashboard. 9c will switch cycle/action paths to this
    builder; until then, this function only runs in tests.

Compat envelope (Q1 from the 9-redesign): the old dashboard expects
`status in {"success", "tls_failed", "connection_failed"}`. Sending the
new enum directly would risk validation_failed. Compat: top-level
`status` maps via _DETAILED_TO_LEGACY_STATUS; new `status_detail` field
carries the precise enum. Old dashboard renders the mapped value; new
dashboard prefers status_detail. Pure additive on the wire.

Contract note: `cert` is included whenever cert data was recovered
(success OR tls_failed-with-cert), `null` only when no cert was
retrieved at all (connection_failed, or tls_failed before cert exchange).
"""

from __future__ import annotations

from typing import Optional

from certwatch.ca_category import categorize_ca
from certwatch.cert_check import CertResult
from certwatch.cert_check_with_discovery import CertCheckResult


# ---- old-style builder (Phase 1 CertResult, in production today) -----


def build_check_payload(host_ref: dict, result: CertResult) -> dict:
    """Build the per-check dict for a /reports submission.

    `host_ref` passes through unchanged — the dashboard owns the
    discriminated-union resolution between manual UUIDs and netbox
    integer IDs."""
    return {
        "host_ref": host_ref,
        "checked_at": result.checked_at,
        "status": result.state,
        "error_reason": result.error_message,
        "cert": cert_dict_from_result(result),
    }


def cert_dict_from_result(r: CertResult) -> Optional[dict]:
    if r.state == "connection_failed":
        return None
    if r.issuer_full_dn is None:
        # tls_failed but cert wasn't recovered (e.g. handshake protocol
        # error before cert exchange). No cert data to report.
        return None
    return {
        "subject_cn": r.subject_cn,
        "subject_sans": list(r.subject_sans),
        "issuer_cn": r.issuer_cn,
        "issuer_o": r.issuer_o,
        "issuer_full_dn": r.issuer_full_dn,
        "ca_category": r.ca_category,
        "is_self_signed": r.is_self_signed,
        "not_before": r.not_before,
        "not_after": r.not_after,
        "days_until_expiry": r.days_until_expiry,
        "signature_algorithm": r.signature_algorithm,
        "key_size": r.key_size,
        "hostname_matches": r.hostname_matches,
        "chain_trusted_by_system": r.chain_trusted_by_system,
        "chain_error_reason": r.chain_error_reason,
    }


# ---- new-style builder (Phase 9 CertCheckResult, used by 9c onward) --


# Compat-envelope mapping: 9-value status enum from
# cert_check_with_discovery → legacy 3-value enum that the existing
# dashboard's /reports validator accepts. Pinned by an exhaustive
# parametrized test (one case per of the 9 detailed values).
_DETAILED_TO_LEGACY_STATUS = {
    # success-family + warning-family all map to "success" — the cert
    # was usable; the old dashboard treats this as a healthy host. The
    # new status_detail carries the more precise reading for new-
    # dashboard renderers.
    "success": "success",
    "cert_expiring_soon": "success",
    "tls_warning": "success",
    # cert-evaluation failures and tls-stage failures map to "tls_failed".
    "cert_expired": "tls_failed",
    "cert_no_usable_hostname": "tls_failed",
    "tls_failed_no_cert": "tls_failed",
    "tls_failed_malformed_cert": "tls_failed",
    # connection-family stays as "connection_failed" — the OLD dashboard
    # already distinguishes between connection vs TLS failures and
    # operators are used to that bucketing.
    "connection_refused": "connection_failed",
    "connection_timeout": "connection_failed",
}


def build_check_payload_from_discovery(
    host_ref: dict, result: CertCheckResult,
) -> dict:
    """Build the per-check dict from a CertCheckResult.

    Compat-envelope wire shape: top-level `status` is one of the legacy
    three values; `status_detail` carries the precise 9-value enum.
    Both always present so the old dashboard validator accepts the
    payload AND new renderers have the precise reading.

    `cert` sub-object follows the same "include when cert was retrieved"
    convention as the original builder. Adds `canonical_hostname`,
    `chain_trust_reason` to the cert sub-object; existing fields
    preserved (subject_cn, subject_sans, issuer_*, is_self_signed,
    not_before/after, days_until_expiry, signature_algorithm, key_size,
    hostname_matches, chain_trusted_by_system, chain_error_reason,
    ca_category)."""
    legacy_status = _DETAILED_TO_LEGACY_STATUS.get(result.status, "tls_failed")
    return {
        "host_ref": host_ref,
        "checked_at": result.checked_at,
        "status": legacy_status,
        "status_detail": result.status,
        "error_reason": result.error_message,
        "cert": cert_dict_from_discovery_result(result),
    }


def cert_dict_from_discovery_result(r: CertCheckResult) -> Optional[dict]:
    """Build the cert sub-object for a CertCheckResult. Returns None
    when no cert was retrieved (connection-family statuses).

    Field set is a superset of the old builder's: every old field is
    preserved + new fields (canonical_hostname, chain_trust_reason).
    Old `chain_error_reason` is populated from chain_trust_reason as a
    backward-compat alias — old dashboard renders it as a string,
    new dashboard prefers chain_trust_reason for the precise enum.
    """
    if r.issuer_full_dn is None:
        # No cert retrieved (connection-family) or cert recovered but
        # has no issuer (which the cert parser would have rejected).
        return None
    return {
        # New field — cert-discovered hostname (canonical for display).
        "canonical_hostname": r.canonical_hostname,
        "subject_cn": r.subject_cn,
        "subject_sans": list(r.subject_sans),
        "issuer_cn": r.issuer_cn,
        "issuer_o": r.issuer_o,
        "issuer_full_dn": r.issuer_full_dn,
        # Old field, populated for backward compat. Best-effort: 9b's
        # categorize_ca uses chain_trusted_by_system as a proxy for
        # Phase 2's chain_path_to_system_root. For expired-but-public
        # certs this drifts (categorizes as "unknown" instead of
        # "well_known_public"); the new status_detail field carries the
        # authoritative reading.
        "ca_category": categorize_ca(
            is_self_signed=bool(r.is_self_signed),
            chain_path_to_system_root=bool(r.chain_trusted_by_system),
            issuer_full_dn=r.issuer_full_dn,
        ),
        "is_self_signed": r.is_self_signed,
        "not_before": r.not_before,
        "not_after": r.not_after,
        "days_until_expiry": r.days_until_expiry,
        "signature_algorithm": r.signature_algorithm,
        "key_size": r.key_size,
        "hostname_matches": r.hostname_matches,
        "chain_trusted_by_system": r.chain_trusted_by_system,
        # New field — short enum-like string ("self_signed",
        # "unknown_issuer", etc.). Source of truth for new-dashboard
        # renderers.
        "chain_trust_reason": r.chain_trust_reason,
        # Old field — same value as chain_trust_reason for compat.
        # Old dashboard renders this as a chain-error string; the
        # values are short enums rather than the OpenSSL prose
        # ("certificate has expired") that the original cert_check
        # produced, but they're operator-readable.
        "chain_error_reason": r.chain_trust_reason,
    }
