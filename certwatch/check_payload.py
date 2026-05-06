"""Shared check-payload builder.

Single canonical translation from `CertResult` (Phase 1's output) to the
contract-formatted per-check dict that lives inside a /reports submission.
Used by:
  - 5d's check_host action handler (single-check on-demand reports)
  - 5e's cert check thread (multi-check scheduled/startup reports)
  - 6 / 8 will reuse for NetBox-backed hosts and e2e fixtures.

Centralized here so the format never drifts between callers — a future
schema change touches one builder, not several.

Contract note: `cert` is included whenever cert data was recovered
(success OR tls_failed-with-cert), `null` only when no cert was
retrieved at all (connection_failed, or tls_failed before cert exchange).
The dashboard's per-check schema includes `chain_trusted_by_system` and
`chain_error_reason` which are only meaningful for failed validations,
so the schema's intent is the more flexible "cert when available"
interpretation. Confirmed authoritative on the dashboard side.
"""

from __future__ import annotations

from typing import Optional

from certwatch.cert_check import CertResult


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
