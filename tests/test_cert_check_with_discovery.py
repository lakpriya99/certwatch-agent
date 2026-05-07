"""Phase 9a — cert_check_with_discovery tests.

Three test categories:

  1. Pure logic (status precedence, hostname extraction from
     constructed certs, chain_trust_reason mapping). No network, no
     subprocess — runs in milliseconds.

  2. Live network against badssl + a known-good (google.com). Marked
     `network` so CI's offline path skips them.

  3. Connection-failure paths against unrouted IPs. Fast (sub-second
     ECONNREFUSED) — runs offline in the default suite.

Phase 9a does NOT wire the new function into the cycle/action paths;
the existing cert_check tests stay green and the new function gets
coverage from this file alone.
"""

from __future__ import annotations

import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from certwatch.cert_check_with_discovery import (
    ALL_STATUSES,
    STATUS_CERT_EXPIRED,
    STATUS_CERT_EXPIRING_SOON,
    STATUS_CERT_NO_USABLE_HOSTNAME,
    STATUS_CONNECTION_REFUSED,
    STATUS_CONNECTION_TIMEOUT,
    STATUS_SUCCESS,
    STATUS_TLS_WARNING,
    CertCheckResult,
    _CHAIN_TRUST_REASON_MAP,
    _determine_status,
    _extract_canonical_hostname_and_sans,
    cert_check_with_discovery,
)


# ============================================================
#  Pure-logic tests: status precedence (decision 7)
# ============================================================


def test_status_precedence_expired_beats_everything():
    """cert_expired is the most critical — even a cert in a trusted
    chain that's also "expiring soon" still reports expired."""
    s = _determine_status(
        canonical_hostname="x",
        days_until_expiry=-5,
        chain_trusted=True,
        expiring_soon_threshold_days=30,
    )
    assert s == STATUS_CERT_EXPIRED


def test_status_precedence_expired_when_chain_not_trusted():
    """Both cert_expired AND tls_warning would apply — expired wins."""
    s = _determine_status(
        canonical_hostname="x",
        days_until_expiry=-5,
        chain_trusted=False,
        expiring_soon_threshold_days=30,
    )
    assert s == STATUS_CERT_EXPIRED


def test_status_precedence_expiring_soon_beats_tls_warning():
    s = _determine_status(
        canonical_hostname="x",
        days_until_expiry=15,  # within default 30-day window
        chain_trusted=False,  # would otherwise produce tls_warning
        expiring_soon_threshold_days=30,
    )
    assert s == STATUS_CERT_EXPIRING_SOON


def test_status_precedence_tls_warning_when_chain_not_trusted_but_cert_valid():
    s = _determine_status(
        canonical_hostname="x",
        days_until_expiry=365,
        chain_trusted=False,
        expiring_soon_threshold_days=30,
    )
    assert s == STATUS_TLS_WARNING


def test_status_success_when_clean():
    s = _determine_status(
        canonical_hostname="x",
        days_until_expiry=365,
        chain_trusted=True,
        expiring_soon_threshold_days=30,
    )
    assert s == STATUS_SUCCESS


def test_status_no_usable_hostname_when_canonical_is_none():
    s = _determine_status(
        canonical_hostname=None,
        days_until_expiry=365,
        chain_trusted=True,
        expiring_soon_threshold_days=30,
    )
    assert s == STATUS_CERT_NO_USABLE_HOSTNAME


def test_status_expiring_soon_threshold_is_inclusive():
    """days_until_expiry == threshold → cert_expiring_soon (inclusive
    boundary). Operators expect "<=N days" semantics."""
    s = _determine_status(
        canonical_hostname="x",
        days_until_expiry=30,  # exactly the threshold
        chain_trusted=True,
        expiring_soon_threshold_days=30,
    )
    assert s == STATUS_CERT_EXPIRING_SOON


def test_status_expiring_soon_threshold_just_outside():
    s = _determine_status(
        canonical_hostname="x",
        days_until_expiry=31,  # one day past threshold
        chain_trusted=True,
        expiring_soon_threshold_days=30,
    )
    assert s == STATUS_SUCCESS


# ============================================================
#  Pure-logic tests: hostname extraction (decisions 1+2)
# ============================================================


def _build_test_cert(
    *,
    subject_cn: str | None = None,
    sans: list | None = None,
    not_before_offset_days: int = -1,
    not_after_offset_days: int = 365,
) -> x509.Certificate:
    """Build a fresh test cert in-memory so we can exercise extraction
    logic without depending on any specific online cert.

    `sans` is a list where each entry is either a string (treated as DNS)
    or a tuple `("ip", "10.0.0.5")` for IP SANs. Order is preserved into
    the cert's SubjectAlternativeName extension."""
    import ipaddress

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject_attrs = []
    if subject_cn is not None:
        subject_attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, subject_cn))
    name = x509.Name(subject_attrs)

    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)  # self-signed for simplicity
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=not_before_offset_days))
        .not_valid_after(dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=not_after_offset_days))
    )

    san_entries = []
    for entry in (sans or []):
        if isinstance(entry, tuple) and len(entry) == 2 and entry[0] == "ip":
            san_entries.append(x509.IPAddress(ipaddress.ip_address(entry[1])))
        else:
            san_entries.append(x509.DNSName(entry))
    if san_entries:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_entries), critical=False,
        )

    return builder.sign(key, hashes.SHA256())


def test_canonical_is_first_san_dns():
    cert = _build_test_cert(
        subject_cn="ignored.example.com",
        sans=["primary.example.com", "secondary.example.com"],
    )
    canonical, sans = _extract_canonical_hostname_and_sans(cert)
    assert canonical == "primary.example.com"
    assert sans == ["primary.example.com", "secondary.example.com"]


def test_canonical_is_first_san_even_when_ip():
    """Decision 2 (locked): canonical = first SAN in cert order, NO
    filtering. If a cert has [IP, FQDN] in that order, canonical is the
    IP. Operator gets an IP-titled host on the dashboard; the other
    SAN appears in the all_sans list. The user accepted this trade-off
    explicitly — see the design decisions block in the redesign brief."""
    cert = _build_test_cert(
        subject_cn="esxi02.lab",
        sans=[("ip", "10.0.0.5"), "app.public.com"],
    )
    canonical, sans = _extract_canonical_hostname_and_sans(cert)
    assert canonical == "10.0.0.5"
    assert sans == ["10.0.0.5", "app.public.com"]


def test_canonical_falls_back_to_cn_when_no_sans():
    cert = _build_test_cert(subject_cn="cn-only.example.com", sans=None)
    canonical, sans = _extract_canonical_hostname_and_sans(cert)
    assert canonical == "cn-only.example.com"
    assert sans == []


def test_canonical_is_none_when_no_san_no_cn():
    cert = _build_test_cert(subject_cn=None, sans=None)
    canonical, sans = _extract_canonical_hostname_and_sans(cert)
    assert canonical is None
    assert sans == []


def test_all_sans_preserves_mixed_dns_ip_order():
    """The cert's GeneralNames sequence is preserved verbatim — the
    dashboard relies on this for the host-detail SANs panel."""
    cert = _build_test_cert(
        subject_cn="ignored",
        sans=["a.example.com", ("ip", "10.0.0.1"), "b.example.com"],
    )
    canonical, sans = _extract_canonical_hostname_and_sans(cert)
    assert sans == ["a.example.com", "10.0.0.1", "b.example.com"]
    assert canonical == "a.example.com"


# ============================================================
#  Status enum + chain_trust_reason map sanity
# ============================================================


def test_all_statuses_listed():
    """Pin the literal taxonomy — same defensive pattern as
    BACKOFF_SCHEDULE. Any drift gets caught."""
    assert ALL_STATUSES == (
        "success",
        "cert_expiring_soon",
        "tls_warning",
        "cert_expired",
        "cert_no_usable_hostname",
        "connection_refused",
        "connection_timeout",
        "tls_failed_no_cert",
        "tls_failed_malformed_cert",
    )


def test_chain_trust_reason_map_known_codes():
    assert _CHAIN_TRUST_REASON_MAP[18] == "self_signed"
    assert _CHAIN_TRUST_REASON_MAP[19] == "self_signed_in_chain"
    assert _CHAIN_TRUST_REASON_MAP[20] == "unknown_issuer"
    assert _CHAIN_TRUST_REASON_MAP[68] == "weak_md_in_chain"


# ============================================================
#  Connection-failure paths (offline, fast)
# ============================================================


def test_connection_refused_to_closed_local_port():
    """127.0.0.1:9 (discard port, typically closed on dev machines)
    produces an immediate TCP RST."""
    r = cert_check_with_discovery(
        "127.0.0.1", port=9,
        connect_timeout=2.0, handshake_timeout=2.0,
    )
    assert r.status == STATUS_CONNECTION_REFUSED
    # No cert recovered → all cert fields stay None
    assert r.canonical_hostname is None
    assert r.subject_cn is None
    assert r.error_message  # populated


def test_connection_timeout_to_unrouted_ip():
    """192.0.2.1 (TEST-NET-1, RFC 5737, guaranteed not routed) — TCP
    SYN times out cleanly."""
    r = cert_check_with_discovery(
        "192.0.2.1", port=443,
        connect_timeout=2.0, handshake_timeout=2.0,
    )
    assert r.status == STATUS_CONNECTION_TIMEOUT
    assert r.canonical_hostname is None


def test_unresolvable_hostname_treated_as_connection_refused():
    """A name that can't be resolved (gaierror) is a connection-side
    failure rather than a TLS-side one. Bucket as connection_refused
    to keep the connection-family count balanced."""
    r = cert_check_with_discovery(
        "this-host-definitely-does-not-exist.invalid.example",
        port=443,
        connect_timeout=2.0, handshake_timeout=2.0,
    )
    assert r.status == STATUS_CONNECTION_REFUSED


# ============================================================
#  Live network — badssl + google.com
# ============================================================


@pytest.mark.network
def test_known_good_google_dot_com():
    r = cert_check_with_discovery("google.com", port=443)
    assert r.status == STATUS_SUCCESS
    assert r.canonical_hostname is not None
    # Google's cert has tons of SANs — at least a few should be present
    assert len(r.subject_sans) > 5
    assert r.chain_trusted_by_system is True
    assert r.chain_trust_reason is None
    assert r.hostname_matches is True
    assert r.is_self_signed is False
    assert r.days_until_expiry is not None and r.days_until_expiry > 0


@pytest.mark.network
def test_expired_badssl_produces_cert_expired():
    """expired.badssl.com cert is from 2015. Status precedence:
    cert_expired wins, regardless of any chain or hostname state."""
    r = cert_check_with_discovery("expired.badssl.com", port=443)
    assert r.status == STATUS_CERT_EXPIRED
    # Cert was retrieved — fields populate
    assert r.canonical_hostname is not None
    assert r.days_until_expiry is not None and r.days_until_expiry < 0


@pytest.mark.network
def test_self_signed_badssl_produces_tls_warning():
    """self-signed.badssl.com — chain_trusted=False, but cert is valid
    (not expired). Status: tls_warning. is_self_signed metadata: True.

    Note: chain_trust_reason can be either "self_signed" (verify_code 18)
    or "unknown_issuer" (verify_code 20) depending on how OpenSSL walks
    the chain — same cert, different OpenSSL paths produce different
    verify_codes. is_self_signed is computed from DN equality (cert.
    subject == cert.issuer), independent of verify_code, and is the
    operator-facing source of truth for "is this self-signed?"."""
    r = cert_check_with_discovery("self-signed.badssl.com", port=443)
    assert r.status == STATUS_TLS_WARNING
    assert r.is_self_signed is True
    assert r.chain_trusted_by_system is False
    # Some chain_trust_reason populates; the exact verify_code OpenSSL
    # picks for a self-signed cert isn't worth pinning.
    assert r.chain_trust_reason  # populated, non-empty


@pytest.mark.network
def test_untrusted_root_badssl_produces_tls_warning():
    """untrusted-root.badssl.com — chain doesn't reach a trusted root,
    but isn't self-signed (rogue intermediate). tls_warning with a
    different chain_trust_reason."""
    r = cert_check_with_discovery("untrusted-root.badssl.com", port=443)
    assert r.status == STATUS_TLS_WARNING
    assert r.is_self_signed is False
    assert r.chain_trusted_by_system is False
    assert r.chain_trust_reason  # populated


@pytest.mark.network
def test_wrong_host_badssl_resolves_via_cert_discovery():
    """The Phase 1 cert_check returned tls_failed for wrong.host.badssl.com
    because the input hostname didn't match the cert's SAN. The new
    cert_check_with_discovery extracts the hostname FROM THE CERT, so
    hostname_matches is True by construction. Whether status is
    success or tls_warning depends on chain trust (LetsEncrypt is in
    the system store, so likely success)."""
    r = cert_check_with_discovery("wrong.host.badssl.com", port=443)
    # By construction we use the cert's own name for verification.
    assert r.hostname_matches is True
    # Cert was retrieved
    assert r.canonical_hostname is not None
    # Status is either success or tls_warning depending on whether
    # the canonical hostname (likely "*.badssl.com" or similar) is
    # itself trusted under SNI.
    assert r.status in (STATUS_SUCCESS, STATUS_TLS_WARNING)


@pytest.mark.network
def test_status_detail_carries_full_status_in_result():
    """The result's `status` field IS the new enum value directly. The
    backward-compat envelope (mapping to old 3-status enum) is the
    serialization layer's job in 9b — not this module's responsibility."""
    r = cert_check_with_discovery("self-signed.badssl.com", port=443)
    assert r.status == STATUS_TLS_WARNING
    assert r.status in ALL_STATUSES


# ============================================================
#  Wire format / structural sanity
# ============================================================


def test_result_dataclass_fields():
    """Pin the dataclass shape — same defensive pattern as the wire-
    bytes assertions in Phase 4. Adding fields is fine; renaming or
    removing breaks downstream serializers (9b)."""
    fields = {f.name for f in CertCheckResult.__dataclass_fields__.values()}
    assert fields == {
        "status",
        "ip_address",
        "port",
        "checked_at",
        "error_message",
        "canonical_hostname",
        "subject_cn",
        "subject_sans",
        "issuer_cn",
        "issuer_o",
        "issuer_full_dn",
        "not_before",
        "not_after",
        "days_until_expiry",
        "signature_algorithm",
        "key_size",
        "hostname_matches",
        "chain_trusted_by_system",
        "chain_trust_reason",
        "is_self_signed",
    }


def test_iso_timestamps_use_z_suffix():
    """All timestamps in the result use the contract's ISO 8601 UTC
    with explicit Z suffix (matches Phase 4's wire conventions)."""
    r = cert_check_with_discovery(
        "127.0.0.1", port=9,
        connect_timeout=1.0, handshake_timeout=1.0,
    )
    assert r.checked_at.endswith("Z")


@pytest.mark.network
def test_iso_timestamps_in_cert_data_use_z_suffix():
    r = cert_check_with_discovery("google.com", port=443)
    assert r.not_before is not None and r.not_before.endswith("Z")
    assert r.not_after is not None and r.not_after.endswith("Z")


@pytest.mark.network
def test_canonical_hostname_extracted_from_cert_independent_of_input():
    """Connect to google.com but receive the cert; canonical_hostname
    is whatever the cert says (likely *.google.com or similar). This is
    the whole point of cert-presented discovery."""
    r = cert_check_with_discovery("google.com", port=443)
    assert r.canonical_hostname is not None
    # The canonical comes from the cert's first SAN; for google.com
    # that's typically a wildcard or a specific google domain. Don't
    # pin the exact value — just verify it's a real string with a dot.
    assert "." in r.canonical_hostname or r.canonical_hostname.replace(".", "").isdigit()
