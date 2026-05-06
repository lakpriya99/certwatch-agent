"""Phase 1 tests — exercise cert_check against badssl.com endpoints + a known-good host.

These tests hit the live internet and are marked `network`. Run with:
    pytest                        # all tests
    pytest -m "not network"       # skip network tests in CI without egress
"""

from __future__ import annotations

import pytest

from certwatch.cert_check import cert_check

pytestmark = pytest.mark.network


def test_known_good_google():
    r = cert_check("google.com")
    assert r.state == "success"
    assert r.chain_trusted_by_system is True
    assert r.chain_error_reason is None
    assert r.hostname_matches is True
    assert r.subject_cn is not None
    assert r.issuer_o  # well-known CA — Google Trust Services / GTS
    assert r.not_before and r.not_before.endswith("Z")
    assert r.not_after and r.not_after.endswith("Z")
    assert r.days_until_expiry is not None and r.days_until_expiry > 0
    assert r.is_self_signed is False
    assert r.ca_category == "well_known_public"
    assert r.signature_algorithm  # populated
    assert r.key_size and r.key_size >= 256
    assert r.error_message is None


def test_expired():
    r = cert_check("expired.badssl.com")
    assert r.state == "tls_failed"
    assert r.chain_trusted_by_system is False
    assert "expired" in (r.chain_error_reason or "").lower()
    # cert is still recovered via stage-2 unverified retry
    assert r.subject_cn is not None
    assert r.days_until_expiry is not None and r.days_until_expiry < 0
    assert r.hostname_matches is True  # cert is FOR badssl.com, just expired
    # KEY ASSERTION: ca_category describes the ISSUER, not the cert validity.
    # An expired cert from a public CA (COMODO) is still well_known_public.
    assert r.ca_category == "well_known_public"


def test_self_signed():
    r = cert_check("self-signed.badssl.com")
    assert r.state == "tls_failed"
    assert r.chain_trusted_by_system is False
    assert r.is_self_signed is True
    assert r.ca_category == "self_signed"  # stub categorizer covers this
    assert r.subject_cn is not None


def test_wrong_host():
    r = cert_check("wrong.host.badssl.com")
    assert r.state == "tls_failed"
    assert r.chain_trusted_by_system is False
    assert r.hostname_matches is False
    # Cert itself is otherwise valid (issued to *.badssl.com), Let's Encrypt issuer
    assert r.subject_cn is not None
    assert r.is_self_signed is False
    # Hostname mismatch is a name-binding error — chain still trusts a public root.
    assert r.ca_category == "well_known_public"


def test_untrusted_root():
    r = cert_check("untrusted-root.badssl.com")
    assert r.state == "tls_failed"
    assert r.chain_trusted_by_system is False
    assert r.subject_cn is not None
    assert r.is_self_signed is False  # has a (rogue) issuer, not self-signed
    # No system trust + no internal pattern match → unknown.
    assert r.ca_category == "unknown"


def test_sha1_intermediate():
    r = cert_check("sha1-intermediate.badssl.com")
    # Modern OpenSSL rejects SHA1 in the chain by default.
    assert r.state == "tls_failed"
    assert r.chain_trusted_by_system is False


def test_connection_failed_unreachable():
    # 192.0.2.0/24 is TEST-NET-1 (RFC 5737) — guaranteed not routed.
    r = cert_check("192.0.2.1", port=443, connect_timeout=2.0)
    assert r.state == "connection_failed"
    assert r.chain_trusted_by_system is None
    assert r.subject_cn is None
    assert r.error_message  # populated


def test_iso_z_format():
    r = cert_check("google.com")
    assert r.checked_at.endswith("Z")
    assert "T" in r.checked_at
    assert "+" not in r.checked_at  # no timezone offset
