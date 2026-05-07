"""Phase 9a — cert-presented hostname discovery.

Three-handshake design: the cert is the source of truth for what a
host's TLS hostname is. NetBox or any other inventory source provides
(ip, port); the agent connects, reads the cert, picks the canonical
hostname FROM THE CERT, then verifies cert against itself.

This is a separate function from `cert_check` (kept for the manual-host
"I know my hostname" path, the badssl regression suite, and Phase 3's
local YAML mode). 9a adds the new function alongside; 9c will switch
the cycle and action paths to it.

  Handshake 1 — discover: connect to ip:port; SSL ctx with
                check_hostname=False, verify_mode=CERT_NONE; get peer
                cert in DER form; parse with cryptography. Goal:
                read what cert the server presents.

  Pick canonical hostname: first SAN in cert order (DNS or IP, no
  filtering — decision 2). CN as last fallback if no SANs at all.
  All SANs captured for the report.

  Handshake 2 — hostname verify: reconnect with SNI=canonical and
                check_hostname=True, verify_mode=CERT_NONE. By
                construction this should succeed (we extracted the
                name from the cert itself). Failure indicates a
                multi-cert server presenting different certs based
                on SNI — flag hostname_matches=False, keep the cert
                from handshake 1.

  Handshake 3 — chain verify: reconnect with the default ssl
                context (full validation against system CA store,
                hostname check on). Success → chain trusted.
                SSLCertVerificationError → parse verify_code into
                a short chain_trust_reason string (e.g.
                "self_signed", "unknown_issuer").

Status taxonomy (decisions 6+7) applied at result-build time:

  Connection-family (mutually exclusive with the rest):
    connection_refused, connection_timeout,
    tls_failed_no_cert, tls_failed_malformed_cert

  Cert-shape failure:
    cert_no_usable_hostname

  Cert-evaluation, in precedence order:
    cert_expired         — past notAfter
    cert_expiring_soon   — days_until_expiry <= threshold
    tls_warning          — chain not trusted by system
    success              — clean
"""

from __future__ import annotations

import datetime as dt
import socket
import ssl
from dataclasses import dataclass, field
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from certwatch.cert_check import (
    _first_attr,
    _iso_z,
    _key_size,
    _signature_algorithm,
    _utc_now_iso,
)


# ---- result dataclass ------------------------------------------------


@dataclass
class CertCheckResult:
    status: str
    ip_address: str
    port: int
    checked_at: str  # ISO 8601 UTC, Z suffix
    error_message: Optional[str] = None

    # Cert metadata, populated whenever a cert was recovered from any
    # handshake. Stays at default for connection-family failures.
    canonical_hostname: Optional[str] = None
    subject_cn: Optional[str] = None
    subject_sans: list[str] = field(default_factory=list)
    issuer_cn: Optional[str] = None
    issuer_o: Optional[str] = None
    issuer_full_dn: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    days_until_expiry: Optional[int] = None
    signature_algorithm: Optional[str] = None
    key_size: Optional[int] = None

    # Verification verdicts.
    hostname_matches: Optional[bool] = None
    chain_trusted_by_system: Optional[bool] = None
    chain_trust_reason: Optional[str] = None
    is_self_signed: Optional[bool] = None


# ---- status taxonomy (string constants for cross-module reference) --


STATUS_SUCCESS = "success"
STATUS_CERT_EXPIRING_SOON = "cert_expiring_soon"
STATUS_TLS_WARNING = "tls_warning"
STATUS_CERT_EXPIRED = "cert_expired"
STATUS_CERT_NO_USABLE_HOSTNAME = "cert_no_usable_hostname"
STATUS_CONNECTION_REFUSED = "connection_refused"
STATUS_CONNECTION_TIMEOUT = "connection_timeout"
STATUS_TLS_FAILED_NO_CERT = "tls_failed_no_cert"
STATUS_TLS_FAILED_MALFORMED_CERT = "tls_failed_malformed_cert"


ALL_STATUSES = (
    STATUS_SUCCESS,
    STATUS_CERT_EXPIRING_SOON,
    STATUS_TLS_WARNING,
    STATUS_CERT_EXPIRED,
    STATUS_CERT_NO_USABLE_HOSTNAME,
    STATUS_CONNECTION_REFUSED,
    STATUS_CONNECTION_TIMEOUT,
    STATUS_TLS_FAILED_NO_CERT,
    STATUS_TLS_FAILED_MALFORMED_CERT,
)


# OpenSSL X509_V_ERR_* codes that mean "the chain has a real trust
# problem" mapped to short, operator-friendly reasons. Date and
# hostname errors are handled by status precedence (cert_expired,
# hostname_matches), so they shouldn't fire on handshake 3 under
# normal conditions; if they do they fall through to the default.
_CHAIN_TRUST_REASON_MAP = {
    2:  "unable_to_get_issuer_cert",
    18: "self_signed",
    19: "self_signed_in_chain",
    20: "unknown_issuer",
    21: "unable_to_verify_leaf_signature",
    24: "invalid_ca",
    27: "cert_untrusted",
    68: "weak_md_in_chain",
}


# ---- internal exception types (one per connection-family status) ----


class _DiscoveryError(Exception):
    """Base for connection-family failures during handshake 1."""

    status: str = ""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


class _ConnectionRefused(_DiscoveryError):
    status = STATUS_CONNECTION_REFUSED


class _ConnectionTimeout(_DiscoveryError):
    status = STATUS_CONNECTION_TIMEOUT


class _NoCert(_DiscoveryError):
    status = STATUS_TLS_FAILED_NO_CERT


class _MalformedCert(_DiscoveryError):
    status = STATUS_TLS_FAILED_MALFORMED_CERT


# ---- public function -------------------------------------------------


def cert_check_with_discovery(
    ip: str,
    port: int = 443,
    *,
    connect_timeout: float = 5.0,
    handshake_timeout: float = 5.0,
    expiring_soon_threshold_days: int = 30,
) -> CertCheckResult:
    """Connect to ip:port, discover the cert's hostname, return a
    `CertCheckResult` with the new status taxonomy.

    `expiring_soon_threshold_days` is the days-until-expiry boundary
    for the `cert_expiring_soon` status. Default 30; the runner will
    typically pass `max(config.alert_thresholds_days)` so any threshold
    triggers the warning.
    """
    checked_at = _utc_now_iso()

    # === Handshake 1: discover the cert ===
    # SNI = the connection target. For IP-only inputs (the production
    # case from NetBox), most servers accept SNI=IP and return the
    # default cert — same as no SNI. For FQDN inputs (manual hosts,
    # badssl tests), SNI=FQDN is required to coax multi-cert servers
    # into returning their actual cert rather than a default fallback.
    # Setting it always keeps the discovery path consistent.
    try:
        cert = _handshake_get_cert(
            ip, port, server_hostname=ip,
            connect_timeout=connect_timeout,
            handshake_timeout=handshake_timeout,
        )
    except _DiscoveryError as e:
        return CertCheckResult(
            status=e.status,
            ip_address=ip,
            port=port,
            checked_at=checked_at,
            error_message=e.message,
        )

    canonical, all_sans = _extract_canonical_hostname_and_sans(cert)
    not_after = cert.not_valid_after_utc
    not_before = cert.not_valid_before_utc
    days_until_expiry = (not_after - dt.datetime.now(dt.timezone.utc)).days

    if canonical is None:
        # Cert exists but has no SAN and no CN. We can't verify TLS
        # against a name we don't have, and we can't faithfully report
        # this host's identity. Still report metadata so the operator
        # can investigate.
        return _result_with_cert_data(
            status=STATUS_CERT_NO_USABLE_HOSTNAME,
            ip=ip, port=port, checked_at=checked_at,
            cert=cert, canonical=None, all_sans=all_sans,
            hostname_matches=None, chain_trusted=None,
            chain_trust_reason=None,
            error_message="cert has no SAN and no CN — no usable hostname",
        )

    # === Handshake 2: hostname verify ===
    hostname_matches = _handshake_verify_hostname(
        ip, port, canonical=canonical,
        connect_timeout=connect_timeout,
        handshake_timeout=handshake_timeout,
    )

    # === Handshake 3: chain verify ===
    chain_trusted, chain_trust_reason = _handshake_verify_chain(
        ip, port, canonical=canonical,
        connect_timeout=connect_timeout,
        handshake_timeout=handshake_timeout,
    )

    status = _determine_status(
        canonical_hostname=canonical,
        days_until_expiry=days_until_expiry,
        chain_trusted=chain_trusted,
        expiring_soon_threshold_days=expiring_soon_threshold_days,
    )

    return _result_with_cert_data(
        status=status,
        ip=ip, port=port, checked_at=checked_at,
        cert=cert, canonical=canonical, all_sans=all_sans,
        hostname_matches=hostname_matches,
        chain_trusted=chain_trusted,
        chain_trust_reason=chain_trust_reason,
        error_message=None,
    )


# ---- handshake helpers -----------------------------------------------


def _handshake_get_cert(
    ip: str,
    port: int,
    *,
    server_hostname: Optional[str],
    connect_timeout: float,
    handshake_timeout: float,
) -> x509.Certificate:
    """Handshake 1: open TCP, wrap unverified, return the parsed leaf cert."""
    try:
        sock = socket.create_connection((ip, port), timeout=connect_timeout)
    except ConnectionRefusedError as e:
        raise _ConnectionRefused(f"{type(e).__name__}: {e}") from e
    except (socket.timeout, TimeoutError) as e:
        raise _ConnectionTimeout(f"{type(e).__name__}: {e}") from e
    except (socket.gaierror, OSError) as e:
        # DNS or other resolution / route failure — treat as refused.
        # (timeout is caught above; reaching here means the connect
        # rejected outright rather than hung.)
        raise _ConnectionRefused(f"{type(e).__name__}: {e}") from e

    sock.settimeout(handshake_timeout)
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ssock = ctx.wrap_socket(sock, server_hostname=server_hostname)
        except (socket.timeout, TimeoutError) as e:
            raise _ConnectionTimeout(f"TLS handshake timeout: {e}") from e
        except ssl.SSLError as e:
            raise _NoCert(f"TLS handshake failed: {e}") from e
        except OSError as e:
            raise _NoCert(f"socket error during TLS: {e}") from e

        try:
            der = ssock.getpeercert(binary_form=True)
        finally:
            try:
                ssock.close()
            except Exception:
                pass

        if not der:
            raise _NoCert("server presented no cert during TLS handshake")

        try:
            return x509.load_der_x509_certificate(der)
        except Exception as e:
            raise _MalformedCert(f"could not parse cert DER: {e}") from e
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _handshake_verify_hostname(
    ip: str,
    port: int,
    *,
    canonical: str,
    connect_timeout: float,
    handshake_timeout: float,
) -> bool:
    """Handshake 2: SNI = canonical, hostname check ON, no trust store.

    Trick: use CERT_REQUIRED + check_hostname=True + an empty trust
    store. Chain validation always fails (no roots), so the resulting
    `SSLCertVerificationError` tells us hostname status via verify_code:

      62 = X509_V_ERR_HOSTNAME_MISMATCH → hostname check failed.
      anything else (typically 19 or 20) → hostname matched; the chain
        failed because we have no trust store, which we don't care
        about here. That's handshake 3's job.

    Returns True when canonical matches the cert the server returns
    under SNI=canonical. False indicates a multi-cert server presenting
    a different cert when SNI is set — uncommon but the reason this
    handshake exists rather than doing in-process matching against the
    cert from handshake 1. We don't treat False as fatal; the cert
    from handshake 1 is still the operative cert for the report.
    """
    try:
        sock = socket.create_connection((ip, port), timeout=connect_timeout)
    except OSError:
        # Server stopped responding between handshakes. Be conservative.
        return False

    sock.settimeout(handshake_timeout)
    try:
        # Bare SSLContext does NOT auto-load OS roots (unlike
        # ssl.create_default_context). Empty trust store is what we want.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        try:
            ssock = ctx.wrap_socket(sock, server_hostname=canonical)
            # Unreachable under empty trust store, but defensive.
            ssock.close()
            return True
        except ssl.SSLCertVerificationError as e:
            return getattr(e, "verify_code", None) != 62
        except (ssl.SSLError, OSError):
            return False
    finally:
        try:
            sock.close()
        except Exception:
            pass


def _handshake_verify_chain(
    ip: str,
    port: int,
    *,
    canonical: str,
    connect_timeout: float,
    handshake_timeout: float,
) -> tuple[Optional[bool], Optional[str]]:
    """Handshake 3: full default-context verification.

    Success → (True, None). SSLCertVerificationError → (False, reason).
    Other errors → (False, "verification_failed") so callers see a
    consistent shape; chain trust is "unknown" but reported as not
    trusted to err on the side of operator visibility.
    """
    try:
        sock = socket.create_connection((ip, port), timeout=connect_timeout)
    except OSError as e:
        return False, f"verification_failed:{type(e).__name__}"

    sock.settimeout(handshake_timeout)
    try:
        ctx = ssl.create_default_context()
        try:
            ssock = ctx.wrap_socket(sock, server_hostname=canonical)
            try:
                pass  # full handshake completed = chain verified
            finally:
                try:
                    ssock.close()
                except Exception:
                    pass
            return True, None
        except ssl.SSLCertVerificationError as e:
            verify_code = getattr(e, "verify_code", None)
            reason = _CHAIN_TRUST_REASON_MAP.get(verify_code)
            if reason is None:
                # Unknown / unmapped code (or None). Fall back to a
                # diagnostic string so operators can still see something.
                if verify_code is not None:
                    reason = f"verify_code_{verify_code}"
                else:
                    reason = "verification_failed"
            return False, reason
        except (ssl.SSLError, OSError) as e:
            return False, f"verification_failed:{type(e).__name__}"
    finally:
        try:
            sock.close()
        except Exception:
            pass


# ---- cert-data extraction --------------------------------------------


def _extract_canonical_hostname_and_sans(
    cert: x509.Certificate,
) -> tuple[Optional[str], list[str]]:
    """Per design decisions 1+2: canonical = first SAN in cert order
    (DNS or IP, no filtering); CN is the fallback only when there are
    no SANs at all. all_sans is the full ordered list as it appears
    in the cert."""
    all_sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        # Iterate the SAN extension's GeneralNames in document order.
        # Cryptography's SubjectAlternativeName is iterable.
        for general_name in ext.value:
            if isinstance(general_name, x509.DNSName):
                all_sans.append(general_name.value)
            elif isinstance(general_name, x509.IPAddress):
                all_sans.append(str(general_name.value))
            # Other GeneralName types (URI, RFC822Name, etc.) skipped —
            # not used for TLS hostname verification.
    except x509.ExtensionNotFound:
        pass

    if all_sans:
        return all_sans[0], all_sans

    # CN fallback per decision 1.
    cn = _first_attr(cert.subject, NameOID.COMMON_NAME)
    if cn:
        return cn, all_sans  # all_sans is [] here
    return None, all_sans


def _determine_status(
    *,
    canonical_hostname: Optional[str],
    days_until_expiry: Optional[int],
    chain_trusted: Optional[bool],
    expiring_soon_threshold_days: int,
) -> str:
    """Apply status precedence per decision 7:
        cert_expired > cert_expiring_soon > tls_warning > success.
    """
    if canonical_hostname is None:
        # Caller handles this case before calling us, but defensive.
        return STATUS_CERT_NO_USABLE_HOSTNAME

    if days_until_expiry is not None and days_until_expiry < 0:
        return STATUS_CERT_EXPIRED

    if (
        days_until_expiry is not None
        and days_until_expiry <= expiring_soon_threshold_days
    ):
        return STATUS_CERT_EXPIRING_SOON

    if chain_trusted is False:
        return STATUS_TLS_WARNING

    return STATUS_SUCCESS


def _result_with_cert_data(
    *,
    status: str,
    ip: str,
    port: int,
    checked_at: str,
    cert: x509.Certificate,
    canonical: Optional[str],
    all_sans: list[str],
    hostname_matches: Optional[bool],
    chain_trusted: Optional[bool],
    chain_trust_reason: Optional[str],
    error_message: Optional[str],
) -> CertCheckResult:
    """Build the CertCheckResult once cert data is in hand. Status,
    canonical, hostname_matches, and chain trust are caller-supplied;
    everything else comes from the cert."""
    nb = cert.not_valid_before_utc
    na = cert.not_valid_after_utc
    days_left = (na - dt.datetime.now(dt.timezone.utc)).days

    return CertCheckResult(
        status=status,
        ip_address=ip,
        port=port,
        checked_at=checked_at,
        error_message=error_message,
        canonical_hostname=canonical,
        subject_cn=_first_attr(cert.subject, NameOID.COMMON_NAME),
        subject_sans=list(all_sans),
        issuer_cn=_first_attr(cert.issuer, NameOID.COMMON_NAME),
        issuer_o=_first_attr(cert.issuer, NameOID.ORGANIZATION_NAME),
        issuer_full_dn=cert.issuer.rfc4514_string(),
        not_before=_iso_z(nb),
        not_after=_iso_z(na),
        days_until_expiry=days_left,
        signature_algorithm=_signature_algorithm(cert),
        key_size=_key_size(cert),
        hostname_matches=hostname_matches,
        chain_trusted_by_system=chain_trusted,
        chain_trust_reason=chain_trust_reason,
        is_self_signed=cert.subject == cert.issuer,
    )
