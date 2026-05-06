"""Cert check: connect to a host:port, fetch the leaf cert, return structured data.

Two-pass design — verified TLS first; on verify failure, reconnect unverified to
recover the cert anyway and record the verify failure as `chain_error_reason`.
That keeps the happy path on the OS trust verdict and still produces useful
data for the failure cases the dashboard cares about (expired, self-signed,
wrong-host, untrusted-root, sha1-intermediate).
"""

from __future__ import annotations

import datetime as dt
import socket
import ssl
from dataclasses import dataclass, field
from typing import Literal, Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from certwatch.ca_category import categorize_ca, chain_path_trusted

ResultState = Literal["success", "connection_failed", "tls_failed"]


@dataclass
class CertResult:
    state: ResultState
    hostname: str
    port: int
    checked_at: str  # ISO 8601 UTC with explicit Z
    error_message: Optional[str] = None
    # Cert fields — populated whenever we recovered a leaf cert (success OR
    # tls_failed-with-cert). Remain None for connection_failed and for
    # tls_failed cases where we couldn't recover a cert at all.
    subject_cn: Optional[str] = None
    subject_sans: list[str] = field(default_factory=list)
    issuer_cn: Optional[str] = None
    issuer_o: Optional[str] = None
    issuer_full_dn: Optional[str] = None
    ca_category: Optional[str] = None
    is_self_signed: Optional[bool] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    days_until_expiry: Optional[int] = None
    signature_algorithm: Optional[str] = None
    key_size: Optional[int] = None
    hostname_matches: Optional[bool] = None
    chain_trusted_by_system: Optional[bool] = None
    chain_error_reason: Optional[str] = None


def cert_check(
    hostname: str,
    port: int = 443,
    *,
    connect_timeout: float = 5.0,
    handshake_timeout: float = 5.0,
) -> CertResult:
    checked_at = _utc_now_iso()

    # Stage 1: TCP connect + verified TLS handshake.
    try:
        sock = socket.create_connection((hostname, port), timeout=connect_timeout)
    except (socket.gaierror, ConnectionRefusedError, socket.timeout, OSError) as e:
        return CertResult(
            state="connection_failed",
            hostname=hostname,
            port=port,
            checked_at=checked_at,
            error_message=f"{type(e).__name__}: {e}",
        )

    sock.settimeout(handshake_timeout)
    verify_error: Optional[str] = None
    verify_code: Optional[int] = None
    try:
        ctx = ssl.create_default_context()
        try:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)
            cert = x509.load_der_x509_certificate(der)
            return _build_result(
                cert,
                hostname=hostname,
                port=port,
                checked_at=checked_at,
                state="success",
                trusted=True,
                verify_code=None,
                error_reason=None,
                hostname_matches_override=True,
            )
        except ssl.SSLCertVerificationError as e:
            verify_code, verify_error = _verify_info(e)
            # fall through to stage 2
        except (ssl.SSLError, socket.timeout, OSError) as e:
            return CertResult(
                state="tls_failed",
                hostname=hostname,
                port=port,
                checked_at=checked_at,
                error_message=f"{type(e).__name__}: {e}",
            )
    finally:
        try:
            sock.close()
        except Exception:
            pass

    # Stage 2: verify failed — reconnect unverified to recover the cert.
    try:
        sock2 = socket.create_connection((hostname, port), timeout=connect_timeout)
    except (socket.gaierror, ConnectionRefusedError, socket.timeout, OSError) as e:
        return CertResult(
            state="tls_failed",
            hostname=hostname,
            port=port,
            checked_at=checked_at,
            error_message=f"verify_failed:{verify_error}; retry_connect:{type(e).__name__}: {e}",
            chain_trusted_by_system=False,
            chain_error_reason=verify_error,
        )

    sock2.settimeout(handshake_timeout)
    try:
        ctx2 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        try:
            with ctx2.wrap_socket(sock2, server_hostname=hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)
        except (ssl.SSLError, socket.timeout, OSError) as e:
            return CertResult(
                state="tls_failed",
                hostname=hostname,
                port=port,
                checked_at=checked_at,
                error_message=f"verify_failed:{verify_error}; retry_handshake:{type(e).__name__}: {e}",
                chain_trusted_by_system=False,
                chain_error_reason=verify_error,
            )
    finally:
        try:
            sock2.close()
        except Exception:
            pass

    cert = x509.load_der_x509_certificate(der)
    return _build_result(
        cert,
        hostname=hostname,
        port=port,
        checked_at=checked_at,
        state="tls_failed",
        trusted=False,
        verify_code=verify_code,
        error_reason=verify_error,
        hostname_matches_override=None,
    )


# ---- internal helpers ----------------------------------------------------


def _build_result(
    cert: x509.Certificate,
    *,
    hostname: str,
    port: int,
    checked_at: str,
    state: ResultState,
    trusted: bool,
    verify_code: Optional[int],
    error_reason: Optional[str],
    hostname_matches_override: Optional[bool],
) -> CertResult:
    nb = cert.not_valid_before_utc
    na = cert.not_valid_after_utc
    days_left = (na - dt.datetime.now(dt.timezone.utc)).days

    sub_cn = _first_attr(cert.subject, NameOID.COMMON_NAME)
    iss_cn = _first_attr(cert.issuer, NameOID.COMMON_NAME)
    iss_o = _first_attr(cert.issuer, NameOID.ORGANIZATION_NAME)
    iss_dn = cert.issuer.rfc4514_string()

    sans = _subject_alt_names(cert)
    is_self_signed = cert.subject == cert.issuer
    hn_match = (
        hostname_matches_override
        if hostname_matches_override is not None
        else _hostname_matches(hostname, cert)
    )

    return CertResult(
        state=state,
        hostname=hostname,
        port=port,
        checked_at=checked_at,
        error_message=error_reason if not trusted else None,
        subject_cn=sub_cn,
        subject_sans=sans,
        issuer_cn=iss_cn,
        issuer_o=iss_o,
        issuer_full_dn=iss_dn,
        ca_category=categorize_ca(
            is_self_signed=is_self_signed,
            chain_path_to_system_root=chain_path_trusted(verify_code),
            issuer_full_dn=iss_dn,
        ),
        is_self_signed=is_self_signed,
        not_before=_iso_z(nb),
        not_after=_iso_z(na),
        days_until_expiry=days_left,
        signature_algorithm=_signature_algorithm(cert),
        key_size=_key_size(cert),
        hostname_matches=hn_match,
        chain_trusted_by_system=trusted,
        chain_error_reason=error_reason,
    )


def _first_attr(name: x509.Name, oid) -> Optional[str]:
    attrs = name.get_attributes_for_oid(oid)
    if not attrs:
        return None
    val = attrs[0].value
    return val if isinstance(val, str) else val.decode("utf-8", errors="replace")


def _subject_alt_names(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return []
    out: list[str] = []
    out.extend(ext.value.get_values_for_type(x509.DNSName))
    # IP SANs are common on internal certs — surface them too.
    for ip in ext.value.get_values_for_type(x509.IPAddress):
        out.append(str(ip))
    return out


def _hostname_matches(hostname: str, cert: x509.Certificate) -> bool:
    """RFC 6125 simple matcher: SAN dNSName preferred, fall back to CN.

    Wildcards allowed only in the leftmost label and only as a single `*` that
    matches exactly one label (no partial-label matching).
    """
    host = hostname.lower().rstrip(".")
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = [s.lower() for s in ext.value.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        sans = []

    if sans:
        return any(_match_dns(host, p) for p in sans)

    cn = _first_attr(cert.subject, NameOID.COMMON_NAME)
    return _match_dns(host, cn.lower()) if cn else False


def _match_dns(hostname: str, pattern: str) -> bool:
    if pattern == hostname:
        return True
    if not pattern.startswith("*."):
        return False
    suffix = pattern[2:]
    if "." not in hostname:
        return False
    return hostname.split(".", 1)[1] == suffix


def _signature_algorithm(cert: x509.Certificate) -> Optional[str]:
    try:
        hash_alg = cert.signature_hash_algorithm
    except Exception:
        return None
    if hash_alg is None:
        return None
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        key_type = "RSA"
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        key_type = "ECDSA"
    elif isinstance(pub, ed25519.Ed25519PublicKey):
        return "Ed25519"
    elif isinstance(pub, ed448.Ed448PublicKey):
        return "Ed448"
    elif isinstance(pub, dsa.DSAPublicKey):
        key_type = "DSA"
    else:
        key_type = "Unknown"
    return f"{hash_alg.name.upper()}with{key_type}"


def _key_size(cert: x509.Certificate) -> Optional[int]:
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey) or isinstance(pub, dsa.DSAPublicKey):
        return pub.key_size
    if isinstance(pub, ec.EllipticCurvePublicKey):
        return pub.curve.key_size
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return 256
    if isinstance(pub, ed448.Ed448PublicKey):
        return 448
    return None


def _verify_info(e: ssl.SSLCertVerificationError) -> tuple[Optional[int], str]:
    # `verify_message` is a friendly string ("certificate has expired");
    # `verify_code` is the numeric OpenSSL code (used for ca_category logic).
    code = getattr(e, "verify_code", None)
    msg = getattr(e, "verify_message", None) or str(e)
    return code, msg


def _iso_z(d: dt.datetime) -> str:
    return d.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
