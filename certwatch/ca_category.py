"""CA categorization — assigns each cert to one of four buckets describing its
ISSUER (not the cert's validity).

Order matters: self_signed > well_known_public > internal_corporate > unknown.

Key subtlety — `well_known_public` describes the issuer chain, not whether the
cert is currently usable. An expired cert from a public CA is still
`well_known_public`. Implemented by interpreting the OpenSSL verify_code:
date and hostname errors leave the chain path itself trusted; signature/path
errors do not.
"""

from __future__ import annotations

import os
from typing import Iterable, Optional

DEFAULT_INTERNAL_CA_PATTERNS = (
    "kurmi",
    "internal",
    "lab ca",
    "corporate ca",
    "intermediate ca",
)

# OpenSSL X509_V_ERR_* codes that mean "chain path validates to a trusted
# root, only date or subject-name binding is wrong". When verify fails with
# one of these, the issuer chain is still well-known-public.
_CHAIN_PATH_OK_CODES = frozenset(
    {
        9,   # CERT_NOT_YET_VALID
        10,  # CERT_HAS_EXPIRED
        11,  # CRL_NOT_YET_VALID
        12,  # CRL_HAS_EXPIRED
        62,  # HOSTNAME_MISMATCH
        63,  # IP_ADDRESS_MISMATCH
        64,  # EMAIL_MISMATCH
    }
)


def chain_path_trusted(verify_code: Optional[int]) -> bool:
    """Did the chain path up to a trusted system root, ignoring expiry/hostname?

    `verify_code is None` means full verify succeeded (chain definitely OK).
    Any other code: trusted only if the failure was time- or name-related.
    """
    if verify_code is None:
        return True
    return verify_code in _CHAIN_PATH_OK_CODES


def categorize_ca(
    *,
    is_self_signed: bool,
    chain_path_to_system_root: bool,
    issuer_full_dn: Optional[str],
    internal_patterns: Optional[Iterable[str]] = None,
) -> str:
    """Return one of: self_signed | well_known_public | internal_corporate | unknown.

    `internal_patterns=None` means resolve from INTERNAL_CA_PATTERNS env var
    (falling back to DEFAULT_INTERNAL_CA_PATTERNS). Pass an explicit empty
    iterable to disable internal-CA detection entirely.
    """
    if is_self_signed:
        return "self_signed"
    if chain_path_to_system_root:
        return "well_known_public"

    patterns = (
        list(internal_patterns)
        if internal_patterns is not None
        else load_internal_patterns_from_env()
    )
    if patterns and issuer_full_dn and _matches_any(issuer_full_dn, patterns):
        return "internal_corporate"
    return "unknown"


def load_internal_patterns_from_env() -> list[str]:
    """Resolve the active pattern list from INTERNAL_CA_PATTERNS.

    Unset → defaults. Empty string → []. Comma-separated otherwise. The env
    var REPLACES the defaults rather than merging — empty string disables
    internal detection (everything untrusted falls to "unknown").
    """
    val = os.environ.get("INTERNAL_CA_PATTERNS")
    if val is None:
        return list(DEFAULT_INTERNAL_CA_PATTERNS)
    return [p.strip() for p in val.split(",") if p.strip()]


def _matches_any(dn: str, patterns: Iterable[str]) -> bool:
    dn_lower = dn.lower()
    return any(p.lower() in dn_lower for p in patterns)
