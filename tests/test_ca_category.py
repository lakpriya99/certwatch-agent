"""Phase 2 unit tests for ca_category — pure logic, no network."""

from __future__ import annotations

import pytest

from certwatch.ca_category import (
    DEFAULT_INTERNAL_CA_PATTERNS,
    categorize_ca,
    chain_path_trusted,
    load_internal_patterns_from_env,
)


# ---- chain_path_trusted -------------------------------------------------


def test_chain_path_trusted_when_verify_succeeded():
    assert chain_path_trusted(None) is True


@pytest.mark.parametrize("code", [9, 10, 11, 12, 62, 63, 64])
def test_chain_path_trusted_for_time_or_name_errors(code):
    assert chain_path_trusted(code) is True


@pytest.mark.parametrize("code", [
    2,   # UNABLE_TO_GET_ISSUER_CERT
    18,  # DEPTH_ZERO_SELF_SIGNED_CERT
    19,  # SELF_SIGNED_CERT_IN_CHAIN
    20,  # UNABLE_TO_GET_ISSUER_CERT_LOCALLY
    21,  # UNABLE_TO_VERIFY_LEAF_SIGNATURE
    24,  # INVALID_CA
    27,  # CERT_UNTRUSTED
    68,  # CA_MD_TOO_WEAK (sha1 in chain)
])
def test_chain_path_not_trusted_for_path_errors(code):
    assert chain_path_trusted(code) is False


# ---- categorize_ca priority --------------------------------------------


def test_self_signed_wins_over_chain_path_trusted():
    # A self-signed cert that somehow got chain_path=True should still be
    # tagged self_signed — order matters.
    cat = categorize_ca(
        is_self_signed=True,
        chain_path_to_system_root=True,
        issuer_full_dn="CN=Self,O=Self",
    )
    assert cat == "self_signed"


def test_well_known_public_when_chain_trusted():
    cat = categorize_ca(
        is_self_signed=False,
        chain_path_to_system_root=True,
        issuer_full_dn="CN=DigiCert TLS RSA SHA256 2020 CA1,O=DigiCert Inc,C=US",
    )
    assert cat == "well_known_public"


def test_internal_corporate_via_default_kurmi_pattern():
    cat = categorize_ca(
        is_self_signed=False,
        chain_path_to_system_root=False,
        issuer_full_dn="CN=Kurmi Internal Lab CA,O=Kurmi Software,C=FR",
    )
    assert cat == "internal_corporate"


@pytest.mark.parametrize("dn", [
    "CN=Acme Internal Issuing CA,O=Acme",
    "CN=Some Lab CA,O=Whatever",
    "CN=Acme Corporate CA,O=Acme",
    "CN=Acme Intermediate CA,O=Acme",
])
def test_internal_corporate_via_other_default_patterns(dn):
    cat = categorize_ca(
        is_self_signed=False,
        chain_path_to_system_root=False,
        issuer_full_dn=dn,
    )
    assert cat == "internal_corporate"


def test_unknown_when_nothing_matches():
    cat = categorize_ca(
        is_self_signed=False,
        chain_path_to_system_root=False,
        issuer_full_dn="CN=Some Random Issuer,O=Mystery Org",
    )
    assert cat == "unknown"


def test_unknown_when_no_issuer_dn():
    cat = categorize_ca(
        is_self_signed=False,
        chain_path_to_system_root=False,
        issuer_full_dn=None,
    )
    assert cat == "unknown"


def test_explicit_empty_patterns_disables_internal_detection():
    cat = categorize_ca(
        is_self_signed=False,
        chain_path_to_system_root=False,
        issuer_full_dn="CN=Kurmi Internal Lab CA,O=Kurmi",
        internal_patterns=[],
    )
    assert cat == "unknown"


def test_explicit_patterns_replace_defaults():
    cat = categorize_ca(
        is_self_signed=False,
        chain_path_to_system_root=False,
        issuer_full_dn="CN=Kurmi Lab CA,O=Kurmi",
        internal_patterns=["acme"],  # "kurmi" is not in this list
    )
    assert cat == "unknown"


def test_pattern_match_is_case_insensitive():
    cat = categorize_ca(
        is_self_signed=False,
        chain_path_to_system_root=False,
        issuer_full_dn="CN=KURMI LAB CA,O=KURMI",
        internal_patterns=["kurmi"],
    )
    assert cat == "internal_corporate"


# ---- env var resolution -----------------------------------------------


def test_env_unset_uses_defaults(monkeypatch):
    monkeypatch.delenv("INTERNAL_CA_PATTERNS", raising=False)
    assert load_internal_patterns_from_env() == list(DEFAULT_INTERNAL_CA_PATTERNS)


def test_env_empty_string_disables(monkeypatch):
    monkeypatch.setenv("INTERNAL_CA_PATTERNS", "")
    assert load_internal_patterns_from_env() == []


def test_env_csv_replaces_defaults(monkeypatch):
    monkeypatch.setenv("INTERNAL_CA_PATTERNS", "acme,foo bar, baz ")
    assert load_internal_patterns_from_env() == ["acme", "foo bar", "baz"]


def test_env_disabled_falls_through_to_unknown(monkeypatch):
    monkeypatch.setenv("INTERNAL_CA_PATTERNS", "")
    cat = categorize_ca(
        is_self_signed=False,
        chain_path_to_system_root=False,
        issuer_full_dn="CN=Kurmi Internal Lab CA,O=Kurmi",
    )
    assert cat == "unknown"


def test_env_csv_used_when_no_explicit_patterns(monkeypatch):
    monkeypatch.setenv("INTERNAL_CA_PATTERNS", "acme")
    cat = categorize_ca(
        is_self_signed=False,
        chain_path_to_system_root=False,
        issuer_full_dn="CN=Acme Issuing CA,O=Acme",
    )
    assert cat == "internal_corporate"
