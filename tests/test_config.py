"""Phase 3 tests — YAML config loading."""

from __future__ import annotations

import pytest

from certwatch.config import HostConfig, load_config


def test_minimal_config(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("hosts:\n  - hostname: example.com\n")
    cfg = load_config(p)
    assert cfg.hosts == (HostConfig(hostname="example.com"),)
    assert cfg.sweep_interval_seconds == 3600
    assert cfg.max_concurrency == 20
    assert cfg.log_level == "INFO"
    assert cfg.tcp_connect_seconds == 5.0
    assert cfg.tls_handshake_seconds == 5.0


def test_full_config(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text(
        """
hosts:
  - hostname: google.com
    port: 443
    display_name: Google
    tags: [public, search]
  - hostname: 10.0.0.1
    port: 8443
sweep_interval_seconds: 1800
max_concurrency: 10
log_level: debug
tcp_connect_seconds: 3
tls_handshake_seconds: 3
"""
    )
    cfg = load_config(p)
    assert len(cfg.hosts) == 2
    assert cfg.hosts[0].hostname == "google.com"
    assert cfg.hosts[0].display_name == "Google"
    assert cfg.hosts[0].tags == ("public", "search")
    assert cfg.hosts[1].hostname == "10.0.0.1"
    assert cfg.hosts[1].port == 8443
    assert cfg.hosts[1].display_name is None
    assert cfg.hosts[1].tags == ()
    assert cfg.sweep_interval_seconds == 1800
    assert cfg.max_concurrency == 10
    assert cfg.log_level == "DEBUG"  # uppercased
    assert cfg.tcp_connect_seconds == 3.0
    assert cfg.tls_handshake_seconds == 3.0


def test_root_must_be_mapping(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("- just a list\n")
    with pytest.raises(ValueError, match="mapping"):
        load_config(p)


def test_missing_hosts_raises(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("max_concurrency: 5\n")
    with pytest.raises(ValueError, match="hosts"):
        load_config(p)


def test_empty_hosts_raises(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("hosts: []\n")
    with pytest.raises(ValueError, match="hosts"):
        load_config(p)


def test_hostname_required(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("hosts:\n  - port: 443\n")
    with pytest.raises(ValueError, match="hostname"):
        load_config(p)


def test_blank_hostname_rejected(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("hosts:\n  - hostname: '   '\n")
    with pytest.raises(ValueError, match="hostname"):
        load_config(p)


def test_tags_must_be_list_of_strings(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("hosts:\n  - hostname: x\n    tags: [1, 2]\n")
    with pytest.raises(ValueError, match="tags"):
        load_config(p)


def test_display_name_must_be_string(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("hosts:\n  - hostname: x\n    display_name: 123\n")
    with pytest.raises(ValueError, match="display_name"):
        load_config(p)


def test_hostname_whitespace_stripped(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("hosts:\n  - hostname: '  example.com  '\n")
    cfg = load_config(p)
    assert cfg.hosts[0].hostname == "example.com"
