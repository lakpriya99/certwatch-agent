"""Local YAML config (Phase 3) — agent operating parameters for offline/dev mode.

The dashboard-connected mode (Phase 5+) sources its host list from the
dashboard `/config` endpoint plus the local NetBox sync, not from this file.
This config is for running the agent against a hand-curated host list during
development and integration testing.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml


@dataclass(frozen=True)
class HostConfig:
    hostname: str
    port: int = 443
    display_name: Optional[str] = None
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class AgentConfig:
    hosts: tuple[HostConfig, ...]
    sweep_interval_seconds: int = 3600
    max_concurrency: int = 20
    log_level: str = "INFO"
    tcp_connect_seconds: float = 5.0
    tls_handshake_seconds: float = 5.0


def load_config(path: str | Path) -> AgentConfig:
    raw = yaml.safe_load(Path(path).read_text())
    if not isinstance(raw, dict):
        raise ValueError(
            f"config root must be a mapping, got {type(raw).__name__}"
        )
    return _parse_config(raw)


def _parse_config(raw: dict) -> AgentConfig:
    hosts_raw = raw.get("hosts")
    if not isinstance(hosts_raw, list) or not hosts_raw:
        raise ValueError("config.hosts must be a non-empty list")

    hosts = tuple(_parse_host(h, i) for i, h in enumerate(hosts_raw))

    return AgentConfig(
        hosts=hosts,
        sweep_interval_seconds=int(raw.get("sweep_interval_seconds", 3600)),
        max_concurrency=int(raw.get("max_concurrency", 20)),
        log_level=str(raw.get("log_level", "INFO")).upper(),
        tcp_connect_seconds=float(raw.get("tcp_connect_seconds", 5.0)),
        tls_handshake_seconds=float(raw.get("tls_handshake_seconds", 5.0)),
    )


def _parse_host(raw: dict, idx: int) -> HostConfig:
    if not isinstance(raw, dict):
        raise ValueError(f"hosts[{idx}] must be a mapping, got {type(raw).__name__}")
    hostname = raw.get("hostname")
    if not isinstance(hostname, str) or not hostname.strip():
        raise ValueError(
            f"hosts[{idx}].hostname is required and must be a non-empty string"
        )
    tags = raw.get("tags", [])
    if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
        raise ValueError(f"hosts[{idx}].tags must be a list of strings if present")
    display = raw.get("display_name")
    if display is not None and not isinstance(display, str):
        raise ValueError(f"hosts[{idx}].display_name must be a string if present")
    return HostConfig(
        hostname=hostname.strip(),
        port=int(raw.get("port", 443)),
        display_name=display,
        tags=tuple(tags),
    )
