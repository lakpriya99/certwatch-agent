"""Phase 5a — agent bootstrap.

Single function `bootstrap()` that:
  1. Validates required env vars
  2. Loads credentials from /data/agent.json (or registers if absent)
  3. Fetches initial config (from register response or get_config)
  4. Returns everything the runner needs to start its loops

This module owns the startup ordering and retry policy for register; it
deliberately does NOT start any threads or set up signal handlers — those
are 5f's job. Bootstrap is idempotent in the "second run sees creds and
skips register" sense, but each call performs at most one registration.
"""

from __future__ import annotations

import logging
import os
import platform as platform_mod
import socket
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional

from certwatch._version import __version__
from certwatch.agent_state import (
    CredentialsCorruptError,
    load_credentials,
    save_credentials,
)
from certwatch.clock import Clock, RealClock, utc_now_iso
from certwatch.dashboard_client import (
    DashboardAuthError,
    DashboardClient,
    DashboardConflictError,
    DashboardError,
    DashboardRetriableError,
    DashboardValidationError,
)

log = logging.getLogger("certwatch")


# Backoff schedule for retriable failures during register (and during
# get_config at bootstrap). 5s, 15s, 30s, 60s, 120s, then steady at 120s.
BACKOFF_SCHEDULE = (5.0, 15.0, 30.0, 60.0, 120.0)


# Minimum config used when bootstrap can't fetch real config from the
# dashboard (subsequent run, get_config fails with a retriable error).
# config_version=0 ensures the first heartbeat that succeeds will signal
# config_refresh_required=true (the dashboard's version is always >= 1
# after registration).
DEFAULT_CONFIG: dict = {
    "config_version": 0,
    "fetched_at": "1970-01-01T00:00:00Z",
    "intervals": {
        "heartbeat_seconds": 15,
        "check_seconds": 3600,
        "netbox_sync_seconds": 3600,
    },
    "timeouts": {
        "tcp_connect_seconds": 5,
        "tls_handshake_seconds": 5,
    },
    "concurrency": {
        "max_parallel_checks": 20,
    },
    "alert_thresholds_days": [30, 7, 1],
    "manual_hosts": [],
}


# Map Python's platform.machine() to Docker arch convention.
_ARCH_MAP = {
    "x86_64": "amd64",
    "amd64": "amd64",
    "aarch64": "arm64",
    "arm64": "arm64",
    "armv7l": "arm/v7",
    "i386": "386",
    "i686": "386",
}


class BootstrapError(Exception):
    """Raised when bootstrap can't proceed and the agent must exit non-zero.

    Distinct from `DashboardError` so the runner / CLI can catch this
    specifically as the "stop the world" signal — bootstrap raising
    BootstrapError means there's nothing the runner can do to recover."""


@dataclass
class BootstrapResult:
    client: DashboardClient
    agent_id: str
    agent_secret: str
    dashboard_url: str
    initial_config: dict
    registered_at: str  # ISO 8601 UTC; from creds file or register response


# ---- env helpers ------------------------------------------------------


def _require_env(env: Mapping[str, str], name: str) -> str:
    val = env.get(name)
    if not val or not val.strip():
        raise BootstrapError(
            f"required environment variable {name} is missing or empty"
        )
    return val.strip()


# ---- system info helpers ---------------------------------------------


def resolve_hostname(
    env: Mapping[str, str], *, agent_id: Optional[str] = None
) -> str:
    """Hostname for register/heartbeat bodies.

    Order of preference:
      1. AGENT_HOSTNAME env var (operator override)
      2. socket.gethostname() if it's meaningful
      3. Fallback: certwatch-<agent_id last 8 chars> if we have an agent_id
      4. Fallback: certwatch-<random hex 8> for first-time register

    The "meaningless" check covers empty string and "localhost", both
    common in misconfigured Docker setups. A meaningless hostname in the
    dashboard's agent list is worse than a recognizable agent_id fragment.
    """
    explicit = env.get("AGENT_HOSTNAME")
    if explicit and explicit.strip():
        return explicit.strip()

    try:
        hn = socket.gethostname()
    except OSError:
        hn = ""
    if hn and hn.lower() not in ("localhost",):
        return hn

    if agent_id:
        return f"certwatch-{agent_id[-8:]}"
    # First register, no agent_id available, gethostname() useless: synthesize
    # a one-time stable token so retries during the same process use the
    # same hostname (avoids the dashboard creating duplicate agent records
    # if a register call succeeds server-side but fails to deliver the
    # response to the agent — though the registration_token mechanism
    # already prevents that, this just keeps logs consistent).
    return f"certwatch-{uuid.uuid4().hex[:8]}"


def resolve_platform() -> Optional[str]:
    """Platform string in Docker's `<system>/<arch>` convention.

    e.g. linux/amd64, linux/arm64, darwin/arm64. Returns None if either
    component can't be determined — the contract documents `platform`
    as optional, and lying with a guessed value is worse than omitting it.
    """
    try:
        sys_name = platform_mod.system().lower()
        machine = platform_mod.machine().lower()
    except Exception:
        return None
    if not sys_name or not machine:
        return None
    arch = _ARCH_MAP.get(machine, machine)
    return f"{sys_name}/{arch}"


# ---- backoff helpers --------------------------------------------------


def _backoff_delay(attempt: int) -> float:
    """attempt=0 means "first retry, sleep before retrying." After all the
    documented steps, stay steady at the last value — these are transient
    errors and the agent never gives up."""
    idx = min(attempt, len(BACKOFF_SCHEDULE) - 1)
    return BACKOFF_SCHEDULE[idx]


# ---- the bootstrap function ------------------------------------------


def validate_netbox_env(env: Mapping[str, str]) -> None:
    """Phase 6: when NETBOX_URL is set, NETBOX_TOKEN and NETBOX_FILTER
    must also be set. Half-configured NetBox state is operator error.

    Called from bootstrap so a misconfiguration fails fast at startup
    rather than silently disabling NetBox sync at runtime."""
    netbox_url = env.get("NETBOX_URL", "").strip()
    if not netbox_url:
        return  # NetBox not configured — fine, sync disabled
    missing = [
        name
        for name in ("NETBOX_TOKEN", "NETBOX_FILTER")
        if not env.get(name) or not env.get(name, "").strip()
    ]
    if missing:
        raise BootstrapError(
            f"NETBOX_URL is set but {', '.join(missing)} is missing — "
            f"NetBox configuration is incomplete. Set all three or unset "
            f"NETBOX_URL to disable NetBox sync."
        )


def bootstrap(
    *,
    env: Mapping[str, str],
    data_dir: str | Path,
    clock: Optional[Clock] = None,
) -> BootstrapResult:
    """Run the agent's startup sequence.

    Raises BootstrapError on conditions that require operator intervention
    (missing env vars, invalid registration token, agent_revoked,
    corrupted /data/agent.json, code-bug 400 on register). Retriable
    failures during register or get_config back off according to
    BACKOFF_SCHEDULE; bootstrap doesn't give up on transient errors.
    """
    if clock is None:
        clock = RealClock()

    data_dir = Path(data_dir)
    creds_path = data_dir / "agent.json"

    # 1. Env validation. DASHBOARD_URL is always required (used as the
    # base URL for the client even on subsequent runs — though we'll
    # cross-check against creds["dashboard_url"] if creds exist).
    dashboard_url_env = _require_env(env, "DASHBOARD_URL")

    # NetBox env vars are validated together so a half-configured agent
    # fails fast rather than silently disabling sync.
    validate_netbox_env(env)

    # 2. Load existing credentials (or learn we need to register).
    try:
        creds = load_credentials(creds_path)
    except CredentialsCorruptError as e:
        # Loud failure per Phase 4b's contract — operator must investigate
        # rather than the agent silently re-registering and orphaning the
        # dashboard's record of this agent.
        raise BootstrapError(
            f"credentials file at {creds_path} is corrupt — operator must "
            f"investigate before agent can start: {e}"
        ) from e

    if creds is not None:
        return _bootstrap_subsequent_run(creds, dashboard_url_env, clock)
    return _bootstrap_first_run(env, dashboard_url_env, creds_path, clock)


def _bootstrap_subsequent_run(
    creds: dict,
    dashboard_url_env: str,
    clock: Clock,
) -> BootstrapResult:
    """Path taken when /data/agent.json already exists."""
    agent_id = creds["agent_id"]
    agent_secret = creds["agent_secret"]
    creds_dashboard_url = creds["dashboard_url"]

    if creds_dashboard_url != dashboard_url_env:
        # Operator changed DASHBOARD_URL but didn't clear /data — credentials
        # are bound to the old dashboard, so we must use that. Log as
        # warning so the operator can spot the mismatch.
        log.warning(
            {
                "event": "dashboard_url_mismatch",
                "creds_dashboard_url": creds_dashboard_url,
                "env_dashboard_url": dashboard_url_env,
                "using": "creds_dashboard_url",
                "note": "agent_secret is bound to creds_dashboard_url; "
                "to switch dashboards, delete /data/agent.json and re-register",
            }
        )

    dashboard_url = creds_dashboard_url
    client = DashboardClient(dashboard_url, agent_id=agent_id, agent_secret=agent_secret)

    log.info(
        {
            "event": "credentials_loaded",
            "agent_id": agent_id,
            "dashboard_url": dashboard_url,
            "registered_at": creds.get("registered_at"),
        }
    )

    initial_config = _fetch_initial_config_with_retry(client, clock)
    return BootstrapResult(
        client=client,
        agent_id=agent_id,
        agent_secret=agent_secret,
        dashboard_url=dashboard_url,
        initial_config=initial_config,
        registered_at=creds.get("registered_at", ""),
    )


def _bootstrap_first_run(
    env: Mapping[str, str],
    dashboard_url: str,
    creds_path: Path,
    clock: Clock,
) -> BootstrapResult:
    """Path taken when /data/agent.json doesn't exist — must register."""
    registration_token = _require_env(env, "REGISTRATION_TOKEN")
    hostname = resolve_hostname(env)  # called once; reused across retries
    plat = resolve_platform()
    started_at = utc_now_iso()  # process-start time, stable across retries

    log.info(
        {
            "event": "first_run_registering",
            "dashboard_url": dashboard_url,
            "hostname": hostname,
            "platform": plat,
            "agent_version": __version__,
        }
    )

    unauthed_client = DashboardClient(dashboard_url)
    register_resp = _register_with_backoff(
        unauthed_client,
        registration_token=registration_token,
        agent_version=__version__,
        hostname=hostname,
        platform=plat,
        started_at=started_at,
        clock=clock,
    )

    agent_id = register_resp["agent_id"]
    agent_secret = register_resp["agent_secret"]
    registered_at = register_resp["registered_at"]
    initial_config = register_resp.get("config", DEFAULT_CONFIG)

    save_credentials(
        creds_path,
        agent_id=agent_id,
        agent_secret=agent_secret,
        dashboard_url=dashboard_url,
        registered_at=registered_at,
    )

    log.info(
        {
            "event": "registration_complete",
            "agent_id": agent_id,
            "registered_at": registered_at,
            "creds_path": str(creds_path),
        }
    )

    client = DashboardClient(dashboard_url, agent_id=agent_id, agent_secret=agent_secret)
    return BootstrapResult(
        client=client,
        agent_id=agent_id,
        agent_secret=agent_secret,
        dashboard_url=dashboard_url,
        initial_config=initial_config,
        registered_at=registered_at,
    )


def _register_with_backoff(
    client: DashboardClient,
    *,
    registration_token: str,
    agent_version: str,
    hostname: str,
    platform: Optional[str],
    started_at: str,
    clock: Clock,
) -> dict:
    """Drive the register call with the documented backoff policy.

    Hard fails (auth, conflict, validation) raise BootstrapError without
    retry. Retriable fails (5xx, network) sleep per BACKOFF_SCHEDULE and
    keep going forever — the agent waits out transient outages."""
    attempt = 0
    while True:
        try:
            return client.register(
                registration_token=registration_token,
                agent_version=agent_version,
                hostname=hostname,
                platform=platform,
                started_at=started_at,
            )
        except DashboardAuthError as e:
            # 401 invalid_registration_token. Operator action required;
            # re-trying with the same (already-consumed) token will keep
            # failing.
            raise BootstrapError(
                f"registration token rejected (code={e.code}): {e.message}. "
                f"Operator must obtain a new token and restart the agent."
            ) from e
        except DashboardConflictError as e:
            # 409 registration_conflict — same handling as 401.
            raise BootstrapError(
                f"registration conflict (code={e.code}): {e.message}. "
                f"Operator must obtain a new token and restart the agent."
            ) from e
        except DashboardValidationError as e:
            # 400 validation_failed — code bug. Don't loop forever on bugs.
            raise BootstrapError(
                f"registration validation failed (code={e.code}): {e.message}. "
                f"This is a code bug — fix and redeploy."
            ) from e
        except DashboardRetriableError as e:
            delay = _backoff_delay(attempt)
            log.warning(
                {
                    "event": "registration_retry",
                    "attempt": attempt + 1,
                    "delay_seconds": delay,
                    "error_class": type(e).__name__,
                    "error_code": e.code,
                    "error_message": e.message,
                    "request_id": e.request_id,
                }
            )
            clock.sleep(delay)
            attempt += 1
        except DashboardError as e:
            # Any other DashboardError subclass (NotFound, base, etc.) —
            # treat as fatal; not specified as retriable in the contract.
            raise BootstrapError(
                f"unexpected registration error (status={e.status_code}, "
                f"code={e.code}): {e.message}"
            ) from e


def _fetch_initial_config_with_retry(
    client: DashboardClient,
    clock: Clock,
    *,
    max_attempts: int = 1,
) -> dict:
    """Try to fetch config on subsequent run. Retriable failures fall back
    to DEFAULT_CONFIG (the heartbeat will retrieve the real one shortly).
    Non-retriable failures (auth, not-found) abort bootstrap."""
    attempt = 0
    while True:
        try:
            cfg = client.get_config()
            log.info(
                {
                    "event": "initial_config_fetched",
                    "config_version": cfg.get("config_version"),
                    "manual_hosts_count": len(cfg.get("manual_hosts", []) or []),
                }
            )
            return cfg
        except DashboardAuthError as e:
            # invalid_token / agent_revoked — agent's identity is no longer
            # valid; nothing to do but exit so the operator can react.
            raise BootstrapError(
                f"credentials rejected at startup (code={e.code}): {e.message}. "
                f"The agent has been revoked or /data/agent.json no longer "
                f"matches a registered agent."
            ) from e
        except DashboardRetriableError as e:
            attempt += 1
            if attempt >= max_attempts:
                # Non-fatal at startup: use defaults and let the heartbeat
                # loop pick up the real config when the dashboard recovers.
                log.warning(
                    {
                        "event": "initial_config_unavailable_using_defaults",
                        "error_class": type(e).__name__,
                        "error_message": e.message,
                    }
                )
                return dict(DEFAULT_CONFIG)
            clock.sleep(_backoff_delay(attempt - 1))
        except DashboardError as e:
            # Validation/NotFound/etc. — fatal, the agent's view of the
            # world doesn't match the dashboard's.
            raise BootstrapError(
                f"unexpected error fetching initial config "
                f"(status={e.status_code}, code={e.code}): {e.message}"
            ) from e
