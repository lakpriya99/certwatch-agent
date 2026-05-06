"""Phase 5a — bootstrap tests.

Exercises the real DashboardClient against a mocked HTTP layer (via
`responses`) and a real on-disk credentials file (in tmp_path), so the
full bootstrap path — env validation, registration backoff, atomic
credentials persistence, initial config — runs end-to-end without any
internal mocking.

Time is faked via FakeClock; tests never actually sleep.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import responses

from certwatch._version import __version__
from certwatch.agent_state import load_credentials, save_credentials
from certwatch.bootstrap import (
    BACKOFF_SCHEDULE,
    DEFAULT_CONFIG,
    BootstrapError,
    BootstrapResult,
    _backoff_delay,
    bootstrap,
    resolve_hostname,
    resolve_platform,
)
from certwatch.clock import FakeClock

DASH = "https://certwatch.lovable.app"
REGISTER_URL = f"{DASH}/api/v1/agents/register"

REG_SUCCESS = {
    "agent_id": "a8f3d12e-7b4c-4d8a-9e1f-2c5b6a7d8e9f",
    "agent_secret": "agtkey_long_random_xyz",
    "registered_at": "2026-05-02T14:30:01Z",
    "config": {
        "config_version": 1,
        "fetched_at": "2026-05-02T14:30:01Z",
        "intervals": {"heartbeat_seconds": 15, "check_seconds": 3600, "netbox_sync_seconds": 3600},
        "timeouts": {"tcp_connect_seconds": 5, "tls_handshake_seconds": 5},
        "concurrency": {"max_parallel_checks": 20},
        "alert_thresholds_days": [30, 7, 1],
        "manual_hosts": [],
    },
}

CONFIG_SUCCESS = {
    "config_version": 7,
    "fetched_at": "2026-05-02T14:35:00Z",
    "intervals": {"heartbeat_seconds": 15, "check_seconds": 3600, "netbox_sync_seconds": 3600},
    "timeouts": {"tcp_connect_seconds": 5, "tls_handshake_seconds": 5},
    "concurrency": {"max_parallel_checks": 20},
    "alert_thresholds_days": [30, 7, 1],
    "manual_hosts": [
        {
            "host_id": "b1c2d3e4-5f6a-7b8c-9d0e-1f2a3b4c5d6e",
            "hostname": "app.example.com",
            "port": 443,
            "added_at": "2026-04-28T10:00:00Z",
        }
    ],
}


def _config_url(agent_id: str) -> str:
    return f"{DASH}/api/v1/agents/{agent_id}/config"


# ---- env validation ---------------------------------------------------


def test_bootstrap_fails_when_dashboard_url_missing(tmp_path):
    with pytest.raises(BootstrapError, match="DASHBOARD_URL"):
        bootstrap(env={}, data_dir=tmp_path, clock=FakeClock())


def test_bootstrap_fails_when_dashboard_url_empty(tmp_path):
    with pytest.raises(BootstrapError, match="DASHBOARD_URL"):
        bootstrap(env={"DASHBOARD_URL": "   "}, data_dir=tmp_path, clock=FakeClock())


def test_bootstrap_first_run_fails_when_registration_token_missing(tmp_path):
    """First run (no agent.json) needs REGISTRATION_TOKEN; missing must
    fail with a clear message rather than silently retrying forever."""
    env = {"DASHBOARD_URL": DASH}
    with pytest.raises(BootstrapError, match="REGISTRATION_TOKEN"):
        bootstrap(env=env, data_dir=tmp_path, clock=FakeClock())


def test_bootstrap_subsequent_run_does_not_require_registration_token(tmp_path):
    """Once /data/agent.json exists, REGISTRATION_TOKEN is no longer needed."""
    save_credentials(
        tmp_path / "agent.json",
        agent_id="aid",
        agent_secret="agtkey_x",
        dashboard_url=DASH,
        registered_at="2026-05-01T00:00:00Z",
    )
    env = {"DASHBOARD_URL": DASH}  # no REGISTRATION_TOKEN
    with responses.RequestsMock() as rsps:
        rsps.add("GET", _config_url("aid"), json=CONFIG_SUCCESS, status=200)
        result = bootstrap(env=env, data_dir=tmp_path, clock=FakeClock())
    assert result.agent_id == "aid"


# ---- first-run register flow -----------------------------------------


def test_bootstrap_first_run_registers_and_saves(tmp_path):
    env = {"DASHBOARD_URL": DASH, "REGISTRATION_TOKEN": "regtok_xyz"}
    fc = FakeClock()
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REGISTER_URL, json=REG_SUCCESS, status=201)
        result = bootstrap(env=env, data_dir=tmp_path, clock=fc)

    assert isinstance(result, BootstrapResult)
    assert result.agent_id == REG_SUCCESS["agent_id"]
    assert result.agent_secret == REG_SUCCESS["agent_secret"]
    assert result.dashboard_url == DASH

    # Credentials persisted with all four fields
    creds = load_credentials(tmp_path / "agent.json")
    assert creds == {
        "agent_id": REG_SUCCESS["agent_id"],
        "agent_secret": REG_SUCCESS["agent_secret"],
        "dashboard_url": DASH,
        "registered_at": REG_SUCCESS["registered_at"],
    }
    # No retries — successful first attempt
    assert fc.sleeps == []


def test_bootstrap_first_run_uses_register_response_config(tmp_path):
    """Initial config comes from the register response on first run; we
    do NOT make an extra get_config call after register."""
    env = {"DASHBOARD_URL": DASH, "REGISTRATION_TOKEN": "regtok_xyz"}
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REGISTER_URL, json=REG_SUCCESS, status=201)
        # NO get_config mocked — the test would fail with a connection
        # error if bootstrap incorrectly tried to call it.
        result = bootstrap(env=env, data_dir=tmp_path, clock=FakeClock())
    assert result.initial_config == REG_SUCCESS["config"]


def test_bootstrap_first_run_register_request_carries_expected_fields(tmp_path):
    env = {
        "DASHBOARD_URL": DASH,
        "REGISTRATION_TOKEN": "regtok_xyz",
        "AGENT_HOSTNAME": "test-agent-01",
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REGISTER_URL, json=REG_SUCCESS, status=201)
        bootstrap(env=env, data_dir=tmp_path, clock=FakeClock())
        sent = json.loads(rsps.calls[0].request.body)
        headers = rsps.calls[0].request.headers
    assert sent["agent_version"] == __version__
    assert sent["hostname"] == "test-agent-01"
    assert sent["started_at"].endswith("Z")
    # platform may or may not be present depending on the test runner's
    # platform.system()/machine() availability — assert only that if
    # present, it's a string
    if "platform" in sent:
        assert isinstance(sent["platform"], str) and "/" in sent["platform"]
    assert headers.get("X-Registration-Token") == "regtok_xyz"
    assert "Authorization" not in headers  # register skips auth


def test_bootstrap_first_run_creates_data_dir(tmp_path):
    """tmp_path / "nested" doesn't exist; save_credentials must mkdir it."""
    env = {"DASHBOARD_URL": DASH, "REGISTRATION_TOKEN": "regtok_xyz"}
    nested = tmp_path / "nested" / "deep"
    assert not nested.exists()
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REGISTER_URL, json=REG_SUCCESS, status=201)
        bootstrap(env=env, data_dir=nested, clock=FakeClock())
    assert (nested / "agent.json").exists()


# ---- register error handling ----------------------------------------


def test_bootstrap_register_invalid_token_does_not_retry(tmp_path):
    """401 invalid_registration_token is a permanent operator-action
    condition. Bootstrap raises immediately."""
    env = {"DASHBOARD_URL": DASH, "REGISTRATION_TOKEN": "regtok_bad"}
    fc = FakeClock()
    err = {
        "error": {
            "code": "invalid_registration_token",
            "message": "Token unknown, expired, or already used",
            "request_id": "req_x",
        }
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REGISTER_URL, json=err, status=401)
        with pytest.raises(BootstrapError) as exc:
            bootstrap(env=env, data_dir=tmp_path, clock=fc)
    assert "invalid_registration_token" in str(exc.value).lower() or "rejected" in str(exc.value).lower()
    assert fc.sleeps == []  # no retries
    # No credentials persisted on failure
    assert not (tmp_path / "agent.json").exists()


def test_bootstrap_register_validation_error_does_not_retry(tmp_path):
    env = {"DASHBOARD_URL": DASH, "REGISTRATION_TOKEN": "regtok_xyz"}
    fc = FakeClock()
    err = {
        "error": {
            "code": "validation_failed",
            "message": "missing field 'hostname'",
            "request_id": "req_v",
        }
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REGISTER_URL, json=err, status=400)
        with pytest.raises(BootstrapError, match="code bug|validation"):
            bootstrap(env=env, data_dir=tmp_path, clock=fc)
    assert fc.sleeps == []


def test_bootstrap_register_conflict_does_not_retry(tmp_path):
    env = {"DASHBOARD_URL": DASH, "REGISTRATION_TOKEN": "regtok_xyz"}
    fc = FakeClock()
    err = {
        "error": {
            "code": "registration_conflict",
            "message": "agent_id already exists",
            "request_id": "req_c",
        }
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REGISTER_URL, json=err, status=409)
        with pytest.raises(BootstrapError):
            bootstrap(env=env, data_dir=tmp_path, clock=fc)
    assert fc.sleeps == []


def test_bootstrap_register_retries_on_5xx_with_correct_backoff(tmp_path):
    """503 → backoff 5s → 503 → backoff 15s → 503 → backoff 30s → 201.
    Exact backoff sequence asserted via FakeClock.sleeps."""
    env = {"DASHBOARD_URL": DASH, "REGISTRATION_TOKEN": "regtok_xyz"}
    fc = FakeClock()
    err = {"error": {"code": "internal_error", "message": "boom"}}
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REGISTER_URL, json=err, status=503)
        rsps.add("POST", REGISTER_URL, json=err, status=503)
        rsps.add("POST", REGISTER_URL, json=err, status=503)
        rsps.add("POST", REGISTER_URL, json=REG_SUCCESS, status=201)
        result = bootstrap(env=env, data_dir=tmp_path, clock=fc)
    assert result.agent_id == REG_SUCCESS["agent_id"]
    assert fc.sleeps == [5.0, 15.0, 30.0]
    assert (tmp_path / "agent.json").exists()


def test_bootstrap_register_backoff_caps_at_steady_state(tmp_path):
    """After the documented schedule (5,15,30,60,120), backoff stays at
    120s forever — the agent waits out long outages without giving up."""
    env = {"DASHBOARD_URL": DASH, "REGISTRATION_TOKEN": "regtok_xyz"}
    fc = FakeClock()
    err = {"error": {"code": "internal_error", "message": "boom"}}
    with responses.RequestsMock() as rsps:
        # 7 failures, then success — should sleep 5,15,30,60,120,120,120
        for _ in range(7):
            rsps.add("POST", REGISTER_URL, json=err, status=503)
        rsps.add("POST", REGISTER_URL, json=REG_SUCCESS, status=201)
        bootstrap(env=env, data_dir=tmp_path, clock=fc)
    assert fc.sleeps == [5.0, 15.0, 30.0, 60.0, 120.0, 120.0, 120.0]


def test_bootstrap_register_retries_on_network_errors(tmp_path, monkeypatch):
    """Network timeouts and connection errors should retry the same way
    as 5xx — they're DashboardRetriableError subclasses too."""
    env = {"DASHBOARD_URL": DASH, "REGISTRATION_TOKEN": "regtok_xyz"}
    fc = FakeClock()

    # First call: simulate a connection error; subsequent: success via responses
    import requests
    call_count = {"n": 0}
    real_request = requests.Session.request

    def flaky(self, method, url, **kw):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise requests.ConnectionError("ECONNREFUSED")
        return real_request(self, method, url, **kw)

    monkeypatch.setattr(requests.Session, "request", flaky)

    with responses.RequestsMock() as rsps:
        rsps.add("POST", REGISTER_URL, json=REG_SUCCESS, status=201)
        result = bootstrap(env=env, data_dir=tmp_path, clock=fc)
    assert result.agent_id == REG_SUCCESS["agent_id"]
    assert fc.sleeps == [5.0]


# ---- subsequent-run path (creds present) ----------------------------


def test_bootstrap_subsequent_run_skips_registration(tmp_path):
    save_credentials(
        tmp_path / "agent.json",
        agent_id="aid",
        agent_secret="agtkey_saved",
        dashboard_url=DASH,
        registered_at="2026-05-01T00:00:00Z",
    )
    env = {"DASHBOARD_URL": DASH}
    with responses.RequestsMock() as rsps:
        rsps.add("GET", _config_url("aid"), json=CONFIG_SUCCESS, status=200)
        # NO register mock — would error if bootstrap incorrectly tried.
        result = bootstrap(env=env, data_dir=tmp_path, clock=FakeClock())
    assert result.agent_id == "aid"
    assert result.agent_secret == "agtkey_saved"


def test_bootstrap_subsequent_run_fetches_initial_config(tmp_path):
    save_credentials(
        tmp_path / "agent.json",
        agent_id="aid",
        agent_secret="agtkey_saved",
        dashboard_url=DASH,
        registered_at="2026-05-01T00:00:00Z",
    )
    env = {"DASHBOARD_URL": DASH}
    with responses.RequestsMock() as rsps:
        rsps.add("GET", _config_url("aid"), json=CONFIG_SUCCESS, status=200)
        result = bootstrap(env=env, data_dir=tmp_path, clock=FakeClock())
    assert result.initial_config == CONFIG_SUCCESS
    assert result.initial_config["config_version"] == 7


def test_bootstrap_subsequent_run_get_config_5xx_uses_defaults(tmp_path):
    """get_config is best-effort at startup — a transient failure falls
    back to DEFAULT_CONFIG, and the heartbeat will fetch the real one
    when the dashboard recovers."""
    save_credentials(
        tmp_path / "agent.json",
        agent_id="aid",
        agent_secret="agtkey_saved",
        dashboard_url=DASH,
        registered_at="2026-05-01T00:00:00Z",
    )
    env = {"DASHBOARD_URL": DASH}
    with responses.RequestsMock() as rsps:
        rsps.add("GET", _config_url("aid"), json={}, status=503)
        result = bootstrap(env=env, data_dir=tmp_path, clock=FakeClock())
    assert result.initial_config == DEFAULT_CONFIG
    # config_version=0 ensures the first heartbeat will signal refresh
    assert result.initial_config["config_version"] == 0


def test_bootstrap_subsequent_run_get_config_auth_error_aborts(tmp_path):
    """invalid_token / agent_revoked at startup is fatal — credentials
    are no longer valid and the agent must exit so operator can react."""
    save_credentials(
        tmp_path / "agent.json",
        agent_id="aid",
        agent_secret="agtkey_revoked",
        dashboard_url=DASH,
        registered_at="2026-05-01T00:00:00Z",
    )
    env = {"DASHBOARD_URL": DASH}
    err = {"error": {"code": "agent_revoked", "message": "revoked", "request_id": "req_r"}}
    with responses.RequestsMock() as rsps:
        rsps.add("GET", _config_url("aid"), json=err, status=401)
        with pytest.raises(BootstrapError, match="revoked|rejected"):
            bootstrap(env=env, data_dir=tmp_path, clock=FakeClock())


def test_bootstrap_dashboard_url_mismatch_uses_creds_value(tmp_path, caplog):
    """env DASHBOARD_URL changed but creds are bound to the old URL.
    Bootstrap uses creds' value (where the agent_secret is valid) and
    logs a warning so the operator can spot the misconfiguration."""
    save_credentials(
        tmp_path / "agent.json",
        agent_id="aid",
        agent_secret="agtkey_saved",
        dashboard_url=DASH,
        registered_at="2026-05-01T00:00:00Z",
    )
    env = {"DASHBOARD_URL": "https://different.lovable.app"}
    with responses.RequestsMock() as rsps:
        # Should call DASH (creds value), not the env value.
        rsps.add("GET", _config_url("aid"), json=CONFIG_SUCCESS, status=200)
        with caplog.at_level("WARNING"):
            result = bootstrap(env=env, data_dir=tmp_path, clock=FakeClock())
    assert result.dashboard_url == DASH
    mismatch_logs = [
        r for r in caplog.records
        if isinstance(r.msg, dict) and r.msg.get("event") == "dashboard_url_mismatch"
    ]
    assert len(mismatch_logs) == 1


def test_bootstrap_corrupt_credentials_raises_bootstrap_error(tmp_path):
    """Corrupted /data/agent.json must NOT silently re-register (which
    would orphan the dashboard's record). Same fail-loud disposition as
    Phase 4b's CredentialsCorruptError contract."""
    creds_path = tmp_path / "agent.json"
    creds_path.write_text("not valid json {{{")
    env = {"DASHBOARD_URL": DASH, "REGISTRATION_TOKEN": "regtok_xyz"}
    with pytest.raises(BootstrapError, match="corrupt"):
        bootstrap(env=env, data_dir=tmp_path, clock=FakeClock())
    # Original corrupt file untouched
    assert creds_path.read_text() == "not valid json {{{"


# ---- helpers: hostname/platform --------------------------------------


def test_resolve_hostname_uses_explicit_env_var():
    assert resolve_hostname({"AGENT_HOSTNAME": "explicit-host"}) == "explicit-host"


def test_resolve_hostname_strips_whitespace_in_explicit():
    assert resolve_hostname({"AGENT_HOSTNAME": "  trimmed  "}) == "trimmed"


def test_resolve_hostname_falls_through_blank_explicit(monkeypatch):
    monkeypatch.setattr("socket.gethostname", lambda: "real-host")
    assert resolve_hostname({"AGENT_HOSTNAME": "   "}) == "real-host"


def test_resolve_hostname_uses_socket_gethostname(monkeypatch):
    monkeypatch.setattr("socket.gethostname", lambda: "container-1234")
    assert resolve_hostname({}) == "container-1234"


def test_resolve_hostname_falls_back_when_localhost(monkeypatch):
    """Common in misconfigured Docker containers. Fallback uses the last
    8 chars of the agent_id verbatim — for standard UUID v4 format that
    yields a clean hex fragment from the final group."""
    monkeypatch.setattr("socket.gethostname", lambda: "localhost")
    out = resolve_hostname({}, agent_id="a8f3d12e-7b4c-4d8a-9e1f-2c5b6a7d8e9f")
    assert out == "certwatch-6a7d8e9f"


def test_resolve_hostname_falls_back_when_empty_string(monkeypatch):
    monkeypatch.setattr("socket.gethostname", lambda: "")
    out = resolve_hostname({}, agent_id="b1c2d3e4-5f6a-7b8c-9d0e-1f2a3b4c5d6e")
    assert out == "certwatch-3b4c5d6e"


def test_resolve_hostname_synthesizes_when_no_agent_id(monkeypatch):
    """First-time register: no agent_id available, hostname is meaningless.
    Fallback synthesizes a stable-per-process token."""
    monkeypatch.setattr("socket.gethostname", lambda: "localhost")
    out = resolve_hostname({})
    assert out.startswith("certwatch-")
    assert len(out) == len("certwatch-") + 8


def test_resolve_platform_returns_docker_convention_format(monkeypatch):
    monkeypatch.setattr("certwatch.bootstrap.platform_mod.system", lambda: "Linux")
    monkeypatch.setattr("certwatch.bootstrap.platform_mod.machine", lambda: "x86_64")
    assert resolve_platform() == "linux/amd64"


def test_resolve_platform_maps_arch_aliases(monkeypatch):
    monkeypatch.setattr("certwatch.bootstrap.platform_mod.system", lambda: "Linux")
    monkeypatch.setattr("certwatch.bootstrap.platform_mod.machine", lambda: "aarch64")
    assert resolve_platform() == "linux/arm64"


def test_resolve_platform_returns_none_when_unknown(monkeypatch):
    monkeypatch.setattr("certwatch.bootstrap.platform_mod.system", lambda: "")
    monkeypatch.setattr("certwatch.bootstrap.platform_mod.machine", lambda: "")
    assert resolve_platform() is None


def test_resolve_platform_passes_through_unknown_machine(monkeypatch):
    """Architecture names we don't have in the map should be passed
    through as-is rather than mangled or dropped."""
    monkeypatch.setattr("certwatch.bootstrap.platform_mod.system", lambda: "Linux")
    monkeypatch.setattr("certwatch.bootstrap.platform_mod.machine", lambda: "riscv64")
    assert resolve_platform() == "linux/riscv64"


# ---- backoff helper ---------------------------------------------------


def test_backoff_delay_follows_schedule():
    assert _backoff_delay(0) == 5.0
    assert _backoff_delay(1) == 15.0
    assert _backoff_delay(2) == 30.0
    assert _backoff_delay(3) == 60.0
    assert _backoff_delay(4) == 120.0


def test_backoff_delay_caps_at_last_value():
    assert _backoff_delay(5) == 120.0
    assert _backoff_delay(50) == 120.0
    assert _backoff_delay(1000) == 120.0


def test_backoff_schedule_matches_contract():
    """Defensive against accidental edits to BACKOFF_SCHEDULE: the
    user-facing contract specifies these exact values."""
    assert BACKOFF_SCHEDULE == (5.0, 15.0, 30.0, 60.0, 120.0)
