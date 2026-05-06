"""Phase 3 tests — check loop orchestration. cert_check is mocked so these
run offline in milliseconds."""

from __future__ import annotations

import threading
import time

import pytest

from certwatch.cert_check import CertResult
from certwatch.check_loop import (
    StopSignal,
    _result_log_payload,
    _summary_counts,
    run_cycle,
    run_loop,
)
from certwatch.config import AgentConfig, HostConfig


def _stub_result(hostname, port, **_kw):
    return CertResult(
        state="success",
        hostname=hostname,
        port=port,
        checked_at="2026-05-05T12:00:00Z",
    )


def _config_with(hosts, **overrides) -> AgentConfig:
    return AgentConfig(
        hosts=tuple(hosts),
        sweep_interval_seconds=overrides.get("sweep_interval_seconds", 3600),
        max_concurrency=overrides.get("max_concurrency", 20),
        log_level=overrides.get("log_level", "INFO"),
        tcp_connect_seconds=overrides.get("tcp_connect_seconds", 5.0),
        tls_handshake_seconds=overrides.get("tls_handshake_seconds", 5.0),
    )


def test_run_cycle_runs_all_hosts():
    config = _config_with(
        [HostConfig(f"h{i}.example.com") for i in range(5)], max_concurrency=3
    )
    results = run_cycle(config, check_fn=_stub_result)
    assert len(results) == 5
    assert {r.hostname for r in results} == {f"h{i}.example.com" for i in range(5)}


def test_run_cycle_passes_timeouts_to_check_fn():
    seen = {}

    def capture(host, port, *, connect_timeout, handshake_timeout):
        seen["connect"] = connect_timeout
        seen["handshake"] = handshake_timeout
        return _stub_result(host, port)

    config = _config_with(
        [HostConfig("h.example.com")],
        tcp_connect_seconds=2.5,
        tls_handshake_seconds=3.5,
    )
    run_cycle(config, check_fn=capture)
    assert seen == {"connect": 2.5, "handshake": 3.5}


def test_run_cycle_respects_concurrency_cap():
    in_flight = 0
    max_seen = 0
    lock = threading.Lock()

    def slow(host, port, **_kw):
        nonlocal in_flight, max_seen
        with lock:
            in_flight += 1
            max_seen = max(max_seen, in_flight)
        time.sleep(0.05)
        with lock:
            in_flight -= 1
        return _stub_result(host, port)

    config = _config_with(
        [HostConfig(f"h{i}") for i in range(10)], max_concurrency=3
    )
    run_cycle(config, check_fn=slow)
    assert max_seen <= 3


def test_run_cycle_skips_new_checks_when_stopped():
    started = 0
    lock = threading.Lock()

    def counting(host, port, **_kw):
        nonlocal started
        with lock:
            started += 1
        time.sleep(0.05)
        return _stub_result(host, port)

    config = _config_with(
        [HostConfig(f"h{i}") for i in range(20)], max_concurrency=2
    )
    stop = StopSignal()

    def trigger():
        time.sleep(0.02)  # let the first 2 worker threads pick up tasks
        stop.request_stop()

    threading.Thread(target=trigger, daemon=True).start()
    results = run_cycle(config, check_fn=counting, stop=stop)

    # The 2 in-flight checks finish; the rest short-circuit. Race-window
    # tolerance: a worker may have grabbed a third task between our stop
    # check and the actual cert_check call. Bound it loosely.
    assert started < 20, "should not start all checks after stop"
    assert started >= 2, "in-flight checks should still complete"
    assert len(results) == started


def test_run_cycle_handles_unhandled_exception_from_check_fn(caplog):
    def boom(host, port, **_kw):
        if host == "bad":
            raise RuntimeError("kaboom")
        return _stub_result(host, port)

    config = _config_with(
        [HostConfig("bad"), HostConfig("good"), HostConfig("good2")]
    )
    with caplog.at_level("ERROR"):
        results = run_cycle(config, check_fn=boom)
    assert {r.hostname for r in results} == {"good", "good2"}
    error_records = [
        r for r in caplog.records
        if isinstance(r.msg, dict) and r.msg.get("event") == "cert_check_unhandled_error"
    ]
    assert len(error_records) == 1
    assert error_records[0].msg["hostname"] == "bad"


def test_run_cycle_logs_summary(caplog):
    def mixed(host, port, **_kw):
        state = {"ok1": "success", "ok2": "success", "down": "connection_failed", "bad-cert": "tls_failed"}[host]
        return CertResult(state=state, hostname=host, port=port, checked_at="2026-05-05T12:00:00Z")

    config = _config_with([HostConfig(h) for h in ("ok1", "ok2", "down", "bad-cert")])
    with caplog.at_level("INFO"):
        run_cycle(config, check_fn=mixed)

    summaries = [
        r.msg for r in caplog.records
        if isinstance(r.msg, dict) and r.msg.get("event") == "cycle_summary"
    ]
    assert len(summaries) == 1
    s = summaries[0]
    assert s["total"] == 4
    assert s["success"] == 2
    assert s["connection_failed"] == 1
    assert s["tls_failed"] == 1
    assert isinstance(s["duration_seconds"], float)


def test_run_loop_exits_promptly_on_stop():
    config = _config_with(
        [HostConfig("h.example.com")], sweep_interval_seconds=3600
    )
    stop = StopSignal()

    def trigger():
        time.sleep(0.05)
        stop.request_stop()

    threading.Thread(target=trigger, daemon=True).start()
    started = time.monotonic()
    run_loop(config, check_fn=_stub_result, stop=stop)
    elapsed = time.monotonic() - started
    # Must exit well before the configured 1-hour interval.
    assert elapsed < 2.0


def test_stop_signal_wait_returns_true_when_set():
    s = StopSignal()
    s.request_stop()
    assert s.wait(0.1) is True


def test_stop_signal_wait_returns_false_on_timeout():
    s = StopSignal()
    started = time.monotonic()
    assert s.wait(0.05) is False
    assert time.monotonic() - started >= 0.04


def test_summary_counts_helper():
    rs = [
        CertResult(state="success", hostname="a", port=443, checked_at=""),
        CertResult(state="success", hostname="b", port=443, checked_at=""),
        CertResult(state="connection_failed", hostname="c", port=443, checked_at=""),
        CertResult(state="tls_failed", hostname="d", port=443, checked_at=""),
        CertResult(state="tls_failed", hostname="e", port=443, checked_at=""),
    ]
    assert _summary_counts(rs) == {
        "success": 2, "connection_failed": 1, "tls_failed": 2,
    }


def test_result_log_payload_includes_display_name_and_tags():
    host = HostConfig("h.example.com", display_name="Hello", tags=("a", "b"))
    r = CertResult(state="success", hostname="h.example.com", port=443, checked_at="2026-05-05T12:00:00Z")
    p = _result_log_payload(r, host, include_sans=True)
    assert p["event"] == "cert_check_result"
    assert p["display_name"] == "Hello"
    assert p["tags"] == ["a", "b"]
    assert p["state"] == "success"
    assert p["hostname"] == "h.example.com"


def test_result_log_payload_falls_back_to_hostname_for_display():
    host = HostConfig("h.example.com")
    r = CertResult(state="success", hostname="h.example.com", port=443, checked_at="")
    p = _result_log_payload(r, host, include_sans=True)
    assert p["display_name"] == "h.example.com"


def test_result_log_payload_omits_san_array_at_info():
    host = HostConfig("h.example.com")
    r = CertResult(
        state="success", hostname="h.example.com", port=443, checked_at="",
        subject_sans=["a.example.com", "b.example.com", "c.example.com"],
    )
    p = _result_log_payload(r, host, include_sans=False)
    assert p["subject_san_count"] == 3
    assert "subject_sans" not in p


def test_result_log_payload_includes_san_array_at_debug():
    host = HostConfig("h.example.com")
    r = CertResult(
        state="success", hostname="h.example.com", port=443, checked_at="",
        subject_sans=["a.example.com", "b.example.com"],
    )
    p = _result_log_payload(r, host, include_sans=True)
    assert p["subject_san_count"] == 2
    assert p["subject_sans"] == ["a.example.com", "b.example.com"]


def test_result_log_payload_san_count_for_empty_sans():
    host = HostConfig("h.example.com")
    r = CertResult(state="connection_failed", hostname="h.example.com", port=443, checked_at="")
    p = _result_log_payload(r, host, include_sans=False)
    assert p["subject_san_count"] == 0
    assert "subject_sans" not in p
