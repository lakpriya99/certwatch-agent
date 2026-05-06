"""Phase 5c — ConfigState unit tests."""

from __future__ import annotations

import threading

import pytest

from certwatch.heartbeat_thread import ConfigState


SAMPLE_CONFIG = {
    "config_version": 1,
    "intervals": {"heartbeat_seconds": 15, "check_seconds": 3600, "netbox_sync_seconds": 3600},
    "timeouts": {"tcp_connect_seconds": 5, "tls_handshake_seconds": 5},
    "concurrency": {"max_parallel_checks": 20},
    "alert_thresholds_days": [30, 7, 1],
    "manual_hosts": [],
}


def test_snapshot_returns_initial_config():
    state = ConfigState(initial=SAMPLE_CONFIG)
    assert state.snapshot() == SAMPLE_CONFIG


def test_snapshot_returns_same_object_until_replaced():
    """No deep copy on snapshot — readers get a reference. The dict is
    treated as immutable by convention; copying every snapshot is wasteful."""
    state = ConfigState(initial=SAMPLE_CONFIG)
    a = state.snapshot()
    b = state.snapshot()
    assert a is b


def test_replace_swaps_config_observably_via_snapshot():
    state = ConfigState(initial=SAMPLE_CONFIG)
    new_config = {**SAMPLE_CONFIG, "config_version": 2}
    state.replace(new_config)
    assert state.snapshot() == new_config
    assert state.snapshot()["config_version"] == 2


def test_replace_then_snapshot_returns_the_replacement_object():
    """Identity check: snapshot is the same object passed to replace."""
    state = ConfigState(initial=SAMPLE_CONFIG)
    new_config = {"config_version": 5}
    state.replace(new_config)
    assert state.snapshot() is new_config


def test_concurrent_reader_never_sees_partial_state():
    """Stress test: 1000 replaces in a writer thread, 1000 snapshots in a
    reader thread. The reader must always see one of the two valid
    configs (old or new), never None or a half-state."""
    config_a = {**SAMPLE_CONFIG, "config_version": 100}
    config_b = {**SAMPLE_CONFIG, "config_version": 200}
    state = ConfigState(initial=config_a)

    stop = threading.Event()
    bad_observations: list = []

    def writer():
        for i in range(1000):
            state.replace(config_a if i % 2 == 0 else config_b)
        stop.set()

    def reader():
        while not stop.is_set():
            snap = state.snapshot()
            if snap is None or "config_version" not in snap:
                bad_observations.append(snap)
                return
            if snap["config_version"] not in (100, 200):
                bad_observations.append(snap)
                return

    w = threading.Thread(target=writer, name="writer")
    r = threading.Thread(target=reader, name="reader")
    r.start()
    w.start()
    w.join(timeout=5.0)
    r.join(timeout=5.0)

    assert not w.is_alive(), "writer thread leaked"
    assert not r.is_alive(), "reader thread leaked"
    assert bad_observations == [], f"reader saw inconsistent state: {bad_observations}"
