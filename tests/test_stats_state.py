"""Phase 5c — StatsState unit tests."""

from __future__ import annotations

import threading

import pytest

from certwatch.clock import FakeClock
from certwatch.heartbeat_thread import StatsState


def test_snapshot_returns_none_when_no_cycles_recorded():
    """Sending an all-None stats dict is pointless noise; the contract
    treats `stats` as optional. None signals 'omit the field entirely'."""
    state = StatsState(clock=FakeClock())
    assert state.snapshot_for_heartbeat() is None


def test_snapshot_returns_only_check_cycle_fields():
    state = StatsState(clock=FakeClock())
    state.record_check_cycle(
        hosts_monitored=47,
        completed_at="2026-05-02T15:00:00Z",
        duration_seconds=102,
        succeeded=45,
        failed=2,
    )
    snap = state.snapshot_for_heartbeat()
    assert snap == {
        "hosts_monitored": 47,
        "last_check_completed_at": "2026-05-02T15:00:00Z",
        "last_check_duration_seconds": 102,
        "checks_succeeded_last_cycle": 45,
        "checks_failed_last_cycle": 2,
    }


def test_snapshot_returns_only_netbox_sync_field():
    state = StatsState(clock=FakeClock())
    state.record_netbox_sync(completed_at="2026-05-02T15:00:00Z")
    snap = state.snapshot_for_heartbeat()
    assert snap == {"last_netbox_sync_at": "2026-05-02T15:00:00Z"}


def test_snapshot_combines_all_recorded_fields():
    state = StatsState(clock=FakeClock())
    state.record_check_cycle(
        hosts_monitored=10, completed_at="t1", duration_seconds=50,
        succeeded=8, failed=2,
    )
    state.record_netbox_sync(completed_at="t2")
    snap = state.snapshot_for_heartbeat()
    assert snap == {
        "hosts_monitored": 10,
        "last_check_completed_at": "t1",
        "last_check_duration_seconds": 50,
        "checks_succeeded_last_cycle": 8,
        "checks_failed_last_cycle": 2,
        "last_netbox_sync_at": "t2",
    }


def test_record_check_cycle_overwrites_previous_values():
    """Each cycle replaces the last cycle's stats — the contract is 'last
    cycle' not 'cumulative'."""
    state = StatsState(clock=FakeClock())
    state.record_check_cycle(
        hosts_monitored=10, completed_at="t1", duration_seconds=50,
        succeeded=8, failed=2,
    )
    state.record_check_cycle(
        hosts_monitored=20, completed_at="t2", duration_seconds=80,
        succeeded=20, failed=0,
    )
    snap = state.snapshot_for_heartbeat()
    assert snap["hosts_monitored"] == 20
    assert snap["last_check_completed_at"] == "t2"
    assert snap["checks_succeeded_last_cycle"] == 20
    assert snap["checks_failed_last_cycle"] == 0


def test_snapshot_returns_a_copy_not_a_reference():
    """A slow heartbeat that holds the snapshot during JSON serialization
    must not block writers, AND mutating the returned dict must not
    pollute subsequent snapshots."""
    state = StatsState(clock=FakeClock())
    state.record_netbox_sync(completed_at="t1")
    snap = state.snapshot_for_heartbeat()
    snap["foo"] = "bar"
    snap["last_netbox_sync_at"] = "tampered"

    again = state.snapshot_for_heartbeat()
    assert "foo" not in again
    assert again["last_netbox_sync_at"] == "t1"


def test_concurrent_writers_and_reader_dont_crash():
    """Two writers + one reader churning. Property: reader either sees
    None (no recordings yet) or a valid dict, never crashes."""
    state = StatsState(clock=FakeClock())
    stop = threading.Event()
    bad_observations: list = []

    def cycle_writer():
        for i in range(500):
            state.record_check_cycle(
                hosts_monitored=i,
                completed_at=f"t{i}",
                duration_seconds=i * 2,
                succeeded=i,
                failed=0,
            )

    def netbox_writer():
        for i in range(500):
            state.record_netbox_sync(completed_at=f"nb{i}")

    def reader():
        while not stop.is_set():
            snap = state.snapshot_for_heartbeat()
            if snap is None:
                continue
            # Field types must always be valid
            for k, v in snap.items():
                if not isinstance(k, str):
                    bad_observations.append(("non-str key", k))
                    return

    threads = [
        threading.Thread(target=cycle_writer, name="cycle"),
        threading.Thread(target=netbox_writer, name="netbox"),
        threading.Thread(target=reader, name="reader"),
    ]
    for t in threads:
        t.start()

    threads[0].join(timeout=5.0)
    threads[1].join(timeout=5.0)
    stop.set()
    threads[2].join(timeout=5.0)

    for t in threads:
        assert not t.is_alive(), f"{t.name} leaked"
    assert bad_observations == []
