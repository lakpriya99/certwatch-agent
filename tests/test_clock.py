"""Phase 5a — Clock protocol tests."""

from __future__ import annotations

import threading
import time

from certwatch.clock import FakeClock, RealClock, utc_now_iso


def test_real_clock_now_is_monotonic_nondecreasing():
    rc = RealClock()
    a = rc.now()
    b = rc.now()
    assert b >= a


def test_real_clock_sleep_does_actually_wait():
    rc = RealClock()
    started = rc.now()
    rc.sleep(0.05)
    assert rc.now() - started >= 0.04


def test_real_clock_sleep_zero_is_noop():
    """Don't pay the syscall on sleep(0); also don't crash on negative."""
    rc = RealClock()
    started = time.monotonic()
    rc.sleep(0)
    rc.sleep(-1.0)
    assert time.monotonic() - started < 0.01


# ---- FakeClock --------------------------------------------------------


def test_fake_clock_starts_at_zero_by_default():
    fc = FakeClock()
    assert fc.now() == 0.0


def test_fake_clock_starts_at_explicit_value():
    fc = FakeClock(start=100.0)
    assert fc.now() == 100.0


def test_fake_clock_sleep_advances_time_without_waiting():
    fc = FakeClock()
    started_real = time.monotonic()
    fc.sleep(60.0)
    fc.sleep(120.0)
    elapsed_real = time.monotonic() - started_real
    assert fc.now() == 180.0
    # Did NOT actually wait 3 minutes.
    assert elapsed_real < 0.1


def test_fake_clock_records_sleep_calls_in_order():
    fc = FakeClock()
    fc.sleep(5)
    fc.sleep(15)
    fc.sleep(30)
    assert fc.sleeps == [5, 15, 30]


def test_fake_clock_sleep_with_negative_records_but_does_not_advance():
    fc = FakeClock(start=10.0)
    fc.sleep(-1)
    assert fc.now() == 10.0
    assert fc.sleeps == [-1]


def test_fake_clock_advance_moves_time_without_recording_sleep():
    fc = FakeClock()
    fc.advance(50.0)
    assert fc.now() == 50.0
    assert fc.sleeps == []


# ---- utc_now_iso ------------------------------------------------------


# ---- wait_for --------------------------------------------------------


def test_real_clock_wait_for_returns_true_when_event_already_set():
    rc = RealClock()
    e = threading.Event()
    e.set()
    started = time.monotonic()
    assert rc.wait_for(60.0, e) is True
    # Returned immediately, didn't actually wait the timeout
    assert time.monotonic() - started < 0.05


def test_real_clock_wait_for_returns_false_on_timeout():
    rc = RealClock()
    e = threading.Event()  # never set
    started = time.monotonic()
    assert rc.wait_for(0.05, e) is False
    assert time.monotonic() - started >= 0.04


def test_real_clock_wait_for_negative_seconds_is_safe():
    """event.wait() doesn't accept negative timeouts. RealClock clamps."""
    rc = RealClock()
    e = threading.Event()
    e.set()
    assert rc.wait_for(-1.0, e) is True


def test_fake_clock_wait_for_returns_true_when_event_already_set():
    fc = FakeClock(start=100.0)
    e = threading.Event()
    e.set()
    assert fc.wait_for(60.0, e) is True
    # Time NOT advanced (real clock would have short-circuited too)
    assert fc.now() == 100.0
    # Sleep still recorded for test introspection
    assert fc.sleeps == [60.0]


def test_fake_clock_wait_for_returns_false_when_event_not_set():
    fc = FakeClock()
    e = threading.Event()
    assert fc.wait_for(60.0, e) is False
    # Time advanced (no early wake)
    assert fc.now() == 60.0
    assert fc.sleeps == [60.0]


def test_utc_now_iso_format():
    s = utc_now_iso()
    assert s.endswith("Z")
    assert "T" in s
    assert "+" not in s
    # YYYY-MM-DDTHH:MM:SSZ → 20 chars
    assert len(s) == 20
