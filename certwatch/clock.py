"""Clock abstraction for the runner.

Used wherever the runner waits — backoff loops, heartbeat cadence, check
loop cadence, action expiration. Production uses `RealClock` which wraps
`time.monotonic()` and `time.sleep()`. Tests inject `FakeClock` to control
time deterministically without actually sleeping.

`now()` returns monotonic seconds (a float that only increases, immune to
NTP wall-clock jumps). For wall-clock ISO timestamps to send to the
dashboard, use `utc_now_iso()` separately — the two concerns are
deliberately split.
"""

from __future__ import annotations

import datetime as dt
import time
import threading
from typing import Protocol


class Clock(Protocol):
    """Monotonic clock + sleep, for code that needs to wait and be testable."""

    def now(self) -> float: ...
    def sleep(self, seconds: float) -> None: ...
    def wait_for(self, seconds: float, event: threading.Event) -> bool:
        """Sleep up to `seconds`, waking early if `event` becomes set.

        Returns True if the event was set (already-set or set-during),
        False if the timeout elapsed normally. Used by retry loops and
        backoff sleeps that need to abort fast on shutdown.
        """
        ...


class RealClock:
    def now(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        if seconds > 0:
            time.sleep(seconds)

    def wait_for(self, seconds: float, event: threading.Event) -> bool:
        # threading.Event.wait returns True if the event was set during
        # (or before) the wait, False on timeout. Negative timeouts behave
        # the same as 0 (an immediate is_set() check).
        return event.wait(timeout=max(0.0, seconds))


class FakeClock:
    """Test double: sleep advances time without waiting; records every call.

    `advance(seconds)` lets tests jump time forward without going through
    sleep — useful for "20 minutes passed in the background while we did
    other things" scenarios. Thread-safe so it can be shared between the
    runner threads and the test thread that's controlling time.

    `wait_for` checks the event WITHOUT actually waiting — tests should
    set the event before calling wait_for if they want to simulate
    "shutdown arrived during this sleep."
    """

    def __init__(self, start: float = 0.0) -> None:
        self._t = start
        self._lock = threading.Lock()
        self.sleeps: list[float] = []

    def now(self) -> float:
        with self._lock:
            return self._t

    def sleep(self, seconds: float) -> None:
        with self._lock:
            if seconds > 0:
                self._t += seconds
            self.sleeps.append(seconds)

    def wait_for(self, seconds: float, event: threading.Event) -> bool:
        # Record the sleep regardless of outcome. Time advances only when
        # the event is NOT already set (mirroring real clock semantics:
        # an already-set event short-circuits before any waiting happens).
        with self._lock:
            self.sleeps.append(seconds)
            if event.is_set():
                return True
            if seconds > 0:
                self._t += seconds
            return False

    def advance(self, seconds: float) -> None:
        with self._lock:
            self._t += seconds


def utc_now_iso() -> str:
    """Wall-clock UTC timestamp in ISO 8601 with explicit Z suffix.

    Separate from Clock.now() because the two answer different questions:
    Clock.now() is "how much time has passed in this process" (monotonic);
    this function is "what's the current wall-clock time" (UTC). NTP
    adjustments move wall clock; they should not move the runner's
    backoff sleeps."""
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
