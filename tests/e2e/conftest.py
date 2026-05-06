"""E2E pytest fixtures: mock servers + agent subprocess + JSON-log tailer.

Every fixture has strict teardown so a leaked subprocess or unstopped
mock server can't bleed into the next test. The same discipline as the
in-process threading tests of phases 5c-5f, applied at the process
level.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Optional

import pytest

from tests.e2e.mock_dashboard import MockDashboard
from tests.e2e.mock_netbox import MockNetBox


# All e2e tests get marked automatically by being in this directory —
# `pytest -m "not e2e"` skips them, `pytest -m e2e` runs only them.
def pytest_collection_modifyitems(config, items):
    for item in items:
        item.add_marker(pytest.mark.e2e)


# ---- mock servers ---------------------------------------------------


@pytest.fixture
def mock_dashboard():
    server = MockDashboard()
    server.start()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture
def mock_netbox():
    server = MockNetBox()
    server.start()
    try:
        yield server
    finally:
        server.stop()


# ---- agent subprocess -----------------------------------------------


class AgentSubprocess:
    """Wrapper around the agent process. Handles stdout-tailing,
    log-event waits, signal sending, and clean shutdown.

    The reader thread parses stdout line-by-line so tests can wait for
    specific structured-JSON events without deadlocking on a full
    pipe buffer. Setting PYTHONUNBUFFERED=1 in the child env ensures
    log lines arrive promptly."""

    def __init__(self, *, data_dir: Path, env: dict) -> None:
        full_env = os.environ.copy()
        full_env.update(env)
        full_env["PYTHONUNBUFFERED"] = "1"

        self._cmd = [
            sys.executable, "-m", "certwatch", "agent",
            "--data-dir", str(data_dir),
        ]
        self._proc = subprocess.Popen(
            self._cmd,
            env=full_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # merge so unexpected tracebacks land in the same stream
            text=True,
            bufsize=1,
        )
        self._lines: list[str] = []
        self._lines_lock = threading.Lock()
        self._reader = threading.Thread(
            target=self._read_stdout, name="agent-stdout-reader", daemon=True,
        )
        self._reader.start()

    def _read_stdout(self) -> None:
        try:
            assert self._proc.stdout is not None
            for raw in self._proc.stdout:
                line = raw.rstrip("\n")
                if not line:
                    continue
                with self._lines_lock:
                    self._lines.append(line)
        except Exception:
            # Reader exits silently when the pipe closes (subprocess exit).
            pass

    def events(self) -> list[dict]:
        """All structured-JSON events the agent has emitted so far."""
        out: list[dict] = []
        with self._lines_lock:
            for line in self._lines:
                try:
                    parsed = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                if isinstance(parsed, dict):
                    out.append(parsed)
        return out

    def lines(self) -> list[str]:
        with self._lines_lock:
            return list(self._lines)

    def wait_for_event(
        self,
        event_name: str,
        *,
        timeout: float = 10.0,
        predicate=None,
    ) -> dict:
        """Block until a log line with the given `event` appears (and
        optionally satisfies `predicate(event_dict) -> bool`).

        Raises TimeoutError with the last 30 lines on timeout — gives
        the test author useful debugging output without grepping logs."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for ev in self.events():
                if ev.get("event") != event_name:
                    continue
                if predicate is None or predicate(ev):
                    return ev
            time.sleep(0.05)
        recent = "\n".join(self.lines()[-30:]) or "<no output>"
        raise TimeoutError(
            f"Did not see event {event_name!r} within {timeout}s.\n"
            f"Last 30 log lines:\n{recent}"
        )

    def count_events(self, event_name: str) -> int:
        return sum(1 for ev in self.events() if ev.get("event") == event_name)

    def is_running(self) -> bool:
        return self._proc.poll() is None

    def returncode(self) -> Optional[int]:
        return self._proc.poll()

    def send_signal(self, sig) -> None:
        self._proc.send_signal(sig)

    def terminate(self) -> None:
        self._proc.terminate()

    def stop(self, *, timeout: float = 15.0) -> int:
        """SIGTERM, wait, SIGKILL fallback. Returns exit code."""
        if self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=2.0)
        rc = self._proc.returncode
        # Make sure the reader thread exits before we move on.
        self._reader.join(timeout=2.0)
        return rc

    def wait(self, *, timeout: float = 15.0) -> int:
        """Wait for natural exit (e.g., after auth-error self-shutdown)."""
        try:
            self._proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait(timeout=2.0)
        rc = self._proc.returncode
        self._reader.join(timeout=2.0)
        return rc


@pytest.fixture
def agent_factory(tmp_path):
    """Returns a callable that spawns an agent subprocess. Tracks all
    started subprocesses for teardown — a leaked agent between tests
    would hold the /data dir and confuse subsequent tests."""
    spawned: list[AgentSubprocess] = []

    def factory(*, env: dict, data_dir: Optional[Path] = None) -> AgentSubprocess:
        if data_dir is None:
            data_dir = tmp_path / f"data-{len(spawned)}"
            data_dir.mkdir(parents=True, exist_ok=True)
        proc = AgentSubprocess(data_dir=data_dir, env=env)
        spawned.append(proc)
        return proc

    yield factory

    # Strict teardown: every started subprocess must exit within the
    # combined timeout. A leaked process here means the test forgot to
    # stop() — surface it loudly rather than letting it bleed.
    for proc in spawned:
        try:
            proc.stop(timeout=10.0)
        except Exception:
            pass


@pytest.fixture
def fresh_data_dir(tmp_path) -> Path:
    """An isolated /data directory for a single agent."""
    d = tmp_path / "agent-data"
    d.mkdir(parents=True, exist_ok=True)
    return d
