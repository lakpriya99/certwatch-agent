"""Phase 4b — agent_state persistence tests.

Filesystem-only; no network. Tests run in tmp_path so they don't touch the
real /data volume.
"""

from __future__ import annotations

import json
import os
import stat

import pytest

import certwatch.agent_state as agent_state
from certwatch.agent_state import (
    CredentialsCorruptError,
    load_credentials,
    save_credentials,
)


# ---- save_credentials -------------------------------------------------


def test_save_credentials_writes_all_fields(tmp_path):
    p = tmp_path / "agent.json"
    save_credentials(
        p,
        agent_id="a8f3d12e-7b4c-4d8a-9e1f-2c5b6a7d8e9f",
        agent_secret="agtkey_test",
        dashboard_url="https://certwatch.lovable.app",
        registered_at="2026-05-02T14:30:01Z",
    )
    data = json.loads(p.read_text())
    assert data == {
        "agent_id": "a8f3d12e-7b4c-4d8a-9e1f-2c5b6a7d8e9f",
        "agent_secret": "agtkey_test",
        "dashboard_url": "https://certwatch.lovable.app",
        "registered_at": "2026-05-02T14:30:01Z",
    }


def test_save_credentials_sets_mode_0600(tmp_path):
    p = tmp_path / "agent.json"
    save_credentials(p, "id", "sec", "url", "ts")
    mode = stat.S_IMODE(os.stat(p).st_mode)
    assert mode == 0o600, f"expected 0o600, got {oct(mode)}"


def test_save_credentials_creates_parent_dirs(tmp_path):
    p = tmp_path / "nested" / "deep" / "agent.json"
    assert not p.parent.exists()
    save_credentials(p, "id", "sec", "url", "ts")
    assert p.exists()


def test_save_credentials_overwrites_existing_file(tmp_path):
    p = tmp_path / "agent.json"
    save_credentials(p, "old-id", "old-sec", "url", "ts1")
    save_credentials(p, "new-id", "new-sec", "url", "ts2")
    data = json.loads(p.read_text())
    assert data["agent_id"] == "new-id"
    assert data["agent_secret"] == "new-sec"


def test_save_credentials_atomic_on_write_failure(tmp_path, monkeypatch):
    """If json.dump fails partway through, the original file must remain
    intact and no .tmp file should be left behind."""
    p = tmp_path / "agent.json"
    p.write_text('{"agent_id": "ORIGINAL"}')

    def failing_dump(payload, f, **kw):
        # Write a partial fragment then fail — simulates disk full or
        # encoder error after some bytes have been emitted.
        f.write('{"partial":')
        f.flush()
        raise RuntimeError("disk full")

    monkeypatch.setattr(agent_state.json, "dump", failing_dump)

    with pytest.raises(RuntimeError, match="disk full"):
        save_credentials(p, "new-id", "new-sec", "url", "ts")

    # Original file untouched (rename never happened)
    assert p.read_text() == '{"agent_id": "ORIGINAL"}'
    # No stale .tmp left over
    assert not (tmp_path / "agent.json.tmp").exists()


def test_save_credentials_uses_tmp_then_rename(tmp_path, monkeypatch):
    """Verify the atomic-write strategy: tmp file appears before rename,
    final file is the rename target."""
    p = tmp_path / "agent.json"
    seen_paths: list[str] = []

    real_replace = os.replace

    def spy_replace(src, dst):
        # Capture what was renamed where.
        seen_paths.append(("replace", str(src), str(dst)))
        real_replace(src, dst)

    monkeypatch.setattr(agent_state.os, "replace", spy_replace)
    save_credentials(p, "id", "sec", "url", "ts")
    assert seen_paths == [("replace", str(tmp_path / "agent.json.tmp"), str(p))]


# ---- load_credentials -------------------------------------------------


def test_load_credentials_returns_none_when_file_missing(tmp_path):
    p = tmp_path / "nope.json"
    assert load_credentials(p) is None


def test_load_credentials_returns_dict_when_file_present(tmp_path):
    p = tmp_path / "agent.json"
    p.write_text(json.dumps({"agent_id": "x", "agent_secret": "y", "dashboard_url": "u", "registered_at": "t"}))
    data = load_credentials(p)
    assert data == {"agent_id": "x", "agent_secret": "y", "dashboard_url": "u", "registered_at": "t"}


def test_load_credentials_raises_on_invalid_json(tmp_path):
    p = tmp_path / "agent.json"
    p.write_text("this is not { valid json")
    with pytest.raises(CredentialsCorruptError):
        load_credentials(p)


def test_load_credentials_raises_on_non_object_root(tmp_path):
    p = tmp_path / "agent.json"
    p.write_text('["unexpected", "list"]')
    with pytest.raises(CredentialsCorruptError, match="root is list"):
        load_credentials(p)


def test_load_credentials_raises_on_empty_file(tmp_path):
    p = tmp_path / "agent.json"
    p.write_text("")
    with pytest.raises(CredentialsCorruptError):
        load_credentials(p)


# ---- round-trip -------------------------------------------------------


def test_save_load_round_trip_preserves_all_fields(tmp_path):
    p = tmp_path / "agent.json"
    save_credentials(
        p,
        agent_id="a8f3d12e-7b4c-4d8a-9e1f-2c5b6a7d8e9f",
        agent_secret="agtkey_long_random_string_xyz",
        dashboard_url="https://certwatch.lovable.app",
        registered_at="2026-05-02T14:30:01Z",
    )
    loaded = load_credentials(p)
    assert loaded == {
        "agent_id": "a8f3d12e-7b4c-4d8a-9e1f-2c5b6a7d8e9f",
        "agent_secret": "agtkey_long_random_string_xyz",
        "dashboard_url": "https://certwatch.lovable.app",
        "registered_at": "2026-05-02T14:30:01Z",
    }


def test_load_after_save_when_path_is_string(tmp_path):
    # Both functions should accept str or Path interchangeably.
    p = str(tmp_path / "agent.json")
    save_credentials(p, "id", "sec", "url", "ts")
    assert load_credentials(p)["agent_id"] == "id"
