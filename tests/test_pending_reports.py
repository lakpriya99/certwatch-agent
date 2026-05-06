"""Phase 5b — pending_reports persistence tests. Filesystem only; no network."""

from __future__ import annotations

import json
import os
import stat
import time

import pytest

import certwatch.pending_reports as pr
from certwatch.pending_reports import (
    PendingReportCorruptError,
    cleanup_stray_tmp_files,
    delete_pending_report,
    increment_attempts,
    list_pending_report_paths,
    load_pending_report,
    pending_dir,
    quarantine_corrupt,
    save_pending_report,
    wire_payload,
)


def _wire(**overrides) -> dict:
    base = {
        "report_id": "abc-123",
        "report_type": "scheduled",
        "started_at": "2026-05-02T15:00:00Z",
        "completed_at": "2026-05-02T15:01:42Z",
        "action_id": None,
        "checks": [],
    }
    base.update(overrides)
    return base


# ---- save_pending_report ---------------------------------------------


def test_save_pending_report_writes_wire_fields_plus_metadata(tmp_path):
    path = save_pending_report(tmp_path, "abc-123", _wire())
    data = json.loads(path.read_text())
    # Wire fields preserved
    for key in ("report_id", "report_type", "started_at", "completed_at",
                "action_id", "checks"):
        assert key in data
    # Agent-side metadata added
    assert data["_persisted_at"].endswith("Z")
    assert data["_attempts"] == 0


def test_save_pending_report_does_not_mutate_caller_dict(tmp_path):
    """The caller passes the wire payload; this fn shouldn't smuggle
    metadata into it (which would later bleed into a real
    submit_report call if the caller reused the dict)."""
    payload = _wire()
    save_pending_report(tmp_path, "abc-123", payload)
    assert "_persisted_at" not in payload
    assert "_attempts" not in payload


def test_save_pending_report_creates_dir_if_missing(tmp_path):
    """A fresh /data has no pending_reports/. First save creates it."""
    pdir = pending_dir(tmp_path)
    assert not pdir.exists()
    save_pending_report(tmp_path, "abc", _wire())
    assert pdir.is_dir()


def test_save_pending_report_creates_dir_with_owner_only_perms(tmp_path):
    save_pending_report(tmp_path, "abc", _wire())
    pdir = pending_dir(tmp_path)
    mode = stat.S_IMODE(os.stat(pdir).st_mode)
    # On systems with permissive umask we asked for 0700 explicitly.
    # Allow any subset (Linux test envs may have masked further).
    assert mode & 0o077 == 0  # group/other bits clear


def test_save_pending_report_file_mode_is_0600(tmp_path):
    path = save_pending_report(tmp_path, "abc", _wire())
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600


def test_save_pending_report_overwrites_existing_file(tmp_path):
    p1 = save_pending_report(tmp_path, "abc", _wire(report_type="scheduled"))
    p2 = save_pending_report(tmp_path, "abc", _wire(report_type="on_demand"))
    assert p1 == p2
    data = json.loads(p2.read_text())
    assert data["report_type"] == "on_demand"
    assert data["_attempts"] == 0  # reset (it's a fresh save)


def test_save_pending_report_atomic_on_write_failure(tmp_path, monkeypatch):
    """Inject failure during json.dump; the original file (if any) must
    survive intact and no .tmp file may linger."""
    # Pre-create an "original" file that must not be corrupted by the failure.
    p = save_pending_report(tmp_path, "abc", _wire(report_type="scheduled"))
    original_bytes = p.read_text()

    def failing_dump(payload, f, **kw):
        f.write('{"partial":')  # write something, then fail
        f.flush()
        raise OSError("disk full")

    monkeypatch.setattr(pr.json, "dump", failing_dump)

    with pytest.raises(OSError, match="disk full"):
        save_pending_report(tmp_path, "abc", _wire(report_type="on_demand"))

    # Original survives
    assert p.read_text() == original_bytes
    # No stray .tmp left over
    assert not (pending_dir(tmp_path) / "abc.json.tmp").exists()


# ---- load_pending_report ---------------------------------------------


def test_load_pending_report_round_trip(tmp_path):
    p = save_pending_report(tmp_path, "abc", _wire(report_type="startup"))
    data = load_pending_report(p)
    assert data["report_id"] == "abc-123"  # from _wire default
    assert data["report_type"] == "startup"
    assert data["_attempts"] == 0


def test_load_pending_report_raises_on_invalid_json(tmp_path):
    pdir = pending_dir(tmp_path)
    pdir.mkdir()
    p = pdir / "bad.json"
    p.write_text("not { valid json")
    with pytest.raises(PendingReportCorruptError):
        load_pending_report(p)


def test_load_pending_report_raises_on_non_object_root(tmp_path):
    pdir = pending_dir(tmp_path)
    pdir.mkdir()
    p = pdir / "list.json"
    p.write_text('["a", "b"]')
    with pytest.raises(PendingReportCorruptError, match="root is list"):
        load_pending_report(p)


def test_load_pending_report_raises_on_empty_file(tmp_path):
    pdir = pending_dir(tmp_path)
    pdir.mkdir()
    p = pdir / "empty.json"
    p.write_text("")
    with pytest.raises(PendingReportCorruptError):
        load_pending_report(p)


# ---- increment_attempts ----------------------------------------------


def test_increment_attempts_returns_new_value(tmp_path):
    p = save_pending_report(tmp_path, "abc", _wire())
    assert increment_attempts(p) == 1
    assert increment_attempts(p) == 2
    assert increment_attempts(p) == 3


def test_increment_attempts_persisted_to_disk(tmp_path):
    """Counter must be observable from disk after each increment so a
    crash mid-loop leaves accurate state for restart-replay."""
    p = save_pending_report(tmp_path, "abc", _wire())
    increment_attempts(p)
    increment_attempts(p)
    data = json.loads(p.read_text())
    assert data["_attempts"] == 2


def test_increment_attempts_preserves_other_fields(tmp_path):
    p = save_pending_report(tmp_path, "abc", _wire(report_type="on_demand"))
    increment_attempts(p)
    data = load_pending_report(p)
    assert data["report_type"] == "on_demand"
    assert data["_persisted_at"].endswith("Z")


# ---- delete_pending_report --------------------------------------------


def test_delete_pending_report_removes_file(tmp_path):
    p = save_pending_report(tmp_path, "abc", _wire())
    assert p.exists()
    delete_pending_report(p)
    assert not p.exists()


def test_delete_pending_report_is_idempotent(tmp_path):
    """Concurrent or already-removed file must not raise — postcondition
    is 'file does not exist', which is already true."""
    p = pending_dir(tmp_path) / "nonexistent.json"
    assert not p.exists()
    delete_pending_report(p)  # no exception
    delete_pending_report(p)  # still no exception


# ---- list_pending_report_paths ---------------------------------------


def test_list_pending_returns_empty_for_missing_dir(tmp_path):
    """Fresh agent has no pending_reports/ — return [] cleanly without
    'if exists' branches scattered around the caller (matches the
    DEFAULT_CONFIG.config_version=0 trick: pick a value that naturally
    forces the right behavior on first interaction)."""
    assert list_pending_report_paths(tmp_path) == []


def test_list_pending_returns_empty_for_empty_dir(tmp_path):
    pending_dir(tmp_path).mkdir()
    assert list_pending_report_paths(tmp_path) == []


def test_list_pending_sorts_by_mtime_ascending(tmp_path):
    p1 = save_pending_report(tmp_path, "first", _wire(report_id="first"))
    time.sleep(0.02)
    p2 = save_pending_report(tmp_path, "second", _wire(report_id="second"))
    time.sleep(0.02)
    p3 = save_pending_report(tmp_path, "third", _wire(report_id="third"))

    # Touch first to bump its mtime — it should come last now.
    later = time.time() + 1
    os.utime(p1, (later, later))

    paths = list_pending_report_paths(tmp_path)
    names = [p.name for p in paths]
    assert names == ["second.json", "third.json", "first.json"]


def test_list_pending_skips_tmp_files(tmp_path):
    save_pending_report(tmp_path, "real", _wire())
    # A leftover .tmp from a crashed write
    (pending_dir(tmp_path) / "stray.json.tmp").write_text("partial junk")
    paths = list_pending_report_paths(tmp_path)
    assert [p.name for p in paths] == ["real.json"]


def test_list_pending_skips_subdirs(tmp_path):
    """The corrupt/ subdir holds quarantined files; replay must not
    pick them up as pending."""
    save_pending_report(tmp_path, "real", _wire())
    (pending_dir(tmp_path) / "corrupt").mkdir()
    (pending_dir(tmp_path) / "corrupt" / "old.json").write_text("{}")
    paths = list_pending_report_paths(tmp_path)
    assert [p.name for p in paths] == ["real.json"]


# ---- cleanup_stray_tmp_files -----------------------------------------


def test_cleanup_stray_tmp_returns_empty_when_dir_missing(tmp_path):
    """Same 'natural empty' principle as list_pending."""
    assert cleanup_stray_tmp_files(tmp_path) == []


def test_cleanup_stray_tmp_deletes_tmp_files(tmp_path):
    pending_dir(tmp_path).mkdir()
    p = pending_dir(tmp_path) / "stray.json.tmp"
    p.write_text("partial")
    deleted = cleanup_stray_tmp_files(tmp_path)
    assert deleted == [p]
    assert not p.exists()


def test_cleanup_stray_tmp_leaves_real_files_untouched(tmp_path):
    real = save_pending_report(tmp_path, "real", _wire())
    (pending_dir(tmp_path) / "stray.json.tmp").write_text("partial")
    cleanup_stray_tmp_files(tmp_path)
    assert real.exists()


# ---- quarantine_corrupt ----------------------------------------------


def test_quarantine_corrupt_moves_file_preserving_contents(tmp_path):
    pdir = pending_dir(tmp_path)
    pdir.mkdir()
    src = pdir / "bad.json"
    bad_content = "this is not { valid json"
    src.write_text(bad_content)

    target = quarantine_corrupt(src, tmp_path)
    assert not src.exists()
    assert target.exists()
    # Contents preserved so operator can inspect
    assert target.read_text() == bad_content
    # Lives in pending_reports/corrupt/
    assert target.parent.name == "corrupt"
    assert target.parent.parent == pdir


def test_quarantine_corrupt_filename_includes_original(tmp_path):
    pdir = pending_dir(tmp_path)
    pdir.mkdir()
    src = pdir / "bad.json"
    src.write_text("garbage")
    target = quarantine_corrupt(src, tmp_path)
    assert "bad.json" in target.name


# ---- wire_payload ----------------------------------------------------


def test_wire_payload_strips_metadata(tmp_path):
    p = save_pending_report(tmp_path, "abc", _wire())
    increment_attempts(p)
    persisted = load_pending_report(p)
    wire = wire_payload(persisted)
    assert "_persisted_at" not in wire
    assert "_attempts" not in wire
    assert set(wire.keys()) == {
        "report_id", "report_type", "started_at",
        "completed_at", "action_id", "checks",
    }


def test_wire_payload_preserves_action_id_when_set():
    persisted = {
        "report_id": "abc",
        "report_type": "on_demand",
        "started_at": "t0",
        "completed_at": "t1",
        "action_id": "act-1",
        "checks": [],
        "_persisted_at": "ts",
        "_attempts": 3,
    }
    wire = wire_payload(persisted)
    assert wire["action_id"] == "act-1"


def test_wire_payload_handles_missing_optional_fields():
    """If a future record is missing a wire field for some reason, don't
    crash — let downstream submit_report's contract validation catch it
    rather than masking with a default here."""
    persisted = {"report_id": "abc", "_persisted_at": "ts", "_attempts": 0}
    wire = wire_payload(persisted)
    assert wire == {"report_id": "abc"}
