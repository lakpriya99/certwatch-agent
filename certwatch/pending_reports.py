"""Pending-report persistence — at-least-once delivery via on-disk queue.

Each pending report is an atomically-written JSON file at
`<data_dir>/pending_reports/<report_id>.json`. Files persist across crashes;
the runner replays them at startup before opening new submission paths.

Two underscore-prefixed metadata fields are agent-side only and must NOT
be sent to the dashboard:
  - `_persisted_at`: wall-clock ISO of first write (used for orphan detection)
  - `_attempts`: count of submit_report calls made for this report_id
                 (operator-debugging value: high counts mean dashboard
                 unreachable; bumped before each call so the on-disk
                 value reflects the work done even if the agent crashes
                 between attempts)

Same atomic-write pattern as `agent_state.save_credentials`: write to
`<file>.tmp`, fsync, `os.replace()` into place, chmod 0o600.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Optional

from certwatch.clock import utc_now_iso

PENDING_REPORTS_DIR_NAME = "pending_reports"
CORRUPT_SUBDIR_NAME = "corrupt"

# Wire-payload fields that get persisted alongside the agent-side metadata.
# Used by replay to reconstruct the submit_report call.
_WIRE_FIELDS = ("report_id", "report_type", "started_at", "completed_at",
                "action_id", "checks")


class PendingReportCorruptError(Exception):
    """Raised when a pending-report file exists but cannot be parsed.

    Quarantine, don't delete — the operator may want to inspect what was
    in flight when the agent crashed. Same fail-loud disposition as
    `CredentialsCorruptError` from Phase 4b.
    """


def pending_dir(data_dir: str | Path) -> Path:
    return Path(data_dir) / PENDING_REPORTS_DIR_NAME


def save_pending_report(
    data_dir: str | Path, report_id: str, payload: dict
) -> Path:
    """Atomically persist a fresh pending report.

    Adds `_persisted_at` and `_attempts=0` to the payload. Creates the
    pending_reports/ directory if missing (mode 0700). Returns the file
    path.

    `payload` is the wire-format submit_report body. The caller passes
    the same dict it would pass to `client.submit_report(...)`; this
    function does not mutate the caller's dict.
    """
    full = dict(payload)
    full["_persisted_at"] = utc_now_iso()
    full["_attempts"] = 0

    pdir = pending_dir(data_dir)
    pdir.mkdir(parents=True, exist_ok=True, mode=0o700)

    target = pdir / f"{report_id}.json"
    _atomic_write_json(target, full)
    return target


def load_pending_report(path: str | Path) -> dict:
    """Return parsed dict; raise PendingReportCorruptError on any read or
    parse failure (including non-object root).
    """
    p = Path(path)
    try:
        with open(p, "r") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise PendingReportCorruptError(
            f"{p} is not valid JSON: {e}"
        ) from e
    except OSError as e:
        raise PendingReportCorruptError(
            f"could not read {p}: {e}"
        ) from e
    if not isinstance(data, dict):
        raise PendingReportCorruptError(
            f"{p} root is {type(data).__name__}, expected object"
        )
    return data


def increment_attempts(path: str | Path) -> int:
    """Atomically read, bump `_attempts`, rewrite. Returns the new value.

    Called BEFORE each submit_report attempt so the on-disk count reflects
    work performed even if the agent crashes between increment and submit.
    """
    p = Path(path)
    data = load_pending_report(p)
    new_value = int(data.get("_attempts", 0)) + 1
    data["_attempts"] = new_value
    _atomic_write_json(p, data)
    return new_value


def delete_pending_report(path: str | Path) -> None:
    """Idempotent unlink — silently tolerates a missing file (a concurrent
    or crash-recovery delete is fine; the postcondition is "file does not
    exist", which is already true)."""
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def list_pending_report_paths(data_dir: str | Path) -> list[Path]:
    """Return all *.json files in pending_reports/, sorted by mtime
    ascending (chronological — oldest first).

    Skips: .tmp files, the corrupt/ subdir, and anything that isn't a
    plain file. A non-existent pending_reports/ dir returns []
    (the natural "fresh agent has no pending reports" case)."""
    pdir = pending_dir(data_dir)
    if not pdir.exists():
        return []
    files: list[Path] = []
    for entry in pdir.iterdir():
        if not entry.is_file():
            continue
        if entry.suffix != ".json":
            continue
        files.append(entry)
    files.sort(key=lambda p: p.stat().st_mtime)
    return files


def cleanup_stray_tmp_files(data_dir: str | Path) -> list[Path]:
    """Find and delete any .tmp files in pending_reports/ — abandoned
    in-progress writes from a crashed previous run. Returns the list of
    paths that were deleted so the caller can log them.
    """
    pdir = pending_dir(data_dir)
    if not pdir.exists():
        return []
    deleted: list[Path] = []
    for entry in pdir.iterdir():
        if entry.is_file() and entry.suffix == ".tmp":
            try:
                entry.unlink()
                deleted.append(entry)
            except FileNotFoundError:
                pass
    return deleted


def quarantine_corrupt(path: str | Path, data_dir: str | Path) -> Path:
    """Move a corrupt pending-report file to pending_reports/corrupt/
    with a wall-clock timestamp suffix.

    Don't delete — the operator may want to inspect the file's contents.
    Returns the new path.
    """
    src = Path(path)
    qdir = pending_dir(data_dir) / CORRUPT_SUBDIR_NAME
    qdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Strip non-filename-safe chars from the timestamp.
    ts = re.sub(r"[^0-9TZ]", "", utc_now_iso())
    target = qdir / f"{src.name}.{ts}"
    os.rename(src, target)
    return target


def wire_payload(persisted: dict) -> dict:
    """Strip the agent-side `_persisted_at` / `_attempts` metadata fields
    from a persisted record, leaving only the contract fields that
    `submit_report` accepts.

    Defensive against future drift: if `_WIRE_FIELDS` adds a field, the
    on-disk record gets it via save_pending_report's payload pass-through,
    and this filter keeps the wire payload consistent.
    """
    return {k: persisted[k] for k in _WIRE_FIELDS if k in persisted}


# ---- internal helpers --------------------------------------------------


def _atomic_write_json(path: Path, payload: dict) -> None:
    """Same atomic-write strategy as agent_state.save_credentials:
    write to <path>.tmp, fsync, os.replace() into place, chmod 0o600."""
    path.parent.mkdir(parents=True, exist_ok=True)

    tmp = path.parent / (path.name + ".tmp")
    fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise

    os.replace(tmp, path)
    os.chmod(path, 0o600)
