"""At-least-once report submission with on-disk pending queue + retry.

Wraps `DashboardClient.submit_report` with three concerns the wire-format
client deliberately doesn't own:

  1. Persist-before-send — every report is written to
     `<data_dir>/pending_reports/<report_id>.json` BEFORE any network
     attempt. The "at-least-once" guarantee depends on this invariant:
     if the network call is in flight when the agent crashes, the file
     is on disk and the next start replays it.

  2. Retry with backoff — same schedule as bootstrap (5/15/30/60/120
     then steady at 120s) for `DashboardRetriableError` (5xx, network).
     Hard-fail responses (400 validation, 413 too-large) delete the file
     and return without retrying — looping on a known-bad payload would
     just accumulate poison.

  3. Restart recovery — `replay_pending_reports()` scans the dir at
     startup, retries each file in mtime-ascending order, quarantines
     corrupt files, and skips orphans from previous (revoked) agent
     identities.

Stateless across calls. Caller owns `report_id` generation and the
"this is one cycle's report" boundary. Two concurrent calls with
different report_ids are safe (different files); same report_id is the
caller's responsibility (one owner per id).
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from certwatch.clock import Clock, RealClock
from certwatch.dashboard_client import (
    DashboardAuthError,
    DashboardClient,
    DashboardConflictError,
    DashboardError,
    DashboardPayloadTooLargeError,
    DashboardRetriableError,
    DashboardValidationError,
)
from certwatch.pending_reports import (
    PendingReportCorruptError,
    cleanup_stray_tmp_files,
    delete_pending_report,
    increment_attempts,
    list_pending_report_paths,
    load_pending_report,
    quarantine_corrupt,
    save_pending_report,
    wire_payload,
)

log = logging.getLogger("certwatch")


# Report-submission backoff schedule. Same values as bootstrap's
# BACKOFF_SCHEDULE but kept independent so the two modules can drift
# in v2 without coupling. Pinned by an exact-value test.
BACKOFF_SCHEDULE = (5.0, 15.0, 30.0, 60.0, 120.0)


@dataclass
class ReportSubmissionResult:
    status: str  # "delivered" | "duplicate" | "rejected" | "shutdown"
    attempts: int
    elapsed: float  # monotonic seconds since the call started
    dashboard_summary: Optional[dict] = None


@dataclass
class ReplayResult:
    replayed_count: int = 0
    skipped_corrupt: int = 0
    skipped_orphan: int = 0
    shutdown_during: bool = False


def submit_report_with_retry(
    *,
    client: DashboardClient,
    data_dir: str | Path,
    report_id: str,
    report_type: str,
    started_at: str,
    completed_at: str,
    action_id: Optional[str],
    checks: list,
    clock: Optional[Clock] = None,
    shutdown_event: Optional[threading.Event] = None,
) -> ReportSubmissionResult:
    """Persist, then submit-with-retry.

    Persistence happens FIRST. If the disk write fails (full disk, perms),
    this function raises and never makes the network call — the at-least-
    once invariant requires the file exist before any send attempt.

    On `DashboardAuthError`, the pending file is preserved and the
    exception is re-raised. The runner catches it, signals global
    shutdown, and the next start (with new credentials) will replay
    the file (or, if revoked permanently, replay will skip it as an
    orphan).

    May block for an unbounded amount of time on retriable errors. The
    caller (cert check thread or action worker) owns its bounded
    responsibilities; this is one of them. The heartbeat thread MUST
    NOT call this — its cadence guarantee depends on never blocking
    here.
    """
    if clock is None:
        clock = RealClock()

    started_mono = clock.now()
    payload = {
        "report_id": report_id,
        "report_type": report_type,
        "started_at": started_at,
        "completed_at": completed_at,
        "action_id": action_id,
        "checks": checks,
    }
    path = save_pending_report(data_dir, report_id, payload)

    return _retry_loop_for_path(
        client=client,
        path=path,
        wire=payload,
        clock=clock,
        shutdown_event=shutdown_event,
        started_mono=started_mono,
    )


def replay_pending_reports(
    *,
    client: DashboardClient,
    data_dir: str | Path,
    credentials_registered_at: str,
    clock: Optional[Clock] = None,
    shutdown_event: Optional[threading.Event] = None,
) -> ReplayResult:
    """Scan `<data_dir>/pending_reports/` and resubmit each report.

    Called once at startup, BEFORE any other thread starts producing new
    reports. Retries each file in mtime-ascending order so the dashboard
    sees old data first.

    Three skip cases:
      - .tmp files (interrupted writes from a previous crash) → deleted,
        warning logged
      - Corrupt JSON or non-object root → moved to pending_reports/corrupt/
        with a timestamp suffix, error logged, replay continues
      - Orphan: `_persisted_at` predates the loaded credentials'
        `registered_at` → file is from a previous (revoked) agent
        identity; skip with warning, file left in place. The dashboard
        no longer knows the old agent_id, so submitting would fail.

    `DashboardAuthError` during replay propagates up — the runner triggers
    global shutdown.
    """
    if clock is None:
        clock = RealClock()

    result = ReplayResult()

    stray = cleanup_stray_tmp_files(data_dir)
    for s in stray:
        log.warning({"event": "stray_tmp_file_cleaned", "path": str(s)})

    paths = list_pending_report_paths(data_dir)
    if not paths:
        log.info({"event": "replay_no_pending_reports"})
        return result

    log.info(
        {"event": "replay_pending_reports_starting", "count": len(paths)}
    )

    for path in paths:
        if shutdown_event is not None and shutdown_event.is_set():
            result.shutdown_during = True
            log.info({"event": "replay_interrupted_by_shutdown"})
            return result

        try:
            persisted = load_pending_report(path)
        except PendingReportCorruptError as e:
            target = quarantine_corrupt(path, data_dir)
            log.error(
                {
                    "event": "pending_report_corrupt_quarantined",
                    "original_path": str(path),
                    "moved_to": str(target),
                    "error": str(e),
                }
            )
            result.skipped_corrupt += 1
            continue

        persisted_at = persisted.get("_persisted_at", "")
        if persisted_at and persisted_at < credentials_registered_at:
            # Orphan: report is older than this agent's identity. Don't
            # try to submit (dashboard wouldn't recognize the agent_id).
            # Don't delete (operator may want to inspect).
            log.warning(
                {
                    "event": "pending_report_orphan_skipped",
                    "report_id": persisted.get("report_id"),
                    "_persisted_at": persisted_at,
                    "credentials_registered_at": credentials_registered_at,
                }
            )
            result.skipped_orphan += 1
            continue

        sub_result = _retry_loop_for_path(
            client=client,
            path=path,
            wire=wire_payload(persisted),
            clock=clock,
            shutdown_event=shutdown_event,
            started_mono=clock.now(),
        )

        if sub_result.status == "shutdown":
            result.shutdown_during = True
            return result

        result.replayed_count += 1

    log.info(
        {
            "event": "replay_pending_reports_complete",
            "replayed_count": result.replayed_count,
            "skipped_corrupt": result.skipped_corrupt,
            "skipped_orphan": result.skipped_orphan,
        }
    )
    return result


# ---- internal retry loop ----------------------------------------------


def _backoff_delay(attempts: int) -> float:
    """`attempts` is the count of submit_report calls already made
    (>=1). First retry sleeps BACKOFF_SCHEDULE[0]=5; after the
    documented schedule, steady at the last value."""
    idx = max(0, min(attempts - 1, len(BACKOFF_SCHEDULE) - 1))
    return BACKOFF_SCHEDULE[idx]


def _retry_loop_for_path(
    *,
    client: DashboardClient,
    path: Path,
    wire: dict,
    clock: Clock,
    shutdown_event: Optional[threading.Event],
    started_mono: float,
) -> ReportSubmissionResult:
    """The actual retry loop. Shared between fresh submissions and replay.

    Increments `_attempts` on disk before each call so the persisted
    counter reflects work performed even if the agent crashes mid-loop.
    """
    while True:
        # NOTE: deliberately no top-of-loop shutdown check. Per the
        # Phase 5e design contract, "the cycle's data made it to disk
        # and we owe the dashboard one delivery attempt before giving
        # up." The first submit attempt always happens — even when
        # shutdown is already set at entry. Shutdown only short-
        # circuits the backoff sleep between retries (see the retriable
        # branch below). This is what makes Scenario 10 (SIGTERM
        # mid-cycle) deliver the partial-results report cleanly.
        attempts = increment_attempts(path)

        try:
            response = client.submit_report(
                report_id=wire["report_id"],
                report_type=wire["report_type"],
                started_at=wire["started_at"],
                completed_at=wire["completed_at"],
                action_id=wire.get("action_id"),
                checks=wire.get("checks", []),
            )
        except DashboardConflictError as e:
            # Idempotent retry succeeded — dashboard already has it.
            body = e.body or {}
            log.info(
                {
                    "event": "report_already_received",
                    "report_id": wire["report_id"],
                    "attempts": attempts,
                    "original_received_at": body.get("original_received_at"),
                    "original_summary": body.get("original_summary"),
                }
            )
            delete_pending_report(path)
            return ReportSubmissionResult(
                status="duplicate",
                attempts=attempts,
                elapsed=clock.now() - started_mono,
                dashboard_summary=body or None,
            )
        except DashboardValidationError as e:
            log.error(
                {
                    "event": "report_rejected_validation",
                    "report_id": wire["report_id"],
                    "attempts": attempts,
                    "error_code": e.code,
                    "error_message": e.message,
                    "request_id": e.request_id,
                }
            )
            delete_pending_report(path)
            return ReportSubmissionResult(
                status="rejected",
                attempts=attempts,
                elapsed=clock.now() - started_mono,
            )
        except DashboardPayloadTooLargeError as e:
            log.error(
                {
                    "event": "report_rejected_too_large",
                    "report_id": wire["report_id"],
                    "attempts": attempts,
                    "checks_count": len(wire.get("checks", []) or []),
                    "error_code": e.code,
                    "error_message": e.message,
                    "request_id": e.request_id,
                }
            )
            delete_pending_report(path)
            return ReportSubmissionResult(
                status="rejected",
                attempts=attempts,
                elapsed=clock.now() - started_mono,
            )
        except DashboardAuthError:
            # Preserve the file; runner will trigger global shutdown.
            log.error(
                {
                    "event": "report_submission_auth_error_preserving_file",
                    "report_id": wire["report_id"],
                    "attempts": attempts,
                    "path": str(path),
                }
            )
            raise
        except DashboardRetriableError as e:
            delay = _backoff_delay(attempts)
            log.warning(
                {
                    "event": "report_submission_retry",
                    "report_id": wire["report_id"],
                    "attempts": attempts,
                    "delay_seconds": delay,
                    "error_class": type(e).__name__,
                    "error_code": e.code,
                    "error_message": e.message,
                }
            )
            if shutdown_event is not None:
                woke_early = clock.wait_for(delay, shutdown_event)
                if woke_early:
                    return ReportSubmissionResult(
                        status="shutdown",
                        attempts=attempts,
                        elapsed=clock.now() - started_mono,
                    )
            else:
                clock.sleep(delay)
            continue
        except DashboardError:
            # Other DashboardError subclass (NotFound, base, etc.) — fatal.
            # File preserved so the operator can see what was in flight.
            raise

        # 200 success path. (continue inside the retriable except branch
        # skips this; other branches return.)
        log.info(
            {
                "event": "report_delivered",
                "report_id": wire["report_id"],
                "attempts": attempts,
                "summary": response.get("summary"),
                "received_at": response.get("received_at"),
            }
        )
        delete_pending_report(path)
        return ReportSubmissionResult(
            status="delivered",
            attempts=attempts,
            elapsed=clock.now() - started_mono,
            dashboard_summary=response.get("summary"),
        )


def _safe_read_attempts(path: Path) -> int:
    """Best-effort read of `_attempts` for the shutdown-result return.

    If the file was just deleted by a concurrent operation, return 0
    rather than crash — the result is informational only at this point."""
    try:
        return int(load_pending_report(path).get("_attempts", 0))
    except (PendingReportCorruptError, FileNotFoundError, OSError):
        return 0
