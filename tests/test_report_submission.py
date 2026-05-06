"""Phase 5b — submit_report_with_retry + replay_pending_reports tests.

Uses real DashboardClient against `responses`-mocked HTTP, real on-disk
pending files in tmp_path, and FakeClock for deterministic backoff
assertions.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest
import requests
import responses

from certwatch.clock import FakeClock
from certwatch.dashboard_client import DashboardAuthError, DashboardClient
from certwatch.pending_reports import (
    load_pending_report,
    pending_dir,
    save_pending_report,
)
import certwatch.pending_reports as pending_reports_mod
from certwatch.report_submission import (
    BACKOFF_SCHEDULE,
    ReplayResult,
    ReportSubmissionResult,
    _backoff_delay,
    replay_pending_reports,
    submit_report_with_retry,
)

DASH = "https://certwatch.lovable.app"
AGENT_ID = "a8f3d12e-7b4c-4d8a-9e1f-2c5b6a7d8e9f"
SECRET = "agtkey_test"
REPORTS_URL = f"{DASH}/api/public/v1/agents/{AGENT_ID}/reports"

REPORT_ID = "d4e5f6a7-8b9c-0d1e-2f3a-4b5c6d7e8f9a"

DASHBOARD_OK_BODY = {
    "received_at": "2026-05-02T15:01:43Z",
    "report_id": REPORT_ID,
    "summary": {
        "total_checks": 1,
        "success": 1,
        "connection_failed": 0,
        "tls_failed": 0,
        "alerts_triggered": 0,
        "ignored_unknown_hosts": 0,
    },
    "action_completed": None,
}


@pytest.fixture
def client():
    return DashboardClient(DASH, agent_id=AGENT_ID, agent_secret=SECRET)


def _submit(client, tmp_path, fc, **overrides):
    defaults = dict(
        client=client,
        data_dir=tmp_path,
        report_id=REPORT_ID,
        report_type="scheduled",
        started_at="2026-05-02T15:00:00Z",
        completed_at="2026-05-02T15:01:42Z",
        action_id=None,
        checks=[{"host_ref": {"type": "manual", "host_id": "h1"},
                 "checked_at": "2026-05-02T15:00:03Z",
                 "status": "success", "error_reason": None,
                 "cert": {"subject_cn": "x", "subject_sans": [],
                          "issuer_cn": "x", "issuer_o": "x",
                          "issuer_full_dn": "CN=x",
                          "ca_category": "well_known_public",
                          "is_self_signed": False,
                          "not_before": "2026-01-01T00:00:00Z",
                          "not_after": "2027-01-01T00:00:00Z",
                          "days_until_expiry": 365,
                          "signature_algorithm": "SHA256withRSA",
                          "key_size": 2048, "hostname_matches": True,
                          "chain_trusted_by_system": True,
                          "chain_error_reason": None}}],
        clock=fc,
    )
    defaults.update(overrides)
    return submit_report_with_retry(**defaults)


# ---- BACKOFF_SCHEDULE pin --------------------------------------------


def test_backoff_schedule_matches_contract():
    """Literal-value pin so accidental edits get caught."""
    assert BACKOFF_SCHEDULE == (5.0, 15.0, 30.0, 60.0, 120.0)


def test_backoff_delay_first_retry_is_5():
    assert _backoff_delay(1) == 5.0


def test_backoff_delay_follows_schedule():
    assert [_backoff_delay(n) for n in (1, 2, 3, 4, 5)] == [5.0, 15.0, 30.0, 60.0, 120.0]


def test_backoff_delay_caps_at_steady_state():
    for attempts in (6, 7, 50, 1000):
        assert _backoff_delay(attempts) == 120.0


# ---- 200 success path ------------------------------------------------


def test_first_try_success_deletes_pending_file(client, tmp_path):
    fc = FakeClock()
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json=DASHBOARD_OK_BODY, status=200)
        result = _submit(client, tmp_path, fc)
    assert result.status == "delivered"
    assert result.attempts == 1
    assert result.dashboard_summary == DASHBOARD_OK_BODY["summary"]
    assert not (pending_dir(tmp_path) / f"{REPORT_ID}.json").exists()
    assert fc.sleeps == []


def test_success_after_5xx_retries_uses_correct_backoff(client, tmp_path):
    """503 → backoff 5 → 503 → backoff 15 → 503 → backoff 30 → 200."""
    fc = FakeClock()
    err = {"error": {"code": "internal_error", "message": "boom"}}
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json=err, status=503)
        rsps.add("POST", REPORTS_URL, json=err, status=503)
        rsps.add("POST", REPORTS_URL, json=err, status=503)
        rsps.add("POST", REPORTS_URL, json=DASHBOARD_OK_BODY, status=200)
        result = _submit(client, tmp_path, fc)
    assert result.status == "delivered"
    assert result.attempts == 4
    assert fc.sleeps == [5.0, 15.0, 30.0]
    assert not (pending_dir(tmp_path) / f"{REPORT_ID}.json").exists()


def test_metadata_fields_not_sent_in_request(client, tmp_path):
    """Wire-bytes assertion: _persisted_at / _attempts must NEVER appear
    on the wire. Same defensive pattern as Phase 4d's action_id null
    assertions."""
    fc = FakeClock()
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json=DASHBOARD_OK_BODY, status=200)
        _submit(client, tmp_path, fc)
        body_str = rsps.calls[0].request.body
        body = json.loads(body_str)
    assert "_persisted_at" not in body
    assert "_attempts" not in body
    assert '"_persisted_at"' not in body_str
    assert '"_attempts"' not in body_str
    # Wire-required fields all present
    for f in ("report_id", "report_type", "started_at",
              "completed_at", "action_id", "checks"):
        assert f in body


# ---- 409 idempotent retry treated as success ------------------------


def test_409_treated_as_duplicate_deletes_file_and_returns_summary(client, tmp_path):
    fc = FakeClock()
    err_body = {
        "error": {
            "code": "report_already_received",
            "message": "duplicate",
            "request_id": "req_dup",
        },
        "original_received_at": "2026-05-02T15:01:43Z",
        "original_summary": {"total_checks": 1, "success": 1,
                              "connection_failed": 0, "tls_failed": 0,
                              "alerts_triggered": 0, "ignored_unknown_hosts": 0},
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json=err_body, status=409)
        result = _submit(client, tmp_path, fc)
    assert result.status == "duplicate"
    # The 409 body is exposed via dashboard_summary (whole envelope, the
    # original_summary inside is what the runner cares about for logs).
    assert result.dashboard_summary["original_summary"]["alerts_triggered"] == 0
    assert result.dashboard_summary["original_received_at"] == "2026-05-02T15:01:43Z"
    assert not (pending_dir(tmp_path) / f"{REPORT_ID}.json").exists()


def test_409_log_includes_original_received_at(client, tmp_path, caplog):
    fc = FakeClock()
    err_body = {
        "error": {"code": "report_already_received", "message": "dup",
                  "request_id": "req_d"},
        "original_received_at": "2026-05-02T15:01:43Z",
        "original_summary": {"success": 5},
    }
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json=err_body, status=409)
        with caplog.at_level("INFO"):
            _submit(client, tmp_path, fc)
    matches = [r.msg for r in caplog.records
               if isinstance(r.msg, dict) and r.msg.get("event") == "report_already_received"]
    assert len(matches) == 1
    assert matches[0]["original_received_at"] == "2026-05-02T15:01:43Z"


# ---- non-retriable rejections delete file --------------------------


def test_400_validation_failed_deletes_file_and_does_not_retry(client, tmp_path):
    fc = FakeClock()
    err = {"error": {"code": "validation_failed",
                     "message": "checks[0]: bad shape", "request_id": "req_v"}}
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json=err, status=400)
        result = _submit(client, tmp_path, fc)
    assert result.status == "rejected"
    assert result.attempts == 1
    assert fc.sleeps == []  # no retries
    assert not (pending_dir(tmp_path) / f"{REPORT_ID}.json").exists()


def test_413_payload_too_large_deletes_file_and_does_not_retry(client, tmp_path):
    fc = FakeClock()
    err = {"error": {"code": "payload_too_large",
                     "message": "max 1000 checks", "request_id": "req_p"}}
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json=err, status=413)
        result = _submit(client, tmp_path, fc)
    assert result.status == "rejected"
    assert fc.sleeps == []
    assert not (pending_dir(tmp_path) / f"{REPORT_ID}.json").exists()


# ---- retriable error preserves file --------------------------------


def test_500_until_shutdown_preserves_file_and_records_backoff(client, tmp_path):
    """500 forever: 10 retries then shutdown signaled. Sleep sequence
    matches BACKOFF_SCHEDULE then steady-at-120, file remains on disk
    for next-start replay, status="shutdown"."""
    fc = FakeClock()
    shutdown = threading.Event()
    err = {"error": {"code": "internal_error", "message": "boom"}}

    call_count = {"n": 0}

    def handler(request):
        call_count["n"] += 1
        if call_count["n"] >= 10:
            # Set during the 10th request — the next backoff will see it
            # and short-circuit via clock.wait_for.
            shutdown.set()
        return (503, {}, json.dumps(err))

    with responses.RequestsMock() as rsps:
        for _ in range(10):
            rsps.add_callback("POST", REPORTS_URL, callback=handler)
        result = _submit(client, tmp_path, fc, shutdown_event=shutdown)

    assert result.status == "shutdown"
    assert result.attempts == 10
    assert fc.sleeps == [5.0, 15.0, 30.0, 60.0, 120.0,
                         120.0, 120.0, 120.0, 120.0, 120.0]
    # File still on disk for next-start replay
    pending = pending_dir(tmp_path) / f"{REPORT_ID}.json"
    assert pending.exists()
    # _attempts on disk reflects the 10 attempts made
    assert load_pending_report(pending)["_attempts"] == 10


def test_network_timeout_treated_as_retriable(client, tmp_path, monkeypatch):
    fc = FakeClock()
    shutdown = threading.Event()
    call_count = {"n": 0}
    real_request = requests.Session.request

    def flaky(self, method, url, **kw):
        call_count["n"] += 1
        if call_count["n"] == 1:
            raise requests.Timeout("read timeout")
        if call_count["n"] >= 2:
            return real_request(self, method, url, **kw)

    monkeypatch.setattr(requests.Session, "request", flaky)

    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json=DASHBOARD_OK_BODY, status=200)
        result = _submit(client, tmp_path, fc, shutdown_event=shutdown)

    assert result.status == "delivered"
    assert result.attempts == 2
    assert fc.sleeps == [5.0]


def test_shutdown_already_set_first_attempt_still_happens(client, tmp_path):
    """Phase 5e design contract: 'the cycle's data made it to disk and
    we owe the dashboard one delivery attempt before giving up.'

    Even when shutdown_event is already set at entry, submit_report_with_retry
    makes the first attempt. Shutdown only short-circuits backoff
    sleeps between retries — never the first try. This is what makes
    SIGTERM-mid-cycle deliver the partial-results report cleanly
    (Phase 8 Scenario 10)."""
    fc = FakeClock()
    shutdown = threading.Event()
    shutdown.set()

    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json=DASHBOARD_OK_BODY, status=200)
        result = _submit(client, tmp_path, fc, shutdown_event=shutdown)

    # First attempt happened, succeeded, report delivered.
    assert result.status == "delivered"
    assert result.attempts == 1
    assert fc.sleeps == []
    # File deleted on success.
    assert not (pending_dir(tmp_path) / f"{REPORT_ID}.json").exists()


# ---- 401 auth error --------------------------------------------------


def test_401_re_raises_and_preserves_file(client, tmp_path):
    """Auth error must propagate so the runner can trigger global
    shutdown. File must NOT be deleted — next start (or operator
    intervention) replays it."""
    fc = FakeClock()
    err = {"error": {"code": "agent_revoked", "message": "revoked",
                     "request_id": "req_r"}}
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json=err, status=401)
        with pytest.raises(DashboardAuthError) as exc:
            _submit(client, tmp_path, fc)
    assert exc.value.code == "agent_revoked"
    assert (pending_dir(tmp_path) / f"{REPORT_ID}.json").exists()


# ---- persist-before-send invariant ----------------------------------


def test_disk_full_during_persist_raises_without_sending(
    client, tmp_path, monkeypatch
):
    """The whole point of at-least-once delivery: persistence happens
    BEFORE the network call. If persistence fails, we must NOT attempt
    to submit (otherwise a successful submit would leave no on-disk
    record, defeating the recovery story for the next attempt)."""
    fc = FakeClock()

    def fail(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(pending_reports_mod.json, "dump", fail)

    # No responses mock: a stray submit_report call would raise
    # ConnectionError which would surface in the test.
    with responses.RequestsMock():
        with pytest.raises(OSError, match="disk full"):
            _submit(client, tmp_path, fc)


def test_persist_happens_before_first_request(client, tmp_path):
    """Verify the order: file exists on disk by the time the first
    submit_report is called."""
    fc = FakeClock()
    saw_file = {"present": False}

    def handler(request):
        saw_file["present"] = (pending_dir(tmp_path) / f"{REPORT_ID}.json").exists()
        return (200, {}, json.dumps(DASHBOARD_OK_BODY))

    with responses.RequestsMock() as rsps:
        rsps.add_callback("POST", REPORTS_URL, callback=handler)
        _submit(client, tmp_path, fc)
    assert saw_file["present"], "pending file must exist before first submit_report call"


# ---- attempts counter on disk --------------------------------------


def test_attempts_observable_on_disk_during_retries(client, tmp_path):
    """Operator-debugging value: _attempts counter visible from disk
    even mid-loop, so a high value signals 'dashboard unreachable'."""
    fc = FakeClock()
    err = {"error": {"code": "internal_error", "message": "boom"}}
    seen_counts = []

    def handler(request):
        path = pending_dir(tmp_path) / f"{REPORT_ID}.json"
        if path.exists():
            seen_counts.append(load_pending_report(path)["_attempts"])
        return (503, {}, json.dumps(err))

    with responses.RequestsMock() as rsps:
        for _ in range(3):
            rsps.add_callback("POST", REPORTS_URL, callback=handler)
        rsps.add("POST", REPORTS_URL, json=DASHBOARD_OK_BODY, status=200)
        _submit(client, tmp_path, fc)

    # By the time each request handler runs, the increment for that
    # attempt has already been persisted.
    assert seen_counts == [1, 2, 3]


# ---- replay_pending_reports -----------------------------------------


def _persisted(report_id: str, persisted_at: str = "2026-05-03T00:00:00Z",
                attempts: int = 0, **wire) -> dict:
    """Build a persisted record dict directly (bypassing save)."""
    base = {
        "report_id": report_id,
        "report_type": "scheduled",
        "started_at": "2026-05-03T00:00:00Z",
        "completed_at": "2026-05-03T00:00:01Z",
        "action_id": None,
        "checks": [],
        "_persisted_at": persisted_at,
        "_attempts": attempts,
    }
    base.update(wire)
    return base


def _write_persisted(tmp_path: Path, report_id: str, persisted_at: str = "2026-05-03T00:00:00Z"):
    pdir = pending_dir(tmp_path)
    pdir.mkdir(parents=True, exist_ok=True)
    p = pdir / f"{report_id}.json"
    p.write_text(json.dumps(_persisted(report_id, persisted_at=persisted_at)))
    return p


def test_replay_no_dir_returns_zero_counts(client, tmp_path):
    """Fresh agent has no pending_reports/. Replay handles that without
    any 'if exists' branches at the call site."""
    result = replay_pending_reports(
        client=client, data_dir=tmp_path,
        credentials_registered_at="2026-05-01T00:00:00Z", clock=FakeClock(),
    )
    assert isinstance(result, ReplayResult)
    assert result.replayed_count == 0
    assert result.skipped_corrupt == 0
    assert result.skipped_orphan == 0
    assert result.shutdown_during is False


def test_replay_empty_dir_returns_zero_counts(client, tmp_path):
    pending_dir(tmp_path).mkdir()
    result = replay_pending_reports(
        client=client, data_dir=tmp_path,
        credentials_registered_at="2026-05-01T00:00:00Z", clock=FakeClock(),
    )
    assert result.replayed_count == 0


def test_replay_submits_files_in_chronological_order(client, tmp_path):
    """mtime-ascending: the dashboard sees old data first, matching
    when each cycle actually ran on the agent."""
    p1 = _write_persisted(tmp_path, "first", persisted_at="2026-05-02T10:00:00Z")
    import time as _t; _t.sleep(0.02)
    p2 = _write_persisted(tmp_path, "second", persisted_at="2026-05-02T11:00:00Z")
    _t.sleep(0.02)
    p3 = _write_persisted(tmp_path, "third", persisted_at="2026-05-02T12:00:00Z")

    seen_order = []

    def handler(request):
        body = json.loads(request.body)
        seen_order.append(body["report_id"])
        return (200, {}, json.dumps({**DASHBOARD_OK_BODY, "report_id": body["report_id"]}))

    with responses.RequestsMock() as rsps:
        for _ in range(3):
            rsps.add_callback("POST", REPORTS_URL, callback=handler)
        result = replay_pending_reports(
            client=client, data_dir=tmp_path,
            credentials_registered_at="2026-05-01T00:00:00Z", clock=FakeClock(),
        )

    assert seen_order == ["first", "second", "third"]
    assert result.replayed_count == 3
    # All three files deleted after delivery
    for p in (p1, p2, p3):
        assert not p.exists()


def test_replay_quarantines_corrupt_files_and_continues(client, tmp_path):
    """One corrupt + two valid files: quarantine the corrupt one, deliver
    the others. Failure isolation — one bad file must not block the
    valid ones."""
    pdir = pending_dir(tmp_path)
    pdir.mkdir()
    bad = pdir / "bad-id.json"
    bad.write_text("not valid json {{{")
    bad_content = bad.read_text()

    _write_persisted(tmp_path, "good-1", persisted_at="2026-05-02T10:00:00Z")
    _write_persisted(tmp_path, "good-2", persisted_at="2026-05-02T11:00:00Z")

    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json={**DASHBOARD_OK_BODY, "report_id": "good-1"}, status=200)
        rsps.add("POST", REPORTS_URL, json={**DASHBOARD_OK_BODY, "report_id": "good-2"}, status=200)
        result = replay_pending_reports(
            client=client, data_dir=tmp_path,
            credentials_registered_at="2026-05-01T00:00:00Z", clock=FakeClock(),
        )

    assert result.replayed_count == 2
    assert result.skipped_corrupt == 1
    # Corrupt file moved to corrupt/, contents preserved
    assert not bad.exists()
    quarantined = list((pdir / "corrupt").iterdir())
    assert len(quarantined) == 1
    assert quarantined[0].read_text() == bad_content
    assert "bad-id" in quarantined[0].name


def test_replay_skips_orphans_with_persisted_at_before_credentials(client, tmp_path):
    """A pending file from a previous (revoked) agent identity. Don't
    submit (dashboard wouldn't recognize the old agent_id), don't delete
    (operator may want to inspect)."""
    orphan = _write_persisted(tmp_path, "orphan-id",
                               persisted_at="2026-05-01T00:00:00Z")
    fresh = _write_persisted(tmp_path, "fresh-id",
                              persisted_at="2026-05-03T00:00:00Z")

    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json={**DASHBOARD_OK_BODY, "report_id": "fresh-id"}, status=200)
        result = replay_pending_reports(
            client=client, data_dir=tmp_path,
            credentials_registered_at="2026-05-02T00:00:00Z", clock=FakeClock(),
        )

    assert result.replayed_count == 1
    assert result.skipped_orphan == 1
    # Orphan file preserved on disk for operator inspection
    assert orphan.exists()
    # Fresh file delivered and deleted
    assert not fresh.exists()


def test_replay_cleans_stray_tmp_files(client, tmp_path, caplog):
    pdir = pending_dir(tmp_path)
    pdir.mkdir()
    stray = pdir / "abandoned.json.tmp"
    stray.write_text("partial garbage")
    _write_persisted(tmp_path, "good-1", persisted_at="2026-05-03T00:00:00Z")

    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json=DASHBOARD_OK_BODY, status=200)
        with caplog.at_level("WARNING"):
            replay_pending_reports(
                client=client, data_dir=tmp_path,
                credentials_registered_at="2026-05-01T00:00:00Z", clock=FakeClock(),
            )

    assert not stray.exists()
    msgs = [r.msg for r in caplog.records
            if isinstance(r.msg, dict) and r.msg.get("event") == "stray_tmp_file_cleaned"]
    assert len(msgs) == 1


def test_replay_shutdown_event_stops_at_next_file_boundary(client, tmp_path):
    """Replay scans files one at a time; shutdown set during one delivery
    is observed at the top of the next iteration."""
    p1 = _write_persisted(tmp_path, "first", persisted_at="2026-05-02T10:00:00Z")
    import time as _t; _t.sleep(0.02)
    p2 = _write_persisted(tmp_path, "second", persisted_at="2026-05-02T11:00:00Z")
    _t.sleep(0.02)
    p3 = _write_persisted(tmp_path, "third", persisted_at="2026-05-02T12:00:00Z")

    shutdown = threading.Event()
    served = []

    def handler(request):
        body = json.loads(request.body)
        served.append(body["report_id"])
        # Set shutdown while serving the FIRST file — the second iteration's
        # top-of-loop check catches it.
        shutdown.set()
        return (200, {}, json.dumps({**DASHBOARD_OK_BODY, "report_id": body["report_id"]}))

    # assert_all_requests_are_fired=False because shutdown intentionally
    # stops replay after the first file; the other two registered mocks
    # won't be consumed and that's the point of this test.
    with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
        for _ in range(3):
            rsps.add_callback("POST", REPORTS_URL, callback=handler)
        result = replay_pending_reports(
            client=client, data_dir=tmp_path,
            credentials_registered_at="2026-05-01T00:00:00Z",
            clock=FakeClock(), shutdown_event=shutdown,
        )

    assert result.shutdown_during is True
    assert result.replayed_count == 1
    assert served == ["first"]
    # Second and third still on disk
    assert not p1.exists()
    assert p2.exists()
    assert p3.exists()


def test_replay_orphan_and_valid_mix(client, tmp_path):
    """Multiple orphans + multiple valid files in the same dir. All
    orphans skipped; all valid ones replayed."""
    _write_persisted(tmp_path, "orphan-1", persisted_at="2026-04-01T00:00:00Z")
    import time as _t; _t.sleep(0.02)
    _write_persisted(tmp_path, "valid-1", persisted_at="2026-05-03T00:00:00Z")
    _t.sleep(0.02)
    _write_persisted(tmp_path, "orphan-2", persisted_at="2026-04-15T00:00:00Z")
    _t.sleep(0.02)
    _write_persisted(tmp_path, "valid-2", persisted_at="2026-05-04T00:00:00Z")

    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json={**DASHBOARD_OK_BODY, "report_id": "valid-1"}, status=200)
        rsps.add("POST", REPORTS_URL, json={**DASHBOARD_OK_BODY, "report_id": "valid-2"}, status=200)
        result = replay_pending_reports(
            client=client, data_dir=tmp_path,
            credentials_registered_at="2026-05-02T00:00:00Z", clock=FakeClock(),
        )
    assert result.replayed_count == 2
    assert result.skipped_orphan == 2


def test_replay_propagates_auth_error(client, tmp_path):
    """If a replayed submit returns 401, the exception bubbles up to the
    caller (the runner will trigger global shutdown). File preserved."""
    p1 = _write_persisted(tmp_path, "first", persisted_at="2026-05-03T00:00:00Z")

    err = {"error": {"code": "agent_revoked", "message": "revoked",
                     "request_id": "req_r"}}
    with responses.RequestsMock() as rsps:
        rsps.add("POST", REPORTS_URL, json=err, status=401)
        with pytest.raises(DashboardAuthError) as exc:
            replay_pending_reports(
                client=client, data_dir=tmp_path,
                credentials_registered_at="2026-05-01T00:00:00Z", clock=FakeClock(),
            )
    assert exc.value.code == "agent_revoked"
    assert p1.exists()


def test_replay_uses_persisted_payload_not_recomputed(client, tmp_path):
    """The replay path must send what's on disk verbatim, not reconstruct
    a payload from scratch — checks etc. were captured at the time of
    the original cycle."""
    pdir = pending_dir(tmp_path)
    pdir.mkdir()
    persisted = _persisted(
        "abc",
        persisted_at="2026-05-03T00:00:00Z",
        report_type="on_demand",
        started_at="custom-start",
        completed_at="custom-end",
        action_id="some-action",
        checks=[{"host_ref": {"type": "manual", "host_id": "h1"},
                  "checked_at": "x", "status": "success",
                  "error_reason": None, "cert": None}],
    )
    (pdir / "abc.json").write_text(json.dumps(persisted))

    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.body)
        return (200, {}, json.dumps({**DASHBOARD_OK_BODY, "report_id": "abc"}))

    with responses.RequestsMock() as rsps:
        rsps.add_callback("POST", REPORTS_URL, callback=handler)
        replay_pending_reports(
            client=client, data_dir=tmp_path,
            credentials_registered_at="2026-05-01T00:00:00Z", clock=FakeClock(),
        )

    body = seen["body"]
    assert body["report_id"] == "abc"
    assert body["report_type"] == "on_demand"
    assert body["started_at"] == "custom-start"
    assert body["completed_at"] == "custom-end"
    assert body["action_id"] == "some-action"
    assert len(body["checks"]) == 1
    # Metadata fields stripped on the wire
    assert "_persisted_at" not in body
    assert "_attempts" not in body
