"""Observational relay hooks and public heartbeat composition; no network I/O."""

import json
from types import SimpleNamespace

import pytest
import relay_diagnostics
import tproxy


@pytest.mark.parametrize("first,second", (("client", "server"), ("server", "client")))
def test_peer_read_order_survives_identical_monotonic_ticks(monkeypatch, first, second):
    monkeypatch.setattr(tproxy, "time", SimpleNamespace(monotonic=lambda: 0.0))
    activity = tproxy._RelayActivity(last_downstream_at=0.0)
    tproxy._note_relay_peer_end(activity, first)
    tproxy._note_relay_peer_end(activity, second)
    assert activity.read_ended_first == first
    assert activity.client_read_ended_at == activity.server_read_ended_at == 0.0


def test_relay_reason_is_first_wins_and_cleanup_is_not_eof():
    activity = tproxy._RelayActivity(last_downstream_at=1.0)
    tproxy._note_relay_termination(activity, "local_partial_record_watchdog")
    activity.server_end_at = 10.0
    tproxy._note_relay_termination(activity, "upstream_eof")
    assert activity.diagnostic_reason == "local_partial_record_watchdog"
    assert activity.server_read_ended_at == 0.0


def test_relay_private_eof_log_and_public_counters_are_distinct(monkeypatch):
    observations = relay_diagnostics.RelayDiagnostics()
    monkeypatch.setattr(tproxy, "_relay_diagnostics", observations)
    records = []
    monkeypatch.setattr(tproxy, "_enqueue_route_preflight_root_diagnostic_record", records.append)
    activity = tproxy._RelayActivity(
        last_downstream_at=1.0, diagnostic_host="cdn.example.com",
        diagnostic_stage="system_plain", diagnostic_reason="upstream_eof",
    )
    tproxy._record_relay_diagnostic(activity)
    assert len(records) == 1
    assert "host=cdn.example.com" in records[0]
    assert "reason=upstream_eof" in records[0]
    snapshot = observations.snapshot()
    assert snapshot["counters"]["upstream_eof"] == 1
    assert "cdn.example.com" not in json.dumps(snapshot)
    assert "recent" not in snapshot


def test_recovery_disposition_does_not_count_or_authorize_another_relay(monkeypatch):
    observations = relay_diagnostics.RelayDiagnostics()
    monkeypatch.setattr(tproxy, "_relay_diagnostics", observations)
    records = []
    monkeypatch.setattr(tproxy, "_enqueue_route_preflight_root_diagnostic_record", records.append)
    activity = tproxy._RelayActivity(
        last_downstream_at=1.0, diagnostic_host="cdn.example.com",
        diagnostic_stage="system_plain", diagnostic_reason="upstream_reset",
    )
    tproxy._record_relay_diagnostic(activity)
    before = observations.snapshot()
    tproxy._record_relay_recovery(activity, "local_ladder_advanced")
    assert observations.snapshot() == before
    assert records[1].startswith(">> relay-recovery ")
    assert "recovery=local_ladder_advanced" in records[1]


def test_relay_diagnostic_sink_failure_does_not_escape(monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError("synthetic-private-error")

    monkeypatch.setattr(tproxy, "_enqueue_route_preflight_root_diagnostic_record", fail)
    activity = tproxy._RelayActivity(
        last_downstream_at=1.0, diagnostic_host="cdn.example.com",
        diagnostic_reason="upstream_reset",
    )
    tproxy._record_relay_diagnostic(activity)
    tproxy._record_relay_recovery(activity, "confirmation_not_scheduled")
    assert activity.diagnostic_reason == "upstream_reset"


def test_heartbeat_resamples_only_public_relay_counters(monkeypatch):
    observations = relay_diagnostics.RelayDiagnostics()
    observations.record(host="private.example.com", stage="system_plain", reason="upstream_reset")
    monkeypatch.setattr(tproxy, "_relay_diagnostics", observations)
    monkeypatch.setattr(tproxy, "_shutdown_started", type("Stop", (), {"is_set": lambda self: False})())
    monkeypatch.setattr(tproxy, "_status_snapshot_cache", {"schema_version": 2, "daemon": {"state": "off"}})
    monkeypatch.setattr(tproxy, "_status_heartbeat_seq", 0)
    snapshots = []
    monkeypatch.setattr(tproxy, "_write_status_snapshot", snapshots.append)
    assert tproxy._publish_cached_status(now=1700000000.0)
    assert snapshots[-1]["daemon"]["relay_diagnostics"]["counters"]["upstream_reset"] == 1
    observations.record(host="private.example.com", stage="geph", reason="write_error")
    assert tproxy._publish_cached_status(now=1700000001.0)
    assert snapshots[-1]["daemon"]["relay_diagnostics"]["counters"]["write_error"] == 1
    assert "private.example.com" not in json.dumps(snapshots)
    assert "recent" not in snapshots[-1]["daemon"]["relay_diagnostics"]
