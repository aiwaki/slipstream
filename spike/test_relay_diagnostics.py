"""Pure synthetic tests; importing diagnostics does not import the daemon."""

import json

import pytest

import relay_diagnostics as diagnostics


@pytest.mark.parametrize("reason", diagnostics.REASONS)
def test_records_each_explicit_reason_without_inference(reason):
    store = diagnostics.RelayDiagnostics()
    assert store.record(host="cdn.example.com", stage="system_plain", reason=reason)
    snapshot = store.snapshot(include_recent=True)
    assert snapshot["available"] is True
    assert snapshot["counters"][reason] == 1
    assert sum(snapshot["counters"].values()) == 1
    assert snapshot["recent"] == [
        {"host": "cdn.example.com", "stage": "system_plain", "reason": reason,
         "recovery": "not_attempted"}
    ]


@pytest.mark.parametrize("stage", diagnostics.STAGES)
def test_fixed_stage_categories(stage):
    store = diagnostics.RelayDiagnostics()
    store.record(host="cdn.example.com", stage=stage, reason="upstream_eof")
    assert store.snapshot(include_recent=True)["recent"][0]["stage"] == stage


@pytest.mark.parametrize(
    "host",
    [
        "https://cdn.example.com/object.js?token=secret",
        "cdn.example.com/object.js",
        "cdn.example.com?token=secret",
        "cdn.example.com#secret",
        "user:secret@cdn.example.com",
        "cdn.example.com\nsecret",
        "cdn.example.com\rsecret",
        "cdn.example.com\x00secret",
        "cdn.example.com:443",
        "127.0.0.1",
        "2001:db8::1",
        "[2001:db8::1]",
        "cdn.example.com.",
        "CDN.example.com",
        "localhost",
        "cdn..example.com",
        "-cdn.example.com",
        "cdn_.example.com",
        "a" * 64 + ".example.com",
        "a." * 127 + "com",
        "cdn.example.123",
        "cdn.exämple.com",
        "",
        None,
        123,
    ],
)
def test_private_or_noncanonical_hosts_are_not_retained_or_formatted(host):
    store = diagnostics.RelayDiagnostics()
    store.record(host=host, stage="local_strategy", reason="write_error")
    assert store.snapshot(include_recent=True)["recent"][0]["host"] == "invalid"
    assert diagnostics.format_event(
        host=host, stage="local_strategy", reason="write_error"
    ) == "relay-end host=invalid stage=local_strategy reason=write_error recovery=not_attempted"


def test_hostile_values_never_call_string_or_equality_methods():
    class Hostile:
        def __str__(self):
            pytest.fail("must not stringify arbitrary objects")

        def __eq__(self, other):
            pytest.fail("must not compare arbitrary objects")

    class HostileString(str):
        def split(self, *args):
            pytest.fail("must not call string subclass methods")

    store = diagnostics.RelayDiagnostics()
    assert store.record(host=Hostile(), stage=Hostile(), reason=Hostile())
    assert store.record(host=HostileString("cdn.example.com"), stage=[], reason={})
    expected = {"host": "invalid", "stage": "unknown", "reason": "unknown",
                "recovery": "not_attempted"}
    assert store.snapshot(include_recent=True)["recent"] == [expected, expected]
    assert diagnostics.format_event(
        host=Hostile(), stage=Hostile(), reason=Hostile()
    ) == "relay-end host=invalid stage=unknown reason=unknown recovery=not_attempted"


def test_history_and_counter_keys_are_bounded_and_snapshots_detached():
    store = diagnostics.RelayDiagnostics()
    for index in range(diagnostics.RECENT_LIMIT + 3):
        assert store.record(
            host=f"host{index}.example.com", stage="geph", reason="authorized_retry"
        )
    snapshot = store.snapshot(include_recent=True)
    assert len(snapshot["recent"]) == diagnostics.RECENT_LIMIT
    assert snapshot["recent"][0]["host"] == "host3.example.com"
    assert set(snapshot["counters"]) == set(diagnostics.REASONS)
    assert snapshot["counters"]["authorized_retry"] == diagnostics.RECENT_LIMIT + 3
    snapshot["recent"][0]["host"] = "mutation.invalid"
    snapshot["recent"].clear()
    snapshot["counters"]["upstream_eof"] = -1
    fresh = store.snapshot(include_recent=True)
    assert fresh["recent"][0]["host"] == "host3.example.com"
    assert fresh["counters"]["upstream_eof"] == 0
    json.dumps(fresh, allow_nan=False)


def test_counters_saturate_instead_of_growing_unbounded():
    store = diagnostics.RelayDiagnostics()
    store._counters["upstream_eof"] = diagnostics.COUNTER_LIMIT - 1
    for _ in range(3):
        assert store.record(host="cdn.example.com", stage="unknown", reason="upstream_eof")
    snapshot = store.snapshot()
    assert snapshot["counters"]["upstream_eof"] == diagnostics.COUNTER_LIMIT
    assert snapshot["counter_saturated"] is True


def test_lock_contention_drops_record_and_reports_unavailable_without_wait():
    store = diagnostics.RelayDiagnostics()
    with store._lock:
        assert not store.record(host="cdn.example.com", stage="unknown", reason="client_eof")
        assert store.snapshot(include_recent=True) == {
            "schema_version": 1,
            "available": False,
            "counters": {},
            "counter_saturated": False,
            "recent": [],
        }
    assert sum(store.snapshot()["counters"].values()) == 0


def test_formatter_failure_is_drop_only_and_does_not_take_lock(monkeypatch):
    store = diagnostics.RelayDiagnostics()

    def fail(*_args):
        raise RuntimeError("secret exception must not be formatted")

    monkeypatch.setattr(diagnostics, "_safe_event", fail)
    assert not store.record(host="cdn.example.com", stage="unknown", reason="upstream_eof")
    assert diagnostics.format_event(
        host="cdn.example.com", stage="unknown", reason="upstream_eof"
    ) is None
    assert store._lock.acquire(blocking=False)
    store._lock.release()


def test_internal_diagnostic_failure_does_not_escape_and_releases_lock():
    class BrokenHistory:
        def append(self, _event):
            raise RuntimeError("secret diagnostic failure")

        def __iter__(self):
            raise RuntimeError("secret diagnostic failure")

    store = diagnostics.RelayDiagnostics()
    store._recent = BrokenHistory()
    assert not store.record(host="cdn.example.com", stage="unknown", reason="cancellation")
    assert store.snapshot(include_recent=True)["available"] is False
    assert store._lock.acquire(blocking=False)
    store._lock.release()


@pytest.mark.parametrize("include_recent", [False, None, 1, "true", [], {}])
def test_public_snapshot_cannot_include_host_history_without_literal_true(include_recent):
    store = diagnostics.RelayDiagnostics()
    store.record(host="cdn.example.com", stage="system_plain", reason="upstream_eof")
    for snapshot in [store.snapshot(), store.snapshot(include_recent=include_recent)]:
        assert "recent" not in snapshot
        assert "cdn.example.com" not in json.dumps(snapshot)
        assert snapshot["counters"]["upstream_eof"] == 1


@pytest.mark.parametrize("recovery", diagnostics.RECOVERY)
def test_recovery_disposition_is_observed_not_computed(recovery):
    store = diagnostics.RelayDiagnostics()
    store.record(host="cdn.example.com", stage="system_plain",
                 reason="upstream_eof", recovery=recovery)
    assert store.snapshot(include_recent=True)["recent"][0]["recovery"] == recovery
    assert diagnostics.format_event(host="cdn.example.com", stage="system_plain",
                                    reason="upstream_eof", recovery=recovery).endswith(
        f" recovery={recovery}"
    )


def test_unknown_recovery_cannot_leak_or_claim_a_committed_route():
    store = diagnostics.RelayDiagnostics()
    store.record(host="cdn.example.com", stage="system_plain", reason="upstream_eof",
                 recovery="secret exception or URL")
    assert store.snapshot(include_recent=True)["recent"][0]["recovery"] == "not_attempted"


def test_lock_implementation_failure_never_escapes():
    class BrokenLock:
        def __init__(self, acquire_fails):
            self.acquire_fails = acquire_fails

        def acquire(self, *, blocking):
            assert blocking is False
            if self.acquire_fails:
                raise RuntimeError("secret")
            return True

        def release(self):
            raise RuntimeError("secret")

    for acquire_fails in (True, False):
        store = diagnostics.RelayDiagnostics()
        store._lock = BrokenLock(acquire_fails)
        assert store.record(host="cdn.example.com", stage="unknown",
                            reason="client_eof") is (not acquire_fails)
        assert store.snapshot()["available"] is (not acquire_fails)
