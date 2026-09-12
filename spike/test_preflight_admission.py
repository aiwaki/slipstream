"""Synthetic root/critical-child admission regressions; no network requests."""

import asyncio
import threading
from concurrent.futures import Future
from types import SimpleNamespace

import pytest
import tproxy
from test_tproxy_doh import (
    _bootstrap_evidence,
    _bootstrap_root_observation,
    _enable_owned_geph_preflight,
    reset_smart_dns_state,  # noqa: F401 -- shared autouse isolation fixture
)


@pytest.fixture(autouse=True)
def isolate_execution_leases(monkeypatch, reset_smart_dns_state):
    monkeypatch.setattr(tproxy, "_route_preflight_execution_leases", {})
    monkeypatch.setattr(
        tproxy, "_enqueue_route_preflight_root_diagnostic_record", lambda _record: None
    )


def _counts():
    with tproxy._route_preflight_lock:
        return (
            tproxy._route_preflight_execution_count_locked(),
            tproxy._route_preflight_reserved_count_locked(),
            len(tproxy._route_preflight_window),
        )


def _complete(*_args):
    return _bootstrap_evidence(
        tproxy.bootstrap_asset_preflight.RangeProbeOutcome.COMPLETE,
        body_bytes=65_536,
    )


def _incomplete():
    return _bootstrap_evidence(
        tproxy.bootstrap_asset_preflight.RangeProbeOutcome.INCOMPLETE,
        body_bytes=16_384,
        termination=tproxy._BOOTSTRAP_RANGE_TERMINATION_EOF,
    )


async def _standalone_child(host, probe=_complete):
    now = tproxy.time.monotonic()
    asset = tproxy.bootstrap_asset_preflight.EphemeralBootstrapAsset(
        exact_host=host, host_header=host, request_target="/entry.js"
    )
    return await tproxy._run_bootstrap_asset_preflight(
        asset,
        "unrelated-parent.example",
        "8.8.8.8",
        now + 1.0,
        now + 2.0,
        direct_probe=probe,
        geph_probe=lambda *_args: pytest.fail("complete direct child needs no Geph"),
        resolver=lambda _host: ["1.1.1.1"],
    )


def test_two_roots_transfer_slots_without_completing_coalesced_waiters(monkeypatch):
    _enable_owned_geph_preflight(monkeypatch)
    parents = ["first-shell.example", "second-shell.example"]
    children = ["first-critical.example", "second-critical.example"]
    root_entered = [threading.Event(), threading.Event()]
    child_entered = [threading.Event(), threading.Event()]
    release_roots = threading.Event()
    release_children = threading.Event()
    root_calls = []
    child_calls = []

    def root_probe(index):
        def probe(*_args):
            root_calls.append(index)
            root_entered[index].set()
            assert release_roots.wait(5.0)
            return _bootstrap_root_observation(children[index])

        return probe

    def child_probe(ip, host, request, *_deadlines):
        index = children.index(host)
        child_calls.append((ip, host, request))
        child_entered[index].set()
        assert release_children.wait(5.0)
        return _incomplete()

    async def scenario():
        owners = [
            asyncio.create_task(
                tproxy._run_initial_route_preflight(
                    parent,
                    "8.8.8.8",
                    direct_probe=root_probe(index),
                    bootstrap_direct_probe=child_probe,
                    bootstrap_geph_probe=_complete,
                    bootstrap_resolver=lambda _host: ["1.1.1.1"],
                )
            )
            for index, parent in enumerate(parents)
        ]
        waiters = []
        try:
            for entered in root_entered:
                assert await asyncio.to_thread(entered.wait, 2.0)
            assert _counts() == (2, 2, 2)
            parent_epochs = {
                parent: tproxy._route_preflight_inflight[(parent, "8.8.8.8")]
                for parent in parents
            }
            waiters = [
                asyncio.create_task(
                    tproxy._run_initial_route_preflight(
                        parent,
                        "8.8.8.8",
                        direct_probe=lambda *_args: pytest.fail("waiter repeated root"),
                    )
                )
                for parent in parents
            ]
            await asyncio.sleep(0)
            assert _counts() == (2, 2, 2)
            release_roots.set()
            for entered in child_entered:
                assert await asyncio.to_thread(entered.wait, 2.0)

            assert _counts() == (2, 0, 4)
            assert len(tproxy._route_preflight_inflight) == 4
            assert all(not task.done() for task in owners + waiters)
            for parent, child in zip(parents, children):
                parent_epoch = parent_epochs[parent]
                assert tproxy._route_preflight_inflight[(parent, "8.8.8.8")] is parent_epoch
                assert not parent_epoch.done()
                child_entries = [
                    (key, epoch)
                    for key, epoch in tproxy._route_preflight_inflight.items()
                    if key[0] == child
                ]
                assert len(child_entries) == 1
                child_key, child_epoch = child_entries[0]
                assert len(child_key) == 3
                assert child_key[1] == "1.1.1.1"
                assert child_epoch is not parent_epoch
                assert tproxy._route_preflight_execution_leases[child_epoch] is (
                    tproxy._route_preflight_execution_leases[parent_epoch]
                )
            assert await tproxy._run_initial_route_preflight(
                "third-shell.example",
                "8.8.4.4",
                direct_probe=lambda *_args: pytest.fail("third execution exceeded cap"),
            ) is None
            assert _counts() == (2, 0, 4)
            release_children.set()
            assert await asyncio.gather(*owners, *waiters) == [None] * 4
        finally:
            release_roots.set()
            release_children.set()
            await asyncio.gather(*owners, *waiters, return_exceptions=True)

    asyncio.run(scenario())
    assert sorted(root_calls) == [0, 1]
    assert len(child_calls) == 2
    assert all(ip == "1.1.1.1" and b"/entry.js" in request for ip, _, request in child_calls)
    assert all(tproxy._auto_geph_learned_exact_host(child) for child in children)
    assert not any(tproxy._auto_geph_learned_exact_host(parent) for parent in parents)
    assert _counts() == (0, 0, 4)
    assert not tproxy._route_preflight_inflight
    assert not tproxy._route_preflight_execution_leases


def test_child_reservation_survives_window_pruning_without_refunding_starts(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(
        tproxy, "time", SimpleNamespace(monotonic=lambda: clock[0], time=lambda: 1_000.0)
    )
    tproxy._route_preflight_window.extend([40.1] * 6)
    root_entered = threading.Event()
    release_root = threading.Event()
    child_calls = []

    def root_probe(*_args):
        root_entered.set()
        assert release_root.wait(5.0)
        return _bootstrap_root_observation("reserved-child.example")

    def child_probe(*args):
        child_calls.append(args)
        return _complete()

    async def scenario():
        owner = asyncio.create_task(
            tproxy._run_initial_route_preflight(
                "reserved-shell.example",
                "8.8.8.8",
                direct_probe=root_probe,
                bootstrap_direct_probe=child_probe,
                bootstrap_resolver=lambda _host: ["1.1.1.1"],
            )
        )
        try:
            assert await asyncio.to_thread(root_entered.wait, 2.0)
            assert _counts() == (1, 1, 7)
            rejected = await _standalone_child(
                "window-full.example",
                lambda *_args: pytest.fail("reserved credit was stolen"),
            )
            assert rejected == (False, tproxy.SEMANTIC_OUTCOME_TERMINAL_ERROR)
            assert _counts() == (1, 1, 7)

            clock[0] = 100.2
            for index in range(6):
                assert await _standalone_child(f"new-window-{index}.example") == (
                    False, tproxy.SEMANTIC_OUTCOME_USABLE
                )
                assert _counts() == (1, 1, index + 2)
            assert await _standalone_child(
                "ninth-start.example",
                lambda *_args: pytest.fail("more than eight starts in live window"),
            ) == (False, tproxy.SEMANTIC_OUTCOME_TERMINAL_ERROR)
            release_root.set()
            assert await owner is None
        finally:
            release_root.set()
            await asyncio.gather(owner, return_exceptions=True)

    asyncio.run(scenario())
    assert len(child_calls) == 1
    assert _counts() == (0, 0, 8)
    assert list(tproxy._route_preflight_window) == [100.0] + [100.2] * 7
    assert not tproxy._route_preflight_execution_leases


def test_root_without_child_releases_only_unused_reservation():
    for index in range(2):
        assert asyncio.run(
            tproxy._run_initial_route_preflight(
                f"root-only-{index}.example",
                "8.8.8.8",
                direct_probe=lambda *_args: tproxy.SEMANTIC_OUTCOME_USABLE,
            )
        ) is None
        assert _counts() == (0, 0, index + 1)
        assert not tproxy._route_preflight_execution_leases


def test_root_does_not_start_without_room_for_its_child_reservation():
    now = tproxy.time.monotonic()
    tproxy._route_preflight_window.extend([now] * 7)
    assert asyncio.run(
        tproxy._run_initial_route_preflight(
            "unreserved-shell.example",
            "8.8.8.8",
            direct_probe=lambda *_args: pytest.fail("root borrowed the child's last credit"),
        )
    ) is None
    assert _counts() == (0, 0, 7)
    assert not tproxy._route_preflight_execution_leases
    assert asyncio.run(_standalone_child("last-unreserved-credit.example")) == (
        False, tproxy.SEMANTIC_OUTCOME_USABLE
    )
    assert _counts() == (0, 0, 8)
    assert asyncio.run(
        _standalone_child(
            "past-last-credit.example",
            lambda *_args: pytest.fail("standalone child exceeded window cap"),
        )
    ) == (False, tproxy.SEMANTIC_OUTCOME_TERMINAL_ERROR)
    assert _counts() == (0, 0, 8)


@pytest.mark.parametrize("phase", ["root", "child"])
def test_cancellation_retains_execution_until_worker_drains(monkeypatch, phase):
    _enable_owned_geph_preflight(monkeypatch)
    parent = "cancelled-shell.example"
    child = "cancelled-child.example"
    entered = threading.Event()
    release = threading.Event()

    def root_probe(*_args, **_kwargs):
        if phase == "root":
            entered.set()
            assert release.wait(5.0)
        return _bootstrap_root_observation(child)

    def child_probe(*_args):
        assert phase == "child", "cancelled root must not admit child"
        entered.set()
        assert release.wait(5.0)
        return _incomplete()

    if phase == "root":
        # Exercise the production shield/control/drain adapter, not the legacy
        # bare-to_thread adapter used for arbitrary injected test callbacks.
        monkeypatch.setattr(tproxy, "_semantic_plain_preflight_probe_detail", root_probe)

        async def resolve_root(_host):
            return ["8.8.8.8"]

        monkeypatch.setattr(tproxy, "system_resolve_async", resolve_root)

    async def scenario():
        owner = asyncio.create_task(
            tproxy._run_initial_route_preflight(
                parent,
                "8.8.8.8",
                direct_probe=root_probe,
                bootstrap_direct_probe=child_probe,
                bootstrap_geph_probe=_complete,
                bootstrap_resolver=lambda _host: ["1.1.1.1"],
            )
        )
        waiter = None
        try:
            assert await asyncio.to_thread(entered.wait, 2.0)
            parent_epoch = tproxy._route_preflight_inflight[(parent, "8.8.8.8")]
            expected = (1, 1, 1) if phase == "root" else (1, 0, 2)
            assert _counts() == expected
            waiter = asyncio.create_task(
                tproxy._run_initial_route_preflight(
                    parent,
                    "8.8.8.8",
                    direct_probe=lambda *_args: pytest.fail("coalesced waiter started I/O"),
                )
            )
            await asyncio.sleep(0)
            owner.cancel()
            await asyncio.sleep(0.01)
            assert not owner.done()
            assert not waiter.done()
            assert not parent_epoch.done()
            assert _counts() == expected
            assert len(tproxy._route_preflight_inflight) == (1 if phase == "root" else 2)
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await owner
            assert await waiter is None
        finally:
            release.set()
            await asyncio.gather(owner, *([waiter] if waiter else []), return_exceptions=True)

    asyncio.run(scenario())
    assert _counts() == (0, 0, 1 if phase == "root" else 2)
    assert not tproxy._route_preflight_inflight
    assert not tproxy._route_preflight_execution_leases
    assert parent not in tproxy._route_preflight_cache
    assert child not in tproxy._route_preflight_cache
    assert not tproxy._auto_geph_learned_exact_host(parent)
    assert not tproxy._auto_geph_learned_exact_host(child)


@pytest.mark.parametrize(
    "case",
    ["foreign_task", "wrong_parent_address", "stale_root_epoch", "not_ready", "already_used"],
)
def test_invalid_or_reused_child_lease_cannot_admit_work(case):
    parent = "lease-owner.example"
    child = "lease-child.example"
    calls = []

    async def scenario():
        now = tproxy.time.monotonic()
        root_key = (parent, "8.8.8.8")
        root_epoch = Future()
        lease = tproxy._RoutePreflightExecutionLease(
            root_key=root_key,
            root_epoch=root_epoch,
            owner_task=asyncio.current_task(),
            child_ready=True,
        )
        tproxy._route_preflight_inflight[root_key] = root_epoch
        tproxy._route_preflight_execution_leases[root_epoch] = lease
        tproxy._route_preflight_window.append(now)

        async def invoke(*, allowed=False):
            asset = tproxy.bootstrap_asset_preflight.EphemeralBootstrapAsset(
                exact_host=child, host_header=child, request_target="/entry.js"
            )

            def direct(*args):
                assert allowed, "invalid scheduling lease started a child probe"
                calls.append(args)
                return _complete()

            return await tproxy._run_bootstrap_asset_preflight(
                asset,
                parent,
                "8.8.4.4" if case == "wrong_parent_address" else "8.8.8.8",
                now + 1.0,
                now + 2.0,
                direct_probe=direct,
                geph_probe=lambda *_args: pytest.fail("lease must not authorize Geph"),
                resolver=lambda _host: ["1.1.1.1"],
                execution_lease=lease,
            )

        if case == "already_used":
            assert await invoke(allowed=True) == (False, tproxy.SEMANTIC_OUTCOME_USABLE)
            assert len(calls) == 1
            assert lease.child_epoch is not None
            assert not lease.child_reserved
        elif case == "stale_root_epoch":
            tproxy._route_preflight_inflight[root_key] = Future()
        elif case == "not_ready":
            lease.child_ready = False
        before = _counts()
        epochs_before = dict(tproxy._route_preflight_inflight)
        if case == "foreign_task":
            result = await asyncio.create_task(invoke())
        else:
            result = await invoke()
        assert result == (False, tproxy.SEMANTIC_OUTCOME_TERMINAL_ERROR)
        assert _counts() == before
        assert tproxy._route_preflight_inflight == epochs_before
        assert len(calls) == (1 if case == "already_used" else 0)
        assert child not in tproxy._route_preflight_cache
        assert not tproxy._auto_geph_learned_exact_host(child)

    asyncio.run(scenario())


def test_root_window_refusal_is_visible_without_running_probe(monkeypatch):
    _enable_owned_geph_preflight(monkeypatch)
    records = []
    monkeypatch.setattr(tproxy, "_enqueue_route_preflight_root_diagnostic_record", records.append)
    now = tproxy.time.monotonic()
    tproxy._route_preflight_window.extend([now] * tproxy.ROUTE_PREFLIGHT_WINDOW_MAX)
    assert asyncio.run(tproxy._run_initial_route_preflight(
        "admission.example", "8.8.8.8",
        direct_probe=lambda *_args: pytest.fail("refused admission must not probe"),
    )) is None
    assert records == [
        ">> route-preflight-state host=admission.example decision=window_refused"
    ]


def test_state_diagnostic_sink_failure_cannot_escape(monkeypatch):
    def fail(_record):
        raise RuntimeError("sink failed")
    monkeypatch.setattr(tproxy, "_enqueue_route_preflight_root_diagnostic_record", fail)
    tproxy._log_route_preflight_state("admission.example", "window_refused")


def test_state_diagnostic_rejects_nonallowlisted_detail(monkeypatch):
    records = []
    monkeypatch.setattr(tproxy, "_enqueue_route_preflight_root_diagnostic_record", records.append)
    tproxy._log_route_preflight_state("admission.example", "arbitrary response detail")
    assert records == []
