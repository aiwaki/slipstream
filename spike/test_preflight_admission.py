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
    monkeypatch.setattr(tproxy, "ROUTE_PREFLIGHT_CONCURRENT_MAX", 2)
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


def test_completed_starts_do_not_block_parent_child_execution(monkeypatch):
    _enable_owned_geph_preflight(monkeypatch)
    now = tproxy.time.monotonic()
    tproxy._route_preflight_window.extend([now] * 20)
    calls = []
    assert asyncio.run(tproxy._run_initial_route_preflight(
        "shell.example", "8.8.8.8",
        direct_probe=lambda *_args: _bootstrap_root_observation("child.example"),
        bootstrap_direct_probe=lambda *_args: calls.append("child") or _complete(),
        bootstrap_resolver=lambda _host: ["1.1.1.1"],
    )) is None
    assert calls == ["child"]
    assert _counts() == (0, 0, 22)
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


def test_retryable_root_can_retry_without_minute_cooldown():
    calls = []
    def probe(*_args):
        calls.append(1)
        return tproxy._SemanticPlainPreflightObservation(
            tproxy.SEMANTIC_OUTCOME_TERMINAL_ERROR,
            retryable_inconclusive=True,
            root_boundary=tproxy._RootPreflightBoundary.TLS_HANDSHAKE_TIMEOUT,
        )
    for _ in range(12):
        assert asyncio.run(tproxy._run_initial_route_preflight(
            "retry.example", "8.8.8.8", direct_probe=probe,
        )) is None
    assert len(calls) == 12
    assert not tproxy._route_preflight_cache
    assert not tproxy._auto_geph_learned_exact_host("retry.example")
    assert _counts() == (0, 0, 12)


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


def test_eight_socket_roots_run_concurrently_and_ninth_is_bounded(monkeypatch):
    assert tproxy.ROUTE_PREFLIGHT_CONCURRENT_MAX == 8
    async def scenario():
        entered = 0
        ready = asyncio.Event()
        release = asyncio.Event()
        async def probe(*_args):
            nonlocal entered
            entered += 1
            if entered == 8:
                ready.set()
            await release.wait()
            return tproxy._SemanticPlainPreflightObservation(tproxy.SEMANTIC_OUTCOME_USABLE)
        monkeypatch.setattr(tproxy, "_run_bounded_direct_route_preflight", probe)
        tasks = [asyncio.create_task(tproxy._run_initial_route_preflight(
            f"parallel-{i}.example", "8.8.8.8", direct_probe=lambda *_: None,
        )) for i in range(8)]
        try:
            await asyncio.wait_for(ready.wait(), 1)
            assert _counts()[0] == 8
            assert await tproxy._run_initial_route_preflight(
                "overflow.example", "8.8.8.8", direct_probe=lambda *_: None,
            ) is None
            assert entered == 8
        finally:
            release.set()
            await asyncio.gather(*tasks)
        assert _counts()[0] == 0
    asyncio.run(scenario())


def test_browser_preflight_has_separate_two_worker_bound(monkeypatch):
    async def scenario():
        entered = 0
        ready = asyncio.Event()
        release = asyncio.Event()
        async def browser(*_args, **_kwargs):
            nonlocal entered
            entered += 1
            if entered == 2:
                ready.set()
            await release.wait()
        monkeypatch.setattr(tproxy, "_run_admitted_headless_owned_geph_preflight", browser)
        tasks = [asyncio.create_task(tproxy._run_headless_owned_geph_preflight()) for _ in range(2)]
        try:
            await asyncio.wait_for(ready.wait(), 1)
            assert await tproxy._run_headless_owned_geph_preflight() is None
            assert entered == 2
        finally:
            release.set()
            await asyncio.gather(*tasks)
        await tproxy._run_headless_owned_geph_preflight()
        assert entered == 3
    asyncio.run(scenario())
