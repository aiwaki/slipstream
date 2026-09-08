"""Pending critical-child joins are waits, never transferable route evidence."""

import asyncio
from concurrent.futures import Future
from types import SimpleNamespace

import pytest
import tproxy
from test_tproxy_doh import reset_smart_dns_state  # noqa: F401


HOST = "critical.example.com"
ADDRESS = "1.1.1.1"


@pytest.fixture
def join_state(monkeypatch, reset_smart_dns_state):
    state = {"learned": False, "ready": True}
    monkeypatch.setattr(tproxy, "_auto_geph_base_host_allowed", lambda h: h == HOST)
    monkeypatch.setattr(
        tproxy, "_auto_geph_learned_exact_host", lambda h: h == HOST and state["learned"]
    )
    monkeypatch.setattr(
        tproxy, "_owned_geph_ready_for_semantic_confirmation", lambda: state["ready"]
    )
    monkeypatch.setattr(
        tproxy, "_new_direct_route_preflight_job",
        lambda *_args: pytest.fail("joined child must not create another root job"),
    )
    return state


def pending_child(*, address=ADDRESS, deadline=None):
    future = Future()
    deadline = tproxy.time.monotonic() + 10.0 if deadline is None else deadline
    future._slipstream_bootstrap_wait = tproxy._PendingBootstrapChildWait(
        future, HOST, address, deadline,
    )
    key = (HOST, address, "private-test-epoch")
    tproxy._route_preflight_inflight[key] = future
    return future


async def start_waiter():
    task = asyncio.create_task(tproxy._run_initial_route_preflight(
        HOST, ADDRESS, deadline_monotonic=tproxy.time.monotonic() + 23.0,
    ))
    for _ in range(3):
        await asyncio.sleep(0)
    assert not task.done()
    return task


def test_pending_child_precedes_usable_root_cache_and_needs_no_new_connection(join_state):
    async def scenario():
        future = pending_child()
        cached = tproxy._RoutePreflightCacheEntry(
            tproxy.time.monotonic() + 60.0, tproxy.SEMANTIC_OUTCOME_USABLE, ADDRESS,
        )
        tproxy._route_preflight_cache[HOST] = cached
        waiter = await start_waiter()
        assert len(tproxy._route_preflight_inflight) == 1
        assert not tproxy._route_preflight_window
        join_state["learned"] = True
        future.set_result(True)
        claim = await waiter
        assert isinstance(claim, tproxy._RoutePreflightOwnedGephClaim)
        assert claim.host == HOST
        assert tproxy._route_preflight_cache[HOST] is cached
        assert not tproxy._route_preflight_window

    asyncio.run(scenario())


@pytest.mark.parametrize("child_result", [False, True, RuntimeError("synthetic")])
def test_child_completion_without_committed_route_is_not_authority(join_state, child_result):
    async def scenario():
        future = pending_child()
        waiter = await start_waiter()
        if isinstance(child_result, Exception):
            future.set_exception(child_result)
        else:
            future.set_result(child_result)
        assert await waiter is None
        assert not tproxy._route_preflight_cache
        assert not tproxy._route_preflight_window

    asyncio.run(scenario())


def test_child_commit_still_requires_current_owned_readiness(join_state):
    async def scenario():
        future = pending_child()
        waiter = await start_waiter()
        join_state.update(learned=True, ready=False)
        future.set_result(True)
        assert await waiter is None

    asyncio.run(scenario())


def test_cancelled_waiter_does_not_cancel_child_or_other_waiter(join_state):
    async def scenario():
        future = pending_child()
        first = await start_waiter()
        second = await start_waiter()
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        assert not future.done()
        assert not second.done()
        join_state["learned"] = True
        future.set_result(True)
        assert isinstance(await second, tproxy._RoutePreflightOwnedGephClaim)

    asyncio.run(scenario())


def test_join_can_outlive_root_proof_budget_without_creating_expired_job(join_state, monkeypatch):
    async def scenario():
        future = pending_child(deadline=tproxy.time.monotonic() + 18.0)
        waits = []

        async def complete_wait(awaitable, *, timeout):
            waits.append(timeout)
            future.set_result(False)
            return await awaitable

        monkeypatch.setattr(tproxy.asyncio, "wait_for", complete_wait)
        assert await tproxy._run_initial_route_preflight(
            HOST, ADDRESS, deadline_monotonic=tproxy.time.monotonic() + 23.0,
        ) is None
        assert len(waits) == 1
        assert 8.0 < waits[0] <= 18.0

    asyncio.run(scenario())


def test_join_deadline_is_capped_and_timeout_does_not_cancel_child(join_state, monkeypatch):
    async def scenario():
        future = pending_child(deadline=tproxy.time.monotonic() + 1000.0)
        waits = []

        async def expire_wait(awaitable, *, timeout):
            waits.append(timeout)
            awaitable.cancel()  # cancel only the same outer shield wait_for would cancel
            raise asyncio.TimeoutError

        monkeypatch.setattr(tproxy.asyncio, "wait_for", expire_wait)
        assert await tproxy._run_initial_route_preflight(
            HOST, ADDRESS, deadline_monotonic=tproxy.time.monotonic() + 1000.0,
        ) is None
        assert len(waits) == 1
        assert 0.0 < waits[0] <= 19.0
        assert not future.done()
        future.set_result(False)
        await asyncio.sleep(0)

    asyncio.run(scenario())


def test_committed_child_gets_fresh_handoff_after_generic_root_budget(join_state, monkeypatch):
    async def scenario():
        clock = [100.0]
        monkeypatch.setattr(tproxy, "time", SimpleNamespace(
            monotonic=lambda: clock[0], time=tproxy.time.time,
        ))
        future = pending_child(deadline=118.0)

        async def complete_wait(awaitable, *, timeout):
            assert timeout == 18.0
            clock[0] = 117.5
            join_state["learned"] = True
            future.set_result(True)
            return await awaitable

        monkeypatch.setattr(tproxy.asyncio, "wait_for", complete_wait)
        claim = await tproxy._run_initial_route_preflight(HOST, ADDRESS)
        assert isinstance(claim, tproxy._RoutePreflightOwnedGephClaim)
        assert claim.deadline_monotonic == 121.5
        assert claim.deadline_monotonic > clock[0]

    asyncio.run(scenario())


def test_pending_child_local_winner_is_rechecked_without_root_health_authority(join_state):
    async def scenario():
        future = pending_child()
        waiter = await start_waiter()
        winner = tproxy._BootstrapLocalWinner(
            HOST, ADDRESS, "8.8.8.8", "split16", False, "a" * 32,
            tproxy.time.monotonic() + 5,
        )
        assert tproxy._store_bootstrap_local_route(winner)
        future.set_result(False)
        claim = await waiter
        assert isinstance(claim, tproxy._BootstrapLocalRouteClaim)
        assert claim.address == "8.8.8.8" and claim.strategy_name == "split16"
        assert not join_state["learned"]
        assert not tproxy._route_preflight_cache

    asyncio.run(scenario())


@pytest.mark.parametrize("local", [False, True])
def test_exact_close_does_not_discard_an_already_admitted_child_join(join_state, local):
    async def scenario():
        future = pending_child(deadline=tproxy.time.monotonic() + 18)
        exact_allowed = asyncio.Event()

        async def closed(*args, **kwargs):
            await exact_allowed.wait()
            return tproxy.SYSTEM_PROBE_CLOSED, None

        now = tproxy.time.monotonic()
        race = asyncio.create_task(tproxy._run_unknown_initial_route_race(
            HOST, ADDRESS, 443, b"client first flight",
            hard_recovery_deadline_monotonic=now + 8,
            semantic_handoff_deadline_monotonic=now + 12,
            exact_probe=closed,
        ))
        for _ in range(4):
            await asyncio.sleep(0)
        exact_allowed.set()
        for _ in range(4):
            await asyncio.sleep(0)
        assert not race.done() and not future.done()
        if local:
            assert tproxy._store_bootstrap_local_route(tproxy._BootstrapLocalWinner(
                HOST, ADDRESS, "8.8.8.8", "split16", False, "a" * 32,
                tproxy.time.monotonic() + 5,
            ))
        else:
            join_state["learned"] = True
        future.set_result(True)
        system, exact, claim = await race
        assert system == tproxy.SYSTEM_PROBE_CLOSED and exact is None
        expected = (tproxy._BootstrapLocalRouteClaim if local
                    else tproxy._RoutePreflightOwnedGephClaim)
        assert isinstance(claim, expected)

    asyncio.run(scenario())


def test_exact_close_still_cancels_generic_preflight_without_child_join(join_state):
    async def scenario():
        stopped = asyncio.Event()

        async def closed(*args, **kwargs):
            return tproxy.SYSTEM_PROBE_CLOSED, None

        async def generic(*args, **kwargs):
            try:
                await asyncio.Event().wait()
            finally:
                stopped.set()

        now = tproxy.time.monotonic()
        result = await tproxy._run_unknown_initial_route_race(
            HOST, ADDRESS, 443, b"client first flight",
            hard_recovery_deadline_monotonic=now + 8,
            semantic_handoff_deadline_monotonic=now + 12,
            exact_probe=closed, route_preflight=generic,
        )
        assert result == (tproxy.SYSTEM_PROBE_CLOSED, None, None)
        assert stopped.is_set()

    asyncio.run(scenario())


def test_held_initial_payload_does_not_override_full_object_local_winner(join_state, monkeypatch):
    async def scenario():
        future = pending_child()
        held_writer = object()
        closed = []

        async def payload(*args, **kwargs):
            return tproxy.SYSTEM_PROBE_PAYLOAD, (object(), held_writer, b"held TLS bytes")

        async def close(writer):
            closed.append(writer)

        monkeypatch.setattr(tproxy, "_close_stream_writer", close)
        now = tproxy.time.monotonic()
        race = asyncio.create_task(tproxy._run_unknown_initial_route_race(
            HOST, ADDRESS, 443, b"client first flight",
            hard_recovery_deadline_monotonic=now + 8,
            semantic_handoff_deadline_monotonic=now + 12,
            exact_probe=payload,
        ))
        for _ in range(4):
            await asyncio.sleep(0)
        assert not race.done() and not closed
        assert tproxy._store_bootstrap_local_route(tproxy._BootstrapLocalWinner(
            HOST, ADDRESS, "8.8.8.8", "split16", False, "a" * 32,
            tproxy.time.monotonic() + 5,
        ))
        future.set_result(True)
        _system, exact, claim = await race
        assert exact is None and isinstance(claim, tproxy._BootstrapLocalRouteClaim)
        assert closed == [held_writer]

    asyncio.run(scenario())


@pytest.mark.parametrize("outcome", ["local", "local_race", "geph", "inconclusive", "cancel_waiter"])
def test_coalesced_root_waits_for_active_child_before_nonce_exists(join_state, monkeypatch, outcome):
    async def scenario():
        root_future = Future()
        root_key = (HOST, ADDRESS)
        entered, release = asyncio.Event(), asyncio.Event()
        monkeypatch.setattr(tproxy, "_new_direct_route_preflight_job",
                            lambda host: SimpleNamespace(capability="b" * 32))

        async def observed(*args, **kwargs):
            entered.set()
            await release.wait()
            if outcome in ("local", "local_race"):
                assert tproxy._store_bootstrap_local_route(tproxy._BootstrapLocalWinner(
                    HOST, ADDRESS, "8.8.8.8", "split16", False, "a" * 32,
                    tproxy.time.monotonic() + 5,
                ))
            elif outcome == "geph":
                join_state["learned"] = True
            return outcome == "geph", tproxy.SEMANTIC_OUTCOME_USABLE

        monkeypatch.setattr(tproxy, "_run_bootstrap_asset_preflight_observed", observed)

        async def owner():
            lease = tproxy._RoutePreflightExecutionLease(
                root_key, root_future, asyncio.current_task(), child_ready=True,
            )
            tproxy._route_preflight_inflight[root_key] = root_future
            tproxy._route_preflight_execution_leases[root_future] = lease
            now = tproxy.time.monotonic()
            await tproxy._run_bootstrap_asset_preflight(
                object(), HOST, ADDRESS, now + 0.5, now + 0.5, execution_lease=lease,
            )
            assert not hasattr(root_future, "_slipstream_bootstrap_wait")
            assert not hasattr(asyncio.current_task(), "_slipstream_bootstrap_join")
            root_future.set_result(outcome == "geph")

        owner_task = asyncio.create_task(owner())
        await entered.wait()
        assert all(len(key) == 2 for key in tproxy._route_preflight_inflight)
        original_deadline = tproxy.time.monotonic() + 0.01
        initial_handoff = original_deadline + tproxy.UNKNOWN_RECOVERY_GEPH_RESERVE
        preflight_tasks = []
        async def preflight(*args, **kwargs):
            preflight_tasks.append(asyncio.current_task())
            return await tproxy._run_initial_route_preflight(*args, **kwargs)
        async def closed(*args, **kwargs):
            return tproxy.SYSTEM_PROBE_CLOSED, None
        if outcome == "local_race":
            waiter = asyncio.create_task(tproxy._run_unknown_initial_route_race(
                HOST, ADDRESS, 443, b"first flight", route_preflight=preflight,
                exact_probe=closed, hard_recovery_deadline_monotonic=original_deadline,
                semantic_handoff_deadline_monotonic=initial_handoff,
            ))
        else:
            waiter = asyncio.create_task(tproxy._run_initial_route_preflight(
                HOST, ADDRESS, deadline_monotonic=initial_handoff,
            ))
        async def until_extended():
            while True:
                actual = preflight_tasks[0] if preflight_tasks else waiter
                if hasattr(actual, "_slipstream_bootstrap_join"):
                    return
                if waiter.done():
                    pytest.fail("root waiter returned before active child completed")
                await asyncio.sleep(0)
        await asyncio.wait_for(until_extended(), 0.5)
        assert not root_future.done() and not owner_task.done()
        if outcome == "cancel_waiter":
            waiter.cancel()
            with pytest.raises(asyncio.CancelledError):
                await waiter
            assert not root_future.done() and not owner_task.done()
        release.set()
        await owner_task
        if outcome != "cancel_waiter":
            claim = await waiter
            if outcome == "local_race":
                system, exact, claim = claim
                assert system == tproxy.SYSTEM_PROBE_CLOSED and exact is None
            if outcome in ("local", "local_race"):
                assert isinstance(claim, tproxy._BootstrapLocalRouteClaim)
            elif outcome == "geph":
                assert isinstance(claim, tproxy._RoutePreflightOwnedGephClaim)
                assert claim.capability != "b" * 32
                assert claim.deadline_monotonic > original_deadline
            else:
                assert claim is None
        assert not hasattr(waiter, "_slipstream_bootstrap_join")
        assert not hasattr(waiter, "_slipstream_bootstrap_owner_wait")

    asyncio.run(scenario())


def test_owner_child_wrapper_survives_exact_close_during_resolution(join_state, monkeypatch):
    async def scenario():
        root_future = Future()
        root_key = (HOST, ADDRESS)
        entered, release = asyncio.Event(), asyncio.Event()

        async def observed(*args, **kwargs):
            entered.set()
            await release.wait()
            return True, "owned_geph"

        monkeypatch.setattr(tproxy, "_run_bootstrap_asset_preflight_observed", observed)

        async def preflight(*args, **kwargs):
            lease = tproxy._RoutePreflightExecutionLease(
                root_key, root_future, asyncio.current_task(), child_ready=True,
            )
            tproxy._route_preflight_inflight[root_key] = root_future
            tproxy._route_preflight_execution_leases[root_future] = lease
            now = tproxy.time.monotonic()
            await tproxy._run_bootstrap_asset_preflight(
                object(), HOST, ADDRESS, now + 1, now + 1, execution_lease=lease,
            )
            return tproxy._owned_geph_preflight_claim(HOST, "a" * 32, now + 4)

        async def closed(*args, **kwargs):
            await entered.wait()
            return tproxy.SYSTEM_PROBE_CLOSED, None

        now = tproxy.time.monotonic()
        race = asyncio.create_task(tproxy._run_unknown_initial_route_race(
            HOST, ADDRESS, 443, b"first flight", exact_probe=closed,
            route_preflight=preflight, hard_recovery_deadline_monotonic=now + 8,
            semantic_handoff_deadline_monotonic=now + 12,
        ))
        await entered.wait()
        for _ in range(4):
            await asyncio.sleep(0)
        assert not race.done()
        release.set()
        system, exact, claim = await race
        assert system == tproxy.SYSTEM_PROBE_CLOSED and exact is None
        assert isinstance(claim, tproxy._RoutePreflightOwnedGephClaim)
        assert not hasattr(root_future, "_slipstream_bootstrap_wait")

    asyncio.run(scenario())


@pytest.mark.parametrize("mismatch", ["epoch", "lease", "host", "ip", "expired", "unready"])
def test_root_child_extension_requires_live_bound_owner(join_state, monkeypatch, mismatch):
    async def scenario():
        future = Future()
        key = (HOST, ADDRESS)
        owner = asyncio.create_task(asyncio.Event().wait())
        lease = tproxy._RoutePreflightExecutionLease(key, future, owner, child_ready=True)
        tproxy._route_preflight_inflight[key] = future
        tproxy._route_preflight_execution_leases[future] = lease
        metadata = tproxy._PendingBootstrapChildWait(
            future, HOST, ADDRESS, tproxy.time.monotonic() + 10,
        )
        if mismatch == "epoch":
            tproxy._route_preflight_inflight[key] = Future()
        elif mismatch == "lease":
            lease.root_epoch = Future()
        elif mismatch == "unready":
            lease.child_ready = False
        else:
            from dataclasses import replace
            metadata = replace(metadata, **{
                "host": {"host": "different.example.com"},
                "ip": {"exact_address": "8.8.8.8"},
                "expired": {"deadline_monotonic": 0},
            }[mismatch])
        future._slipstream_bootstrap_wait = metadata
        with tproxy._route_preflight_lock:
            assert tproxy._route_preflight_owner_child_deadline_locked(
                future, key, tproxy.time.monotonic(),
            ) is None
        owner.cancel()
        await asyncio.gather(owner, return_exceptions=True)

    asyncio.run(scenario())


@pytest.mark.parametrize("case", [
    "different_ip", "root_epoch", "missing_metadata", "wrong_future",
    "wrong_host", "wrong_address", "expired", "nonfinite", "boolean",
])
def test_join_rejects_unrelated_or_unbound_epochs(join_state, case):
    async def scenario():
        future = pending_child(address="8.8.8.8" if case == "different_ip" else ADDRESS)
        metadata = future._slipstream_bootstrap_wait
        if case == "root_epoch":
            tproxy._route_preflight_inflight.clear()
            tproxy._route_preflight_inflight[(HOST, ADDRESS)] = future
        elif case == "missing_metadata":
            del future._slipstream_bootstrap_wait
        elif case not in {"different_ip"}:
            future._slipstream_bootstrap_wait = tproxy._PendingBootstrapChildWait(
                Future() if case == "wrong_future" else future,
                "other.example.com" if case == "wrong_host" else HOST,
                "8.8.8.8" if case == "wrong_address" else ADDRESS,
                tproxy.time.monotonic() - 1 if case == "expired"
                else float("inf") if case == "nonfinite"
                else True if case == "boolean"
                else metadata.deadline_monotonic,
            )
        assert not await tproxy._wait_for_pending_bootstrap_children(
            HOST, ADDRESS,
        )
        assert not future.done()
        future.set_result(False)

    asyncio.run(scenario())
