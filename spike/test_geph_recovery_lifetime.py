"""A shared owned-Geph recovery belongs to its worker, not an individual waiter."""

import asyncio
import json
import os
import socket
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
import tproxy


@pytest.fixture(autouse=True)
def isolated_recovery(monkeypatch):
    forbidden_calls = []

    def forbidden(*args, **kwargs):
        forbidden_calls.append("external effect")
        raise AssertionError("recovery lifetime fixture forbids external I/O")

    for owner, names in (
        (socket.socket, ("connect", "connect_ex", "bind", "listen")),
        (socket, ("getaddrinfo", "create_connection")),
        (asyncio, ("open_connection", "start_server", "create_subprocess_exec",
                   "create_subprocess_shell")),
        (subprocess, ("Popen",)), (os, ("system",)),
        (tproxy, ("_run", "_console_user_home", "execute_owned_geph_restart")),
        (tproxy.geph_backend, ("read_enabled",)),
    ):
        for name in names:
            monkeypatch.setattr(owner, name, forbidden)
    monkeypatch.setattr(tproxy, "_owned_geph_runtime_recovery_future", None)
    monkeypatch.setattr(tproxy, "_owned_geph_runtime_recovery_lock", threading.Lock())
    pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="geph-lifetime-fixture")
    monkeypatch.setattr(tproxy, "_POOL", pool)
    # Keep the production wait_for and its additive one-second budget real.
    monkeypatch.setattr(tproxy, "GEPH_RESTART_SUCCESSOR_GRACE", 0.0)
    monkeypatch.setattr(tproxy, "GEPH_RESTART_PAYLOAD_READY_GRACE", 0.0)
    try:
        yield pool
    finally:
        pool.shutdown(wait=True, cancel_futures=True)
        assert all(not thread.is_alive() for thread in pool._threads)
        assert forbidden_calls == []


class ControlledRecovery:
    def __init__(self, monkeypatch, outcome=True):
        loop = asyncio.get_running_loop()
        self.entered = asyncio.Event()
        self.returned = asyncio.Event()
        self.release = threading.Event()
        self.subscriptions = asyncio.Queue()
        self.tasks = []
        self.calls = []
        self.threads = []
        self.outcome = outcome
        self.wrappers = []
        self.exception_observations = asyncio.Queue()

        def recover(host):
            self.calls.append(host)
            self.threads.append(threading.current_thread())
            loop.call_soon_threadsafe(self.entered.set)
            try:
                assert self.release.wait(2.0), "fixture failed to release its worker"
                if isinstance(self.outcome, BaseException):
                    raise self.outcome
                return self.outcome
            finally:
                loop.call_soon_threadsafe(self.returned.set)

        original_wrap = asyncio.wrap_future

        def observe_subscription(future, *args, **kwargs):
            result = original_wrap(future, *args, **kwargs)
            original_exception = result.exception

            def observe_exception():
                value = original_exception()
                self.exception_observations.put_nowait(result)
                return value

            result.exception = observe_exception
            self.wrappers.append(result)
            self.subscriptions.put_nowait(asyncio.current_task())
            return result

        monkeypatch.setattr(tproxy, "_recover_owned_geph_for_replay_blocking", recover)
        monkeypatch.setattr(asyncio, "wrap_future", observe_subscription)

    def caller(self):
        task = asyncio.create_task(
            tproxy._coalesced_owned_geph_recovery_for_replay("fixture.invalid")
        )
        self.tasks.append(task)
        return task

    async def subscribed(self, task):
        async def find_task():
            while await self.subscriptions.get() is not task:
                pass
        await asyncio.wait_for(find_task(), 1.0)

    async def close(self):
        self.release.set()
        for task in self.tasks:
            if not task.done():
                task.cancel()
        await asyncio.wait_for(asyncio.gather(*self.tasks, return_exceptions=True), 1.0)
        await asyncio.wait_for(self.returned.wait(), 1.0)
        assert all(task.done() for task in self.tasks)


def result_kind(value):
    return type(value).__name__ if isinstance(value, BaseException) else value


def test_cancelled_owner_still_publishes_worker_result_to_follower(monkeypatch):
    async def case():
        worker = ControlledRecovery(monkeypatch)
        try:
            monkeypatch.setattr(tproxy, "GEPH_RESTART_SUCCESSOR_GRACE", 2.0)
            owner = worker.caller()
            await asyncio.wait_for(worker.entered.wait(), 1.0)
            monkeypatch.setattr(tproxy, "GEPH_RESTART_SUCCESSOR_GRACE", 0.0)
            follower = worker.caller()
            await worker.subscribed(follower)
            shared = tproxy._owned_geph_runtime_recovery_future
            owner.cancel()
            with pytest.raises(asyncio.CancelledError):
                await owner
            assert not worker.returned.is_set()
            worker.release.set()
            await asyncio.wait_for(worker.returned.wait(), 1.0)
            result = await asyncio.wait_for(follower, 1.5)
            observed = {"case": "owner_cancel", "follower": result,
                        "worker_returned": worker.returned.is_set(),
                        "shared_done": shared.done(), "shared_cancelled": shared.cancelled()}
        finally:
            await worker.close()
        return worker, observed

    worker, observed = asyncio.run(case())
    assert worker.calls == ["fixture.invalid"]
    assert worker.returned.is_set()
    print(json.dumps(observed, sort_keys=True))
    assert observed["follower"] is True, "owner cancellation lost the completed recovery result"


@pytest.mark.parametrize("departure", ["cancel", "timeout"])
def test_departing_follower_cannot_cancel_owner_or_other_follower(monkeypatch, departure):
    async def case():
        worker = ControlledRecovery(monkeypatch)
        try:
            monkeypatch.setattr(tproxy, "GEPH_RESTART_SUCCESSOR_GRACE", 2.0)
            owner = worker.caller()
            await asyncio.wait_for(worker.entered.wait(), 1.0)
            monkeypatch.setattr(tproxy, "GEPH_RESTART_SUCCESSOR_GRACE", 0.0)
            leaving = worker.caller()
            await worker.subscribed(leaving)
            # The staying caller's later deadline must outlast the leaving one.
            monkeypatch.setattr(tproxy, "GEPH_RESTART_SUCCESSOR_GRACE", 1.0)
            staying = worker.caller()
            await worker.subscribed(staying)
            shared = tproxy._owned_geph_runtime_recovery_future
            if departure == "cancel":
                leaving.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await leaving
                departed = "CancelledError"
            else:
                departed = await asyncio.wait_for(leaving, 1.5)
                assert departed is False, "the leaving follower did not reach its own timeout"
            assert not worker.returned.is_set()
            cancelled_before_worker_return = shared.cancelled()
            worker.release.set()
            results = await asyncio.wait_for(
                asyncio.gather(owner, staying, return_exceptions=True), 1.0,
            )
            observed = {"case": "follower_" + departure, "departed": departed,
                        "surviving_results": [result_kind(value) for value in results],
                        "shared_cancelled_before_worker_return": cancelled_before_worker_return}
        finally:
            await worker.close()
        return worker, observed

    worker, observed = asyncio.run(case())
    assert worker.calls == ["fixture.invalid"]
    assert worker.returned.is_set()
    print(json.dumps(observed, sort_keys=True))
    assert observed["surviving_results"] == [True, True], (
        "one follower cancelled the shared result for the owner and another follower"
    )


def test_queued_recovery_survives_all_waiters_leaving(monkeypatch, isolated_recovery):
    async def case():
        loop = asyncio.get_running_loop()
        blocker_entered = asyncio.Event()
        unblock = threading.Event()

        def occupy_executor():
            loop.call_soon_threadsafe(blocker_entered.set)
            assert unblock.wait(2.0), "fixture failed to release executor blocker"

        blocker = isolated_recovery.submit(occupy_executor)
        worker = ControlledRecovery(monkeypatch)
        try:
            await asyncio.wait_for(blocker_entered.wait(), 1.0)
            first = worker.caller()
            await worker.subscribed(first)
            following = worker.caller()
            await worker.subscribed(following)
            shared = tproxy._owned_geph_runtime_recovery_future
            assert not shared.running() and not shared.done()
            assert worker.calls == []
            first.cancel()
            following.cancel()
            results = await asyncio.gather(first, following, return_exceptions=True)
            assert all(isinstance(value, asyncio.CancelledError) for value in results)
            assert not shared.cancelled() and not shared.done()
            arriving = worker.caller()
            await worker.subscribed(arriving)
            assert tproxy._owned_geph_runtime_recovery_future is shared
            assert worker.calls == []
            unblock.set()
            await asyncio.wait_for(worker.entered.wait(), 1.0)
            worker.release.set()
            assert await asyncio.wait_for(arriving, 1.0) is True
            assert worker.calls == ["fixture.invalid"]
        finally:
            unblock.set()
            await worker.close()
            await asyncio.wait_for(asyncio.wrap_future(blocker), 1.0)

    asyncio.run(case())


@pytest.mark.parametrize("error_type", [OSError, ValueError])
def test_abandoned_error_is_observed_and_next_wave_is_independent(monkeypatch, error_type):
    async def case():
        worker = ControlledRecovery(monkeypatch, error_type("synthetic recovery failure"))
        try:
            first = worker.caller()
            await asyncio.wait_for(worker.entered.wait(), 1.0)
            await worker.subscribed(first)
            following = worker.caller()
            await worker.subscribed(following)
            abandoned_wrappers = set(worker.wrappers)
            assert len(abandoned_wrappers) == 2
            first.cancel()
            following.cancel()
            results = await asyncio.gather(first, following, return_exceptions=True)
            assert all(isinstance(value, asyncio.CancelledError) for value in results)
            worker.release.set()

            async def both_exceptions_observed():
                observed = set()
                while not abandoned_wrappers <= observed:
                    observed.add(await worker.exception_observations.get())

            await asyncio.wait_for(both_exceptions_observed(), 1.0)
            assert all(wrapper.done() and not wrapper.cancelled()
                       for wrapper in abandoned_wrappers)
            first_job = tproxy._owned_geph_runtime_recovery_future
            # A subsequent awaited error keeps the old expected/unexpected contract.
            next_wave = worker.caller()
            if error_type is OSError:
                assert await asyncio.wait_for(next_wave, 1.0) is False
            else:
                with pytest.raises(ValueError, match="synthetic recovery failure"):
                    await asyncio.wait_for(next_wave, 1.0)
            assert tproxy._owned_geph_runtime_recovery_future is not first_job
            worker.outcome = True
            assert await asyncio.wait_for(worker.caller(), 1.0) is True
            assert worker.calls == ["fixture.invalid"] * 3
        finally:
            await worker.close()

    asyncio.run(case())


def test_submit_rejection_publishes_no_placeholder_and_allows_next_wave(
    monkeypatch, isolated_recovery,
):
    async def case():
        calls = []
        original_submit = isolated_recovery.submit

        def reject(*args, **kwargs):
            calls.append(True)
            raise RuntimeError("synthetic closed executor")

        monkeypatch.setattr(isolated_recovery, "submit", reject)
        assert await tproxy._coalesced_owned_geph_recovery_for_replay("fixture.invalid") is False
        assert calls == [True]
        assert tproxy._owned_geph_runtime_recovery_future is None
        monkeypatch.setattr(isolated_recovery, "submit", original_submit)
        worker = ControlledRecovery(monkeypatch)
        try:
            caller = worker.caller()
            await asyncio.wait_for(worker.entered.wait(), 1.0)
            worker.release.set()
            assert await asyncio.wait_for(caller, 1.0) is True
            assert worker.calls == ["fixture.invalid"]
        finally:
            await worker.close()

    asyncio.run(case())


def test_existing_shared_happy_regression_under_same_io_guards(monkeypatch):
    from test_tproxy_doh import test_owned_geph_replay_recovery_is_coalesced

    test_owned_geph_replay_recovery_is_coalesced(monkeypatch)
