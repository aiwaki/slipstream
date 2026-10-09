"""A cancelled connection must not cancel another connection's shared work."""
import asyncio
import threading

import pytest
import tproxy


class BlockingWork:
    def __init__(self, loop, result):
        self.loop = loop
        self.result = result
        self.entered = asyncio.Event()
        self.release = threading.Event()
        self.finished = threading.Event()
        self.calls = []

    def __call__(self, host):
        self.calls.append(host)
        self.loop.call_soon_threadsafe(self.entered.set)
        try:
            assert self.release.wait(2), "test failed to release worker"
            if isinstance(self.result, Exception):
                raise self.result
            return self.result
        finally:
            self.finished.set()


async def cancel(task):
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.parametrize("resolver", ("doh", "app_dns"))
@pytest.mark.parametrize("cancel_owner", (False, True))
def test_cancelled_dns_waiter_does_not_poison_shared_lookup(
    monkeypatch, resolver, cancel_owner
):
    async def scenario():
        work = BlockingWork(asyncio.get_running_loop(), ["93.184.216.34"])
        inflight = {}
        monkeypatch.setattr(tproxy, f"{resolver}_resolve", work)
        monkeypatch.setattr(tproxy, f"_{resolver}_inflight", inflight)
        resolve = getattr(tproxy, f"{resolver}_resolve_async")
        owner = asyncio.create_task(resolve("example.com"))
        survivor = None
        try:
            await work.entered.wait()
            follower = asyncio.create_task(resolve("example.com"))
            await asyncio.sleep(0)
            survivor = follower if cancel_owner else owner
            await cancel(owner if cancel_owner else follower)
            # The resolver still owns its entry until the actual thread exits.
            assert "example.com" in inflight
            late = asyncio.create_task(resolve("example.com"))
            await asyncio.sleep(0)
            work.release.set()
            assert await asyncio.gather(survivor, late) == [
                ["93.184.216.34"], ["93.184.216.34"]
            ]
            assert work.calls == ["example.com"]
            assert inflight == {}
        finally:
            work.release.set()
            await asyncio.gather(owner, *([survivor] if survivor else []), return_exceptions=True)

    asyncio.run(scenario())


@pytest.mark.parametrize("cancel_owner", (False, True))
def test_geph_recovery_survives_waiter_cancellation(monkeypatch, cancel_owner):
    async def scenario():
        work = BlockingWork(asyncio.get_running_loop(), True)
        monkeypatch.setattr(tproxy, "_owned_geph_runtime_recovery_future", None)
        monkeypatch.setattr(tproxy, "_recover_owned_geph_for_replay_blocking", work)
        owner = asyncio.create_task(tproxy._coalesced_owned_geph_recovery_for_replay("chatgpt.com"))
        tasks = [owner]
        try:
            await work.entered.wait()
            follower = asyncio.create_task(tproxy._coalesced_owned_geph_recovery_for_replay("openai.com"))
            tasks.append(follower)
            await asyncio.sleep(0)
            survivor = follower if cancel_owner else owner
            await cancel(owner if cancel_owner else follower)
            shared = tproxy._owned_geph_runtime_recovery_future
            assert not shared.done()
            late = asyncio.create_task(tproxy._coalesced_owned_geph_recovery_for_replay("example.com"))
            tasks.append(late)
            await asyncio.sleep(0)
            work.release.set()
            assert await asyncio.wait_for(asyncio.gather(survivor, late), 1) == [True, True]
            assert work.calls == ["chatgpt.com"]
            assert shared.done() and shared.result() is True
        finally:
            work.release.set()
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    asyncio.run(scenario())


def test_timed_out_geph_waiter_cannot_release_active_recovery(monkeypatch):
    async def scenario():
        work = BlockingWork(asyncio.get_running_loop(), True)
        monkeypatch.setattr(tproxy, "_owned_geph_runtime_recovery_future", None)
        monkeypatch.setattr(tproxy, "_recover_owned_geph_for_replay_blocking", work)
        owner = asyncio.create_task(tproxy._coalesced_owned_geph_recovery_for_replay("chatgpt.com"))
        try:
            await work.entered.wait()
            monkeypatch.setattr(tproxy, "GEPH_RESTART_SUCCESSOR_GRACE", -0.98)
            monkeypatch.setattr(tproxy, "GEPH_RESTART_PAYLOAD_READY_GRACE", 0)
            assert not await tproxy._coalesced_owned_geph_recovery_for_replay("openai.com")
            shared = tproxy._owned_geph_runtime_recovery_future
            assert not shared.done()
            work.release.set()
            assert await owner is True
            assert work.calls == ["chatgpt.com"]
        finally:
            work.release.set()
            await asyncio.gather(owner, return_exceptions=True)

    asyncio.run(scenario())


def test_cancelled_recovery_initiator_keeps_restart_drain_until_worker_finishes(monkeypatch):
    async def scenario():
        work = BlockingWork(asyncio.get_running_loop(), "ready")
        monkeypatch.setattr(tproxy, "_owned_geph_runtime_recovery_future", None)
        monkeypatch.setattr(tproxy, "_geph_owned", True)
        monkeypatch.setattr(tproxy, "_geph_port", tproxy.GEPH_OWNED_PORT)
        monkeypatch.setattr(tproxy, "_geph_active_sessions", 0)
        monkeypatch.setattr(tproxy, "_geph_restart_draining", False)
        monkeypatch.setattr(tproxy, "_shutdown_started", threading.Event())
        monkeypatch.setattr(tproxy, "request_owned_geph_restart", lambda *a, **kw: True)
        monkeypatch.setattr(tproxy, "_owned_geph_confirmation_pid", lambda: 42)
        monkeypatch.setattr(tproxy, "_owned_geph_confirmation_pid_matches", lambda pid: pid == 42)
        monkeypatch.setattr(tproxy, "_wait_for_owned_geph_payload_ready", work)
        monkeypatch.setattr(tproxy, "_retry_pending_auto_geph_confirmations_after_drain", lambda: None)
        def execute(**kwargs):
            assert tproxy._begin_geph_restart_drain()
            return "restarted"
        monkeypatch.setattr(tproxy, "execute_owned_geph_restart", execute)
        owner = asyncio.create_task(tproxy._coalesced_owned_geph_recovery_for_replay("chatgpt.com"))
        follower = None
        try:
            await work.entered.wait()
            await cancel(owner)
            assert tproxy._geph_restart_draining
            assert not tproxy._geph_session_started()
            follower = asyncio.create_task(tproxy._coalesced_owned_geph_recovery_for_replay("openai.com"))
            await asyncio.sleep(0)
            assert tproxy._geph_restart_draining
            work.release.set()
            assert await asyncio.wait_for(follower, 1)
            assert work.calls == [42]
            assert not tproxy._geph_restart_draining
            assert tproxy._geph_session_started()
            tproxy._geph_session_finished(retry_pending=False)
        finally:
            work.release.set()
            await asyncio.gather(owner, *([follower] if follower else []), return_exceptions=True)
    asyncio.run(scenario())


@pytest.mark.parametrize("resolver", ("doh", "app_dns"))
def test_shared_dns_failure_releases_entry_for_later_retry(monkeypatch, resolver):
    async def scenario():
        work = BlockingWork(asyncio.get_running_loop(), OSError("lookup failed"))
        inflight = {}
        monkeypatch.setattr(tproxy, f"{resolver}_resolve", work)
        monkeypatch.setattr(tproxy, f"_{resolver}_inflight", inflight)
        resolve = getattr(tproxy, f"{resolver}_resolve_async")
        owner = asyncio.create_task(resolve("example.com"))
        try:
            await work.entered.wait()
            follower = asyncio.create_task(resolve("example.com"))
            await asyncio.sleep(0)
            work.release.set()
            assert await asyncio.gather(owner, follower) == [[], []]
            assert inflight == {}
            work.result = ["93.184.216.34"]
            assert await resolve("example.com") == ["93.184.216.34"]
            assert work.calls == ["example.com", "example.com"]
        finally:
            work.release.set()
            await asyncio.gather(owner, return_exceptions=True)
    asyncio.run(scenario())


@pytest.mark.parametrize("resolver", ("doh", "app_dns"))
def test_shared_dns_submit_failure_does_not_publish_inflight_work(monkeypatch, resolver):
    class ClosedPool:
        def submit(self, *args):
            raise RuntimeError("executor shut down")

    inflight = {}
    monkeypatch.setattr(tproxy, "_POOL", ClosedPool())
    monkeypatch.setattr(tproxy, f"_{resolver}_inflight", inflight)
    resolve = getattr(tproxy, f"{resolver}_resolve_async")
    assert asyncio.run(resolve("example.com")) == []
    assert inflight == {}
