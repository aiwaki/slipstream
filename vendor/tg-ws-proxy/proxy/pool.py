import asyncio
import logging
import time

from collections import deque
from urllib.parse import urlencode
from typing import Dict, List, Optional, Tuple, Set

from .raw_websocket import RawWebSocket, WsHandshakeError
from .stats import stats
from .config import proxy_config
from .utils import ws_domains, DC_DEFAULT_IPS

log = logging.getLogger('tg-mtproto-proxy')

async def _await_cleanup(coro):
    # Cleanup owns resources after caller cancellation. Keep draining even if
    # a second cancellation arrives, then preserve it for the caller.
    task = asyncio.create_task(coro)
    cancelled = False
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            cancelled = True
    result = task.result()
    if cancelled:
        raise asyncio.CancelledError
    return result


async def _reclaim_unclaimed(tasks, claimed):
    # A later connector may have returned a socket while an earlier one was
    # still pending. Cancellation must collect every child, including those
    # whose result was never consumed by the refill loop.
    for task in tasks:
        if not task.done():
            task.cancel()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    await asyncio.gather(*(
        _WsPool._quiet_close(ws) for task, ws in zip(tasks, results)
        if task not in claimed and ws is not None and not isinstance(ws, BaseException)
    ))


class _PoolLifecycle:
    def _track(self, coro, *, refill=False):
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        if refill:
            self._refill_tasks.add(task)
            task.add_done_callback(self._refill_tasks.discard)

    async def close(self):
        self._closing = True
        await _await_cleanup(self._close())

    async def _close(self):
        tasks = list(self._tasks)
        # Expired connections already popped from idle remain owned by close
        # tasks, including tasks that have not taken their first step yet.
        for task in list(self._refill_tasks):
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._tasks.clear()
        idle = [ws for bucket in self._idle.values() for ws, _ in bucket]
        self._idle.clear()
        self._refilling.clear()
        await asyncio.gather(*(self._quiet_close(ws) for ws in idle))


class _WsPool(_PoolLifecycle):
    WS_POOL_MAX_AGE = 120.0
    
    def __init__(self):
        self._tasks = set()
        self._refill_tasks = set()
        self._closing = False
        self._idle: Dict[Tuple[int, bool], deque] = {}
        self._refilling: Set[Tuple[int, bool]] = set()
        self.fronting_until: float = 0.0

    async def get(self, dc: int, is_media: bool,
                  target_ip: str, domains: List[str]
                  ) -> Optional[RawWebSocket]:
        if self._closing:
            return None
        key = (dc, is_media)
        now = time.monotonic()

        bucket = self._idle.get(key)
        if bucket is None:
            bucket = deque()
            self._idle[key] = bucket
        while bucket:
            ws, created = bucket.popleft()
            age = now - created
            if (age > self.WS_POOL_MAX_AGE or ws._closed
                    or ws.writer.transport.is_closing()):
                self._track(self._quiet_close(ws))
                continue
            stats.pool_hits += 1
            log.debug("WS pool hit DC%d%s (age=%.1fs, left=%d)",
                      dc, 'm' if is_media else '', age, len(bucket))
            self._schedule_refill(key, target_ip, domains)
            return ws

        stats.pool_misses += 1
        self._schedule_refill(key, target_ip, domains)
        return None

    def _schedule_refill(self, key, target_ip, domains):
        if self._closing or key in self._refilling:
            return
        self._refilling.add(key)
        self._track(self._refill(key, target_ip, domains), refill=True)

    async def _refill(self, key, target_ip, domains):
        dc, is_media = key
        tasks, claimed = [], set()
        try:
            bucket = self._idle.setdefault(key, deque())
            needed = proxy_config.pool_size - len(bucket)
            if needed <= 0:
                return
            tasks = [asyncio.create_task(
                self._connect_one(target_ip, domains, time.monotonic() < self.fronting_until))
                for _ in range(needed)]
            for t in tasks:
                try:
                    ws = await t
                    if ws:
                        bucket.append((ws, time.monotonic()))
                        claimed.add(t)
                except Exception:
                    pass
            log.debug("WS pool refilled DC%d%s: %d ready",
                      dc, 'm' if is_media else '', len(bucket))
        finally:
            try:
                await _await_cleanup(_reclaim_unclaimed(tasks, claimed))
            finally:
                self._refilling.discard(key)

    @staticmethod
    async def _connect_one(target_ip, domains, fronting_active) -> Optional[RawWebSocket]:
        for domain in domains:
            try:
                return await RawWebSocket.connect(
                    target_ip, domain, timeout=8, sni="sprinthost.ru" if fronting_active else None)
            except WsHandshakeError as exc:
                if exc.is_redirect:
                    continue
                return None
            except Exception:
                return None
        return None

    @staticmethod
    async def _quiet_close(ws):
        try:
            await ws.close()
        except Exception:
            pass

    async def warmup(self):
        for dc, target_ip in proxy_config.dc_redirects.items():
            if target_ip is None:
                continue
            for is_media in (False, True):
                domains = ws_domains(dc, is_media)
                self._schedule_refill((dc, is_media), target_ip, domains)
        log.info("WS pool warmup started for %d DC(s)", len(proxy_config.dc_redirects))

    async def reset(self):
        await self.close()
        self._closing = False
        self.fronting_until = 0.0


class _CfWorkerPool(_PoolLifecycle):
    WS_POOL_MAX_AGE = 100.0

    def __init__(self):
        self._tasks = set()
        self._refill_tasks = set()
        self._closing = False
        self._idle: Dict[Tuple[int, str], deque] = {}
        self._refilling: Set[Tuple[int, str]] = set()

    async def get(self, dc: int, worker_domain: str, fallback_dst: str) -> Optional[RawWebSocket]:
        if self._closing:
            return None
        now = time.monotonic()
        key = (dc, worker_domain)

        bucket = self._idle.get(key)
        if bucket is None:
            bucket = deque()
            self._idle[key] = bucket
        while bucket:
            ws, created = bucket.popleft()
            age = now - created
            if (age > self.WS_POOL_MAX_AGE or ws._closed
                    or ws.writer.transport.is_closing()):
                self._track(self._quiet_close(ws))
                continue
            stats.cf_pool_hits += 1
            log.debug("CF worker pool hit DC%d (age=%.1fs, left=%d)",
                      dc, age, len(bucket))
            self._schedule_refill(key, fallback_dst)
            return ws

        stats.cf_pool_misses += 1
        self._schedule_refill(key, fallback_dst)
        return None

    def _schedule_refill(self, key, fallback_dst):
        if self._closing or key in self._refilling:
            return
        self._refilling.add(key)
        self._track(self._refill(key, fallback_dst), refill=True)

    async def _refill(self, key, fallback_dst):
        dc, worker_domain = key
        tasks, claimed = [], set()
        try:
            bucket = self._idle.setdefault(key, deque())
            needed = proxy_config.pool_size - len(bucket)
            if needed <= 0:
                return
            tasks = [asyncio.create_task(
                self._connect_one(worker_domain, fallback_dst, dc))
                for _ in range(needed)]
            for t in tasks:
                try:
                    ws = await t
                    if ws:
                        bucket.append((ws, time.monotonic()))
                        claimed.add(t)
                except Exception:
                    pass
            log.debug("CF worker pool refilled DC%d: %d ready",
                      dc, len(bucket))
        finally:
            try:
                await _await_cleanup(_reclaim_unclaimed(tasks, claimed))
            finally:
                self._refilling.discard(key)

    @staticmethod
    async def _connect_one(worker_domain, fallback_dst, dc) -> Optional[RawWebSocket]:
        query = urlencode({
            'dst': fallback_dst,
            'dc': str(dc),
        })
        path = f'/apiws?{query}'
        try:
            return await RawWebSocket.connect(
                worker_domain, worker_domain, timeout=8, path=path)
        except Exception:
            return None

    @staticmethod
    async def _quiet_close(ws):
        try:
            await ws.close()
        except Exception:
            pass

    async def warmup(self):
        cf_fallbacks = {
            dc: ip for dc, ip in DC_DEFAULT_IPS.items()
            if dc not in proxy_config.dc_redirects
        }

        if not cf_fallbacks or not proxy_config.cfproxy_worker_domains:
            return

        for worker_domain in proxy_config.cfproxy_worker_domains:
            for dc, fallback_dst in cf_fallbacks.items():
                self._schedule_refill((dc, worker_domain), fallback_dst)

        log.info("CF worker pool warmup started for %d DC(s)", len(cf_fallbacks))

    async def reset(self):
        await self.close()
        self._closing = False


ws_pool = _WsPool()
cf_worker_pool = _CfWorkerPool()