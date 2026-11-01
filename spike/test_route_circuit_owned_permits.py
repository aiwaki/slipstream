"""Offline characterization of exact runtime wrappers and registry source slices.

Only stdlib state and asyncio Events execute. No daemon module/startup is imported.
The runtime functions are extracted from current source; daemon startup is never imported.
"""
import ast
import asyncio
import dataclasses
import os
from pathlib import Path
import socket
import subprocess
import sys
import pytest
import types
import unittest


ROOT = Path(__file__).resolve().parent.parent
OBSERVED = {}


def forbidden(*args, **kwargs):
    raise AssertionError("external I/O forbidden in permit characterization")




import route_circuit as REDUCER
import route_circuit_registry as REGISTRY


def runtime():
    source = (ROOT / "spike/tproxy.py").read_text()
    configs = [node for node in ast.parse(source).body
               if isinstance(node, ast.Assign)
               and any(isinstance(target, ast.Name) and target.id in {
                   "RUNTIME_ROUTE_CIRCUIT_CONFIG", "RUNTIME_ROUTE_CIRCUIT_REGISTRY_CONFIG"
               } for target in node.targets)]
    assert len(configs) == 2
    clock = [0]
    ns = {
        "asyncio": asyncio, "sys": sys, "route_circuit": REDUCER,
        "route_circuit_registry": REGISTRY, "VERBOSE": False,
        "ROUTE_UNKNOWN": "unknown", "SERVICE_GENERIC": "generic",
        "ROUTE_LOCAL_BYPASS": "local_bypass", "ROUTE_GEO_EXIT": "geo_exit",
        "BACKEND_LOCAL_ENGINE": "local_engine", "GEO_BACKEND_SMART_DNS": "smart_dns",
        "GEO_BACKEND_GEPH": "geph",
    }
    exec(compile(ast.Module(body=configs, type_ignores=[]), "exact-current-config", "exec"), ns)
    ns["_runtime_route_circuits"] = REGISTRY.RouteCircuitRegistry(
        ns["RUNTIME_ROUTE_CIRCUIT_CONFIG"], ns["RUNTIME_ROUTE_CIRCUIT_REGISTRY_CONFIG"])
    names = {
        "_runtime_route_circuit_now_ms", "_runtime_route_circuit_key",
        "_apply_runtime_route_circuit", "_runtime_route_circuit_request_task",
        "_retain_runtime_route_circuit_permit", "runtime_route_circuit_before_request",
        "runtime_route_circuit_record_result", "runtime_route_circuit_allows",
        "reset_runtime_route_circuits", "runtime_route_circuit_snapshot",
    }
    functions = [node for node in ast.parse(source).body
                 if isinstance(node, ast.FunctionDef) and node.name in names]
    exec(compile(ast.Module(body=functions, type_ignores=[]),
                 str(ROOT / "spike/tproxy.py"), "exec"), ns)
    ns["_runtime_route_circuit_now_ms"] = lambda: clock[0]
    return types.SimpleNamespace(**ns), clock


def snapshot(rt):
    return [dataclasses.asdict(entry) for entry in rt.runtime_route_circuit_snapshot()]


class Permits(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        from unittest.mock import patch
        targets = (
            (socket.socket, ("connect", "connect_ex", "bind", "listen")),
            (socket, ("getaddrinfo", "create_connection")),
            (asyncio, ("open_connection", "start_server", "create_subprocess_exec", "create_subprocess_shell")),
            (subprocess, ("Popen",)), (os, ("system",)),
        )
        for owner, names in targets:
            for name in names:
                guard = patch.object(owner, name, forbidden)
                guard.start()
                self.addCleanup(guard.stop)

    async def test_cancelled_half_open_releases_its_slot_immediately(self):
        rt, clock = runtime()
        policy = {"route_class": "geo_exit", "service_group": "openai"}
        backend = "geph"
        for tick in (0, 1):
            clock[0] = tick
            rt.runtime_route_circuit_record_result(policy, backend, False)
        started = asyncio.Event()

        async def abandoned_attempt():
            self.assertTrue(rt.runtime_route_circuit_allows(policy, backend))
            started.set()
            await asyncio.Event().wait()

        clock[0] = 1001
        task = asyncio.create_task(abandoned_attempt())
        try:
            await asyncio.wait_for(started.wait(), 1)
            self.assertEqual(snapshot(rt)[0]["state"]["half_open_in_flight"], 1)
        finally:
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        await asyncio.sleep(0)  # Drain task-done callbacks, no time-based retry.
        after_cancel = snapshot(rt)
        clock[0] = 1002
        allowed = rt.runtime_route_circuit_allows(policy, backend)
        OBSERVED[self._testMethodName] = {
            "after_cancel": after_cancel, "next_attempt_allowed": allowed,
            "time_before_next_admission_ms": clock[0],
            "production_idle_ttl_ms": rt.RUNTIME_ROUTE_CIRCUIT_REGISTRY_CONFIG.idle_ttl_ms,
        }
        self.assertEqual(after_cancel[0]["state"]["phase"], "half_open")
        self.assertEqual(after_cancel[0]["state"]["half_open_in_flight"], 0,
                         "cancelled owner retained the only half-open permit")
        self.assertTrue(allowed)

    async def late_completion(self, ok):
        rt, clock = runtime()
        policy = {"route_class": "local_bypass", "service_group": "discord"}
        backend = "local_engine"
        tasks = []

        async def start(tick, outcome):
            clock[0] = tick
            started, release = asyncio.Event(), asyncio.Event()

            async def attempt():
                self.assertTrue(rt.runtime_route_circuit_allows(policy, backend))
                started.set()
                await release.wait()
                return rt.runtime_route_circuit_record_result(policy, backend, outcome)

            task = asyncio.create_task(attempt())
            tasks.append(task)
            await asyncio.wait_for(started.wait(), 1)
            return task, release

        try:
            old, finish_old = await start(0, ok)
            for tick in (1, 2):
                failed, finish = await start(tick, False)
                finish.set()
                await failed
            self.assertEqual(snapshot(rt)[0]["state"]["phase"], "open")
            current, finish_current = await start(1002, True)
            before_old_result = snapshot(rt)
            clock[0] = 1003
            finish_old.set()
            old_decision = await old
            after_old_result = snapshot(rt)
            clock[0] = 1004
            finish_current.set()
            current_decision = await current
            after_current_result = snapshot(rt)
            OBSERVED[self._testMethodName] = {
                "before_old_result": before_old_result,
                "after_old_result": after_old_result,
                "after_current_result": after_current_result,
                "old_result_decision": dataclasses.asdict(old_decision) if old_decision else None,
                "current_result_decision": dataclasses.asdict(current_decision) if current_decision else None,
                "route": policy, "backend": backend,
            }
            self.assertEqual(after_old_result, before_old_result,
                             "prior Closed attempt changed another task's HalfOpen generation")
            self.assertEqual(after_current_result, [])
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def test_old_success_cannot_complete_another_tasks_half_open(self):
        await self.late_completion(True)

    async def test_old_failure_cannot_reopen_another_tasks_half_open(self):
        await self.late_completion(False)

    async def test_repeated_admission_keeps_one_callback_and_no_completed_references(self):
        rt, clock = runtime()
        policy = {"route_class": "geo_exit", "service_group": "openai"}
        task = asyncio.current_task()
        for tick in range(0, 20, 2):
            clock[0] = tick
            self.assertTrue(rt.runtime_route_circuit_allows(policy, "geph"))
            key = rt._runtime_route_circuit_key(policy, "geph")
            self.assertIsNotNone(task._slipstream_route_circuit_permits[key])
            clock[0] += 1
            rt.runtime_route_circuit_record_result(policy, "geph", True)
            self.assertEqual(task._slipstream_route_circuit_permits, {key: None})
            # Replayed evidence after a completed attempt cannot count again.
            self.assertIsNone(rt.runtime_route_circuit_record_result(policy, "geph", False))
            self.assertEqual(snapshot(rt), [])
        callbacks = [callback for callback, _ in task._callbacks
                     if callback.__name__ == "finished"]
        self.assertEqual(len(callbacks), 1)
        self.assertIsNone(callbacks[0].__closure__)

    async def test_unowned_closed_health_is_kept_but_cannot_finish_owned_half_open(self):
        rt, clock = runtime()
        policy = {"route_class": "geo_exit", "service_group": "openai"}
        rt.runtime_route_circuit_record_result(policy, "geph", False)
        clock[0] = 1
        rt.runtime_route_circuit_record_result(policy, "geph", True)
        self.assertEqual(snapshot(rt), [])
        for tick in (2, 3):
            clock[0] = tick
            rt.runtime_route_circuit_record_result(policy, "geph", False)
        started, release = asyncio.Event(), asyncio.Event()

        async def probe():
            self.assertTrue(rt.runtime_route_circuit_allows(policy, "geph"))
            started.set()
            await release.wait()
            rt.runtime_route_circuit_record_result(policy, "geph", True)

        clock[0] = 1003
        task = asyncio.create_task(probe())
        try:
            await asyncio.wait_for(started.wait(), 1)
            before = snapshot(rt)
            for ok in (False, True):
                clock[0] += 1
                decision = rt.runtime_route_circuit_record_result(policy, "geph", ok)
                self.assertEqual(decision.reason, "unowned_completion")
                self.assertEqual(snapshot(rt), before)
            release.set()
            await task
            self.assertEqual(snapshot(rt), [])
            self.assertFalse(hasattr(task, "_slipstream_route_circuit_permits"))
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def test_rejected_attempt_tombstone_and_external_backend_cannot_record(self):
        rt, clock = runtime()
        policy = {"route_class": "geo_exit", "service_group": "openai"}
        for tick in (0, 1):
            clock[0] = tick
            rt.runtime_route_circuit_record_result(policy, "geph", False)
        clock[0] = 2
        self.assertFalse(rt.runtime_route_circuit_allows(policy, "geph"))
        before = snapshot(rt)
        self.assertIsNone(rt.runtime_route_circuit_record_result(policy, "geph", True))
        self.assertEqual(snapshot(rt), before)
        self.assertTrue(rt.runtime_route_circuit_allows(policy, "geph", owned=False))
        self.assertIsNone(rt.runtime_route_circuit_record_result(policy, "geph", True, owned=False))
        self.assertEqual(snapshot(rt), before)


KEY = REDUCER.RouteCircuitKey("openai", "geo_exit", "geph")
OTHER = REDUCER.RouteCircuitKey("steam", "geo_exit", "geph")


def registry(max_entries=2, slots=1, successes=1):
    return REGISTRY.RouteCircuitRegistry(
        REDUCER.CircuitConfig(2, 1000, slots, successes),
        REGISTRY.RouteCircuitRegistryConfig(max_entries, 5000),
    )


def open_circuit(reg, at=0):
    for tick in (at, at + 1):
        reg.apply(REDUCER.CircuitEvent(REDUCER.EVENT_RECORD_FAILURE, KEY, tick))


@pytest.mark.parametrize("ending", ("clear", "ttl", "lru", "phase"))
@pytest.mark.parametrize("action", ("complete", "abandon"))
def test_old_generation_cannot_consume_successor_slot(ending, action):
    reg = registry(max_entries=1, slots=2 if ending == "phase" else 1)
    open_circuit(reg)
    _, old = reg.before_request_owned(KEY, 1001)
    if ending == "clear":
        reg.clear()
        next_at = 1002
    elif ending == "ttl":
        reg.before_request_owned(OTHER, 6001)
        next_at = 6002
    elif ending == "lru":
        reg.before_request_owned(OTHER, 1002)
        next_at = 1003
    else:
        _, peer = reg.before_request_owned(KEY, 1002)
        reg.complete_owned(peer, False, 1003)
        next_at = 1004
    open_circuit(reg, next_at)
    _, current = reg.before_request_owned(KEY, next_at + 1001)
    before = reg.snapshot()
    if action == "complete":
        assert reg.complete_owned(old, True, next_at + 1002) is None
    else:
        assert reg.abandon_owned(old) is False
    assert reg.snapshot() == before
    assert reg.complete_owned(current, True, next_at + 1003).reason == "half_open_recovered"
    assert not reg.snapshot()


def test_foreign_duplicate_and_backward_completion_preserve_owner():
    reg, foreign = registry(), registry()
    open_circuit(reg)
    _, permit = reg.before_request_owned(KEY, 1001)
    assert foreign.complete_owned(permit, False, 1002) is None
    assert not permit.consumed
    with pytest.raises(ValueError, match="backwards"):
        reg.complete_owned(permit, False, 1000)
    assert not permit.consumed
    reg.complete_owned(permit, False, 1002)
    before = reg.snapshot()
    assert reg.complete_owned(permit, False, 1003) is None
    assert reg.abandon_owned(permit) is False
    assert reg.snapshot() == before
    with pytest.raises(ValueError, match="backwards"):
        reg.complete_owned(None, False, 1002)


def test_partial_success_keeps_other_probe_releasable_and_activity_clock():
    reg = registry(slots=2, successes=2)
    open_circuit(reg)
    _, first = reg.before_request_owned(KEY, 1001)
    _, second = reg.before_request_owned(KEY, 1002)
    reg.complete_owned(first, True, 4000)
    assert reg.abandon_owned(second)
    assert reg.snapshot()[0].state.half_open_successes == 1
    assert reg.snapshot()[0].state.half_open_in_flight == 0
    assert reg.snapshot()[0].last_touched_ms == 4000
    _, third = reg.before_request_owned(KEY, 6003)
    assert reg.complete_owned(third, True, 6004).reason == "half_open_recovered"


def test_epoch_capacity_and_protected_routes_remain_bounded():
    reg = registry(max_entries=2)
    for index in range(20):
        key = REDUCER.RouteCircuitKey(str(index), "geo_exit", "geph")
        decision, token = reg.before_request_owned(key, index)
        assert decision.kind == REDUCER.DECISION_ALLOW and token is not None
        assert len(reg._generations) <= 2
    invalid = REDUCER.RouteCircuitKey("discord", "local_bypass", "geph")
    decision, token = reg.before_request_owned(invalid, 20)
    assert decision.reason == "protected_route_mismatch" and token is None
    assert reg.record_unowned(REDUCER.CircuitEvent(
        REDUCER.EVENT_RECORD_SUCCESS, invalid, 21)).reason == "protected_route_mismatch"


def test_closed_replay_observation_restores_health_once_only():
    reg = registry()
    _, original = reg.before_request_owned(KEY, 0)
    reg.complete_owned(original, False, 1)
    assert reg.snapshot()[0].state.consecutive_failures == 1
    observation = reg.begin_closed_observation(KEY, 2)
    assert observation is not None
    assert reg.complete_owned(observation, True, 3).reason == "success_recorded"
    assert not reg.snapshot()
    assert reg.complete_owned(observation, False, 4) is None
    assert reg.complete_owned(original, False, 5) is None
    assert not reg.snapshot()


def test_replay_observation_is_inert_in_open_and_half_open():
    reg = registry()
    open_circuit(reg)
    before = reg.snapshot()
    assert reg.begin_closed_observation(KEY, 2) is None
    assert reg.snapshot() == before
    _, probe = reg.before_request_owned(KEY, 1001)
    before = reg.snapshot()
    assert reg.begin_closed_observation(KEY, 1002) is None
    assert reg.snapshot() == before
    assert reg.complete_owned(probe, True, 1003).reason == "half_open_recovered"


@pytest.mark.parametrize("successor_phase", ("half_open", "closed"))
def test_replay_observation_cannot_report_into_a_later_generation(successor_phase):
    reg = registry()
    observation = reg.begin_closed_observation(KEY, 0)
    open_circuit(reg, 1)
    _, probe = reg.before_request_owned(KEY, 1002)
    if successor_phase == "closed":
        reg.complete_owned(probe, True, 1003)
        reg.record_unowned(REDUCER.CircuitEvent(REDUCER.EVENT_RECORD_FAILURE, KEY, 1004))
    before = reg.snapshot()
    assert reg.complete_owned(observation, True, 1005) is None
    assert reg.snapshot() == before
