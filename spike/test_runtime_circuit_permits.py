"""Request cancellation and stale completions cannot consume another probe."""
import asyncio

import pytest
import tproxy
from route_circuit_registry import RouteCircuitRegistry


@pytest.fixture
def circuit(monkeypatch):
    registry = RouteCircuitRegistry(
        tproxy.RUNTIME_ROUTE_CIRCUIT_CONFIG, tproxy.RUNTIME_ROUTE_CIRCUIT_REGISTRY_CONFIG)
    monkeypatch.setattr(tproxy, '_runtime_route_circuits', registry)
    return registry


POLICY = {'route_class': tproxy.ROUTE_GEO_EXIT, 'service_group': 'openai'}
BACKEND = tproxy.GEO_BACKEND_GEPH


def test_cancelled_half_open_caller_releases_its_probe_immediately(circuit):
    for at in (0, 1):
        tproxy.runtime_route_circuit_record_result(POLICY, BACKEND, False, now_ms=at)

    async def scenario():
        entered = asyncio.Event()
        async def request():
            assert tproxy.runtime_route_circuit_allows(POLICY, BACKEND, now_ms=1001)
            entered.set()
            await asyncio.Future()
        owner = asyncio.create_task(request())
        await entered.wait()
        owner.cancel()
        await asyncio.gather(owner, return_exceptions=True)
        assert tproxy.runtime_route_circuit_allows(POLICY, BACKEND, now_ms=1002)
        assert circuit.snapshot()[0].state.half_open_in_flight == 1
    asyncio.run(scenario())


def test_closed_epoch_completion_cannot_close_new_half_open_probe(circuit):
    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()
        async def old_request():
            assert tproxy.runtime_route_circuit_allows(POLICY, BACKEND, now_ms=0)
            entered.set()
            await release.wait()
            tproxy.runtime_route_circuit_record_result(POLICY, BACKEND, True, now_ms=1003)
        old = asyncio.create_task(old_request())
        await entered.wait()
        for at in (1, 2):
            tproxy.runtime_route_circuit_record_result(POLICY, BACKEND, False, now_ms=at)
        assert tproxy.runtime_route_circuit_allows(POLICY, BACKEND, now_ms=1002)
        release.set()
        await old
        assert circuit.snapshot()[0].state.phase == 'half_open'
        assert circuit.snapshot()[0].state.half_open_in_flight == 1
        tproxy.runtime_route_circuit_record_result(POLICY, BACKEND, True, now_ms=1004)
        assert not circuit.snapshot()
    asyncio.run(scenario())


def test_unadmitted_completion_does_not_consume_another_tasks_probe(circuit):
    for at in (0, 1):
        tproxy.runtime_route_circuit_record_result(POLICY, BACKEND, False, now_ms=at)

    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()
        async def admitted_request():
            assert tproxy.runtime_route_circuit_allows(POLICY, BACKEND, now_ms=1001)
            entered.set()
            await release.wait()
        owner = asyncio.create_task(admitted_request())
        await entered.wait()
        # Independently proven/replayed payloads can arrive without entering
        # this circuit. They must not complete another request's probe.
        tproxy.runtime_route_circuit_record_result(POLICY, BACKEND, True, now_ms=1002)
        assert circuit.snapshot()[0].state.half_open_in_flight == 1
        release.set()
        await owner
    asyncio.run(scenario())


def test_sequential_admissions_replace_consumed_permit_and_results_are_one_shot(circuit):
    async def scenario():
        assert tproxy.runtime_route_circuit_allows(POLICY, BACKEND, now_ms=0)
        tproxy.runtime_route_circuit_record_result(POLICY, BACKEND, False, now_ms=1)
        tproxy.runtime_route_circuit_record_result(POLICY, BACKEND, False, now_ms=2)
        assert circuit.snapshot()[0].state.consecutive_failures == 1
        assert tproxy.runtime_route_circuit_allows(POLICY, BACKEND, now_ms=3)
        tproxy.runtime_route_circuit_record_result(POLICY, BACKEND, False, now_ms=4)
        assert circuit.snapshot()[0].state.phase == 'open'
        assert not tproxy.runtime_route_circuit_allows(POLICY, BACKEND, now_ms=5)
        tproxy.runtime_route_circuit_record_result(POLICY, BACKEND, True, now_ms=6)
        assert circuit.snapshot()[0].state.phase == 'open'
        assert tproxy.runtime_route_circuit_allows(POLICY, BACKEND, now_ms=1004)
        tproxy.runtime_route_circuit_record_result(POLICY, BACKEND, True, now_ms=1005)
        assert not circuit.snapshot()
    asyncio.run(scenario())


def test_replaced_unfinished_attempt_releases_slot_and_task_registration(circuit):
    for at in (0, 1):
        tproxy.runtime_route_circuit_record_result(POLICY, BACKEND, False, now_ms=at)

    async def scenario():
        async def sequential_attempts():
            assert tproxy.runtime_route_circuit_allows(POLICY, BACKEND, now_ms=1001)
            assert tproxy.runtime_route_circuit_allows(POLICY, BACKEND, now_ms=1002)
            assert circuit.snapshot()[0].state.half_open_in_flight == 1
        request = asyncio.create_task(sequential_attempts())
        await request
        # An already-registered awaiter may run before a callback installed
        # during the task's first step; allow that scheduled callback to run.
        await asyncio.sleep(0)
        assert not hasattr(request, '_slipstream_route_circuit_permits')
        assert circuit.snapshot()[0].state.half_open_in_flight == 0
    asyncio.run(scenario())
