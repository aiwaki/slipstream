"""Exact resource-qualified local routes remain ephemeral and local-only."""

import asyncio
from dataclasses import replace
from types import SimpleNamespace

import pytest
import tproxy
from test_tproxy_doh import reset_smart_dns_state  # noqa: F401


HOST = "critical.example.com"
ORIGINAL = "1.1.1.1"
SELECTED = "8.8.8.8"


@pytest.fixture(autouse=True)
def local_state(monkeypatch, reset_smart_dns_state):
    saved = tproxy._bootstrap_local_routes.copy()
    tproxy._bootstrap_local_routes.clear()
    monkeypatch.setattr(tproxy, "_auto_geph_base_host_allowed", lambda h: h == HOST)
    yield
    tproxy._bootstrap_local_routes.clear()
    tproxy._bootstrap_local_routes.update(saved)


def winner(**changes):
    fields = dict(
        host=HOST, exact_address=ORIGINAL, address=SELECTED,
        strategy_name="split64", via_xbox_dns=False, capability="a" * 32,
        deadline_monotonic=tproxy.time.monotonic() + 5,
    )
    fields.update(changes)
    return tproxy._BootstrapLocalWinner(**fields)


def stored_claim(**changes):
    assert tproxy._store_bootstrap_local_route(winner(**changes))
    return tproxy._bootstrap_local_route_claim(HOST, ORIGINAL, tproxy.time.monotonic() + 10)


@pytest.mark.parametrize("strategy,xbox", [("split64", False), ("split16", False), ("plain", True)])
def test_local_winner_claim_keeps_exact_address_and_strategy(strategy, xbox):
    now = tproxy.time.monotonic()
    claim = stored_claim(strategy_name=strategy, via_xbox_dns=xbox)
    assert claim.host == HOST and claim.exact_address == ORIGINAL
    assert claim.address == SELECTED and claim.strategy_name == strategy
    assert claim.via_xbox_dns is xbox
    assert 0 < claim.deadline_monotonic - now <= 4.1
    assert tproxy._bootstrap_local_route_claim(HOST, SELECTED, now + 10) is None
    assert tproxy._bootstrap_local_route_claim("unrelated.example.com", ORIGINAL, now + 10) is None
    assert not tproxy._route_preflight_window


@pytest.mark.parametrize("changes", [
    {"host": "discord.com"}, {"address": "127.0.0.1"},
    {"exact_address": "10.0.0.1"}, {"address": "::1"},
    {"strategy_name": "fake5"}, {"strategy_name": "plain"},
    {"via_xbox_dns": True}, {"capability": "not-a-private-epoch"},
    {"deadline_monotonic": 0}, {"deadline_monotonic": float("inf")},
    {"deadline_monotonic": True},
])
def test_invalid_local_winner_never_enters_cache(changes):
    assert not tproxy._store_bootstrap_local_route(winner(**changes))
    assert not tproxy._bootstrap_local_routes


def test_local_route_has_fixed_ttl_bounded_size_and_identity_safe_invalidation(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(tproxy, "time", SimpleNamespace(
        monotonic=lambda: clock[0], time=tproxy.time.time,
    ))
    monkeypatch.setattr(tproxy, "_BOOTSTRAP_LOCAL_ROUTE_MAX", 2)
    old = stored_claim()
    replacement = stored_claim(capability="b" * 32)
    tproxy._invalidate_bootstrap_local_route(old)
    assert tproxy._bootstrap_local_route_claim(HOST, ORIGINAL, 110).capability == "b" * 32
    assert tproxy._store_bootstrap_local_route(winner(exact_address="1.0.0.1"))
    assert tproxy._store_bootstrap_local_route(winner(exact_address="8.8.4.4"))
    assert len(tproxy._bootstrap_local_routes) == 2
    assert (HOST, ORIGINAL) not in tproxy._bootstrap_local_routes
    assert replacement.expires_at_monotonic == 130.0
    clock[0] = 130.0
    assert tproxy._bootstrap_local_route_claim(HOST, "1.0.0.1", 140) is None


def test_local_route_dials_one_new_first_flight_only(monkeypatch):
    claim = stored_claim()
    calls = []
    result = (object(), object(), b"server bytes")

    async def dial(*args):
        calls.append(args)
        return result

    monkeypatch.setattr(tproxy, "dial_strategy", dial)
    assert asyncio.run(tproxy._dial_bootstrap_local_route(
        claim, HOST, ORIGINAL, 443, b"head", b"body",
    )) is result
    assert calls == [(SELECTED, 443, b"head", b"body", HOST, tproxy.STRAT_BY_NAME["split64"])]


@pytest.mark.parametrize("change", ["host", "original", "port", "selected", "strategy", "capability"])
def test_local_claim_cannot_be_retargeted(monkeypatch, change):
    claim = stored_claim()
    host, original, port = HOST, ORIGINAL, 443
    if change == "host":
        host = "unrelated.example.com"
    elif change == "original":
        original = SELECTED
    elif change == "port":
        port = 80
    elif change == "selected":
        claim = replace(claim, address="8.8.4.4")
    elif change == "strategy":
        claim = replace(claim, strategy_name="split16")
    else:
        claim = replace(claim, capability="b" * 32)

    async def forbidden(*args):
        pytest.fail("retargeted claim started network work")

    monkeypatch.setattr(tproxy, "dial_strategy", forbidden)
    assert asyncio.run(tproxy._dial_bootstrap_local_route(
        claim, host, original, port, b"head", b"body",
    )) is None


def test_empty_local_result_is_closed_not_counted_as_payload(monkeypatch):
    claim = stored_claim()
    closed = []

    async def dial(*args):
        return object(), object(), b""

    async def close(writer):
        closed.append(writer)

    monkeypatch.setattr(tproxy, "dial_strategy", dial)
    monkeypatch.setattr(tproxy, "_close_stream_writer", close)
    assert asyncio.run(tproxy._dial_bootstrap_local_route(
        claim, HOST, ORIGINAL, 443, b"head", b"body",
    )) is None
    assert len(closed) == 1
    assert not tproxy._bootstrap_local_routes


@pytest.mark.parametrize("failure", [None, OSError("synthetic"), asyncio.CancelledError()])
def test_local_dial_failure_invalidates_without_retry(monkeypatch, failure):
    claim = stored_claim()
    calls = []

    async def failed(*args):
        calls.append(args)
        if failure is not None:
            raise failure
        return None

    monkeypatch.setattr(tproxy, "dial_strategy", failed)
    operation = tproxy._dial_bootstrap_local_route(claim, HOST, ORIGINAL, 443, b"h", b"b")
    if isinstance(failure, asyncio.CancelledError):
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(operation)
    else:
        assert asyncio.run(operation) is None
    assert len(calls) == 1
    assert not tproxy._bootstrap_local_routes


@pytest.mark.parametrize("preflight", [False, True])
@pytest.mark.parametrize("failed", [False, True, "cancel_delivery"])
def test_handler_uses_local_winner_without_geph_or_a_second_strategy(monkeypatch, preflight, failed):
    class Reader:
        def __init__(self):
            self.parts = [b"\x16\x03\x01\x00\x01", b"x"]

        async def readexactly(self, _size):
            return self.parts.pop(0)

    class Writer:
        def __init__(self):
            self.writes = []
            self.closed = False

        def get_extra_info(self, _name):
            return object()

        def write(self, data):
            self.writes.append(data)

        async def drain(self):
            if self is writer and failed == "cancel_delivery":
                raise asyncio.CancelledError

        async def wait_closed(self):
            pass

        def close(self):
            self.closed = True

    calls, relays, races = [], [], []
    writer = Writer()
    upstream_writer = Writer()

    async def race(*args, **kwargs):
        assert preflight
        races.append(True)
        claim = stored_claim()
        return tproxy.SYSTEM_PROBE_UNCLEAR, None, claim

    async def dial(*args):
        calls.append(args)
        return None if failed is True else (object(), upstream_writer, b"server-first")

    async def relay(*args, **kwargs):
        relays.append((args, kwargs))
        return 0, 0

    async def forbidden(*args, **kwargs):
        pytest.fail("qualified local route entered an unrelated route")

    if not preflight:
        stored_claim()
    monkeypatch.setattr(tproxy, "orig_dst", lambda sock: (ORIGINAL, 443))
    monkeypatch.setattr(tproxy, "parse_sni", lambda body: HOST)
    monkeypatch.setattr(tproxy, "_recursive_proxy_destination", lambda *_: False)
    monkeypatch.setattr(tproxy, "_run_unknown_initial_route_race", race)
    monkeypatch.setattr(tproxy, "dial_strategy", dial)
    monkeypatch.setattr(tproxy, "relay_local_stream", relay)
    monkeypatch.setattr(tproxy, "_try_unknown_owned_geph_route", forbidden)
    monkeypatch.setattr(tproxy, "_try_xbox_dns_local_connect", forbidden)
    monkeypatch.setattr(tproxy, "resolve_connection_ips", forbidden)
    monkeypatch.setattr(tproxy, "runtime_route_circuit_record_result", lambda *a, **k: None)
    monkeypatch.setattr(tproxy, "_register_pending_navigation_relay", lambda *a, **k: None)
    monkeypatch.setattr(tproxy, "note_local_result", lambda *a, **k: None)
    if failed == "cancel_delivery":
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(tproxy._handle_impl(Reader(), writer))
        assert upstream_writer.closed and not tproxy._bootstrap_local_routes
        assert len(calls) == 1 and not relays
        return
    asyncio.run(tproxy._handle_impl(Reader(), writer))
    assert len(calls) == 1 and calls[0][0] == SELECTED
    assert calls[0][-1] is tproxy.STRAT_BY_NAME["split64"]
    assert bool(races) is preflight
    assert writer.writes == ([] if failed else [b"server-first"])
    assert len(relays) == (0 if failed else 1)
    if failed:
        assert writer.closed and not tproxy._bootstrap_local_routes
