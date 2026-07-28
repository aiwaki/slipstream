import asyncio
import json
import os
from pathlib import Path
import socket
import stat
import struct
import tempfile

import pytest

from semantic_route_signal import (
    ACTION_CONFIRM_EXACT_HOST_GEO_EXIT,
    ACTION_NONE,
    ROUTE_DIRECT,
    ROUTE_UNKNOWN,
)
from semantic_route_signal_runtime import (
    MAX_RUNTIME_ENTRIES,
    REASON_CONFIRMATION_NOT_SCHEDULED,
    SemanticRouteSignalRuntime,
    encode_frame,
    start_owned_semantic_signal_server,
    start_semantic_signal_server_supervisor,
)


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = json.loads(
    (ROOT / "contracts" / "semantic-route-signal-v1.json").read_text()
)
CONTRACT_V2 = json.loads(
    (ROOT / "contracts" / "semantic-route-signal-v2.json").read_text()
)


def _payload(**overrides):
    return json.dumps(
        {
            **CONTRACT["signal_defaults"],
            **overrides,
        }
    ).encode()


def _payload_v2(**overrides):
    return json.dumps(
        {
            **CONTRACT_V2["signal_defaults"],
            **overrides,
        }
    ).encode()


def _runtime(
    *,
    route_class=ROUTE_UNKNOWN,
    backend_ready=True,
    schedule=True,
    now_ms=1_050_000,
    now_mono=10.0,
    scheduled_hosts=None,
):
    scheduled_hosts = [] if scheduled_hosts is None else scheduled_hosts
    return SemanticRouteSignalRuntime(
        route_class_for_host=lambda _host: route_class,
        owned_geph_ready=lambda: backend_ready,
        request_confirmation=lambda host: (
            scheduled_hosts.append(host) is None and schedule
        ),
        wall_clock_ms=lambda: now_ms,
        monotonic_clock=lambda: now_mono,
    )


def test_runtime_schedules_only_the_normalized_unknown_host():
    scheduled = []
    runtime = _runtime(scheduled_hosts=scheduled)

    response = runtime.handle(_payload(host="Weather.COM."))

    assert response == {
        "schema_version": 1,
        "accepted": True,
        "action": ACTION_CONFIRM_EXACT_HOST_GEO_EXIT,
        "reason": "accepted",
    }
    assert scheduled == ["weather.com"]


def test_runtime_reclassifies_protected_routes_before_backend_or_effect():
    backend_calls = []
    scheduled = []
    runtime = SemanticRouteSignalRuntime(
        route_class_for_host=lambda _host: ROUTE_DIRECT,
        owned_geph_ready=lambda: backend_calls.append(True),
        request_confirmation=scheduled.append,
        wall_clock_ms=lambda: 1_050_000,
        monotonic_clock=lambda: 10.0,
    )

    response = runtime.handle(_payload(host="www.google.com"))

    assert response["accepted"] is False
    assert response["reason"] == "protected_route"
    assert backend_calls == []
    assert scheduled == []


def test_runtime_rejects_replay_and_same_host_reload_loop():
    runtime = _runtime()
    first = runtime.handle(_payload())
    replay = runtime.handle(_payload())
    another_id = runtime.handle(
        _payload(signal_id="fedcba9876543210fedcba9876543210")
    )

    assert first["accepted"] is True
    assert replay["reason"] == "replay"
    assert another_id["reason"] == "rate_limited"


def test_runtime_does_not_claim_acceptance_when_scheduler_refuses():
    runtime = _runtime(schedule=False)

    response = runtime.handle(_payload())

    assert response == {
        "schema_version": 1,
        "accepted": False,
        "action": ACTION_NONE,
        "reason": REASON_CONFIRMATION_NOT_SCHEDULED,
    }


def test_v2_uses_only_the_complete_response_confirmation_effect():
    regional = []
    incomplete = []
    runtime = SemanticRouteSignalRuntime(
        route_class_for_host=lambda _host: ROUTE_UNKNOWN,
        owned_geph_ready=lambda: True,
        request_confirmation=lambda host: regional.append(host) is None,
        request_incomplete_confirmation=lambda host: (
            incomplete.append(host) is None
        ),
        wall_clock_ms=lambda: 1_050_000,
        monotonic_clock=lambda: 10.0,
    )

    response = runtime.handle(_payload_v2(host="Example.NET."))

    assert response["accepted"] is True
    assert regional == []
    assert incomplete == ["example.net"]


def test_v2_never_falls_back_to_the_regional_confirmation_effect():
    regional = []
    runtime = SemanticRouteSignalRuntime(
        route_class_for_host=lambda _host: ROUTE_UNKNOWN,
        owned_geph_ready=lambda: True,
        request_confirmation=lambda host: regional.append(host) is None,
        wall_clock_ms=lambda: 1_050_000,
        monotonic_clock=lambda: 10.0,
    )

    response = runtime.handle(_payload_v2())

    assert response["accepted"] is False
    assert response["reason"] == REASON_CONFIRMATION_NOT_SCHEDULED
    assert regional == []


def test_scheduler_refusal_does_not_rate_limit_a_new_signal():
    scheduled = iter((False, True))
    runtime = SemanticRouteSignalRuntime(
        route_class_for_host=lambda _host: ROUTE_UNKNOWN,
        owned_geph_ready=lambda: True,
        request_confirmation=lambda _host: next(scheduled),
        wall_clock_ms=lambda: 1_050_000,
        monotonic_clock=lambda: 10.0,
    )

    first = runtime.handle(_payload())
    second = runtime.handle(
        _payload(signal_id="fedcba9876543210fedcba9876543210")
    )

    assert first["reason"] == REASON_CONFIRMATION_NOT_SCHEDULED
    assert second["accepted"] is True


def test_runtime_state_is_bounded():
    counter = {"now": 10.0}
    runtime = SemanticRouteSignalRuntime(
        route_class_for_host=lambda _host: ROUTE_DIRECT,
        owned_geph_ready=lambda: False,
        request_confirmation=lambda _host: False,
        wall_clock_ms=lambda: 1_050_000,
        monotonic_clock=lambda: counter["now"],
    )

    for index in range(MAX_RUNTIME_ENTRIES + 20):
        runtime.handle(_payload(signal_id=f"{index:032x}"))
        counter["now"] += 0.001

    assert runtime.state_sizes() == (MAX_RUNTIME_ENTRIES, 0)


def test_owner_only_socket_round_trip_and_exact_cleanup():
    async def scenario():
        with tempfile.TemporaryDirectory(prefix="ss-sem-", dir="/tmp") as directory:
            socket_path = Path(directory) / "semantic.sock"
            runtime = _runtime()
            owned = await start_owned_semantic_signal_server(
                str(socket_path),
                os.getuid(),
                os.getgid(),
                runtime,
            )
            record = os.lstat(socket_path)
            assert stat.S_ISSOCK(record.st_mode)
            assert stat.S_IMODE(record.st_mode) == 0o600

            reader, writer = await asyncio.open_unix_connection(socket_path)
            writer.write(encode_frame(_payload()))
            await writer.drain()
            length = struct.unpack("<I", await reader.readexactly(4))[0]
            response = json.loads(await reader.readexactly(length))
            writer.close()
            await writer.wait_closed()

            assert response["accepted"] is True
            await owned.close()
            assert not socket_path.exists()

    asyncio.run(scenario())


def test_socket_refuses_to_replace_regular_file(tmp_path):
    async def scenario():
        socket_path = tmp_path / "semantic.sock"
        socket_path.write_text("not a socket")

        with pytest.raises(OSError, match="unowned"):
            await start_owned_semantic_signal_server(
                str(socket_path),
                os.getuid(),
                os.getgid(),
                _runtime(),
            )

        assert socket_path.read_text() == "not a socket"

    asyncio.run(scenario())


def test_socket_refuses_to_replace_active_socket():
    async def scenario():
        with tempfile.TemporaryDirectory(prefix="ss-sem-", dir="/tmp") as directory:
            socket_path = Path(directory) / "semantic.sock"
            active = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            active.bind(str(socket_path))
            active.listen(1)
            try:
                with pytest.raises(OSError, match="already active"):
                    await start_owned_semantic_signal_server(
                        str(socket_path),
                        os.getuid(),
                        os.getgid(),
                        _runtime(),
                    )
            finally:
                active.close()
                socket_path.unlink()

    asyncio.run(scenario())


def test_supervisor_starts_after_login_and_rebinds_on_session_change():
    async def wait_for(predicate):
        for _ in range(100):
            if predicate():
                return
            await asyncio.sleep(0.01)
        raise AssertionError("semantic socket state did not converge")

    async def scenario():
        with tempfile.TemporaryDirectory(prefix="ss-sem-", dir="/tmp") as directory:
            socket_path = Path(directory) / "semantic.sock"
            identity = {"value": None}
            errors = []
            supervisor = await start_semantic_signal_server_supervisor(
                str(socket_path),
                lambda: identity["value"],
                _runtime(),
                poll_interval=0.01,
                error_handler=errors.append,
            )
            try:
                assert not socket_path.exists()

                identity["value"] = (os.getuid(), os.getgid(), "session-a")
                await wait_for(socket_path.exists)
                assert supervisor._session_identity[2] == "session-a"

                identity["value"] = (os.getuid(), os.getgid(), "session-b")
                await wait_for(
                    lambda: (
                        socket_path.exists()
                        and supervisor._session_identity is not None
                        and supervisor._session_identity[2] == "session-b"
                    )
                )

                identity["value"] = None
                await wait_for(lambda: not socket_path.exists())
                assert errors == []
            finally:
                await supervisor.close()
            assert not socket_path.exists()

    asyncio.run(scenario())
