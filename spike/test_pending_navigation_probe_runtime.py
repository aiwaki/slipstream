import asyncio
import json
import os
from pathlib import Path
import plistlib
import pwd
import socket
import stat
import struct
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace

import pytest
import pending_navigation_probe_runtime as probe_runtime
import tproxy


def test_browser_worker_disposable_environment_is_closed_and_ci_only():
    fixture = {
        "CI": "true",
        "GITHUB_ACTIONS": "true",
        "SLIPSTREAM_DISPOSABLE_CI": "1",
        "SLIPSTREAM_BROWSER_PROBE_CHROME": "/tmp/Chrome",
        "SLIPSTREAM_BROWSER_PROBE_ORIGIN": "https://pending.invalid:8443/",
        "SLIPSTREAM_BROWSER_PROBE_HOST_RESOLVER_RULES": (
            "MAP pending.invalid 127.0.0.1"
        ),
        "SLIPSTREAM_BROWSER_PROBE_IGNORE_CERTIFICATE_ERRORS": "1",
        "SLIPSTREAM_BROWSER_PROBE_SOCKET": "/tmp/probe.sock",
        "UNRELATED_SECRET": "must-not-cross",
    }

    forwarded = probe_runtime.browser_worker_disposable_environment(fixture)

    assert set(forwarded) == probe_runtime._BROWSER_WORKER_DISPOSABLE_ENVIRONMENT
    assert "UNRELATED_SECRET" not in forwarded
    fixture.pop("GITHUB_ACTIONS")
    assert probe_runtime.browser_worker_disposable_environment(fixture) == {}


def test_tproxy_lazy_worker_receives_only_the_closed_disposable_environment(
    monkeypatch,
):
    forwarded = {
        "CI": "true",
        "GITHUB_ACTIONS": "true",
        "SLIPSTREAM_DISPOSABLE_CI": "1",
        "SLIPSTREAM_BROWSER_PROBE_ORIGIN": "https://pending.invalid:8443/",
    }
    observed = {}

    class Launcher:
        def __init__(self, **kwargs):
            observed["launcher"] = kwargs

        def launch(self):
            return True

    class Worker:
        def __init__(self, **kwargs):
            observed["worker"] = kwargs

    runtime = SimpleNamespace(state_size=lambda: 0)
    monkeypatch.setattr(tproxy, "_pending_navigation_probe_worker", None)
    monkeypatch.setattr(tproxy, "_pending_navigation_probe_runtime", runtime)
    monkeypatch.setattr(
        probe_runtime,
        "browser_worker_disposable_environment",
        lambda: forwarded,
    )
    monkeypatch.setattr(
        probe_runtime,
        "PendingNavigationBrowserWorkerLauncher",
        Launcher,
    )
    monkeypatch.setattr(
        probe_runtime,
        "LazyPendingNavigationProbeWorker",
        Worker,
    )

    worker = tproxy._get_pending_navigation_probe_worker()

    assert isinstance(worker, Worker)
    assert observed["launcher"] == {"disposable_environment": forwarded}
    assert observed["worker"]["pending_jobs"] is runtime.state_size


def test_disposable_upstream_mapping_is_exact_ci_only_and_unknown_host_only():
    environment = {
        "CI": "true",
        "GITHUB_ACTIONS": "true",
        "SLIPSTREAM_DISPOSABLE_CI": "1",
        "SLIPSTREAM_PENDING_NAVIGATION_FIXTURE_HOST": "pending.invalid",
        "SLIPSTREAM_PENDING_NAVIGATION_FIXTURE_IP": "93.184.216.34",
        "SLIPSTREAM_PENDING_NAVIGATION_FIXTURE_PORT": "18443",
    }

    assert tproxy._disposable_pending_navigation_fixture_endpoint(
        "pending.invalid",
        "93.184.216.34",
        443,
        environment=environment,
    ) == ("127.0.0.1", 18443)
    assert tproxy._disposable_pending_navigation_fixture_endpoint(
        None,
        "93.184.216.34",
        443,
        environment=environment,
    ) is None
    assert tproxy._disposable_pending_navigation_fixture_endpoint(
        "discord.com",
        "93.184.216.34",
        443,
        environment=environment,
    ) is None
    assert tproxy._disposable_pending_navigation_fixture_endpoint(
        "pending.invalid",
        "93.184.216.35",
        443,
        environment=environment,
    ) is None
    environment.pop("GITHUB_ACTIONS")
    assert tproxy._disposable_pending_navigation_fixture_endpoint(
        "pending.invalid",
        "93.184.216.34",
        443,
        environment=environment,
    ) is None


def test_disposable_strategy_mapping_skips_real_fake_packet_injection(monkeypatch):
    environment = {
        "CI": "true",
        "GITHUB_ACTIONS": "true",
        "SLIPSTREAM_DISPOSABLE_CI": "1",
        "SLIPSTREAM_PENDING_NAVIGATION_FIXTURE_HOST": "pending.invalid",
        "SLIPSTREAM_PENDING_NAVIGATION_FIXTURE_IP": "93.184.216.34",
        "SLIPSTREAM_PENDING_NAVIGATION_FIXTURE_PORT": "18443",
    }
    calls = []

    async def plain(ip, port, blob):
        calls.append((ip, port, blob))
        return "fixture"

    async def forbidden(*_args, **_kwargs):
        raise AssertionError("fake packet injection reached the fixture")

    monkeypatch.setattr(
        tproxy,
        "_PENDING_NAVIGATION_FIXTURE_ENVIRONMENT",
        environment,
    )
    monkeypatch.setattr(tproxy, "dial_and_probe", plain)
    monkeypatch.setattr(tproxy, "dial_and_probe_fake", forbidden)
    strategy = {"cap": 0, "fake": True}

    result = asyncio.run(tproxy.dial_strategy(
        "93.184.216.34",
        443,
        b"head",
        b"body",
        "pending.invalid",
        strategy,
    ))

    assert result == "fixture"
    assert calls[0][0:2] == ("127.0.0.1", 18443)


def test_exact_system_probe_uses_the_disposable_loopback_upstream(monkeypatch):
    async def scenario():
        received = []

        async def handle(reader, writer):
            received.append(await reader.readexactly(5))
            writer.write(b"server-first")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = int(server.sockets[0].getsockname()[1])
        environment = {
            "CI": "true",
            "GITHUB_ACTIONS": "true",
            "SLIPSTREAM_DISPOSABLE_CI": "1",
            "SLIPSTREAM_PENDING_NAVIGATION_FIXTURE_HOST": "pending.invalid",
            "SLIPSTREAM_PENDING_NAVIGATION_FIXTURE_IP": "93.184.216.34",
            "SLIPSTREAM_PENDING_NAVIGATION_FIXTURE_PORT": str(port),
        }
        monkeypatch.setattr(
            tproxy,
            "_PENDING_NAVIGATION_FIXTURE_ENVIRONMENT",
            environment,
        )
        fixture_host = tproxy._PENDING_NAVIGATION_FIXTURE_HOST.set(
            "pending.invalid"
        )
        try:
            state, connection = await tproxy._try_exact_system_probe(
                "93.184.216.34",
                443,
                b"hello",
            )
            assert state == tproxy.SYSTEM_PROBE_PAYLOAD
            assert connection[2] == b"server-first"
            await tproxy._close_stream_writer(connection[1])
        finally:
            tproxy._PENDING_NAVIGATION_FIXTURE_HOST.reset(fixture_host)
            server.close()
            await server.wait_closed()
        assert received == [b"hello"]

    asyncio.run(scenario())


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = json.loads(
    (ROOT / "contracts" / "pending-navigation-probe-v1.json").read_text()
)


def _job(index=1, **overrides):
    return {
        "schema_version": 1,
        "capability": f"{index:032x}",
        "host": "unknown.example",
        "request_started_at_unix_ms": 1_000_000,
        "issued_at_unix_ms": 1_010_000,
        "expires_at_unix_ms": 1_040_000,
        **overrides,
    }


def _result(job, **overrides):
    return {
        "schema_version": 1,
        "capability": job["capability"],
        "host": job["host"],
        "request_started_at_unix_ms": job[
            "request_started_at_unix_ms"
        ],
        "observed_at_unix_ms": 1_018_001,
        "outcome": tproxy.PENDING_NAVIGATION_PROBE_OUTCOME_PENDING,
        **overrides,
    }


def _request(operation, **payload):
    return json.dumps({
        "schema_version": 1,
        "operation": operation,
        **payload,
    }).encode()


def _runtime(clock, submitted=None, max_live_jobs=32):
    submitted = [] if submitted is None else submitted
    return probe_runtime.PendingNavigationProbeRuntime(
        submit_result=lambda result: submitted.append(result) is None,
        wall_clock_ms=lambda: clock["wall"],
        monotonic_clock=lambda: clock["mono"],
        max_live_jobs=max_live_jobs,
    )


def test_contract_matches_runtime_bounds_and_owner_only_path():
    assert probe_runtime.CAPABILITY_TTL_MS == int(
        tproxy.PENDING_NAVIGATION_PROBE_TTL * 1000
    )
    assert probe_runtime.MAX_LIVE_JOBS == (
        tproxy.PENDING_NAVIGATION_PROBE_STATE_MAX
    )
    assert CONTRACT["bounds"]["capability_bits"] == (
        probe_runtime.CAPABILITY_HEX_CHARS * 4
    )
    assert CONTRACT["bounds"]["min_pending_observation_ms"] == int(
        tproxy.UNKNOWN_PRE_RESPONSE_IDLE * 1000
    )
    assert CONTRACT["bounds"] == {
        "capability_bits": 128,
        "capability_ttl_ms": probe_runtime.CAPABILITY_TTL_MS,
        "max_live_capabilities": probe_runtime.MAX_LIVE_JOBS,
        "min_pending_observation_ms": 8000,
    }
    assert probe_runtime.CONTRACT_PENDING_OBSERVATION_MS == (
        CONTRACT["bounds"]["min_pending_observation_ms"]
    )
    assert CONTRACT["outcomes"] == {
        "route_effect": "navigation_pending",
        "consume_without_route_effect": "navigation_terminal",
    }
    assert CONTRACT["invariants"][
        "terminal_observation_has_no_route_effect"
    ] is True
    assert CONTRACT["ipc"] == {
        "socket_path": probe_runtime.PENDING_NAVIGATION_PROBE_SOCKET_PATH,
        "claim_lease_ms": int(probe_runtime.CLAIM_LEASE_SECONDS * 1000),
        "max_enqueue_age_ms": probe_runtime.MAX_ENQUEUE_AGE_MS,
        "max_request_bytes": probe_runtime.MAX_IPC_BYTES,
        "owner_only_mode": "0600",
        "request_fields": {
            "claim": ["schema_version", "operation"],
            "submit": ["schema_version", "operation", "result"],
        },
        "response_fields": [
            "schema_version",
            "accepted",
            "operation",
            "reason",
            "job",
        ],
        "runtime_composed": True,
    }
    assert CONTRACT["worker_lifecycle"] == {
        "lazy": True,
        "max_concurrent_workers": 1,
        "retry_after_worker_loss_ms": int(
            probe_runtime.CLAIM_LEASE_SECONDS * 1000
        ),
        "same_host_recursive_jobs": False,
        "browser_observer_composed": True,
    }


def test_queue_is_bounded_exact_and_uses_a_monotonic_expiry():
    clock = {"wall": 1_010_000, "mono": 100.0}
    runtime = _runtime(clock, max_live_jobs=2)

    assert not runtime.enqueue(_job(schema_version=True))
    assert not runtime.enqueue(_job(host="UNKNOWN.example"))
    assert not runtime.enqueue(_job(expires_at_unix_ms=1_040_001))
    assert not runtime.enqueue(_job(
        issued_at_unix_ms=1_010_001,
        expires_at_unix_ms=1_040_001,
    ))
    assert runtime.enqueue(_job(1))
    assert not runtime.enqueue(_job(1))
    assert runtime.enqueue(_job(2))
    assert runtime.enqueue(_job(3))
    assert runtime.state_size() == 2

    clock["wall"] = 900_000
    clock["mono"] = 130.0
    assert runtime.state_size() == 0


def test_claim_lease_redelivers_after_worker_loss_but_not_after_expiry():
    clock = {"wall": 1_010_000, "mono": 100.0}
    runtime = _runtime(clock)
    job = _job()
    assert runtime.enqueue(job)

    first = runtime.handle(_request("claim"))
    assert first == {
        "schema_version": 1,
        "accepted": True,
        "operation": "claim",
        "reason": "job_ready",
        "job": job,
    }
    assert runtime.handle(_request("claim"))["reason"] == "no_job"
    clock["mono"] = 105.001
    assert runtime.handle(_request("claim"))["job"] == job
    clock["mono"] = 130.0
    assert runtime.handle(_request("claim"))["reason"] == "no_job"


def test_submit_removes_the_job_and_reports_effect_outcome():
    clock = {"wall": 1_010_000, "mono": 100.0}
    submitted = []
    runtime = _runtime(clock, submitted)
    job = _job()
    result = _result(job)
    assert runtime.enqueue(job)

    response = runtime.handle(_request("submit", result=result))
    assert response == {
        "schema_version": 1,
        "accepted": True,
        "operation": "submit",
        "reason": "accepted",
        "job": None,
    }
    assert submitted == [result]
    assert runtime.state_size() == 0

    rejecting = probe_runtime.PendingNavigationProbeRuntime(
        submit_result=lambda _result: False,
        wall_clock_ms=lambda: clock["wall"],
        monotonic_clock=lambda: clock["mono"],
    )
    assert rejecting.handle(_request("submit", result=result))["reason"] == (
        "result_rejected"
    )

    def fail(_result):
        raise RuntimeError("effect failed")

    failing = probe_runtime.PendingNavigationProbeRuntime(
        submit_result=fail,
        wall_clock_ms=lambda: clock["wall"],
        monotonic_clock=lambda: clock["mono"],
    )
    assert failing.enqueue(job)
    assert failing.handle(_request("submit", result=result))["reason"] == (
        "effect_unavailable"
    )
    assert failing.state_size() == 0


def test_request_parser_rejects_duplicates_extra_fields_and_wrong_shapes():
    clock = {"wall": 1_010_000, "mono": 100.0}
    runtime = _runtime(clock)
    invalid = (
        b'{"schema_version":1,"schema_version":1,"operation":"claim"}',
        _request("claim", unexpected=True),
        _request("other"),
        b"[]",
        b"not-json",
        b"x" * (probe_runtime.MAX_IPC_BYTES + 1),
    )
    for payload in invalid:
        assert runtime.handle(payload) == {
            "schema_version": 1,
            "accepted": False,
            "operation": "none",
            "reason": "invalid_request",
            "job": None,
        }


def test_worker_response_parser_rejects_duplicate_expanded_and_wrong_operation():
    valid = {
        "schema_version": 1,
        "accepted": True,
        "operation": "claim",
        "reason": "no_job",
        "job": None,
    }
    invalid = (
        (
            b'{"schema_version":1,"accepted":true,"accepted":true,'
            b'"operation":"claim","reason":"no_job","job":null}'
        ),
        json.dumps({**valid, "unexpected": True}).encode(),
        json.dumps({**valid, "operation": "submit"}).encode(),
    )
    for payload in invalid:
        with pytest.raises(probe_runtime.PendingNavigationProbeRuntimeError):
            probe_runtime._parse_response(payload, "claim")


def test_owner_only_socket_carries_one_job_to_its_exact_relay():
    async def round_trip(path, payload):
        reader, writer = await asyncio.open_unix_connection(path)
        writer.write(probe_runtime.encode_frame(payload))
        await writer.drain()
        length = struct.unpack("<I", await reader.readexactly(4))[0]
        response = json.loads(await reader.readexactly(length))
        writer.close()
        await writer.wait_closed()
        return response

    async def scenario():
        tproxy._pending_navigation_probe_capabilities.clear()
        tproxy._active_pending_navigation_relays.clear()
        clock = {"wall": 1_010_000, "mono": 100.0}
        first = tproxy._RelayActivity(
            last_downstream_at=90.0,
            downstream_bytes=64,
            first_downstream_seen=True,
            track_tls_records=True,
            tls_framing_valid=True,
            tls_complete_records=1,
            pending_navigation_started_at_unix_ms=1_000_000,
        )
        second = tproxy._RelayActivity(
            last_downstream_at=90.0,
            downstream_bytes=64,
            first_downstream_seen=True,
            track_tls_records=True,
            tls_framing_valid=True,
            tls_complete_records=1,
            pending_navigation_started_at_unix_ms=1_000_000,
        )
        for activity, address in ((first, "1.1.1.1"), (second, "8.8.8.8")):
            assert tproxy._register_pending_navigation_relay(
                activity,
                "unknown.example",
                address,
                tproxy.ROUTE_UNKNOWN,
                tproxy.AUTO_GEPH_STAGE_SYSTEM,
                scheduler=lambda *args, **kwargs: False,
            )
        job = tproxy._issue_pending_navigation_probe(
            first,
            now=clock["mono"],
            now_unix_ms=clock["wall"],
            token_factory=lambda: "f" * 32,
        )
        runtime = probe_runtime.PendingNavigationProbeRuntime(
            submit_result=lambda result: (
                tproxy._submit_pending_navigation_probe_result(
                    result,
                    now=clock["mono"],
                )
            ),
            wall_clock_ms=lambda: clock["wall"],
            monotonic_clock=lambda: clock["mono"],
        )
        assert runtime.enqueue(job)

        with tempfile.TemporaryDirectory(prefix="ss-probe-", dir="/tmp") as directory:
            socket_path = Path(directory) / "probe.sock"
            owned = await probe_runtime.start_owned_pending_navigation_probe_server(
                str(socket_path),
                os.getuid(),
                os.getgid(),
                runtime,
            )
            record = os.lstat(socket_path)
            assert stat.S_ISSOCK(record.st_mode)
            assert stat.S_IMODE(record.st_mode) == 0o600
            claimed = await round_trip(socket_path, _request("claim"))
            assert claimed["job"] == job

            clock.update({"wall": 1_018_001, "mono": 108.001})
            submitted = await round_trip(
                socket_path,
                _request("submit", result=_result(job)),
            )
            assert submitted["accepted"] is True
            assert first.downstream_idle_retry
            assert not second.downstream_idle_retry
            await owned.close()
            assert not socket_path.exists()

        tproxy._unregister_pending_navigation_relay(first)
        tproxy._unregister_pending_navigation_relay(second)

    try:
        asyncio.run(scenario())
    finally:
        tproxy._local_payload_idle_failures.pop("unknown.example", None)
        tproxy._xbox_dns_candidates.pop("unknown.example", None)
        tproxy._pending_navigation_probe_capabilities.clear()
        tproxy._active_pending_navigation_relays.clear()


def test_worker_client_requires_owner_socket_and_exact_responses():
    async def scenario():
        clock = {"wall": 1_010_000, "mono": 100.0}
        submitted = []
        runtime = _runtime(clock, submitted)
        job = _job()
        result = _result(job)
        assert runtime.enqueue(job)

        with tempfile.TemporaryDirectory(prefix="ss-worker-", dir="/tmp") as directory:
            socket_path = Path(directory) / "probe.sock"
            owned = await probe_runtime.start_owned_pending_navigation_probe_server(
                str(socket_path),
                os.getuid(),
                os.getgid(),
                runtime,
            )
            client = probe_runtime.PendingNavigationProbeWorkerClient(
                str(socket_path)
            )
            assert await asyncio.to_thread(client.claim) == job
            response = await asyncio.to_thread(client.submit, result)
            assert response["accepted"] is True
            assert submitted == [result]

            socket_path.chmod(0o660)
            with pytest.raises(
                probe_runtime.PendingNavigationProbeRuntimeError,
                match="unowned_socket",
            ):
                await asyncio.to_thread(client.claim)
            socket_path.chmod(0o600)
            await owned.close()
            assert not socket_path.exists()

    asyncio.run(scenario())


def test_probe_server_rejects_oversized_frames_and_removes_exact_socket():
    async def scenario():
        clock = {"wall": 1_010_000, "mono": 100.0}
        runtime = _runtime(clock)
        with tempfile.TemporaryDirectory(
            prefix="ss-probe-frame-",
            dir="/tmp",
        ) as directory:
            socket_path = Path(directory) / "probe.sock"
            owned = (
                await probe_runtime
                .start_owned_pending_navigation_probe_server(
                    str(socket_path),
                    os.getuid(),
                    os.getgid(),
                    runtime,
                )
            )
            reader, writer = await asyncio.open_unix_connection(socket_path)
            writer.write(
                struct.pack("<I", probe_runtime.MAX_IPC_BYTES + 1)
            )
            await writer.drain()
            length = struct.unpack("<I", await reader.readexactly(4))[0]
            response = json.loads(await reader.readexactly(length))
            assert response == {
                "schema_version": 1,
                "accepted": False,
                "operation": "none",
                "reason": "invalid_request",
                "job": None,
            }
            writer.close()
            await writer.wait_closed()
            await owned.close()
            assert not socket_path.exists()

    asyncio.run(scenario())


def test_probe_server_refuses_regular_or_active_socket_paths():
    async def scenario():
        with tempfile.TemporaryDirectory(
            prefix="ss-probe-path-",
            dir="/tmp",
        ) as directory:
            regular_path = Path(directory) / "regular.sock"
            regular_path.write_text("not a socket")
            with pytest.raises(OSError, match="unowned"):
                await probe_runtime.start_owned_pending_navigation_probe_server(
                    str(regular_path),
                    os.getuid(),
                    os.getgid(),
                    _runtime({"wall": 1_010_000, "mono": 100.0}),
                )

            active_path = Path(directory) / "active.sock"
            active = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            active.bind(str(active_path))
            active.listen(1)
            try:
                with pytest.raises(OSError, match="already active"):
                    await probe_runtime.start_owned_pending_navigation_probe_server(
                        str(active_path),
                        os.getuid(),
                        os.getgid(),
                        _runtime({"wall": 1_010_000, "mono": 100.0}),
                    )
            finally:
                active.close()
                active_path.unlink()

    asyncio.run(scenario())


def test_probe_supervisor_starts_after_login_and_rebinds_session():
    async def wait_for(predicate):
        for _ in range(100):
            if predicate():
                return
            await asyncio.sleep(0.01)
        raise AssertionError("pending-navigation socket state did not converge")

    async def scenario():
        with tempfile.TemporaryDirectory(
            prefix="ss-probe-supervisor-",
            dir="/tmp",
        ) as directory:
            socket_path = Path(directory) / "probe.sock"
            identity = {"value": None}
            errors = []
            supervisor = (
                await probe_runtime
                .start_pending_navigation_probe_server_supervisor(
                    str(socket_path),
                    lambda: identity["value"],
                    _runtime({"wall": 1_010_000, "mono": 100.0}),
                    poll_interval=0.01,
                    error_handler=errors.append,
                )
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


def test_lazy_worker_starts_once_only_for_a_live_job():
    clock = {"wall": 1_010_000, "mono": 100.0}
    runtime = _runtime(clock)
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    launches = []

    def launch_worker():
        launches.append("started")
        entered.set()
        assert release.wait(1.0)
        claimed = runtime.handle(_request("claim"))["job"]
        assert claimed == _job()
        assert runtime.handle(
            _request("submit", result=_result(claimed))
        )["accepted"]
        finished.set()

    worker = probe_runtime.LazyPendingNavigationProbeWorker(
        pending_jobs=runtime.state_size,
        launch_worker=launch_worker,
        retry_seconds=0.01,
    )
    assert not worker.notify_job_ready()
    assert not worker.active()
    assert runtime.enqueue(_job())
    assert worker.notify_job_ready()
    assert entered.wait(1.0)
    assert not worker.notify_job_ready()
    release.set()
    assert finished.wait(1.0)
    deadline = time.monotonic() + 1.0
    while worker.active() and time.monotonic() < deadline:
        time.sleep(0.001)
    assert launches == ["started"]
    assert runtime.state_size() == 0
    assert not worker.active()
    assert worker.close()


def test_lazy_worker_reports_launch_failure_through_bounded_handler():
    pending = {"count": 1}
    failures = []
    attempted = threading.Event()

    def launch_worker():
        attempted.set()
        pending["count"] = 0
        raise probe_runtime.PendingNavigationProbeRuntimeError(
            "browser_worker_start_timeout"
        )

    worker = probe_runtime.LazyPendingNavigationProbeWorker(
        pending_jobs=lambda: pending["count"],
        launch_worker=launch_worker,
        retry_seconds=0.01,
        error_handler=failures.append,
    )
    assert worker.notify_job_ready()
    assert attempted.wait(1.0)
    deadline = time.monotonic() + 1.0
    while worker.active() and time.monotonic() < deadline:
        time.sleep(0.001)

    assert [str(error) for error in failures] == [
        "browser_worker_start_timeout"
    ]
    assert worker.close()


def test_console_worker_launcher_uses_one_exact_aqua_job_and_cleans_up():
    with tempfile.TemporaryDirectory(
        prefix="ss-browser-launcher-",
        dir="/tmp",
    ) as directory:
        root = Path(directory)
        executable = root / "Slipstream.app" / "Contents" / "MacOS" / "slipstream"
        executable.parent.mkdir(parents=True)
        executable.write_bytes(b"#!/bin/sh\nexit 0\n")
        executable.chmod(0o755)
        runtime_root = root / "runtime"
        identity = probe_runtime.ConsoleUserIdentity(
            uid=os.getuid(),
            gid=os.getgid(),
            username=pwd.getpwuid(os.getuid()).pw_name,
            home=str(root),
        )
        state = {
            "loaded": False,
            "loaded_prints": 0,
            "running": False,
            "payload": None,
        }

        def completed(command, returncode=0, stdout="", stderr=""):
            return subprocess.CompletedProcess(
                command,
                returncode,
                stdout,
                stderr,
            )

        def runner(command):
            if command[:2] == ("/bin/launchctl", "print"):
                if not state["loaded"]:
                    return completed(
                        command,
                        113,
                        stderr="Could not find service",
                    )
                state["loaded_prints"] += 1
                if state["loaded_prints"] <= 2:
                    if state["loaded_prints"] == 2:
                        state["running"] = False
                    return completed(command, stdout="pid = 4242\n")
                state["running"] = False
                return completed(command, stdout="last exit code = 0\n")
            if command[:2] == ("/bin/launchctl", "bootstrap"):
                state["loaded"] = True
                state["running"] = True
                state["payload"] = plistlib.loads(Path(command[3]).read_bytes())
                return completed(command)
            if command[:2] == ("/bin/launchctl", "bootout"):
                state["loaded"] = False
                return completed(command)
            if command[:2] == ("/bin/launchctl", "kill"):
                state["running"] = False
                return completed(command)
            if command[:2] == ("/bin/ps", "-p"):
                if not state["running"]:
                    return completed(command, 1)
                return completed(
                    command,
                    stdout=(
                        f"{identity.uid} {executable} "
                        f"{probe_runtime.PENDING_NAVIGATION_BROWSER_WORKER_ARGUMENT}\n"
                    ),
                )
            raise AssertionError(command)

        launcher = probe_runtime.PendingNavigationBrowserWorkerLauncher(
            executable=executable,
            runtime_root=runtime_root,
            identity_probe=lambda: identity,
            command_runner=runner,
            sleep=lambda _seconds: None,
        )
        assert launcher.launch()
        payload = state["payload"]
        assert payload["ProgramArguments"] == [
            str(executable),
            probe_runtime.PENDING_NAVIGATION_BROWSER_WORKER_ARGUMENT,
        ]
        assert payload["RunAtLoad"] is True
        assert payload["ProcessType"] == "Interactive"
        assert payload["LimitLoadToSessionType"] == "Aqua"
        assert payload["WorkingDirectory"] == str(root)
        assert list(runtime_root.iterdir()) == []


def test_console_worker_launcher_rejects_mutable_or_replaced_executables():
    with tempfile.TemporaryDirectory(
        prefix="ss-browser-launcher-invalid-",
        dir="/tmp",
    ) as directory:
        root = Path(directory)
        executable = root / "slipstream"
        executable.write_text("#!/bin/sh\n")
        executable.chmod(0o775)
        identity = probe_runtime.ConsoleUserIdentity(
            uid=os.getuid(),
            gid=os.getgid(),
            username=pwd.getpwuid(os.getuid()).pw_name,
            home=str(root),
        )
        launcher = probe_runtime.PendingNavigationBrowserWorkerLauncher(
            executable=executable,
            runtime_root=root / "runtime",
            identity_probe=lambda: identity,
        )
        with pytest.raises(
            probe_runtime.PendingNavigationProbeRuntimeError,
            match="browser_worker_unowned",
        ):
            launcher.launch()


def test_console_worker_launcher_cleans_only_exact_stale_runtime():
    with tempfile.TemporaryDirectory(
        prefix="ss-browser-stale-",
        dir="/tmp",
    ) as directory:
        root = Path(directory)
        executable = root / "slipstream"
        executable.write_text("#!/bin/sh\n")
        executable.chmod(0o755)
        account = pwd.getpwuid(os.getuid())
        identity = probe_runtime.ConsoleUserIdentity(
            uid=os.getuid(),
            gid=os.getgid(),
            username=account.pw_name,
            home=account.pw_dir,
        )
        runtime_root = root / "runtime"
        label = (
            f"{probe_runtime.PENDING_NAVIGATION_BROWSER_WORKER_LABEL_PREFIX}."
            "0123456789abcdef"
        )

        def completed(command, returncode=0, stdout="", stderr=""):
            return subprocess.CompletedProcess(
                command,
                returncode,
                stdout,
                stderr,
            )

        def runner(command):
            if command[:2] == ("/bin/launchctl", "print"):
                return completed(
                    command,
                    113,
                    stderr="Could not find service",
                )
            if command[:2] == ("/bin/launchctl", "bootout"):
                return completed(command, 113)
            raise AssertionError(command)

        launcher = probe_runtime.PendingNavigationBrowserWorkerLauncher(
            executable=executable,
            runtime_root=runtime_root,
            identity_probe=lambda: identity,
            command_runner=runner,
            sleep=lambda _seconds: None,
        )
        paths = launcher._prepare_launch(identity, label)
        assert paths.directory.exists()
        assert launcher.cleanup_stale(remove_root=True)
        assert not runtime_root.exists()

        paths = launcher._prepare_launch(identity, label)
        payload = plistlib.loads(paths.plist.read_bytes())
        payload["ProgramArguments"] = ["/tmp/unowned"]
        paths.plist.write_bytes(plistlib.dumps(payload))
        paths.plist.chmod(0o600)
        assert not launcher.cleanup_stale(remove_root=True)
        assert paths.directory.exists()

        payload["ProgramArguments"] = [
            str(executable),
            probe_runtime.PENDING_NAVIGATION_BROWSER_WORKER_ARGUMENT,
        ]
        payload["EnvironmentVariables"]["CI"] = "true"
        paths.plist.write_bytes(plistlib.dumps(payload))
        paths.plist.chmod(0o600)
        assert not launcher.cleanup_stale(remove_root=True)
        assert paths.directory.exists()

        paths.plist.write_bytes(plistlib.dumps(["not", "a", "dictionary"]))
        paths.plist.chmod(0o600)
        assert not launcher.cleanup_stale(remove_root=True)
        assert paths.directory.exists()


def test_console_worker_launcher_stops_one_exact_stale_loaded_job():
    with tempfile.TemporaryDirectory(
        prefix="ss-browser-stale-loaded-",
        dir="/tmp",
    ) as directory:
        root = Path(directory)
        executable = root / "slipstream"
        executable.write_text("#!/bin/sh\n")
        executable.chmod(0o755)
        account = pwd.getpwuid(os.getuid())
        identity = probe_runtime.ConsoleUserIdentity(
            uid=os.getuid(),
            gid=os.getgid(),
            username=account.pw_name,
            home=account.pw_dir,
        )
        runtime_root = root / "runtime"
        label = (
            f"{probe_runtime.PENDING_NAVIGATION_BROWSER_WORKER_LABEL_PREFIX}."
            "fedcba9876543210"
        )
        state = {
            "loaded": True,
            "running": True,
            "commands": [],
            "paths": None,
        }

        def completed(command, returncode=0, stdout="", stderr=""):
            return subprocess.CompletedProcess(
                command,
                returncode,
                stdout,
                stderr,
            )

        def runner(command):
            state["commands"].append(command)
            if command[:2] == ("/bin/launchctl", "print"):
                if not state["loaded"]:
                    return completed(
                        command,
                        113,
                        stderr="Could not find service",
                    )
                if state["running"]:
                    return completed(command, stdout="pid = 4242\n")
                return completed(command, stdout="last exit code = 1\n")
            if command[:2] == ("/bin/ps", "-p"):
                return completed(
                    command,
                    stdout=(
                        f"{identity.uid} {executable} "
                        f"{probe_runtime.PENDING_NAVIGATION_BROWSER_WORKER_ARGUMENT}\n"
                    ),
                )
            if command[:2] == ("/bin/launchctl", "kill"):
                state["running"] = False
                state["paths"].stderr.write_text(
                    "slipstream browser probe failed: worker_terminated\n"
                )
                state["paths"].stderr.chmod(0o600)
                return completed(command)
            if command[:2] == ("/bin/launchctl", "bootout"):
                state["loaded"] = False
                return completed(command)
            raise AssertionError(command)

        launcher = probe_runtime.PendingNavigationBrowserWorkerLauncher(
            executable=executable,
            runtime_root=runtime_root,
            identity_probe=lambda: identity,
            command_runner=runner,
            sleep=lambda _seconds: None,
        )
        state["paths"] = launcher._prepare_launch(identity, label)
        assert launcher.cleanup_stale(remove_root=True)
        assert not runtime_root.exists()
        assert not state["running"]
        assert any(
            command[:3] == ("/bin/launchctl", "kill", "SIGTERM")
            for command in state["commands"]
        )
        assert any(
            command[:2] == ("/bin/launchctl", "bootout")
            for command in state["commands"]
        )
        term_index = next(
            index for index, command in enumerate(state["commands"])
            if command[:3] == ("/bin/launchctl", "kill", "SIGTERM")
        )
        exit_index = next(
            index for index, command in enumerate(state["commands"])
            if index > term_index
            and command[:2] == ("/bin/launchctl", "print")
        )
        bootout_index = next(
            index for index, command in enumerate(state["commands"])
            if command[:2] == ("/bin/launchctl", "bootout")
        )
        assert term_index < exit_index < bootout_index


def test_stale_cleanup_accepts_only_persisted_closed_ci_environment(monkeypatch):
    with tempfile.TemporaryDirectory(
        prefix="ss-browser-stale-ci-",
        dir="/tmp",
    ) as directory:
        root = Path(directory)
        executable = root / "slipstream"
        executable.write_text("#!/bin/sh\n")
        executable.chmod(0o755)
        account = pwd.getpwuid(os.getuid())
        identity = probe_runtime.ConsoleUserIdentity(
            uid=os.getuid(),
            gid=os.getgid(),
            username=account.pw_name,
            home=account.pw_dir,
        )
        runtime_root = root / "runtime"
        label = (
            f"{probe_runtime.PENDING_NAVIGATION_BROWSER_WORKER_LABEL_PREFIX}."
            "0123456789abcdef"
        )
        markers = {
            "CI": "true",
            "GITHUB_ACTIONS": "true",
            "SLIPSTREAM_DISPOSABLE_CI": "1",
        }
        full_environment = {
            **markers,
            "SLIPSTREAM_BROWSER_PROBE_CHROME": "/tmp/Chrome",
            "SLIPSTREAM_BROWSER_PROBE_ORIGIN": "https://fixture.invalid/",
        }
        for name, value in markers.items():
            monkeypatch.setenv(name, value)

        def completed(command, returncode=0, stdout="", stderr=""):
            return subprocess.CompletedProcess(command, returncode, stdout, stderr)

        def runner(command):
            if command[:2] == ("/bin/launchctl", "print"):
                return completed(command, 113, stderr="Could not find service")
            if command[:2] == ("/bin/launchctl", "bootout"):
                return completed(command, 113)
            raise AssertionError(command)

        writer = probe_runtime.PendingNavigationBrowserWorkerLauncher(
            executable=executable,
            runtime_root=runtime_root,
            identity_probe=lambda: identity,
            command_runner=runner,
            disposable_environment=full_environment,
        )
        writer._prepare_launch(identity, label)
        cleaner = probe_runtime.PendingNavigationBrowserWorkerLauncher(
            executable=executable,
            runtime_root=runtime_root,
            identity_probe=lambda: identity,
            command_runner=runner,
            sleep=lambda _seconds: None,
            disposable_environment=markers,
        )

        assert cleaner.cleanup_stale(remove_root=True)
        assert not runtime_root.exists()


def test_stale_worker_identity_rejects_root_and_invalid_home(monkeypatch):
    identity_for_uid = (
        probe_runtime.PendingNavigationBrowserWorkerLauncher._identity_for_uid
    )
    monkeypatch.setattr(
        probe_runtime.pwd,
        "getpwuid",
        lambda uid: SimpleNamespace(
            pw_gid=0 if uid == 0 else 20,
            pw_name="root" if uid == 0 else "user",
            pw_dir="/var/root" if uid == 0 else "relative-home",
        ),
    )
    with pytest.raises(
        probe_runtime.PendingNavigationProbeRuntimeError,
        match="browser_worker_runtime_unowned",
    ):
        identity_for_uid(0)
    with pytest.raises(
        probe_runtime.PendingNavigationProbeRuntimeError,
        match="browser_worker_runtime_unowned",
    ):
        identity_for_uid(501)


def test_console_worker_error_diagnostic_accepts_only_one_safe_class():
    with tempfile.TemporaryDirectory(
        prefix="ss-browser-worker-error-",
        dir="/tmp",
    ) as directory:
        path = Path(directory) / "worker.stderr.log"
        identity = probe_runtime.ConsoleUserIdentity(
            uid=os.getuid(),
            gid=os.getgid(),
            username=pwd.getpwuid(os.getuid()).pw_name,
            home=directory,
        )
        path.write_bytes(
            b"slipstream browser probe failed: devtools_file_invalid\n"
        )
        path.chmod(0o600)
        read_error = (
            probe_runtime.PendingNavigationBrowserWorkerLauncher
            ._read_worker_error
        )
        assert read_error(path, identity) == "devtools_file_invalid"

        path.write_bytes(
            b"slipstream browser probe failed: devtools_file_invalid\n"
            b"https://private.example/path\n"
        )
        assert read_error(path, identity) == "unknown"

        path.write_bytes(b"x" * 257)
        assert read_error(path, identity) == "unknown"


def test_lazy_worker_retries_after_a_lost_claim_lease():
    clock = {"wall": 1_010_000, "mono": 100.0}
    runtime = _runtime(clock)
    assert runtime.enqueue(_job())
    completed = threading.Event()
    launches = []

    def launch_worker():
        claimed = runtime.handle(_request("claim"))["job"]
        launches.append(claimed)
        if len(launches) == 1:
            assert claimed == _job()
            clock["mono"] += probe_runtime.CLAIM_LEASE_SECONDS + 0.001
            raise RuntimeError("worker disappeared")
        assert claimed == _job()
        assert runtime.handle(
            _request("submit", result=_result(claimed))
        )["accepted"]
        completed.set()

    worker = probe_runtime.LazyPendingNavigationProbeWorker(
        pending_jobs=runtime.state_size,
        launch_worker=launch_worker,
        retry_seconds=0.001,
    )
    assert worker.notify_job_ready()
    assert completed.wait(1.0)
    assert launches == [_job(), _job()]
    assert runtime.state_size() == 0
    assert worker.close()
