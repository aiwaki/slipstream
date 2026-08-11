import asyncio
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import threading
import time

import pending_navigation_probe_runtime as probe_runtime
import pytest
import tproxy
from semantic_route_signal_runtime import (
    encode_frame,
    start_owned_semantic_signal_server,
)


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
        "runtime_composed": False,
    }
    assert CONTRACT["worker_lifecycle"] == {
        "lazy": True,
        "max_concurrent_workers": 1,
        "retry_after_worker_loss_ms": int(
            probe_runtime.CLAIM_LEASE_SECONDS * 1000
        ),
        "same_host_recursive_jobs": False,
        "browser_observer_composed": False,
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
        writer.write(encode_frame(payload))
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
            owned = await start_owned_semantic_signal_server(
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
            owned = await start_owned_semantic_signal_server(
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
