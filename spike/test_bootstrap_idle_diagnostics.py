"""Synthetic diagnostic-only bootstrap checks; no network or route mutations."""

import asyncio
from collections import deque
import threading
from types import SimpleNamespace

import pytest
import tproxy


HOST = "diagnostic-child.example"
REQUEST = b"GET /assets/synthetic-entry.js HTTP/1.1\r\nRange: bytes=0-65535\r\n\r\n"
Outcome = tproxy.bootstrap_asset_preflight.RangeProbeOutcome


def _evidence(outcome, *, validator="same-object", total=1_210_087):
    return tproxy.bootstrap_asset_preflight.RangeProbeEvidence(
        outcome,
        total_length=total,
        range_end=tproxy.bootstrap_asset_preflight.DEFAULT_RANGE_END,
        validator_digest=validator,
        received_body_bytes=65_536 if outcome is Outcome.COMPLETE else 16_384,
    )


def _observation(outcome, **kwargs):
    return tproxy._BootstrapRangeProbeObservation(
        _evidence(outcome, **kwargs),
        tproxy._BOOTSTRAP_RANGE_TERMINATION_COMPLETE
        if outcome is Outcome.COMPLETE
        else tproxy._BOOTSTRAP_RANGE_TERMINATION_IDLE_TIMEOUT,
    )


@pytest.fixture(autouse=True)
def no_diagnostic_authority(monkeypatch):
    def forbidden(*_args, **_kwargs):
        pytest.fail("diagnostic-only comparison attempted route authority")

    for name in (
        "_new_direct_route_preflight_job",
        "_commit_preflight_owned_geph_proof",
        "save_auto_geph",
        "_owned_geph_confirmation_pid",
        "_owned_geph_confirmation_pid_matches",
        "_run",
    ):
        monkeypatch.setattr(tproxy, name, forbidden)
    states = {}
    for name in (
        "_auto_geph", "_route_preflight_cache", "_route_preflight_inflight",
        "_route_preflight_execution_leases",
    ):
        states[name] = {}
        monkeypatch.setattr(tproxy, name, states[name])
    yield
    assert all(not state for state in states.values())


@pytest.fixture
def owned_diagnostic(monkeypatch):
    clock = [100.0]
    owner = {"ready": True, "pid": 41, "matches": True}
    monkeypatch.setattr(tproxy, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(
        tproxy, "_owned_geph_ready_for_semantic_confirmation", lambda: owner["ready"]
    )

    def owned_pid(_deadline, *, expected_pid=None, cancel_event=None):
        if not owner["matches"] or (
            expected_pid is not None and expected_pid != owner["pid"]
        ):
            return None
        return owner["pid"]

    monkeypatch.setattr(tproxy, "_bootstrap_diagnostic_owned_pid", owned_pid)
    return clock, owner


@pytest.fixture
def owned_commands(monkeypatch):
    """Real ownership validators, but synthetic state and subprocess results only."""
    backend = SimpleNamespace(
        clock=100.0, cost=0.25, ready=True, calls=[],
        state={"pid": 41, "executable": "/synthetic/geph", "config": "/synthetic/config"},
        command="/synthetic/geph --config /synthetic/config",
    )
    monkeypatch.setattr(tproxy, "time", SimpleNamespace(monotonic=lambda: backend.clock))
    monkeypatch.setattr(tproxy, "_read_geph_ownership", lambda: backend.state)
    monkeypatch.setattr(
        tproxy, "_owned_geph_ready_for_semantic_confirmation", lambda: backend.ready,
    )
    monkeypatch.setattr(tproxy, "_geph_port", 9954)

    def run(args, **kwargs):
        backend.calls.append((args, kwargs))
        backend.clock += backend.cost
        stdout = backend.command if args[0] == "/bin/ps" else "41\n"
        return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    backend.run = run
    monkeypatch.setattr(tproxy.subprocess, "run", run)
    return backend


@pytest.mark.parametrize(
    ("observation", "expected"),
    (
        (_observation(Outcome.COMPLETE), "diagnostic_same_object_complete"),
        (
            _observation(Outcome.COMPLETE, validator="different-object"),
            "diagnostic_mismatch",
        ),
        (_observation(Outcome.COMPLETE, total=2_000_000), "diagnostic_mismatch"),
        (_observation(Outcome.INCOMPLETE), "diagnostic_incomplete"),
        (_observation(Outcome.UNKNOWN), "diagnostic_invalid"),
        (object(), "diagnostic_invalid"),
        (_observation(Outcome.DEADLINE_EXCEEDED), "diagnostic_deadline"),
    ),
)
def test_idle_diagnostic_returns_only_fixed_non_authorizing_outcomes(
    owned_diagnostic, observation, expected,
):
    calls = []

    def probe(host, request, deadline):
        calls.append((host, request, deadline))
        return observation

    result = tproxy._bootstrap_idle_geph_diagnostic(
        HOST, REQUEST, _evidence(Outcome.INCOMPLETE), 110.0, geph_probe=probe,
    )
    assert result == expected
    assert len(calls) == 1
    assert calls[0][0] == HOST
    assert calls[0][1] is REQUEST
    assert calls[0][2] == 100.0 + tproxy.ROUTE_PREFLIGHT_BOOTSTRAP_GEPH_RESERVE


@pytest.mark.parametrize("phase", ("before", "precheck", "probe", "postcheck"))
def test_idle_diagnostic_deadline_covers_owner_checks_and_probe(
    monkeypatch, owned_diagnostic, phase,
):
    clock, _owner = owned_diagnostic
    checks = []
    probes = []

    def owned_pid(deadline, *, expected_pid=None, cancel_event=None):
        checks.append(expected_pid)
        assert deadline == 101.5
        if (phase == "precheck" and len(checks) == 1) or (
            phase == "postcheck" and len(checks) == 2
        ):
            clock[0] = 101.5
        return 41

    def probe(_host, request, deadline):
        probes.append((request, deadline))
        if phase == "probe":
            clock[0] = 101.5
        return _observation(Outcome.COMPLETE)

    monkeypatch.setattr(tproxy, "_bootstrap_diagnostic_owned_pid", owned_pid)
    final_deadline = 100.0 if phase == "before" else 101.5
    result = tproxy._bootstrap_idle_geph_diagnostic(
        HOST, REQUEST, _evidence(Outcome.INCOMPLETE), final_deadline,
        geph_probe=probe,
    )
    assert result == "diagnostic_deadline"
    assert len(probes) == (1 if phase in {"probe", "postcheck"} else 0)
    assert checks == ([] if phase == "before" else [None, 41] if phase == "postcheck" else [None])
    if probes:
        assert probes[0][0] is REQUEST
        assert probes[0][1] == final_deadline


@pytest.mark.parametrize("unavailable", ("ready", "pid"))
def test_idle_diagnostic_refuses_missing_owned_prerequisite(owned_diagnostic, unavailable):
    _clock, owner = owned_diagnostic
    owner[unavailable] = False if unavailable == "ready" else None
    result = tproxy._bootstrap_idle_geph_diagnostic(
        HOST, REQUEST, _evidence(Outcome.INCOMPLETE), 110.0,
        geph_probe=lambda *_args: pytest.fail("unowned backend must not be used"),
    )
    assert result == "diagnostic_prerequisite_refused"


@pytest.mark.parametrize("host", ("discord.com", "updates.discord.com", "youtube.com", "r1.googlevideo.com"))
def test_idle_diagnostic_keeps_protected_hosts_excluded(owned_diagnostic, host):
    result = tproxy._bootstrap_idle_geph_diagnostic(
        host, REQUEST, _evidence(Outcome.INCOMPLETE), 110.0,
        geph_probe=lambda *_args: pytest.fail("protected host reached Geph"),
    )
    assert result == "diagnostic_prerequisite_refused"


@pytest.mark.parametrize("phase", ("before", "after"))
def test_idle_diagnostic_rejects_owner_change(owned_diagnostic, phase):
    _clock, owner = owned_diagnostic
    calls = []
    if phase == "before":
        owner["matches"] = False

    def probe(*_args):
        calls.append(True)
        owner["pid"] = 42
        return _observation(Outcome.COMPLETE)

    assert tproxy._bootstrap_idle_geph_diagnostic(
        HOST, REQUEST, _evidence(Outcome.INCOMPLETE), 110.0, geph_probe=probe,
    ) == ("diagnostic_owner_changed" if phase == "after" else "diagnostic_prerequisite_refused")
    assert len(calls) == (1 if phase == "after" else 0)


@pytest.mark.parametrize("phase", ("before", "precheck", "probe", "postcheck"))
def test_idle_diagnostic_cancellation_fences_all_blocking_boundaries(
    monkeypatch, owned_diagnostic, phase,
):
    cancelled = threading.Event()
    checks = []
    probes = []
    if phase == "before":
        cancelled.set()

    def owned_pid(_deadline, *, expected_pid=None, cancel_event=None):
        assert cancel_event is cancelled
        checks.append(expected_pid)
        if (phase == "precheck" and len(checks) == 1) or (
            phase == "postcheck" and len(checks) == 2
        ):
            cancelled.set()
        return 41

    def probe(*_args):
        probes.append(True)
        if phase == "probe":
            cancelled.set()
        return _observation(Outcome.COMPLETE)

    monkeypatch.setattr(tproxy, "_bootstrap_diagnostic_owned_pid", owned_pid)
    result = tproxy._bootstrap_idle_geph_diagnostic(
        HOST, REQUEST, _evidence(Outcome.INCOMPLETE), 110.0,
        geph_probe=probe, cancel_event=cancelled,
    )
    assert result == "diagnostic_cancelled"
    assert len(probes) == (1 if phase in {"probe", "postcheck"} else 0)
    assert checks == ([] if phase == "before" else [None, 41] if phase == "postcheck" else [None])


def test_idle_diagnostic_exception_does_not_expose_request(owned_diagnostic):
    def probe(*_args):
        raise RuntimeError(REQUEST.decode("ascii"))

    assert tproxy._bootstrap_idle_geph_diagnostic(
        HOST, REQUEST, _evidence(Outcome.INCOMPLETE), 110.0, geph_probe=probe,
    ) == "diagnostic_exception"


def test_idle_diagnostic_real_ownership_commands_share_probe_budget(owned_commands):
    backend = owned_commands
    probes = []

    def probe(host, request, deadline):
        assert host == HOST
        assert request is REQUEST
        probes.append(deadline)
        backend.clock += 0.5
        return _observation(Outcome.COMPLETE)

    assert tproxy._bootstrap_idle_geph_diagnostic(
        HOST, REQUEST, _evidence(Outcome.INCOMPLETE), 110.0, geph_probe=probe,
    ) == "diagnostic_same_object_complete"
    assert probes == [103.0]
    assert backend.clock == 102.0
    assert [kwargs["timeout"] for _args, kwargs in backend.calls] == [
        3.0, 2.75, 2.5, 1.75, 1.5, 1.25,
    ]
    assert [args for args, _kwargs in backend.calls] == [
        ["/usr/sbin/lsof", "-nP", f"-iTCP:{tproxy.GEPH_OWNED_PORT}", "-sTCP:LISTEN", "-t"],
        ["/bin/ps", "-p", "41", "-o", "command="],
        ["/usr/sbin/lsof", "-nP", f"-iTCP:{tproxy.GEPH_OWNED_PORT}", "-sTCP:LISTEN", "-t"],
    ] * 2
    for _args, kwargs in backend.calls:
        assert kwargs["capture_output"] is True
        assert kwargs["text"] is True
        assert kwargs["env"] is tproxy._RUN_ENV


@pytest.mark.parametrize("remaining", (2.0, 10.0))
def test_diagnostic_owned_pid_caps_each_subprocess_timeout(owned_commands, remaining):
    backend = owned_commands
    assert tproxy._bootstrap_diagnostic_owned_pid(100.0 + remaining) == 41
    assert [kwargs["timeout"] for _args, kwargs in backend.calls] == [
        min(remaining - spent, tproxy.RUN_COMMAND_TIMEOUT_SECONDS)
        for spent in (0.0, 0.25, 0.5)
    ]


@pytest.mark.parametrize("stop", ("deadline", "cancelled"))
def test_diagnostic_owned_pid_does_not_start_after_stop(owned_commands, stop):
    cancelled = threading.Event()
    if stop == "cancelled":
        cancelled.set()
    with pytest.raises(TimeoutError if stop == "deadline" else InterruptedError):
        tproxy._bootstrap_diagnostic_owned_pid(
            100.0 if stop == "deadline" else 103.0, cancel_event=cancelled,
        )
    assert owned_commands.calls == []


@pytest.mark.parametrize("stop", ("deadline", "cancelled"))
@pytest.mark.parametrize("after_command", (1, 2, 3, 6))
def test_idle_diagnostic_stops_between_commands_and_after_final_owner_read(
    monkeypatch, owned_commands, stop, after_command,
):
    backend = owned_commands
    cancelled = threading.Event()
    probes = []

    def run(args, **kwargs):
        result = backend.run(args, **kwargs)
        if len(backend.calls) == after_command:
            if stop == "deadline":
                backend.clock = 103.0
            else:
                cancelled.set()
        return result

    def probe(*_args):
        probes.append(True)
        return _observation(Outcome.COMPLETE)

    monkeypatch.setattr(tproxy.subprocess, "run", run)
    assert tproxy._bootstrap_idle_geph_diagnostic(
        HOST, REQUEST, _evidence(Outcome.INCOMPLETE), 110.0,
        geph_probe=probe, cancel_event=cancelled,
    ) == f"diagnostic_{stop}"
    assert len(backend.calls) == after_command
    assert len(probes) == (1 if after_command == 6 else 0)


@pytest.mark.parametrize("failure", ("expected_pid", "wrong_command", "listener_replaced"))
def test_diagnostic_owned_pid_rejects_invalid_actual_ownership(
    monkeypatch, owned_commands, failure,
):
    backend = owned_commands
    if failure == "wrong_command":
        backend.command = "/synthetic/external-geph --config /synthetic/config"

    def run(args, **kwargs):
        result = backend.run(args, **kwargs)
        if failure == "listener_replaced" and len(backend.calls) == 3:
            result.stdout = "42\n"
        return result

    monkeypatch.setattr(tproxy.subprocess, "run", run)
    assert tproxy._bootstrap_diagnostic_owned_pid(
        103.0, expected_pid=42 if failure == "expected_pid" else None,
    ) is None
    assert len(backend.calls) == {
        "expected_pid": 1, "wrong_command": 2, "listener_replaced": 3,
    }[failure]


@pytest.mark.parametrize("failure", ("timeout", "exception"))
def test_idle_diagnostic_command_failures_return_no_sensitive_output(
    monkeypatch, owned_commands, capsys, caplog, failure,
):
    synthetic_private = "synthetic-transient-query-do-not-export"

    def run(args, **kwargs):
        owned_commands.calls.append((args, kwargs))
        if failure == "timeout":
            raise tproxy.subprocess.TimeoutExpired(
                [synthetic_private], kwargs["timeout"],
                output=synthetic_private, stderr=synthetic_private,
            )
        raise OSError(synthetic_private)

    monkeypatch.setattr(tproxy.subprocess, "run", run)
    assert tproxy._bootstrap_idle_geph_diagnostic(
        HOST, REQUEST, _evidence(Outcome.INCOMPLETE), 110.0,
        geph_probe=lambda *_args: pytest.fail("failed owner check must stop probe"),
    ) == ("diagnostic_deadline" if failure == "timeout" else "diagnostic_exception")
    assert len(owned_commands.calls) == 1
    captured = capsys.readouterr()
    assert synthetic_private not in captured.out + captured.err + caplog.text


@pytest.mark.parametrize("phase", ("precheck", "postcheck"))
def test_idle_diagnostic_rechecks_readiness_after_owner_read(
    monkeypatch, owned_diagnostic, phase,
):
    _clock, owner = owned_diagnostic
    checks = []
    probes = []

    def owned_pid(_deadline, *, expected_pid=None, cancel_event=None):
        checks.append(expected_pid)
        if len(checks) == (1 if phase == "precheck" else 2):
            owner["ready"] = False
        return 41

    def probe(*_args):
        probes.append(True)
        return _observation(Outcome.COMPLETE)

    monkeypatch.setattr(tproxy, "_bootstrap_diagnostic_owned_pid", owned_pid)
    assert tproxy._bootstrap_idle_geph_diagnostic(
        HOST, REQUEST, _evidence(Outcome.INCOMPLETE), 110.0, geph_probe=probe,
    ) == "diagnostic_prerequisite_refused"
    assert checks == ([None] if phase == "precheck" else [None, 41])
    assert len(probes) == (1 if phase == "postcheck" else 0)


class _SocksSocket:
    def __init__(self):
        self.responses = deque((b"\x05\x00", b"\x05\x00\x00\x01", b"\x7f\x00\x00\x01", b"\x01\xbb"))
        self.requests = []

    def settimeout(self, _timeout):
        pass

    def sendall(self, request):
        self.requests.append(request)

    def recv(self, _size):
        return self.responses.popleft()

    def close(self):
        pass


@pytest.mark.parametrize("explicit_port", (None, 9909))
def test_socks_connector_preserves_default_and_accepts_fixed_port(monkeypatch, explicit_port):
    destinations = []
    sock = _SocksSocket()
    monkeypatch.setattr(tproxy, "_geph_port", 9954)

    def connect(address, **_kwargs):
        destinations.append(address)
        return sock

    monkeypatch.setattr(tproxy.socket, "create_connection", connect)
    assert tproxy._socks5_connect_blocking(
        HOST, 443, socks_port=explicit_port,
    ) is sock
    assert destinations == [("127.0.0.1", 9954 if explicit_port is None else explicit_port)]


def test_bootstrap_range_pins_owned_port_even_when_general_backend_changes(monkeypatch):
    destinations = []
    sock = _SocksSocket()
    response = object()
    monkeypatch.setattr(tproxy, "_geph_port", 9954)

    def connect(address, **_kwargs):
        destinations.append(address)
        monkeypatch.setattr(tproxy, "_geph_port", 0)
        return sock

    def observe(actual_sock, host, request, io_deadline, classification_deadline):
        assert actual_sock is sock
        assert host == HOST
        assert request is REQUEST
        assert io_deadline == classification_deadline == deadline
        return response

    monkeypatch.setattr(tproxy.socket, "create_connection", connect)
    monkeypatch.setattr(tproxy, "_bootstrap_range_response_on_tls_socket", observe)
    deadline = tproxy.time.monotonic() + 3.0
    assert tproxy._bootstrap_asset_geph_range_probe(HOST, REQUEST, deadline) is response
    assert destinations == [("127.0.0.1", tproxy.GEPH_OWNED_PORT)]


@pytest.mark.parametrize("cause", ("cancel", "timeout"))
def test_owned_worker_sets_cancellation_event_before_draining(monkeypatch, cause):
    async def scenario():
        cancelled = threading.Event()
        entered = asyncio.Event()
        release = asyncio.Event()
        draining = asyncio.Event()
        original_drain = tproxy._drain_root_preflight_worker

        async def worker_body():
            entered.set()
            await release.wait()
            return "late result"

        async def observed_drain(worker):
            assert cancelled.is_set()
            draining.set()
            return await original_drain(worker)

        monkeypatch.setattr(tproxy, "_drain_root_preflight_worker", observed_drain)
        worker = asyncio.create_task(worker_body())
        await entered.wait()
        owner = asyncio.create_task(tproxy._await_owned_preflight_worker(
            worker, timeout=0.0 if cause == "timeout" else 10.0,
            cancel_event=cancelled,
        ))
        await asyncio.sleep(0)
        if cause == "cancel":
            owner.cancel()
        await draining.wait()
        assert not worker.done()
        assert not owner.done()
        if cause == "cancel":
            owner.cancel()
            await asyncio.sleep(0)
            assert not worker.done()
            assert not owner.done()
        release.set()
        expected = asyncio.CancelledError if cause == "cancel" else asyncio.TimeoutError
        with pytest.raises(expected):
            await owner
        assert worker.done() and not worker.cancelled()
        assert worker.result() == "late result"

    async def bounded():
        await asyncio.wait_for(scenario(), timeout=2.0)

    asyncio.run(bounded())
