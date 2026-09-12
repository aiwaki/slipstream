"""Autonomous exact-object recovery: no browser retry, network or learned setup."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import ssl
import threading
from types import SimpleNamespace

import pytest
import tproxy
from test_bootstrap_tls_stream import Context, RawSocket, emit_then_raise
from test_tproxy_doh import (
    _bootstrap_root_observation,
    _enable_owned_geph_preflight,
    reset_smart_dns_state,  # noqa: F401 -- shared autouse state isolation
)


HOST = "critical-child.example"
EXACT_IP = "1.1.1.1"
XBOX_IP = "4.2.2.2"
CAPABILITY = "c" * 32
STAGES = (tproxy.AUTO_GEPH_STAGE_XBOX_DNS, *tproxy.ROUTE_PREFLIGHT_BOOTSTRAP_LOCAL_STRATEGIES)
Outcome = tproxy.bootstrap_asset_preflight.RangeProbeOutcome


def observation(
    outcome=Outcome.INCOMPLETE, *, termination=None, measured=True,
    idle=6.0, validator="same-object", total=1_210_087,
):
    evidence = tproxy.bootstrap_asset_preflight.RangeProbeEvidence(
        outcome, total_length=total,
        range_end=tproxy.bootstrap_asset_preflight.DEFAULT_RANGE_END,
        validator_digest=validator,
        received_body_bytes=65_536 if outcome is Outcome.COMPLETE else 16_384,
    )
    if termination is None:
        termination = (
            tproxy._BOOTSTRAP_RANGE_TERMINATION_COMPLETE
            if outcome is Outcome.COMPLETE
            else tproxy._BOOTSTRAP_RANGE_TERMINATION_IDLE_TIMEOUT
        )
    return tproxy._BootstrapRangeProbeObservation(evidence, termination, measured, idle)


@pytest.fixture(autouse=True)
def isolated_recovery(monkeypatch, reset_smart_dns_state):
    _enable_owned_geph_preflight(monkeypatch)
    clock = SimpleNamespace(
        now=100.0, allow_committed_state=False,
        commit=tproxy._commit_preflight_owned_geph_proof,
        enqueue_diagnostic=tproxy._enqueue_bootstrap_asset_diagnostic,
    )
    monkeypatch.setattr(tproxy, "time", SimpleNamespace(
        monotonic=lambda: clock.now,
        time=lambda: 1_750_000_000.0 + clock.now,
    ))
    monkeypatch.setattr(tproxy, "_network_wide_unknown_failure_visible", lambda _now: False)

    def forbidden(*_args, **_kwargs):
        pytest.fail("blocking object observation attempted external state or stage progress")

    for name in (
        "_browser_navigation_provenance_accepted", "save_auto_geph",
        "_commit_preflight_owned_geph_proof", "system_resolve", "xbox_dns_resolve",
    ):
        monkeypatch.setattr(tproxy, name, forbidden)
    monkeypatch.setattr(tproxy.socket, "create_connection", forbidden)
    monkeypatch.setattr(tproxy, "_enqueue_bootstrap_asset_diagnostic", lambda _record: None)
    monkeypatch.setattr(tproxy, "_enqueue_route_preflight_root_diagnostic_record", lambda _record: None)
    yield clock
    if not clock.allow_committed_state:
        assert not tproxy._auto_geph
        assert not tproxy._route_preflight_cache
    assert not tproxy._route_preflight_inflight
    assert not tproxy._route_preflight_execution_leases


def asset(host=HOST):
    return tproxy.bootstrap_asset_preflight.EphemeralBootstrapAsset(
        exact_host=host, host_header=host,
        request_target="/assets/synthetic-entry.js?synthetic=transient",
    )


def run_blocking(
    *, direct=None, local_probe=None, geph_probe=None,
    xbox_resolver=None, cancel_event=None, host=HOST,
):
    target = asset(host)
    result = tproxy._bootstrap_asset_preflight_blocking(
        target, "parent-shell.example", "8.8.8.8", 108.0, 125.0,
        direct_probe=(lambda *_args: observation()) if direct is None else direct,
        local_probe=(lambda *_args: observation()) if local_probe is None else local_probe,
        geph_probe=(lambda *_args: observation(Outcome.COMPLETE)) if geph_probe is None else geph_probe,
        xbox_resolver=(lambda *_args, **_kwargs: [XBOX_IP]) if xbox_resolver is None else xbox_resolver,
        exact_address=EXACT_IP, proof_capability=CAPABILITY, cancel_event=cancel_event,
    )
    with pytest.raises(RuntimeError, match="forgotten"):
        target.build_range_request()
    return result


@pytest.mark.parametrize(
    ("sample", "expected"),
    [
        (observation(), True),
        (observation(idle=5.999), False),
        (observation(measured=False), False),
        (observation(idle=True), False),
        (observation(idle=float("nan")), False),
        (observation(idle=float("inf")), False),
        (observation(Outcome.UNKNOWN), False),
        (observation(Outcome.DEADLINE_EXCEEDED), False),
        (observation(termination=tproxy._BOOTSTRAP_RANGE_TERMINATION_EOF), False),
    ],
)
def test_only_valid_measured_wire_idle_is_autonomous_stall(sample, expected):
    assert tproxy._bootstrap_measured_stall(sample) is expected


def reader_composition(monkeypatch, clock, *, drip, initial_plaintext):
    """Use the real stream and range parser; inject only TLS I/O and clocks."""
    response = (
        b"HTTP/1.1 206 Partial Content\r\n"
        b"Content-Type: application/javascript\r\n"
        b"Content-Length: 65536\r\n"
        b"Content-Range: bytes 0-65535/1210087\r\n"
        b'ETag: "synthetic-object"\r\n\r\n' + b"x" * 16384
    )

    class ReaderContext(Context):
        def wrap_bio(self, *args, **kwargs):
            tls = super().wrap_bio(*args, **kwargs)
            tls.handshake_actions.extend([
                emit_then_raise(b"clienthello", ssl.SSLWantReadError()), None,
            ])
            if initial_plaintext:
                tls.read_actions.extend([
                    ssl.SSLWantReadError(), response[:16384], response[16384:],
                ])
            return tls

    incoming = [(0.125, b"server-handshake")]
    if initial_plaintext:
        incoming.append((0.125, b"first-response-record"))
    if drip:
        incoming.extend([(2.0, b"encrypted-record-fragment")] * 4)
    raw = RawSocket(clock, incoming)
    context = ReaderContext()
    inspect = tproxy.bootstrap_asset_preflight.inspect_range_response
    monkeypatch.setattr(tproxy, "_local_payload_ssl_context", lambda: context)
    monkeypatch.setattr(
        tproxy.bootstrap_asset_preflight, "inspect_range_response",
        lambda data, **kwargs: inspect(data, **kwargs, clock=lambda: clock.now),
    )
    result = tproxy._bootstrap_range_response_on_tls_socket(
        raw, HOST, b"GET /synthetic.js HTTP/1.1\r\n\r\n",
        107.25 if drip else 115.0, 120.0,
    )
    assert isinstance(context.tls.incoming, ssl.MemoryBIO)
    assert raw.close_count == 1
    return result, raw


def test_reader_composition_true_encrypted_idle_qualifies_incomplete_stall(
    monkeypatch, isolated_recovery,
):
    result, raw = reader_composition(
        monkeypatch, isolated_recovery, drip=False, initial_plaintext=True,
    )
    assert result.termination == tproxy._BOOTSTRAP_RANGE_TERMINATION_IDLE_TIMEOUT
    assert result.evidence.outcome is Outcome.INCOMPLETE
    assert result.evidence.received_body_bytes == 16384
    assert result.wire_bytes_measured is True
    assert result.wire_idle_seconds == 6.0
    assert isolated_recovery.now == 106.25
    assert raw.read_timeouts == [6.0, 6.0, 6.0]
    assert tproxy._bootstrap_measured_stall(result) is True


@pytest.mark.parametrize("initial_plaintext", [True, False])
def test_reader_composition_encrypted_drips_at_absolute_deadline_never_qualify_stall(
    monkeypatch, isolated_recovery, initial_plaintext,
):
    result, raw = reader_composition(
        monkeypatch, isolated_recovery, drip=True, initial_plaintext=initial_plaintext,
    )
    assert result.termination == tproxy._BOOTSTRAP_RANGE_TERMINATION_IDLE_TIMEOUT
    assert result.evidence.outcome is (Outcome.INCOMPLETE if initial_plaintext else Outcome.UNKNOWN)
    assert result.evidence.received_body_bytes == (16384 if initial_plaintext else 0)
    assert result.wire_bytes_measured is True
    assert 0.0 < result.wire_idle_seconds < 6.0
    assert isolated_recovery.now == 107.25
    assert raw.read_timeouts[-1] == (1.0 if initial_plaintext else 1.125)
    assert tproxy._bootstrap_measured_stall(result) is False
    assert tproxy._bootstrap_failed_object(result) is False


@pytest.mark.parametrize("final_deadline", (120.0, 109.0))
def test_local_orchestrator_starts_three_concurrent_same_request_workers(
    isolated_recovery, final_deadline,
):
    request = b"GET /synthetic.js HTTP/1.1\r\n\r\n"
    cancelled = threading.Event()
    rendezvous = threading.Barrier(3, timeout=2.0)
    calls = []
    dns_calls = []

    def resolve(host, **kwargs):
        dns_calls.append((host, kwargs))
        return ["127.0.0.1", XBOX_IP]

    def local(ip, host, actual_request, deadline, final, strategy, event):
        calls.append((ip, host, actual_request, deadline, final, strategy, event, threading.get_ident()))
        rendezvous.wait()
        return observation()

    results = tproxy._bootstrap_local_object_observations(
        HOST, EXACT_IP, request, final_deadline,
        cancel_event=cancelled, local_probe=local, xbox_resolver=resolve,
    )
    deadline = min(108.0, final_deadline - 3.0)
    assert tuple(stage for stage, _ip, _obs in results) == STAGES
    assert len(calls) == len({call[-1] for call in calls}) == 3
    assert {(call[0], call[5]) for call in calls} == {
        (XBOX_IP, tproxy.PLAIN_STRATEGY), (EXACT_IP, "split64"), (EXACT_IP, "split16"),
    }
    for _ip, host, actual, observed_deadline, final, _strategy, event, _tid in calls:
        assert host == HOST and actual is request and event is cancelled
        assert observed_deadline == deadline and final == final_deadline
    assert dns_calls == [(HOST, {"timeout": 3.0, "deadline": deadline, "cancel_event": cancelled})]


def test_local_orchestrator_drains_owned_workers_after_cancellation():
    cancelled = threading.Event()
    entered = threading.Event()
    release = threading.Event()
    lock = threading.Lock()
    active = []
    done = []

    def local(_ip, _host, _request, _deadline, _final, strategy, event):
        assert event is cancelled
        with lock:
            active.append(strategy)
            if len(active) == 3:
                entered.set()
        assert release.wait(2.0)
        done.append(strategy)
        return observation()

    with ThreadPoolExecutor(max_workers=1) as outer:
        future = outer.submit(
            tproxy._bootstrap_local_object_observations,
            HOST, EXACT_IP, b"request", 120.0,
            cancel_event=cancelled, local_probe=local,
            xbox_resolver=lambda *_args, **_kwargs: [XBOX_IP],
        )
        try:
            assert entered.wait(2.0)
            cancelled.set()
            assert not future.done()
            assert not done
        finally:
            release.set()
        assert len(future.result(timeout=2.0)) == 3
    assert sorted(active) == sorted(done) == sorted([tproxy.PLAIN_STRATEGY, "split64", "split16"])


def test_one_blocking_job_qualifies_local_stages_and_fresh_geph_proof(isolated_recovery):
    clock = isolated_recovery
    direct_requests = []
    local_requests = []
    geph_requests = []
    rendezvous = threading.Barrier(3, timeout=2.0)

    def direct(ip, host, request, healthy, final):
        assert (ip, host, healthy, final) == (EXACT_IP, HOST, 108.0, 125.0)
        direct_requests.append(request)
        clock.now = 106.0
        return observation()

    def local(ip, host, request, deadline, final, strategy, _event):
        assert request is direct_requests[0]
        assert (host, deadline, final) == (HOST, 114.0, 125.0)
        local_requests.append((ip, strategy, request))
        rendezvous.wait()
        clock.now = 112.0  # The old direct job has expired; no browser retry occurs.
        return observation(termination=(
            tproxy._BOOTSTRAP_RANGE_TERMINATION_EOF
            if strategy == "split64" else tproxy._BOOTSTRAP_RANGE_TERMINATION_IDLE_TIMEOUT
        ))

    def geph(host, request, deadline):
        geph_requests.append((host, request, deadline))
        assert len(local_requests) == 3
        clock.now = 113.0
        return observation(Outcome.COMPLETE)

    result = run_blocking(direct=direct, local_probe=local, geph_probe=geph)
    assert result.diagnostic_decision == "proof_ready"
    assert result.outcome == "owned_geph"
    assert result.local_winner is None
    proof = result.proof
    assert proof is not None
    assert (proof.host, proof.exact_address, proof.confirmed_pid) == (HOST, EXACT_IP, 41)
    assert proof.capability == CAPABILITY
    assert proof.deadline_monotonic == 115.0
    assert proof.issued_at_unix_ms == int((1_750_000_000.0 + 112.0) * 1000)
    assert len(direct_requests) == len(geph_requests) == 1
    assert geph_requests[0][0] == HOST and geph_requests[0][1] is direct_requests[0]
    assert geph_requests[0][2] == 115.0
    assert len(local_requests) == 3


@pytest.mark.parametrize("commit_guard", [
    "none", "deadline", "readiness", "locked_deadline", "locked_readiness",
])
def test_admitted_child_commits_before_held_parent_releases_without_browser_retry(
    monkeypatch, isolated_recovery, commit_guard,
):
    clock = isolated_recovery
    clock.allow_committed_state = True
    children_entered = threading.Event()
    release_children = threading.Event()
    lock = threading.Lock()
    local_calls = []
    root_calls = []
    direct_requests = []
    geph_requests = []
    order = []
    holder = {}
    owner_checks = []
    original_owner = tproxy._bootstrap_diagnostic_owned_pid

    def owner(deadline, *, expected_pid=None, cancel_event=None):
        owner_checks.append(expected_pid)
        pid = original_owner(deadline, expected_pid=expected_pid, cancel_event=cancel_event)
        guard_index = 4 if commit_guard.startswith("locked_") else 3
        if len(owner_checks) == guard_index:
            if commit_guard.endswith("deadline"):
                clock.now = deadline
            elif commit_guard.endswith("readiness"):
                monkeypatch.setattr(tproxy, "_geph_up", False)
        return pid

    def root_probe(*_args):
        root_calls.append(True)
        return _bootstrap_root_observation(HOST)

    def direct(_ip, _host, request, _healthy, _final):
        direct_requests.append(request)
        clock.now = 106.0
        return observation()

    def local(ip, host, request, _deadline, _final, strategy, _event):
        assert host == HOST and request is direct_requests[0]
        with lock:
            local_calls.append((ip, strategy))
            if len(local_calls) == 3:
                children_entered.set()
        assert release_children.wait(2.0)
        clock.now = 112.0
        return observation()

    def geph(host, request, deadline):
        geph_requests.append((host, request, deadline))
        return observation(Outcome.COMPLETE)

    def observe_commit(*args):
        assert not holder["task"].done()
        committed = clock.commit(*args)
        order.append(("commit", committed))
        return committed

    monkeypatch.setattr(tproxy, "_bootstrap_local_range_probe", local)
    monkeypatch.setattr(tproxy, "_bootstrap_diagnostic_owned_pid", owner)
    monkeypatch.setattr(tproxy, "xbox_dns_resolve", lambda *_args, **_kwargs: [XBOX_IP])
    monkeypatch.setattr(tproxy, "_commit_preflight_owned_geph_proof", observe_commit)
    monkeypatch.setattr(tproxy, "save_auto_geph", lambda: None)

    async def scenario():
        async def held_parent():
            result = await tproxy._run_initial_route_preflight(
                "app-shell.example", "8.8.8.8", direct_probe=root_probe,
                geph_probe=lambda *_args: pytest.fail("usable parent needs no root Geph"),
                bootstrap_direct_probe=direct, bootstrap_geph_probe=geph,
                bootstrap_resolver=lambda _host: [EXACT_IP],
            )
            order.append(("parent_released", None))
            return result

        task = asyncio.create_task(held_parent())
        holder["task"] = task
        try:
            assert await asyncio.to_thread(children_entered.wait, 2.0)
            assert not task.done()
            assert not tproxy._auto_geph_learned_exact_host(HOST)
        finally:
            release_children.set()
        return await asyncio.wait_for(task, timeout=2.0)

    assert asyncio.run(scenario()) is None
    committed = commit_guard == "none"
    assert order == [("commit", committed), ("parent_released", None)]
    assert owner_checks == [None, 41, 41] + (
        [41] if committed or commit_guard.startswith("locked_") else []
    )
    assert len(root_calls) == len(direct_requests) == len(geph_requests) == 1
    assert len(local_calls) == 3
    assert geph_requests[0][1] is direct_requests[0]
    assert tproxy._auto_geph_learned_exact_host(HOST) is committed
    assert not tproxy._auto_geph_learned_exact_host("app-shell.example")
    if committed:
        assert tproxy._route_preflight_cache[HOST].outcome == "owned_geph"
    else:
        assert HOST not in tproxy._route_preflight_cache


@pytest.mark.parametrize("measured,idle", [(False, 6.0), (True, 0.5)])
def test_unmeasured_or_continuously_progressing_deadline_remains_diagnostic_only(measured, idle):
    geph_calls = []

    def no_local(*_args):
        pytest.fail("unqualified timing-only outcome started autonomous local recovery")

    def geph(*args):
        geph_calls.append(args)
        return observation(Outcome.COMPLETE)

    result = run_blocking(
        direct=lambda *_args: observation(measured=measured, idle=idle),
        local_probe=no_local, geph_probe=geph,
    )
    assert result.proof is None and result.local_winner is None
    assert result.outcome == tproxy._ROUTE_PREFLIGHT_RETRYABLE_INCONCLUSIVE
    assert result.diagnostic_geph == "diagnostic_same_object_complete"
    assert len(geph_calls) == 1


@pytest.mark.parametrize("winner_kind", ["owned_geph", "local_split64"])
def test_same_origin_parent_returns_fresh_committed_claim_without_browser_retry(
    monkeypatch, isolated_recovery, winner_kind,
):
    clock = isolated_recovery
    clock.allow_committed_state = True
    host = "app-shell.example"
    children_entered = threading.Event()
    release_children = threading.Event()
    lock = threading.Lock()
    holder = {}
    root_calls = []
    direct_requests = []
    local_calls = []
    geph_requests = []
    created_jobs = []
    committed_capabilities = []
    order = []
    original_job = tproxy._new_direct_route_preflight_job
    original_local_commit = tproxy._commit_bootstrap_local_winner

    def create_job(*args, **kwargs):
        job = original_job(*args, **kwargs)
        created_jobs.append(job)
        return job

    def root_probe(*_args):
        root_calls.append(True)
        clock.now = 104.0  # Four seconds of the root's eight are already spent.
        return _bootstrap_root_observation(host)

    def direct(ip, child_host, request, healthy_deadline, final_deadline):
        assert (ip, child_host) == (EXACT_IP, host)
        assert (healthy_deadline, final_deadline) == (112.0, 123.0)
        direct_requests.append(request)
        clock.now = 110.0
        return observation()

    def local(ip, child_host, request, deadline, final, strategy, _event):
        assert child_host == host and request is direct_requests[0]
        assert (deadline, final) == (118.0, 123.0)
        with lock:
            local_calls.append((ip, strategy))
            if len(local_calls) == 3:
                children_entered.set()
        assert release_children.wait(2.0)
        clock.now = 116.0
        return observation(
            Outcome.COMPLETE
            if winner_kind == "local_split64" and strategy == "split64"
            else Outcome.INCOMPLETE
        )

    def geph(child_host, request, deadline):
        assert winner_kind == "owned_geph", "working local object must veto Geph"
        assert len(local_calls) == 3
        assert (child_host, deadline) == (host, 119.0)
        assert request is direct_requests[0]
        geph_requests.append(request)
        clock.now = 117.0
        return observation(Outcome.COMPLETE)

    def observe_geph_commit(*args):
        assert not holder["task"].done()
        committed = clock.commit(*args)
        if args[0] is not None:
            committed_capabilities.append(args[0].capability)
            order.append(("geph_commit", committed))
        return committed

    def observe_local_commit(*args):
        assert not holder["task"].done()
        committed = original_local_commit(*args)
        committed_capabilities.append(args[0].capability)
        order.append(("local_commit", committed))
        return committed

    monkeypatch.setattr(tproxy, "_new_direct_route_preflight_job", create_job)
    monkeypatch.setattr(tproxy, "_bootstrap_local_range_probe", local)
    monkeypatch.setattr(tproxy, "xbox_dns_resolve", lambda *_args, **_kwargs: [XBOX_IP])
    monkeypatch.setattr(tproxy, "_commit_preflight_owned_geph_proof", observe_geph_commit)
    monkeypatch.setattr(tproxy, "_commit_bootstrap_local_winner", observe_local_commit)
    monkeypatch.setattr(tproxy, "save_auto_geph", lambda: None)

    async def scenario():
        async def held_parent():
            claim = await tproxy._run_initial_route_preflight(
                host, EXACT_IP, direct_probe=root_probe,
                geph_probe=lambda *_args: pytest.fail("usable root needs no root Geph"),
                bootstrap_direct_probe=direct, bootstrap_geph_probe=geph,
                bootstrap_resolver=lambda _host: [EXACT_IP],
            )
            order.append(("parent_released", None))
            return claim

        task = asyncio.create_task(held_parent())
        holder["task"] = task
        try:
            assert await asyncio.to_thread(children_entered.wait, 2.0)
            assert not task.done()
            assert not tproxy._auto_geph_learned_exact_host(host)
            assert not tproxy._bootstrap_local_routes
        finally:
            release_children.set()
        return await asyncio.wait_for(task, timeout=2.0)

    claim = asyncio.run(scenario())
    assert len(root_calls) == len(direct_requests) == 1
    assert set(local_calls) == {
        (XBOX_IP, tproxy.PLAIN_STRATEGY), (EXACT_IP, "split64"), (EXACT_IP, "split16"),
    }
    assert len(committed_capabilities) == 1
    assert claim.host == host
    assert claim.deadline_monotonic == clock.now + tproxy.UNKNOWN_RECOVERY_GEPH_RESERVE
    assert claim.deadline_monotonic > 108.0  # The original root budget expired.
    if winner_kind == "owned_geph":
        assert isinstance(claim, tproxy._RoutePreflightOwnedGephClaim)
        assert claim.capability not in {job.capability for job in created_jobs}
        assert claim.capability not in committed_capabilities
        assert len(geph_requests) == 1
        assert order == [("geph_commit", True), ("parent_released", None)]
        assert tproxy._auto_geph_learned_exact_host(host)
        assert tproxy._route_preflight_cache[host].outcome == "owned_geph"
        assert not tproxy._bootstrap_local_routes
    else:
        assert isinstance(claim, tproxy._BootstrapLocalRouteClaim)
        assert (claim.exact_address, claim.address, claim.strategy_name) == (
            EXACT_IP, EXACT_IP, "split64",
        )
        assert not claim.via_xbox_dns
        assert claim.capability == committed_capabilities[0]
        assert not geph_requests
        assert order == [("local_commit", True), ("parent_released", None)]
        assert not tproxy._auto_geph_learned_exact_host(host)
        assert tproxy._route_preflight_cache[host].outcome == tproxy.SEMANTIC_OUTCOME_USABLE
        assert (host, EXACT_IP) in tproxy._bootstrap_local_routes


@pytest.mark.parametrize("strategy", [tproxy.PLAIN_STRATEGY, "split64", "split16"])
@pytest.mark.parametrize("matching", [True, False])
def test_any_complete_local_response_vetoes_geph_and_only_matching_object_selects_local(
    strategy, matching,
):
    def local(_ip, _host, _request, _deadline, _final, candidate, _event):
        return (
            observation(Outcome.COMPLETE, validator="same-object" if matching else "other-object")
            if candidate == strategy else observation()
        )

    result = run_blocking(
        local_probe=local,
        geph_probe=lambda *_args: pytest.fail("working local response must veto Geph"),
    )
    assert result.proof is None
    if not matching:
        assert result.local_winner is None
        assert result.outcome == tproxy._ROUTE_PREFLIGHT_RETRYABLE_INCONCLUSIVE
        return
    winner = result.local_winner
    assert result.outcome == tproxy.SEMANTIC_OUTCOME_USABLE
    assert winner is not None
    assert (winner.host, winner.exact_address, winner.capability) == (HOST, EXACT_IP, CAPABILITY)
    assert winner.strategy_name == strategy
    assert winner.via_xbox_dns is (strategy == tproxy.PLAIN_STRATEGY)
    assert winner.address == (XBOX_IP if strategy == tproxy.PLAIN_STRATEGY else EXACT_IP)
    assert winner.deadline_monotonic == 125.0


@pytest.mark.parametrize("failure", ["unknown", "deadline", "slow_progress", "mismatch"])
def test_one_unqualified_local_object_prevents_proof(failure):
    geph_calls = []
    samples = {
        "unknown": observation(Outcome.UNKNOWN),
        "deadline": observation(Outcome.DEADLINE_EXCEEDED),
        "slow_progress": observation(idle=0.25),
        "mismatch": observation(validator="different-local-object"),
    }

    def local(_ip, _host, _request, _deadline, _final, strategy, _event):
        return samples[failure] if strategy == "split16" else observation()

    def geph(*args):
        geph_calls.append(args)
        return observation(Outcome.COMPLETE)

    result = run_blocking(local_probe=local, geph_probe=geph)
    assert result.proof is None and result.local_winner is None
    assert len(geph_calls) == (1 if failure == "mismatch" else 0)


@pytest.mark.parametrize("geph_observation", [
    observation(Outcome.COMPLETE, validator="different-object"),
    observation(Outcome.COMPLETE, total=2_000_000),
    observation(Outcome.INCOMPLETE),
    observation(Outcome.DEADLINE_EXCEEDED),
])
def test_geph_must_complete_the_same_exact_object(geph_observation):
    result = run_blocking(geph_probe=lambda *_args: geph_observation)
    assert result.proof is None and result.local_winner is None
    assert result.diagnostic_geph == "comparison_refused"


@pytest.mark.parametrize("host", ["discord.com", "updates.discord.com", "youtube.com", "r1.googlevideo.com"])
def test_protected_host_never_starts_direct_local_or_geph(host):
    def forbidden(*_args, **_kwargs):
        pytest.fail("protected host reached recovery probe")

    result = run_blocking(host=host, direct=forbidden, local_probe=forbidden, geph_probe=forbidden)
    assert result.proof is None and result.local_winner is None


def test_missing_owned_backend_prevents_geph_probe(monkeypatch):
    monkeypatch.setattr(tproxy, "_owned_geph_confirmation_pid", lambda: None)
    result = run_blocking(geph_probe=lambda *_args: pytest.fail("unowned Geph used"))
    assert result.proof is None and result.diagnostic_geph == "prerequisite_refused"


@pytest.mark.parametrize("phase", ["before", "local", "geph"])
def test_cancellation_never_mints_proof(phase):
    cancelled = threading.Event()
    geph_calls = []
    if phase == "before":
        cancelled.set()

    def direct(*_args):
        if phase == "before":
            pytest.fail("cancelled owner started a direct object probe")
        return observation()

    def local(*_args):
        if phase == "local":
            cancelled.set()
        return observation()

    def geph(*args):
        geph_calls.append(args)
        if phase == "geph":
            cancelled.set()
        return observation(Outcome.COMPLETE)

    result = run_blocking(
        direct=direct, local_probe=local, geph_probe=geph, cancel_event=cancelled,
    )
    assert result.proof is None and result.local_winner is None
    assert len(geph_calls) == (1 if phase == "geph" else 0)


@pytest.mark.parametrize("change", ["pid", "deadline", "readiness", "cancelled"])
def test_post_geph_owner_check_cannot_publish_stale_proof(
    monkeypatch, isolated_recovery, change,
):
    clock = isolated_recovery
    cancelled = threading.Event()
    checks = []

    def owner(deadline, *, expected_pid=None, cancel_event=None):
        checks.append(expected_pid)
        if expected_pid is not None:
            if change == "pid":
                return None
            if change == "deadline":
                clock.now = deadline
            elif change == "readiness":
                monkeypatch.setattr(tproxy, "_geph_up", False)
            elif change == "cancelled":
                cancelled.set()
        return 41

    monkeypatch.setattr(tproxy, "_bootstrap_diagnostic_owned_pid", owner)
    result = run_blocking(cancel_event=cancelled)
    assert checks == [None, 41]
    assert result.proof is None and result.local_winner is None
    assert result.diagnostic_comparison == (
        {"pid": "owner_changed", "deadline": "owner_deadline",
         "readiness": "backend_not_ready", "cancelled": "cancelled"}[change],
        "complete", "unobserved",
    )


def capture_local_diagnostic(monkeypatch, clock, result):
    records = []
    diagnostic = tproxy._BootstrapAssetDiagnostic(
        parent="parent-shell.example", child=HOST,
    )
    monkeypatch.setattr(
        tproxy, "_enqueue_route_preflight_root_diagnostic_record", records.append,
    )
    tproxy._copy_bootstrap_asset_diagnostic(diagnostic, result)
    clock.enqueue_diagnostic(diagnostic)
    assert len(records) == 1
    return diagnostic, records[0]


@pytest.mark.parametrize(
    ("last_outcome", "decision", "last_state"),
    [
        (Outcome.INCOMPLETE, "proof_ready", "incomplete_idle_timeout"),
        (Outcome.UNKNOWN, "local_recovery_inconclusive", "invalid"),
        (Outcome.COMPLETE, "local_recovery_complete", "complete"),
    ],
)
def test_local_diagnostic_actual_result_exports_ordered_stage_states(
    monkeypatch, isolated_recovery, last_outcome, decision, last_state,
):
    def local(_ip, _host, _request, _deadline, _final, strategy, _event):
        if strategy == tproxy.PLAIN_STRATEGY:
            return observation(termination=tproxy._BOOTSTRAP_RANGE_TERMINATION_EOF)
        return observation(last_outcome) if strategy == "split16" else observation()

    result = run_blocking(local_probe=local)
    expected = ("incomplete_eof", "incomplete_idle_timeout", last_state)
    assert result.diagnostic_decision == decision
    assert result.diagnostic_local == expected
    assert (result.proof is not None) is (decision == "proof_ready")
    assert (result.local_winner is not None) is (decision == "local_recovery_complete")
    diagnostic, record = capture_local_diagnostic(monkeypatch, isolated_recovery, result)
    assert diagnostic.local == expected
    assert f"decision={decision} " in record
    assert record.endswith(
        "local_xbox=incomplete_eof local_split64=incomplete_idle_timeout "
        f"local_split16={last_state}"
    )
    for private_value in (EXACT_IP, XBOX_IP, "same-object", "/assets/", "synthetic=transient"):
        assert private_value not in record


def test_local_diagnostic_omits_stages_that_never_started(monkeypatch, isolated_recovery):
    result = run_blocking(direct=lambda *_args: observation(Outcome.COMPLETE))
    assert result.diagnostic_local == ()
    diagnostic, record = capture_local_diagnostic(monkeypatch, isolated_recovery, result)
    assert diagnostic.local == ()
    assert "decision=direct_complete " in record
    assert "local_xbox=" not in record
    assert "local_split64=" not in record
    assert "local_split16=" not in record


class HostileLocalDiagnostic:
    def __str__(self):
        pytest.fail("diagnostic formatter stringified an untrusted value")

    def __hash__(self):
        pytest.fail("diagnostic formatter hashed an untrusted value")


class HostileLocalTuple(tuple):
    def __len__(self):
        pytest.fail("diagnostic formatter inspected a tuple subclass")


def test_local_diagnostic_rejects_hostile_tuple_members(monkeypatch, isolated_recovery):
    result = SimpleNamespace(
        diagnostic_decision="local_recovery_inconclusive",
        diagnostic_direct="incomplete_idle_timeout", diagnostic_geph="not_started",
        diagnostic_local=(
            "https://synthetic.example/private?token=synthetic-value\nforged=1",
            HostileLocalDiagnostic(), "complete",
        ),
    )
    _diagnostic, record = capture_local_diagnostic(monkeypatch, isolated_recovery, result)
    assert record.endswith("local_xbox=unknown local_split64=unknown local_split16=complete")
    assert "synthetic" not in record and "forged" not in record and "\n" not in record


@pytest.mark.parametrize("local", [
    "local_xbox=complete\nsecret=synthetic-value",
    ["complete", "complete", "complete"],
    ("complete", "complete"),
    HostileLocalTuple(("complete", "complete", "complete")),
])
def test_local_diagnostic_omits_malformed_container(monkeypatch, isolated_recovery, local):
    result = SimpleNamespace(
        diagnostic_decision="local_recovery_inconclusive",
        diagnostic_direct="incomplete_idle_timeout", diagnostic_geph="not_started",
        diagnostic_local=local,
    )
    _diagnostic, record = capture_local_diagnostic(monkeypatch, isolated_recovery, result)
    assert "decision=local_recovery_inconclusive " in record
    assert record.endswith("geph=not_started")
    assert "local_xbox=" not in record and "synthetic" not in record and "\n" not in record


@pytest.mark.parametrize("failure,guard,state", [
    ("incomplete", "direct_same_object", "incomplete_idle_timeout"),
    ("unknown", "direct_same_object", "invalid"),
    ("mismatch", "direct_same_object", "complete"),
    ("xbox", "xbox_same_object", "complete"),
    ("split64", "split64_same_object", "complete"),
    ("split16", "split16_same_object", "complete"),
    ("deadline", "probe_deadline", "complete"),
    ("job_deadline", "job_deadline", "complete"),
    ("authority", "authority", "complete"),
    ("network", "network_wide", "complete"),
])
def test_comparison_diagnostic_reports_first_refusal_without_proof(
    monkeypatch, isolated_recovery, failure, guard, state,
):
    clock = isolated_recovery
    stage = {"xbox": tproxy.PLAIN_STRATEGY}.get(failure, failure)

    def local(_ip, _host, _request, _deadline, _final, strategy, _event):
        return observation(validator="other-object" if strategy == stage else "same-object")

    def geph(_host, _request, deadline):
        if failure == "deadline":
            clock.now = deadline
        elif failure == "job_deadline":
            monkeypatch.setattr(tproxy.time, "time", lambda: 1_750_001_000.0)
        elif failure == "authority":
            monkeypatch.setattr(tproxy, "_validated_route_preflight_outcome", lambda *_args: None)
        elif failure == "network":
            monkeypatch.setattr(tproxy, "_network_wide_unknown_failure_visible", lambda _now: True)
        return observation(
            {"incomplete": Outcome.INCOMPLETE, "unknown": Outcome.UNKNOWN}.get(failure, Outcome.COMPLETE),
            validator="different-object" if failure == "mismatch" else "same-object",
        )

    result = run_blocking(local_probe=local, geph_probe=geph)
    assert result.proof is None and result.local_winner is None
    assert result.diagnostic_decision == "geph_comparison_refused"
    assert result.diagnostic_geph == "comparison_refused"
    assert result.diagnostic_comparison == (guard, state, "unobserved")
    diagnostic, record = capture_local_diagnostic(monkeypatch, clock, result)
    assert diagnostic.comparison == result.diagnostic_comparison
    assert f"geph_guard={guard} geph_result={state} geph_io=unobserved" in record
    assert "/assets/" not in record and "other-object" not in record


def test_comparison_diagnostic_rejects_hostile_details(monkeypatch, isolated_recovery):
    result = SimpleNamespace(
        diagnostic_decision="geph_comparison_refused", diagnostic_direct="complete",
        diagnostic_geph="comparison_refused",
        diagnostic_comparison=(HostileLocalDiagnostic(), "token=synthetic\nforged=1", "https://secret.invalid/"),
    )
    _diagnostic, record = capture_local_diagnostic(monkeypatch, isolated_recovery, result)
    assert record.endswith("geph_guard=unknown geph_result=unknown geph_io=unknown")
    assert "synthetic" not in record and "secret" not in record and "\n" not in record


@pytest.mark.parametrize("phase", ["tls_setup", "tls_handshake", "request_write", "response_read", "response_classify"])
def test_range_diagnostic_keeps_only_io_phase_and_closes_socket(monkeypatch, phase):
    closed = []

    def fail():
        raise OSError("https://private.invalid/asset?token=synthetic")

    sock = SimpleNamespace(settimeout=lambda _timeout: None, close=lambda: closed.append(True))
    sock.sendall = lambda _request: fail() if phase == "request_write" else None
    sock.recv = lambda _count: fail() if phase == "response_read" else b""
    context = SimpleNamespace(wrap_socket=lambda *_args, **_kw: fail() if phase == "tls_handshake" else sock)
    monkeypatch.setattr(tproxy, "_local_payload_ssl_context", lambda: fail() if phase == "tls_setup" else context)
    if phase == "response_classify":
        monkeypatch.setattr(tproxy.bootstrap_asset_preflight, "inspect_range_response", lambda *_args, **_kw: fail())
    result = tproxy._bootstrap_range_response_on_tls_socket(sock, HOST, b"transient-request", 120.0)
    assert result.evidence.outcome is Outcome.UNKNOWN
    assert result.diagnostic_io == phase
    assert closed == [True]
    assert "private" not in repr(result) and "synthetic" not in repr(result)


def test_comparison_diagnostic_failure_preserves_original_refusal():
    class HostileObservation(tproxy._BootstrapRangeProbeObservation):
        def __getattribute__(self, name):
            if name == "diagnostic_io":
                raise RuntimeError("diagnostic-only failure")
            return super().__getattribute__(name)

    sample = observation(Outcome.INCOMPLETE)
    result = run_blocking(geph_probe=lambda *_args: HostileObservation(sample.evidence, sample.termination))
    assert result.diagnostic_comparison == ()
    assert result.diagnostic_decision == "geph_comparison_refused"
    assert result.outcome == tproxy.SEMANTIC_OUTCOME_NAVIGATION_PENDING
    assert result.proof is None and result.local_winner is None


@pytest.mark.parametrize("remaining,io_state,outcome", [
    (0.0, "socks_deadline", Outcome.DEADLINE_EXCEEDED),
    (3.0, "socks_connect", Outcome.UNKNOWN),
])
def test_geph_io_diagnostic_distinguishes_absent_socket(monkeypatch, remaining, io_state, outcome):
    calls = []
    monkeypatch.setattr(tproxy, "_socks5_connect_blocking", lambda *_args, **kwargs: calls.append(kwargs))
    result = tproxy._bootstrap_asset_geph_range_probe(HOST, b"transient-request", 100.0 + remaining)
    assert result.diagnostic_io == io_state
    assert result.evidence.outcome is outcome
    assert len(calls) == (1 if remaining else 0)
    if calls:
        assert calls[0]["socks_port"] == tproxy.GEPH_OWNED_PORT
