"""Admission to recheck must outlive expiring proof, without reusing proof."""
import pytest
import tproxy as t


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    for name in ('_local_partial_stalls', '_local_partial_recheck_until',
                 '_local_zero_payload_failures', '_auto_geph_candidates',
                 '_app_dns_candidates', '_app_dns_attempts'):
        monkeypatch.setattr(t, name, {})


def test_recheck_survives_proof_expiry_while_local_ladder_remains():
    host = 'recheck-expiry.example'
    t._record_partial_tls_stall_evidence(host, t.AUTO_GEPH_STAGE_SYSTEM, 1000)
    t._note_app_dns_attempt(host, 1000)
    t._prune_local_partial_stalls(1301)
    assert host not in t._local_partial_stalls
    assert t.unknown_recovery_stage(host, now=1301) == t.UNKNOWN_RECOVERY_LOCAL_LADDER
    assert t._partial_route_recheck_pending(host, 1301)
    assert not t._auto_geph_candidate_proven(host, 1301)
    assert not t._partial_route_recheck_pending(host, 1600)


@pytest.mark.parametrize('host', ['discord.com', 'www.youtube.com'])
def test_protected_hosts_never_gain_recheck_marker(host):
    assert not t._record_partial_tls_stall_evidence(host, t.AUTO_GEPH_STAGE_SYSTEM, 1000)
    assert not t._partial_route_recheck_pending(host, 1001)


def test_marker_storage_is_bounded(monkeypatch):
    monkeypatch.setattr(t, 'AUTO_GEPH_STATE_MAX', 2)
    for i in range(4):
        t._record_partial_tls_stall_evidence(f'host{i}.example', t.AUTO_GEPH_STAGE_SYSTEM, 1000)
    assert len(t._local_partial_recheck_until) == 2
    assert t._partial_route_recheck_pending('host3.example', 1001)


def test_partial_failure_moves_cached_tls_winner_behind_untried(monkeypatch):
    host = 'partial-winner.example'
    failed = t.GENERAL_STRATS[0]
    monkeypatch.setattr(t.time, 'monotonic', lambda: 1001.0)
    monkeypatch.setattr(t, '_strat_cache', {host: failed})
    monkeypatch.setattr(t, '_strat_scores', t.OrderedDict())
    monkeypatch.setattr(t, '_local_payload_idle_failures', {})
    # A popular TLS-only winner must not hide a later incomplete body.
    for _ in range(100):
        t._record_strategy_result(host, failed, True)
    t._record_partial_tls_stall_evidence(
        host, t.AUTO_GEPH_STAGE_STRATEGY_PREFIX + failed, 1000.0,
    )
    ordered = t._strategy_order_for_attempt(host)
    assert ordered[-1]['name'] == failed
    assert ordered[0]['name'] != failed
    assert not t._auto_geph_candidate_proven(host, 1001.0)


def test_partial_priority_expires_and_explicit_repeat_is_preserved(monkeypatch):
    host = 'partial-expiry.example'
    failed = t.GENERAL_STRATS[0]
    baseline = [t.STRAT_BY_NAME[name] for name in t.GENERAL_STRATS]
    monkeypatch.setattr(t, 'strategy_order', lambda host: list(baseline))
    monkeypatch.setattr(t, '_local_payload_idle_failures', {})
    monkeypatch.setattr(t.time, 'monotonic', lambda: 1001.0)
    stage = t.AUTO_GEPH_STAGE_STRATEGY_PREFIX + failed
    t._record_partial_tls_stall_evidence(host, stage, 1000.0)
    assert t._strategy_order_for_attempt(host, stage)[0]['name'] == failed
    monkeypatch.setattr(t.time, 'monotonic', lambda: 1301.0)
    assert t._strategy_order_for_attempt(host) == baseline
