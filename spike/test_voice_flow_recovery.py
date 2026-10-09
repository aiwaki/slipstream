"""Failure-class fixtures, not proof of a live Discord or ISP failure."""
from collections import OrderedDict
import pytest
import tproxy

KEY = ('192.0.2.1', 41000, '198.51.100.1', 50001)
RTP = b'\x80\x78' + b'\0' * 10


@pytest.mark.parametrize('reset_at', [8, 37, 121, 307])
def test_continuous_media_recovers_after_classifier_state_loss(reset_at):
    """Control survives but inbound media is withheld until another primer.

    The fixture models the proposed failure class explicitly. It does not
    manufacture a claim that a real filter or Discord behaves this way.
    """
    flows = OrderedDict()
    allowed = False
    resumed = None
    refreshes = []
    for tick in range((reset_at + 40) * 50):
        now = tick / 50
        if tick == reset_at * 50:
            allowed = False
        prime, count = tproxy.observe_voice_flow(flows, KEY, now, payload=RTP)
        if prime:
            allowed = True
            if count == tproxy.VOICE_CUTOFF:
                refreshes.append(now)
        if now >= reset_at and allowed and resumed is None:
            resumed = now
    assert resumed is not None
    assert resumed - reset_at <= tproxy.VOICE_FLOW_REFRESH_INTERVAL
    assert all(b-a >= tproxy.VOICE_FLOW_REFRESH_INTERVAL for a,b in zip(refreshes,refreshes[1:]))


def test_unknown_and_own_decoy_cannot_trigger_refresh():
    flows = OrderedDict()
    for n in range(tproxy.VOICE_CUTOFF):
        assert tproxy.observe_voice_flow(flows, KEY, n, payload=b"unknown")[0]
    for now in range(5, 1000):
        payload = b'unknown' if now % 2 else tproxy._fake_stun()
        assert not tproxy.observe_voice_flow(flows, KEY, now, payload=payload)[0]
    assert tproxy.observe_voice_flow(flows, KEY, 1000, payload=RTP)[0]
    assert not tproxy.observe_voice_flow(flows, KEY, 1000, payload=RTP)[0]


def test_refresh_does_not_reopen_initial_burst():
    flows = OrderedDict()
    for n in range(5):
        tproxy.observe_voice_flow(flows, KEY, n, payload=RTP)
    assert tproxy.observe_voice_flow(flows, KEY, 34, payload=RTP)[0]
    for n in range(100):
        assert not tproxy.observe_voice_flow(flows, KEY, 34+n/100, payload=RTP)[0]


def test_independent_flows_and_bounded_table(monkeypatch):
    monkeypatch.setattr(tproxy, 'VOICE_FLOWS_MAX', 2)
    flows = OrderedDict()
    for key in ('a', 'b', 'c'):
        assert tproxy.observe_voice_flow(flows, key, 0, payload=RTP)[0]
    assert list(flows) == ['b', 'c']


def test_voice_clock_is_monotonic(monkeypatch):
    monkeypatch.setattr(tproxy.time, 'time', lambda: pytest.fail('wall clock used'))
    monkeypatch.setattr(tproxy.time, 'monotonic', lambda: 123.)
    flows = OrderedDict()
    tproxy.observe_voice_flow(flows, KEY, payload=RTP)
    assert flows[KEY].last_seen == 123.


def test_listen_only_keepalive_refreshes_previously_identified_voice_flow():
    flows = OrderedDict()
    discovery = b"\x00\x01\x00\x46" + bytes(70)
    tproxy.observe_voice_flow(flows, KEY, 0, payload=discovery)
    for n in range(1, 5):
        tproxy.observe_voice_flow(flows, KEY, n, payload=bytes(8))
    assert tproxy.observe_voice_flow(flows, KEY, 34, payload=bytes(8))[0]
    # Observer captures its own fake, but that cannot trigger renewal.
    assert not tproxy.observe_voice_flow(flows, KEY, 100, payload=tproxy._fake_stun())[0]
    assert tproxy.observe_voice_flow(flows, KEY, 100, payload=bytes(8))[0]
