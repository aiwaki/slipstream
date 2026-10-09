"""Root redirects must not hide a broken final document."""
from collections import deque
import time

import pytest
import tproxy


def redirect(target):
    return (b'HTTP/1.1 302 Found\r\nLocation: ' + target.encode()
            + b'\r\nContent-Length: 0\r\n\r\n')


class Stream:
    def __init__(self, response):
        self.chunks = deque([response, b''])
        self.request = b''
        self.closed = False

    def settimeout(self, timeout):
        assert timeout > 0

    def do_handshake(self):
        pass

    def sendall(self, request):
        self.request = request

    def recv(self, size):
        return self.chunks.popleft()

    def close(self):
        self.closed = True


def run_probe(monkeypatch, responses):
    streams = [Stream(response) for response in responses]
    pending = deque(streams)
    calls = []
    deadline = time.monotonic() + 3

    def connect(ip, budget, control):
        assert ip == '8.8.8.8'
        assert budget == deadline
        if calls:
            assert streams[len(calls) - 1].closed
        calls.append((ip, budget))
        return pending.popleft()

    monkeypatch.setattr(tproxy, '_open_root_preflight_socket', connect)
    monkeypatch.setattr(tproxy, '_open_root_preflight_tls_stream',
                        lambda sock, host, budget: sock)
    observation = tproxy._semantic_plain_preflight_probe_detail(
        '8.8.8.8', 'redirect.example', 10, deadline_monotonic=deadline)
    return observation, streams, calls


def test_redirect_does_not_hide_truncated_destination(monkeypatch):
    partial = (b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n'
               b'Content-Length: 240000\r\n\r\n<html>' + b'x' * 16000)
    observation, streams, calls = run_probe(monkeypatch, [redirect('/en'), partial])
    assert len(calls) == 2
    assert streams[1].request.startswith(b'GET /en HTTP/1.1\r\n')
    assert observation.outcome == tproxy.SEMANTIC_OUTCOME_NAVIGATION_PENDING
    assert observation.safe_incomplete
    assert all(stream.closed for stream in streams)


@pytest.mark.parametrize('targets', [('/en', '/'), ('/a', '/b', '/c')])
def test_redirect_cycle_and_hop_limit_are_not_healthy(monkeypatch, targets):
    observation, streams, calls = run_probe(monkeypatch, [redirect(x) for x in targets])
    assert len(calls) == len(targets)
    assert observation.outcome == tproxy.SEMANTIC_OUTCOME_NAVIGATION_PENDING
    assert observation.retryable_inconclusive
    assert not observation.safe_incomplete


def test_redirect_does_not_connect_other_origin(monkeypatch):
    _, streams, calls = run_probe(monkeypatch, [redirect('https://elsewhere.example/en')])
    assert len(calls) == 1
    assert streams[0].closed


def test_redirect_inspects_assets_relative_to_final_document(monkeypatch):
    body = b'<html><head><link rel="stylesheet" href="style.css"></head><body>page</body></html>'
    response = (b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: '
                + str(len(body)).encode() + b'\r\n\r\n' + body)
    inspector = tproxy.bootstrap_asset_preflight.inspect_critical_bootstrap_assets
    bases = []

    def inspect(base, *args, **kwargs):
        bases.append(base)
        return inspector(base, *args, **kwargs)

    monkeypatch.setattr(tproxy.bootstrap_asset_preflight,
                        'inspect_critical_bootstrap_assets', inspect)
    observation, _, calls = run_probe(monkeypatch, [redirect('/en/page'), response])
    assert len(calls) == 2
    assert bases == ['https://redirect.example/en/page']
    assert observation.outcome == tproxy.SEMANTIC_OUTCOME_USABLE
    for asset in observation.bootstrap_assets:
        asset.forget()


def test_redirect_cancellation_prevents_next_connection(monkeypatch):
    deadline = time.monotonic() + 3
    control = tproxy._RootPreflightProbeControl(deadline)
    stream = Stream(redirect('/en'))
    calls = []

    def close():
        stream.closed = True
        control.cancel()

    stream.close = close
    monkeypatch.setattr(tproxy, '_open_root_preflight_socket',
                        lambda *args: calls.append(args) or stream)
    monkeypatch.setattr(tproxy, '_open_root_preflight_tls_stream',
                        lambda sock, *args: sock)
    observation = tproxy._semantic_plain_preflight_probe_detail(
        '8.8.8.8', 'redirect.example', 10,
        deadline_monotonic=deadline, control=control)
    assert len(calls) == 1
    assert observation.root_boundary == tproxy._RootPreflightBoundary.OUTER_BUDGET_TIMEOUT
    assert not observation.safe_incomplete


def test_redirect_does_not_renew_expired_budget(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(tproxy.time, 'monotonic', lambda: clock[0])
    original_close = Stream.close

    def close(stream):
        original_close(stream)
        clock[0] += 4

    monkeypatch.setattr(Stream, 'close', close)
    observation, _, calls = run_probe(monkeypatch, [redirect('/en')])
    assert len(calls) == 1
    assert observation.root_boundary == tproxy._RootPreflightBoundary.OUTER_BUDGET_TIMEOUT
    assert observation.retryable_inconclusive
    assert not observation.safe_incomplete
