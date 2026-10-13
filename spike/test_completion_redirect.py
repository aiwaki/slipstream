"""Local failure and alternate payload checks must traverse the root redirect."""
from collections import deque
from types import SimpleNamespace
import pytest
import tproxy
from test_root_preflight_redirect import Stream, redirect


@pytest.mark.parametrize('protocol', ['http/1.1', 'h2'])
@pytest.mark.parametrize('alternate', [False, True])
def test_completion_probe_follows_root_redirect(monkeypatch, protocol, alternate):
    body = b'x' * 1024
    final = b'HTTP/1.1 200 OK\r\nContent-Length: ' + (b'1024' if alternate else b'240000') + b'\r\n\r\n' + body
    streams = [Stream(redirect('/en')), Stream(final)]
    pending = deque(streams)
    def connect(*args, **kwargs):
        if len(pending) == 1: assert streams[0].closed
        return pending.popleft()
    monkeypatch.setattr(tproxy.socket, 'create_connection', connect)
    monkeypatch.setattr(tproxy, '_socks5_connect_blocking', connect)
    monkeypatch.setattr(tproxy, '_incomplete_response_ssl_context',
                        lambda: SimpleNamespace(wrap_socket=lambda sock, **kw: sock))
    monkeypatch.setattr(tproxy, '_selected_alpn_protocol', lambda sock: protocol)
    paths = []
    deadlines = []
    def h2(sock, host, **kwargs):
        paths.append(kwargs.get('request_target', '/'))
        deadlines.append(kwargs['deadline'])
        first = sock is streams[0]
        return SimpleNamespace(
            complete=first or alternate, protocol_error=False,
            status=302 if first else 200,
            headers=((b'location', b'/en'),) if first else (),
            incomplete=not first and not alternate,
            content_encoding_is_identity=True, body=b'' if first else body,
            body_length=0 if first else len(body))
    monkeypatch.setattr(tproxy, 'probe_http2_response', h2)
    if alternate:
        assert tproxy._incomplete_response_geph_payload_probe('example.com') == len(body)
    else:
        assert tproxy._incomplete_response_plain_payload_probe('8.8.8.8', 'example.com')
    assert not pending
    assert all(s.closed for s in streams)
    if protocol == 'h2':
        assert paths == ['/', '/en']
        assert deadlines[0] == deadlines[1]
    else:
        assert streams[1].request.startswith(b'GET /en HTTP/1.1\r\n')


@pytest.mark.parametrize('alternate', [False, True])
@pytest.mark.parametrize('target', ['/', 'https://other.example/en', '//other.example/en'])
def test_completion_redirect_cannot_loop_or_cross_origin(monkeypatch, alternate, target):
    stream = Stream(redirect(target))
    calls = []
    def connect(*args, **kwargs):
        calls.append(True)
        assert len(calls) == 1
        return stream
    monkeypatch.setattr(tproxy.socket, 'create_connection', connect)
    monkeypatch.setattr(tproxy, '_socks5_connect_blocking', connect)
    monkeypatch.setattr(tproxy, '_incomplete_response_ssl_context',
                        lambda: SimpleNamespace(wrap_socket=lambda sock, **kw: sock))
    monkeypatch.setattr(tproxy, '_selected_alpn_protocol', lambda sock: None)
    result = (tproxy._incomplete_response_geph_payload_probe('example.com') if alternate
              else tproxy._incomplete_response_plain_payload_probe('8.8.8.8', 'example.com'))
    assert not result
    assert len(calls) == 1


@pytest.mark.parametrize('alternate', [False, True])
def test_completion_redirect_expired_budget_does_not_dial(monkeypatch, alternate):
    def forbidden(*args, **kwargs):
        pytest.fail('expired redirect budget opened a new socket')
    monkeypatch.setattr(tproxy.socket, 'create_connection', forbidden)
    monkeypatch.setattr(tproxy, '_socks5_connect_blocking', forbidden)
    if alternate:
        assert not tproxy._incomplete_response_geph_payload_probe('example.com', _deadline=0)
    else:
        assert not tproxy._incomplete_response_plain_payload_probe('8.8.8.8', 'example.com', _deadline=0)
