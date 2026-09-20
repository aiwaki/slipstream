"""Scope of Darwin stale-state repair and listener startup ordering."""
import asyncio
import ctypes
import socket
from types import SimpleNamespace

import pytest
import pf_adapter
import tproxy


HEADER = 'Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)\n'


@pytest.mark.parametrize('family,address', [(socket.AF_INET,'127.0.0.1'),(socket.AF_INET6,'::1')])
@pytest.mark.parametrize('reverse', [False,True])
def test_selector_matches_only_tcp_loopback_and_one_port(family,address,reverse):
    data=pf_adapter._loopback_state_kill_request(family,1080,reverse)
    request=pf_adapter.PfiocStateKill.from_buffer_copy(data)
    assert len(data)==216 and request.af==family and request.proto==socket.IPPROTO_TCP
    addr=socket.inet_pton(family,address)
    for endpoint in (request.src,request.dst):
        assert bytes(endpoint.address.address_mask[:len(addr)])==addr
        assert bytes(endpoint.address.address_mask[16:16+len(addr)])==b'\xff'*len(addr)
        assert endpoint.neg==0 and endpoint.address.type==0
    exact=request.src if reverse else request.dst
    other=request.dst if reverse else request.src
    assert exact.op==2 and list(exact.ports)==[socket.htons(1080)]*2
    assert other.op==0 and not any(other.ports)


@pytest.mark.parametrize('output', ['',HEADER+'tcp4 invalid',
    HEADER+'tcp4 0 0 127.0.0.1.1080 127.0.0.1.49000 ESTABLISHED',
    HEADER+'tcp4 0 0 127.0.0.1.49000 127.0.0.1.1080 SYN_SENT',
    HEADER+'tcp6 0 0 ::1.1080 *.* LISTEN'])
def test_live_or_unproven_snapshot_never_opens_pf(output):
    def forbidden(*a,**k):raise AssertionError('must not mutate PF')
    assert not pf_adapter.clear_inactive_loopback_proxy_states(
        lambda *a:SimpleNamespace(returncode=0,stdout=output),1080,opener=forbidden)


def test_no_global_pf_flush_and_preserve_other_ports():
    calls=[]
    class Device:
        def __enter__(self):return self
        def __exit__(self,*a):pass
        def fileno(self):return 7
    def opener(*a,**k):
        assert a[0]=='/dev/pf';return Device()
    def ioctl(fd,command,data,mutate):
        assert command==0xc0d84429
        request=pf_adapter.PfiocStateKill.from_buffer_copy(data)
        assert (request.src if request.src.op else request.dst).ports[0]==socket.htons(1080)
        calls.append(command)
    output=HEADER+'tcp4 0 0 127.0.0.1.5000 127.0.0.1.5001 ESTABLISHED\n'
    assert pf_adapter.clear_inactive_loopback_proxy_states(
        lambda *a:SimpleNamespace(returncode=0,stdout=output),1080,opener=opener,ioctl_fn=ioctl)
    assert len(calls)==4


def test_cleanup_occurs_after_exclusive_bind_before_listen(monkeypatch):
    events=[]
    class Server:
        sockets=[SimpleNamespace(family=socket.AF_INET),SimpleNamespace(family=socket.AF_INET6)]
        async def start_serving(self):events.append('listen')
    async def bind(*a,**kw):
        assert kw.get('start_serving') is False and not kw.get('reuse_port')
        events.append('bind');return Server()
    def cleanup(*a):events.append('cleanup');return True
    monkeypatch.setattr(tproxy.asyncio,'start_server',bind)
    monkeypatch.setattr(tproxy.os,'geteuid',lambda:0)
    monkeypatch.setattr(tproxy.sys,'platform','darwin')
    monkeypatch.setattr(tproxy.pf_adapter,'clear_inactive_loopback_proxy_states',cleanup)
    asyncio.run(tproxy._start_transparent_loopback_server(1080))
    assert events==['bind','cleanup','listen']


def test_local_proxy_rules_are_bidirectional_stateless_before_reply_to():
    rules=tproxy.PF_RULES.format(port=1080)
    before=rules[:rules.index('reply-to')]
    for host in ('127.0.0.1','::1'):
        assert f'from {host} to {host} port 1080 flags any no state' in before
        assert f'from {host} port 1080 to {host} flags any no state' in before
    assert 'rdr on lo0 inet proto tcp from any to ! 127.0.0.0/8 port 443' in rules
    assert 'proto udp' not in rules


def test_cancel_keeps_binding_until_cleanup_finishes(monkeypatch):
    import threading
    started, release = threading.Event(), threading.Event()
    events = []
    class Server:
        sockets = [SimpleNamespace(family=socket.AF_INET), SimpleNamespace(family=socket.AF_INET6)]
        async def start_serving(self): events.append('listen')
        def close(self): events.append('close')
        async def wait_closed(self): pass
    async def bind(*a, **kw): return Server()
    def cleanup(*a):
        started.set()
        assert release.wait(5)
        events.append('cleaned')
        return True
    monkeypatch.setattr(tproxy.asyncio, 'start_server', bind)
    monkeypatch.setattr(tproxy.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(tproxy.sys, 'platform', 'darwin')
    monkeypatch.setattr(tproxy.pf_adapter, 'clear_inactive_loopback_proxy_states', cleanup)
    async def run():
        task = asyncio.create_task(tproxy._start_transparent_loopback_server(1080))
        assert await asyncio.to_thread(started.wait, 5)
        task.cancel()
        await asyncio.sleep(0)
        assert 'close' not in events
        release.set()
        with pytest.raises(asyncio.CancelledError): await task
    asyncio.run(run())
    assert events == ['cleaned', 'close']
