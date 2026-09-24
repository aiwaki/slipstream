import asyncio
import unittest

import https_connect
from managed_https_proxy import ProxyLease


class Writer:
    def __init__(self):
        self.data = bytearray()

    def get_extra_info(self, _name):
        return ('127.0.0.1', 12345)

    def write(self, data):
        self.data.extend(data)

    async def drain(self):
        pass


class ConnectTests(unittest.TestCase):
    def test_pac_fetch_does_not_resolve_or_open_upstream(self):
        async def run():
            reader = asyncio.StreamReader()
            reader.feed_data(b'GET /slipstream-https.pac HTTP/1.1\r\nHost: localhost\r\n\r\n')
            async def resolve(_host):
                raise AssertionError('PAC must not dial')
            writer = Writer()
            self.assertIsNone(await https_connect.admit(reader, writer, resolve))
            self.assertIn(b'PROXY 127.0.0.1:12345', writer.data)
            self.assertIn(b'Connection: close', writer.data)
        asyncio.run(run())

    def test_tunnel_bytes_are_not_consumed(self):
        async def run():
            reader = asyncio.StreamReader()
            reader.feed_data(b'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n\x16TLS')
            async def resolve(host):
                self.assertEqual(host, 'example.com')
                return ['93.184.215.14']
            writer = Writer()
            result = await https_connect.admit(reader, writer, resolve)
            self.assertEqual(result, ('example.com', '93.184.215.14', 443))
            self.assertEqual(await reader.readexactly(4), b'\x16TLS')
            self.assertIn(b'200 Connection Established', writer.data)
        asyncio.run(run())

    def test_invalid_authorities_and_smuggling(self):
        for request in (
            b'GET https://example.com/ HTTP/1.1\r\n\r\n',
            b'CONNECT example.com:80 HTTP/1.1\r\n\r\n',
            b'CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n',
            b'CONNECT example.com:443 HTTP/1.1\r\nHost: other.com:443\r\n\r\n',
            b'CONNECT example.com:443 HTTP/1.1\r\nContent-Length: 1\r\n\r\n',
            b'CONNECT example.com:443 HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n',
            b'CONNECT example..com:443 HTTP/1.1\r\n\r\n',
            b'CONNECT example.com:443 HTTP/1.1\r\n folded: value\r\n\r\n',
        ):
            with self.subTest(request=request), self.assertRaises(ValueError):
                https_connect.parse_authority(request)

    def test_mixed_private_dns_never_opens_tunnel(self):
        async def run():
            reader = asyncio.StreamReader()
            reader.feed_data(b'CONNECT example.com:443 HTTP/1.1\r\n\r\n')
            async def resolve(_host):
                return ['93.184.215.14', '127.0.0.1']
            writer = Writer()
            with self.assertRaises(ValueError):
                await https_connect.admit(reader, writer, resolve)
            self.assertNotIn(b'200', writer.data)
        asyncio.run(run())


class Store:
    def __init__(self):
        self.data = {'State:/Network/Global/IPv4': {'PrimaryService': 'wifi'}}
        self.added = []
        self.closed = False

    def get(self, key):
        return self.data.get(key)

    def add(self, key, value):
        if key in self.data:
            return False
        self.data[key] = value
        self.added.append(key)
        return True

    def close(self):
        for key in self.added:
            self.data.pop(key)
        self.closed = True


class LeaseTests(unittest.TestCase):
    def test_partial_dual_stack_admission_rolls_back_only_own_key(self):
        store = Store()
        store.data['State:/Network/Global/IPv6'] = {'PrimaryService': 'zzz'}
        foreign = 'State:/Network/Service/zzz/Proxies'
        store.data[foreign] = {'HTTPSProxy': 'foreign'}
        before = dict(store.data)
        with self.assertRaises(ValueError):
            ProxyLease(1080, lambda: store).start()
        self.assertEqual(store.data, before)

    def test_primary_network_change_requests_new_lease(self):
        store = Store()
        lease = ProxyLease(1080, lambda: store)
        lease.start()
        self.assertFalse(lease.needs_refresh())
        store.data['State:/Network/Global/IPv4'] = {'PrimaryService': 'ethernet'}
        self.assertTrue(lease.needs_refresh())
        lease.close()

    def test_scoped_foreign_proxy_is_not_overridden(self):
        store = Store()
        store.data['State:/Network/Global/Proxies'] = {'__SCOPED__': {'utun0': {'SOCKSEnable': 1}}}
        with self.assertRaises(ValueError):
            ProxyLease(1080, lambda: store).start()
        self.assertEqual(store.added, [])

    def test_restores_without_touching_persistent_preferences(self):
        store = Store()
        setup = 'Setup:/Network/Service/wifi/Proxies'
        store.data[setup] = {'ExceptionsList': ['*.local']}
        before = dict(store.data)
        lease = ProxyLease(1080, lambda: store)
        lease.start()
        self.assertEqual(store.data[setup], before[setup])
        lease.close()
        self.assertEqual(store.data, before)

    def test_never_replaces_existing_state(self):
        store = Store()
        key = 'State:/Network/Service/wifi/Proxies'
        store.data[key] = {'HTTPSProxy': 'foreign'}
        with self.assertRaises(ValueError):
            ProxyLease(1080, lambda: store).start()
        self.assertEqual(store.data[key], {'HTTPSProxy': 'foreign'})

    def test_explicit_off_preference_is_preserved(self):
        store = Store()
        store.data['Setup:/Network/Service/wifi/Proxies'] = {'HTTPSEnable': 0}
        with self.assertRaises(ValueError):
            ProxyLease(1080, lambda: store).start()
        self.assertEqual(store.added, [])


if __name__ == '__main__':
    unittest.main()


def test_connect_authority_overrides_cover_name_only_on_its_stream(monkeypatch):
    import tproxy
    import pytest

    class ReachedPolicy(Exception):
        pass

    names = []
    def policy(host):
        names.append(host)
        raise ReachedPolicy()

    def no_nat(_sock):
        raise OSError('no NAT entry')

    async def resolve(_host):
        return ['93.184.215.14']

    monkeypatch.setattr(tproxy, 'orig_dst', no_nat)
    monkeypatch.setattr(tproxy, 'system_resolve_async', resolve)
    monkeypatch.setattr(tproxy, 'parse_sni', lambda _body: 'cloudflare-ech.com')
    monkeypatch.setattr(tproxy, 'runtime_route_policy', policy)

    async def run():
        reader = asyncio.StreamReader()
        reader.feed_data(b'CONNECT example.com:443 HTTP/1.1\r\n\r\n\x16\x03\x01\x00\x01X')
        with pytest.raises(ReachedPolicy):
            await tproxy._handle_impl(reader, Writer())
        # A separate PF flow must continue to use its own SNI, never the name
        # previously received in CONNECT even when the destination IP matches.
        monkeypatch.setattr(tproxy, 'orig_dst', lambda _sock: ('93.184.215.14', 443))
        reader = asyncio.StreamReader()
        reader.feed_data(b'\x16\x03\x01\x00\x01X')
        with pytest.raises(ReachedPolicy):
            await tproxy._handle_impl(reader, Writer())
    asyncio.run(run())
    assert names == ['example.com', 'cloudflare-ech.com']


def test_darwin_untranslated_loopback_nat_entry_serves_pac(monkeypatch):
    import tproxy
    monkeypatch.setattr(tproxy, 'orig_dst', lambda _sock: ('127.0.0.1', 1080))
    class ClosingWriter(Writer):
        def close(self):
            self.closed = True
    async def run():
        reader = asyncio.StreamReader()
        reader.feed_data(b'GET /slipstream-https.pac HTTP/1.1\r\n\r\n')
        writer = ClosingWriter()
        await tproxy._handle_impl(reader, writer)
        assert b'200 OK' in writer.data
        assert b'FindProxyForURL' in writer.data
        assert writer.closed
    asyncio.run(run())
