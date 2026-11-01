"""Offline TLS/H2 protocol checks for the bundled Telegram media transport."""
import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import importlib
import importlib.util
import ipaddress
from pathlib import Path
import ssl
import struct
import sys
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.errors import ErrorCodes
from h2.events import DataReceived, RequestReceived, StreamEnded, StreamReset
import httpx
import pytest

_ROOT = Path(__file__).resolve().parents[1] / 'vendor/tg-ws-proxy/proxy'
_NAME = 'slipstream_tg_vendor'
if _NAME not in sys.modules:
    spec = importlib.util.spec_from_file_location(
        _NAME, _ROOT / '__init__.py', submodule_search_locations=[str(_ROOT)])
    package = importlib.util.module_from_spec(spec)
    sys.modules[_NAME] = package
    spec.loader.exec_module(package)
transport_module = importlib.import_module(_NAME + '.h2_transport')


@pytest.fixture
def tls_contexts(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=1))
                   .not_valid_after(now + timedelta(days=1))
                   .add_extension(x509.SubjectAlternativeName([
                       x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
                   .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / 'server.pem', tmp_path / 'server-key.pem'
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert_path, key_path)
    server.set_alpn_protocols(['h2'])
    client = ssl.create_default_context(cafile=str(cert_path))
    return server, client


class H2Peer:
    """A real local H2 server; stalled requests use explicit event barriers."""
    def __init__(self):
        self.requests = {}
        self.received = asyncio.Queue()
        self.reset = asyncio.Queue()
        self.tasks = set()
        self.writers = set()
        self.connections = 0
        self.api_status = None

    def accept(self, reader, writer):
        self.connections += 1
        self.writers.add(writer)
        task = asyncio.create_task(self.serve(reader, writer))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def serve(self, reader, writer):
        h2 = H2Connection(config=H2Configuration(client_side=False, header_encoding='utf-8'))
        h2.initiate_connection()
        writer.write(h2.data_to_send())
        pending = {}
        try:
            while data := await reader.read(64 * 1024):
                for event in h2.receive_data(data):
                    stream_id = getattr(event, 'stream_id', None)
                    if isinstance(event, RequestReceived):
                        self.requests[stream_id] = [dict(event.headers)[':path'], bytearray()]
                    elif isinstance(event, DataReceived):
                        self.requests[stream_id][1].extend(event.data)
                        h2.acknowledge_received_data(event.flow_controlled_length, stream_id)
                    elif isinstance(event, StreamReset):
                        pending.pop(stream_id, None)
                        self.reset.put_nowait(stream_id)
                    elif isinstance(event, StreamEnded):
                        path, body = self.requests[stream_id]
                        self.received.put_nowait((stream_id, path))
                        if path == '/api' and self.api_status is not None:
                            h2.send_headers(stream_id, [(':status', str(self.api_status))], end_stream=True)
                        elif path == '/reset':
                            h2.reset_stream(stream_id, ErrorCodes.INTERNAL_ERROR)
                        elif path == '/eof':
                            return
                        elif path == '/pending':
                            continue
                        elif path == '/partial':
                            h2.send_headers(stream_id, [(':status', '200')])
                            h2.send_data(stream_id, b'first')
                        else:
                            payload = bytes(body) if body else path.encode()
                            h2.send_headers(stream_id, [(':status', '200'),
                                                      ('content-length', str(len(payload)))])
                            pending[stream_id] = payload
                for stream_id, payload in list(pending.items()):
                    while payload:
                        count = min(len(payload), h2.max_outbound_frame_size,
                                    h2.local_flow_control_window(stream_id))
                        if count <= 0:
                            break
                        chunk, payload = payload[:count], payload[count:]
                        h2.send_data(stream_id, chunk, end_stream=not payload)
                    if payload:
                        pending[stream_id] = payload
                    else:
                        pending.pop(stream_id)
                writer.write(h2.data_to_send())
                await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
            self.writers.discard(writer)


@asynccontextmanager
async def local_h2(tls_contexts):
    server_context, client_context = tls_contexts
    peer = H2Peer()
    server = await asyncio.start_server(peer.accept, '127.0.0.1', 0, ssl=server_context)
    transport = transport_module.H2Transport(client_context, max_streams=4)
    port = server.sockets[0].getsockname()[1]
    try:
        async with httpx.AsyncClient(transport=transport, timeout=2,
                                    base_url=f'https://127.0.0.1:{port}') as client:
            yield client, transport, peer
    finally:
        server.close()
        # Accepted TLS transports belong to these handlers; close them before
        # joining Server.wait_closed on Python versions which wait for clients.
        for writer in list(peer.writers):
            writer.close()
        for task in list(peer.tasks):
            task.cancel()
        await asyncio.gather(*peer.tasks, return_exceptions=True)
        await server.wait_closed()


def run_scenario(coro):
    # A single generous outer watchdog diagnoses hangs without timing races.
    asyncio.run(asyncio.wait_for(coro, timeout=8))


def test_h2_real_tls_multiplexes_and_preserves_chunked_payload(tls_contexts):
    async def scenario():
        async with local_h2(tls_contexts) as (client, transport, peer):
            payload = bytes(range(256)) * 180  # multiple H2 frames, exact bytes
            responses = await asyncio.gather(*(client.post(f'/echo/{n}', content=payload) for n in range(4)))
            assert all(r.status_code == 200 and r.content == payload for r in responses)
            assert all(r.http_version == 'HTTP/2' for r in responses)
            assert peer.connections == 1
            assert len(peer.requests) == 4
            assert not transport.connection.streams
        assert transport.closed and transport.connection.reader_task.done()
        assert not peer.tasks and not peer.writers
    run_scenario(scenario())


@pytest.mark.parametrize('failure', ['reset', 'eof'])
def test_h2_real_tls_peer_failure_is_reported_and_next_request_recovers(tls_contexts, failure):
    async def scenario():
        async with local_h2(tls_contexts) as (client, transport, peer):
            with pytest.raises(httpx.HTTPError):
                await client.get('/' + failure)
            assert not transport.connection.streams
            response = await client.get('/healthy')
            assert response.content == b'/healthy'
            assert peer.connections == (2 if failure == 'eof' else 1)
    run_scenario(scenario())


def test_h2_real_tls_cancelled_request_releases_stream_and_keeps_peer_usable(tls_contexts):
    async def scenario():
        async with local_h2(tls_contexts) as (client, transport, peer):
            request = asyncio.create_task(client.get('/pending'))
            stream_id, path = await peer.received.get()
            assert path == '/pending'
            request.cancel()
            with pytest.raises(asyncio.CancelledError):
                await request
            assert not transport.connection.streams
            assert await peer.reset.get() == stream_id
            assert (await client.get('/healthy')).content == b'/healthy'
            assert peer.connections == 1
    run_scenario(scenario())


def test_h2_real_tls_partial_response_timeout_releases_stream(tls_contexts):
    async def scenario():
        async with local_h2(tls_contexts) as (client, transport, peer):
            async with client.stream('GET', '/partial', timeout=.1) as response:
                chunks = response.aiter_bytes()
                assert await anext(chunks) == b'first'
                with pytest.raises(httpx.ReadTimeout):
                    await anext(chunks)
            assert not transport.connection.streams
            assert (await client.get('/healthy')).content == b'/healthy'
    run_scenario(scenario())


@pytest.mark.parametrize('tag_name', ['PROTO_TAG_ABRIDGED', 'PROTO_TAG_INTERMEDIATE', 'PROTO_TAG_SECURE'])
def test_h2_media_404_reaches_native_client_without_replay(tls_contexts, tag_name):
    """The 1.11.1 resume fix must deliver -404, not hide it behind retries."""
    cf_h2 = importlib.import_module(_NAME + '.cf_h2')
    utils = importlib.import_module(_NAME + '.utils')
    class IdentityCipher:
        def update(self, data):
            return data
    class NativeWriter:
        def __init__(self):
            self.data = bytearray()
        def write(self, data):
            self.data.extend(data)
        async def drain(self):
            pass
    async def scenario():
        async with local_h2(tls_contexts) as (client, transport, peer):
            peer.api_status = 404
            host = str(client.base_url).removeprefix('https://').rstrip('/')
            lane = cf_h2._HttpLane(host, 1)
            await lane.client.aclose()
            lane.client = client
            channel = cf_h2._HttpChannel(lane, 1, 'loopback')
            tag = getattr(utils, tag_name)
            reader, writer = asyncio.StreamReader(), NativeWriter()
            # A valid unencrypted packet, including its native length prefix.
            body = b'\x00' * 16 + struct.pack('<I', 4) + b'data'
            prefix = b'\x06' if tag == utils.PROTO_TAG_ABRIDGED else struct.pack('<I', len(body))
            reader.feed_data(prefix + body)
            context = SimpleNamespace(clt_enc=IdentityCipher(), clt_dec=IdentityCipher())
            try:
                await cf_h2.bridge_h2(reader, writer, channel, context, tag)
                offset = 1 if tag == utils.PROTO_TAG_ABRIDGED else 4
                assert struct.unpack('<i', writer.data[offset:offset + 4])[0] == -404
                assert channel.transport_error == -404 and channel.closed
                assert len(peer.requests) == lane.requests == 1
                assert lane.replays == 0
                assert not lane.inflight and not lane.queued_bytes
                assert not channel.pending and not transport.connection.streams
            finally:
                await lane.close()
    run_scenario(scenario())
