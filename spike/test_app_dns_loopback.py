"""Real TLS/RFC8484 tests, with only the outbound IP/port redirected locally."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import socket
import ssl
import struct
import threading
import time
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
import pytest

import app_dns


@pytest.fixture
def dns_tls(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'cloudflare-dns.com')])
    now = datetime.now(timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=1))
                   .not_valid_after(now + timedelta(days=1))
                   .add_extension(x509.SubjectAlternativeName([
                       x509.DNSName('cloudflare-dns.com')]), critical=False)
                   .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / 'dns.pem', tmp_path / 'dns-key.pem'
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert_path, key_path)
    client = ssl.create_default_context(cafile=str(cert_path))
    return server, client


@contextmanager
def local_doh(monkeypatch, dns_tls, case):
    server_context, client_context = dns_tls
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(1)
    listener.settimeout(3)
    local_address = listener.getsockname()
    evidence = {'requests': [], 'sni': [], 'connections': [], 'errors': []}
    server_context.set_servername_callback(lambda sock, name, ctx: evidence['sni'].append(name))

    def serve():
        try:
            raw, _ = listener.accept()
            raw.settimeout(3)
            with server_context.wrap_socket(raw, server_side=True) as stream:
                request = bytearray()
                while b'\r\n\r\n' not in request:
                    data = stream.recv(4096)
                    if not data:
                        raise AssertionError('client closed before HTTP headers')
                    request.extend(data)
                headers, body = bytes(request).split(b'\r\n\r\n', 1)
                fields = {key.strip().lower(): value.strip() for key, value in (
                    line.split(b':', 1) for line in headers.split(b'\r\n')[1:])}
                length = int(fields[b'content-length'])
                while len(body) < length:
                    data = stream.recv(length - len(body))
                    if not data:
                        raise AssertionError('client closed before DNS query')
                    body += data
                evidence['requests'].append((headers, body))
                query_id = int.from_bytes(body[:2], 'big')
                response_id = (query_id + 1) % 65536 if case == 'wrong_id' else query_id
                flags = 0x8380 if case == 'dns_tc' else 0x8180
                packet = (struct.pack('!6H', response_id, flags, 1, 1, 0, 0) + body[12:]
                          + b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4)
                          + socket.inet_aton('8.8.4.4'))
                if case == 'truncated_dns':
                    packet = packet[:-1]
                status = b'503 Service Unavailable' if case == 'http_error' else b'200 OK'
                mime = b'text/html' if case == 'wrong_type' else b'application/dns-message'
                response = b'HTTP/1.1 ' + status + b'\r\nContent-Type: ' + mime + b'\r\n'
                if case == 'chunked':
                    response += b'Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n'
                    response += hex(len(packet))[2:].encode() + b'\r\n' + packet + b'\r\n0\r\n\r\n'
                else:
                    declared = len(packet) + (1 if case == 'truncated_http' else 0)
                    response += f'Content-Length: {declared}\r\nConnection: close\r\n\r\n'.encode() + packet
                stream.sendall(response)
        except BaseException as exc:
            evidence['errors'].append(exc)
        finally:
            listener.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    original_socket = socket.socket
    original_connect = socket.create_connection

    def redirect(address):
        assert address == ('1.1.1.1', 443), 'unexpected external connection'
        evidence['connections'].append(address)
        return local_address

    class RedirectedSocket(original_socket):
        def connect(self, address):
            return super().connect(redirect(address))

    def create_connection(address, timeout, *args, **kwargs):
        return original_connect(redirect(address), timeout, *args, **kwargs)

    # Keep production TLS, SNI, HTTP framing, DNS encoding and parsing. Only
    # the connector's numeric destination and the fixture trust anchor differ.
    socket_api = SimpleNamespace(**{name: getattr(socket, name) for name in dir(socket)})
    socket_api.socket = RedirectedSocket
    socket_api.create_connection = create_connection
    monkeypatch.setattr(app_dns, 'socket', socket_api)
    monkeypatch.setattr(app_dns, '_tls_context', lambda: client_context)
    try:
        yield evidence
    finally:
        listener.close()
        thread.join(timeout=4)
        assert not thread.is_alive(), 'fixture HTTPS server did not stop'
        assert not evidence['errors'], evidence['errors']


@pytest.mark.parametrize('bounded', [False, True])
@pytest.mark.parametrize('case', [
    'success', 'chunked', 'wrong_id', 'truncated_http', 'truncated_dns',
    'dns_tc', 'http_error', 'wrong_type',
])
def test_direct_doh_real_tls_requires_complete_matching_response(monkeypatch, dns_tls, bounded, case):
    with local_doh(monkeypatch, dns_tls, case) as evidence:
        if bounded:
            result = app_dns._query_endpoint_bounded(
                '1.1.1.1', 'cloudflare-dns.com', 'fixture.example',
                time.monotonic() + 2, threading.Event())
        else:
            result = app_dns._query_endpoint(
                '1.1.1.1', 'cloudflare-dns.com', 'fixture.example', 2)
    assert result == (['8.8.4.4'] if case in {'success', 'chunked'} else [])
    assert evidence['connections'] == [('1.1.1.1', 443)]
    assert evidence['sni'] == ['cloudflare-dns.com']
    headers, query = evidence['requests'][0]
    assert headers.startswith(b'POST /dns-query HTTP/1.1\r\n')
    assert b'host: cloudflare-dns.com' in headers.lower()
    assert b'content-type: application/dns-message' in headers.lower()
    assert query[12:] == b'\x07fixture\x07example\x00\x00\x01\x00\x01'
