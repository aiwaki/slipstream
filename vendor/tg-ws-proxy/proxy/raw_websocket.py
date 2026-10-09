import os
import logging
import base64
import struct
import asyncio
import socket as _socket

from typing import List, Optional, Tuple
from .config import proxy_config
from .utils import create_ssl_context

log = logging.getLogger('tg-mtproto-proxy')
CLOSE_TIMEOUT = 1.0
MAX_UPGRADE_HEADERS = 64 * 1024


_st_BB = struct.Struct('>BB')
_st_BBH = struct.Struct('>BBH')
_st_BBQ = struct.Struct('>BBQ')
_st_BB4s = struct.Struct('>BB4s')
_st_BBH4s = struct.Struct('>BBH4s')
_st_BBQ4s = struct.Struct('>BBQ4s')
_st_H = struct.Struct('>H')
_st_Q = struct.Struct('>Q')

_ssl_ctx = create_ssl_context()
_ssl_ctx_fronting = create_ssl_context(check_hostname=False)


class WsHandshakeError(Exception):
    def __init__(self, status_code: int, status_line: str,
                 headers: Optional[dict] = None, location: Optional[str] = None):
        self.status_code = status_code
        self.status_line = status_line
        self.headers = headers or {}
        self.location = location
        super().__init__(f"HTTP {status_code}: {status_line}")

    @property
    def is_redirect(self) -> bool:
        return self.status_code in (301, 302, 303, 307, 308)


def _xor_mask(data: bytes, mask: bytes) -> bytes:
    if not data:
        return data
    n = len(data)
    mask_rep = (mask * (n // 4 + 1))[:n]
    return (int.from_bytes(data, 'big') ^
            int.from_bytes(mask_rep, 'big')).to_bytes(n, 'big')


def set_sock_opts(transport, buffer_size):
    sock = transport.get_extra_info('socket')
    if sock is None:
        return
    
    try:
        sock.setsockopt(_socket.IPPROTO_TCP, _socket.TCP_NODELAY, 1)
    except (OSError, AttributeError):
        pass
    
    try:
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_RCVBUF, buffer_size)
        sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_SNDBUF, buffer_size)
    except OSError:
        pass


async def close_writer(writer):
    """Release TCP even if TLS shutdown or a cancelled drain never finishes."""
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), CLOSE_TIMEOUT)
    except BaseException as exc:
        abort = getattr(writer.transport, 'abort', None)
        if abort is not None:
            abort()
        if not isinstance(exc, Exception):
            raise


class RawWebSocket:
    __slots__ = ('reader', 'writer', '_closed', '_fragmented', '_fragment_bytes')

    OP_CONT = 0x0
    MAX_MESSAGE_LEN = 16 * 1024 * 1024

    OP_BINARY = 0x2
    OP_CLOSE = 0x8
    OP_PING = 0x9
    OP_PONG = 0xA

    def __init__(self, reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self._closed = False
        self._fragmented = False
        self._fragment_bytes = 0

    @staticmethod
    async def connect(host: str, domain: str, timeout: float = 10.0,
                      path: str = '/apiws', *,
                      sni: Optional[str] = None, secure=True) -> 'RawWebSocket':
        ssl_context = _ssl_ctx_fronting if sni else _ssl_ctx
        if sni is None:
            sni = domain

        deadline = asyncio.get_running_loop().time() + timeout
        reader, writer = await asyncio.wait_for(
            (asyncio.open_connection(host, 443, ssl=ssl_context,
                                     server_hostname=sni) if secure
             else asyncio.open_connection(host, 80)),
            timeout=min(timeout, 10))
        
        try:
            set_sock_opts(writer.transport, proxy_config.buffer_size)

            ws_key = base64.b64encode(os.urandom(16)).decode()

            req = (
                f'GET {path} HTTP/1.1\r\n'
                f'Host: {domain}\r\n'
                f'Upgrade: websocket\r\n'
                f'Connection: Upgrade\r\n'
                f'Sec-WebSocket-Key: {ws_key}\r\n'
                f'Sec-WebSocket-Version: 13\r\n'
                f'Sec-WebSocket-Protocol: binary\r\n'
                f'\r\n'
            )

            writer.write(req.encode())
            await asyncio.wait_for(
                writer.drain(), max(0.0, deadline - asyncio.get_running_loop().time()))

            response_lines: list[str] = []
            header_bytes = 0
            while True:
                line = await asyncio.wait_for(
                    reader.readline(), max(0.0, deadline - asyncio.get_running_loop().time()))
                header_bytes += len(line)
                if header_bytes > MAX_UPGRADE_HEADERS:
                    raise WsHandshakeError(0, 'response headers too large')
                if not line:
                    raise WsHandshakeError(0, 'incomplete response headers')
                if line in (b'\r\n', b'\n'):
                    break
                response_lines.append(
                    line.decode('utf-8', errors='replace').strip())

            if not response_lines:
                raise WsHandshakeError(0, 'empty response')

            first_line = response_lines[0]
            parts = first_line.split(' ', 2)
            try:
                status_code = int(parts[1]) if len(parts) >= 2 else 0
            except ValueError:
                status_code = 0

            if status_code == 101:
                return RawWebSocket(reader, writer)

            headers: dict[str, str] = {}
            for hl in response_lines[1:]:
                if ':' in hl:
                    k, v = hl.split(':', 1)
                    headers[k.strip().lower()] = v.strip()

            raise WsHandshakeError(status_code, first_line, headers,
                                    location=headers.get('location'))

        except BaseException:
            await close_writer(writer)
            raise

    async def send(self, data: bytes):
        await self.send_batch([data])

    async def send_batch(self, parts: List[bytes]):
        if self._closed:
            raise ConnectionError("WebSocket closed")
        try:
            for part in parts:
                self.writer.write(
                    self._build_frame(self.OP_BINARY, part, mask=True))
            await self.writer.drain()
        except BaseException:
            # Includes the initial relay handshake before a bridge owns the
            # connection. A partial send cannot be safely replayed.
            self._closed = True
            await close_writer(self.writer)
            raise

    async def recv(self) -> Optional[bytes]:
        while not self._closed:
            fin, opcode, payload = await self._read_frame()

            if opcode == self.OP_CLOSE:
                self._closed = True
                code, reason = self._parse_close(payload)
                log.debug("WS OP_CLOSE from upstream: code=%s reason=%r",
                          code, reason)
                try:
                    self.writer.write(self._build_frame(
                        self.OP_CLOSE,
                        payload[:2] if payload else b'', mask=True))
                    await asyncio.wait_for(self.writer.drain(), CLOSE_TIMEOUT)
                except Exception:
                    pass
                return None

            if opcode == self.OP_PING:
                try:
                    self.writer.write(
                        self._build_frame(self.OP_PONG, payload, mask=True))
                    await self.writer.drain()
                except Exception:
                    pass
                continue

            if opcode == self.OP_PONG:
                continue

            if opcode in (0x1, 0x2):
                if self._fragmented:
                    raise ConnectionError("New WebSocket message before final continuation")
                self._fragment_bytes = len(payload)
                self._fragmented = not fin
                if payload:
                    return payload
                continue
            if opcode == 0x0:
                if not self._fragmented:
                    raise ConnectionError("Unexpected WebSocket continuation")
                self._fragment_bytes += len(payload)
                if self._fragment_bytes > self.MAX_MESSAGE_LEN:
                    raise ConnectionError("WebSocket message too large")
                self._fragmented = not fin
                # MTProto consumes a byte stream; preserve each fragment without
                # accumulating the whole WebSocket message in memory.
                if payload:
                    return payload
                continue
            raise ConnectionError("Unsupported WebSocket opcode")
        return None

    async def close(self):
        was_closed = self._closed
        self._closed = True
        try:
            if not was_closed:
                self.writer.write(
                    self._build_frame(self.OP_CLOSE, b'', mask=True))
                await asyncio.wait_for(self.writer.drain(), CLOSE_TIMEOUT)
        except Exception:
            pass
        finally:
            # Peer CLOSE and cancellation still require local TCP cleanup.
            await close_writer(self.writer)

    _WS_CLOSE_REASONS = {
        1000: 'normal', 1001: 'going_away', 1002: 'protocol_error',
        1003: 'unsupported_data', 1006: 'abnormal', 1007: 'bad_data',
        1008: 'policy_violation', 1009: 'too_big', 1010: 'missing_extension',
        1011: 'internal_error',
    }

    @classmethod
    def _parse_close(cls, payload: Optional[bytes]) -> Tuple[Optional[int], str]:
        if not payload or len(payload) < 2:
            return None, ''
        try:
            code = int.from_bytes(payload[:2], 'big')
            text = payload[2:].decode('utf-8', errors='replace')
            name = cls._WS_CLOSE_REASONS.get(code)
            return code, f"{text} ({name})" if name else text
        except Exception:
            return None, ''

    @staticmethod
    def _build_frame(opcode: int, data: bytes,
                     mask: bool = False) -> bytes:
        length = len(data)
        fb = 0x80 | opcode
        if not mask:
            if length < 126:
                return _st_BB.pack(fb, length) + data
            if length < 65536:
                return _st_BBH.pack(fb, 126, length) + data
            return _st_BBQ.pack(fb, 127, length) + data
        mask_key = os.urandom(4)
        masked = _xor_mask(data, mask_key)
        if length < 126:
            return _st_BB4s.pack(fb, 0x80 | length, mask_key) + masked
        if length < 65536:
            return _st_BBH4s.pack(fb, 0x80 | 126, length, mask_key) + masked
        return _st_BBQ4s.pack(fb, 0x80 | 127, length, mask_key) + masked

    async def _read_frame(self) -> Tuple[bool, int, bytes]:
        hdr = await self.reader.readexactly(2)
        fin = bool(hdr[0] & 0x80)
        opcode = hdr[0] & 0x0F
        length = hdr[1] & 0x7F
        if length == 126:
            length = _st_H.unpack(await self.reader.readexactly(2))[0]
        elif length == 127:
            length = _st_Q.unpack(await self.reader.readexactly(8))[0]
        if length > self.MAX_MESSAGE_LEN:
            raise ConnectionError(f"WS frame too large: {length} bytes")
        if hdr[1] & 0x80:
            mask_key = await self.reader.readexactly(4)
            payload = await self.reader.readexactly(length)
            return fin, opcode, _xor_mask(payload, mask_key)
        payload = await self.reader.readexactly(length)
        return fin, opcode, payload
