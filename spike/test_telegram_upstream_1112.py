"""Local protocol regressions for the tg-ws-proxy 1.11.2 integration."""
import asyncio
import importlib
import struct
import time

import httpx
import pytest

from test_telegram_h2_transport import local_h2, run_scenario, tls_contexts

cf = importlib.import_module('slipstream_tg_vendor.cf_h2')
bridge = importlib.import_module('slipstream_tg_vendor.bridge')
raw = importlib.import_module('slipstream_tg_vendor.raw_websocket')
utils = importlib.import_module('slipstream_tg_vendor.utils')


@pytest.mark.parametrize('length', [0, 1, 511, 512, 513, 65535, 65536, 65537])
def test_mask_fast_path_preserves_wire_bytes(length):
    data = (bytes(range(256)) * (length // 256 + 1))[:length]
    mask = b'\x01\x7f\x80\xff'
    expected = bytes(value ^ mask[i % 4] for i, value in enumerate(data))
    assert raw._xor_mask(data, mask) == expected
    assert raw._xor_mask(expected, mask) == data


@pytest.mark.parametrize('proto', [utils.PROTO_ABRIDGED_INT,
                                  utils.PROTO_INTERMEDIATE_INT,
                                  utils.PROTO_PADDED_INTERMEDIATE_INT])
def test_splitter_preserves_ciphertext_across_headers_and_incomplete_tail(proto):
    def frame(payload):
        size = len(payload)
        if proto == utils.PROTO_ABRIDGED_INT:
            words = size // 4
            return (bytes([words]) if words < 127 else b'\x7f' + words.to_bytes(3, 'little')) + payload
        return struct.pack('<I', size) + payload

    first = bytearray(frame(b'p' * 65536))
    first[0 if proto == utils.PROTO_ABRIDGED_INT else 3] |= 0x80
    packets = [bytes(first), frame(b't' * 8), frame(b'x' * 32)[:6]]
    plain = b''.join(packets)
    # Distinct wire bytes prove plaintext is used only for boundaries.
    wire = bytes(value ^ 0xA5 for value in plain)
    splitter = bridge.MsgSplitter(proto)
    parts, offset = [], 0
    for count in [1, 1, 1, 17, 65500, len(plain)]:
        end = min(offset + count, len(plain))
        parts.extend(splitter.split(wire[offset:end], plain[offset:end]))
        offset = end
    parts.extend(splitter.flush())
    assert parts == [bytes(value ^ 0xA5 for value in packet) for packet in packets]
    assert splitter.flush() == []


class IdentityCipher:
    def update(self, data):
        return data


async def read_padded(body, padding):
    reader = asyncio.StreamReader()
    wire = body + b'z' * padding
    reader.feed_data(struct.pack('<I', len(wire) | 0x80000000) + wire)
    reader.feed_eof()
    return await cf._read_packet(reader, IdentityCipher(), utils.PROTO_TAG_SECURE)


def test_plaintext_padding_accepts_every_supported_length():
    async def scenario():
        body = b'\x00' * 8 + b'm' * 8 + struct.pack('<I', 20) + b'p' * 20
        for padding in range(257):
            decoded, quick = await read_padded(body, padding)
            assert decoded == body and quick
    run_scenario(scenario())


@pytest.mark.parametrize('declared,payload,padding', [
    (0, 20, 0), (24, 20, 0), (21, 21, 0), (20, 20, 257), (0xffffffff, 20, 0),
])
def test_plaintext_padding_rejects_invalid_lengths(declared, payload, padding):
    async def scenario():
        body = b'\x00' * 8 + b'm' * 8 + struct.pack('<I', declared) + b'p' * payload
        with pytest.raises(ValueError):
            await read_padded(body, padding)
    run_scenario(scenario())


def test_extended_padding_does_not_relax_decoded_packet_limit(monkeypatch):
    async def scenario():
        body = b'\x00' * 8 + b'm' * 8 + struct.pack('<I', 20) + b'p' * 20
        monkeypatch.setattr(cf, 'MAX_PACKET', len(body))
        assert (await read_padded(body, 256))[0] == body
        oversized = body[:16] + struct.pack('<I', 24) + b'p' * 24
        for value in [oversized, b'k' * 8 + b'm' * 16 + b'c' * 32]:
            with pytest.raises(ValueError):
                await read_padded(value, 0)
    run_scenario(scenario())


def test_last_stalled_h2_stream_reconnects_without_losing_ended_reply(tls_contexts):
    async def scenario():
        async with local_h2(tls_contexts) as (client, transport, peer):
            saved = await client.send(client.build_request('GET', '/buffered'), stream=True)
            old = transport.connection
            stream = old.streams[saved.extensions['stream_id']]
            while not stream.ended:
                stream.changed.clear()
                if not stream.ended:
                    await stream.wait()
            with pytest.raises(httpx.ReadTimeout):
                await client.get('/pending', timeout=.05)
            assert old.error is not None and old.writer.is_closing()
            assert await saved.aread() == b'/buffered'
            await saved.aclose()
            assert (await client.get('/healthy')).content == b'/healthy'
            assert transport.connection is not old and peer.connections == 2
            assert not old.streams and not transport.connection.streams
    run_scenario(scenario())


def test_h2_batches_large_parallel_uploads_and_replies_exactly(tls_contexts):
    async def scenario():
        async with local_h2(tls_contexts) as (client, transport, peer):
            payloads = [bytes([index]) * (1024 * 1024 + index) for index in range(4)]
            responses = await asyncio.gather(*(
                client.post('/echo/' + str(index), content=payload)
                for index, payload in enumerate(payloads)))
            assert [response.content for response in responses] == payloads
            assert peer.connections == 1 and not transport.connection.streams
    run_scenario(scenario())


def test_reply_identity_refreshes_budget_but_keeps_backoff_and_max_age(monkeypatch):
    async def scenario():
        lane = cf._HttpLane('fixture.invalid', 1)
        await lane.client.aclose()
        reply = b'r' * 40

        async def handler(request):
            return httpx.Response(200, content=reply, extensions={'http_version': b'HTTP/2'})

        lane.client = httpx.AsyncClient(transport=httpx.MockTransport(handler), trust_env=False)
        channel = cf._HttpChannel(lane, 1, 'budget-fixture')
        try:
            body = b'samekey!' + b'a' * 32
            await channel.send(body, False)
            assert await channel.receive() == reply
            await asyncio.gather(*list(channel.pending))
            entry = channel.replay_history[-1]
            for value, expected in [(reply, 2), (b's' * 40, 0)]:
                reply = value
                now = time.monotonic()
                entry.sent_at = now
                entry.last_attempt_at = now - cf.REPLAY_RETRY_SECONDS - 1
                entry.attempts = 1
                channel.last_progress = now - cf.REPLAY_IDLE_SECONDS - 1
                assert await channel.send(body, False, replay=True)
                assert await channel.receive() == reply
                await asyncio.gather(*list(channel.pending))
                assert entry.attempts == expected and entry.replayed
                assert channel._replay_blocker(entry, entry.last_attempt_at) == 'backoff-or-progress'
                assert channel._replay_blocker(entry, entry.sent_at + cf.REPLAY_MAX_AGE + 1) == 'expired'
            assert not channel.pending and lane.inflight == 0
        finally:
            await lane.close()
    run_scenario(scenario())
