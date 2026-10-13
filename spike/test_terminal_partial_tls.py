"""An upstream close inside a TLS record must not look like completion."""
import asyncio
import pytest
import tproxy as t


@pytest.mark.parametrize('ending', ['eof', 'reset'])
@pytest.mark.parametrize('payload_size', [128, 20000])
def test_terminal_partial_record_enters_recovery(ending, payload_size):
    complete = b'\x17\x03\x03\x00\x08' + b'a' * 8
    # More than one full record exercises streams beyond low-byte heuristics.
    data = complete * (payload_size // 13 + 1) + b'\x17\x03\x03\x40\x00' + b'b' * 128
    activity, delivered = asyncio.run(run_relay(data, ending))
    assert delivered == data
    assert activity.server_ended_first
    assert activity.partial_tls_record_stalled
    assert t._local_stream_stalled(activity)


@pytest.mark.parametrize('ending', ['eof', 'reset'])
def test_complete_record_close_does_not_fabricate_partial_failure(ending):
    data = b'\x17\x03\x03\x00\x08' + b'a' * 8
    activity, delivered = asyncio.run(run_relay(data, ending))
    assert delivered == data
    assert not activity.partial_tls_record_stalled


def test_disabled_detector_does_not_change_other_routes():
    data = b'\x17\x03\x03\x00\x08' + b'a' * 8 + b'\x17\x03\x03\x40\x00' + b'b'
    activity, _ = asyncio.run(run_relay(data, 'eof', enabled=False))
    assert not activity.partial_tls_record_stalled


async def run_relay(data, ending, enabled=True):
    class BlockingReader:
        async def read(self, size):
            await asyncio.Event().wait()

    class Upstream:
        sent = False
        async def read(self, size):
            if not self.sent:
                self.sent = True
                return data
            if ending == 'reset':
                raise ConnectionResetError()
            return b''

    class Writer:
        def __init__(self):
            self.payload = bytearray()
        def write(self, data):
            self.payload.extend(data)
        async def drain(self):
            pass
        def close(self):
            pass
        async def wait_closed(self):
            pass

    output = Writer()
    activity = t._RelayActivity(last_downstream_at=t.time.monotonic())
    await asyncio.wait_for(t.relay_local_stream(
        BlockingReader(), Writer(), Upstream(), output, activity,
        detect_partial_tls_stall=enabled,
    ), timeout=1)
    return activity, bytes(output.payload)
