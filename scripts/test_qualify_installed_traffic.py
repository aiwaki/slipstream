import contextlib
import io
import json
from pathlib import Path
import random
import struct
import subprocess
import unittest
from unittest.mock import patch
import zlib

import qualify_installed_traffic as traffic
import verify_macos_app_bundle as verifier


def png(large=True):
    def chunk(kind, data):
        return struct.pack('!I', len(data)) + kind + data + struct.pack('!I', zlib.crc32(kind + data))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('!IIBBBBB', 1, 1, 8, 6, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(random.Random(0).randbytes(traffic.MIN_BYTES) if large else b'\x00\x00\x00\x00\xff')) + chunk(b'IEND', b''))


class TrafficTests(unittest.TestCase):
    def test_rejects_truncation_corruption_and_trailing_bytes(self):
        body = png()
        self.assertTrue(traffic.complete_png(body))
        for bad in (body[:12], body[:-1], body[:-12], body + b'x', body[:40] + b'x' + body[41:]):
            self.assertFalse(traffic.complete_png(bad))

    def test_valid_small_placeholder_does_not_qualify_large_response(self):
        body = png(large=False)
        self.assertTrue(traffic.complete_png(body))
        def runner(command, **kwargs):
            Path(command[command.index('--output') + 1]).write_bytes(body)
            return subprocess.CompletedProcess(command, 0, '200', '')
        self.assertEqual(traffic.qualify(runner)['status'], 'fail')

    def test_full_body_does_not_override_failed_transport(self):
        def runner(command, **kwargs):
            Path(command[command.index('--output') + 1]).write_bytes(png())
            return subprocess.CompletedProcess(command, 28, '200', 'timeout')
        self.assertFalse(traffic.probe('proxy_ipv4', runner)['pass'])

    def test_ipv6_failure_prevents_overall_success(self):
        def runner(command, **kwargs):
            self.assertEqual(command[:2], ['/usr/bin/curl', '-q'])
            self.assertEqual(kwargs['timeout'], 12)
            Path(command[command.index('--output') + 1]).write_bytes(png())
            return subprocess.CompletedProcess(command, 7 if 'http://[::1]:1080' in command else 0, '200', '')
        report = traffic.qualify(runner)
        self.assertEqual(report['status'], 'fail')
        self.assertEqual(sum(item['pass'] for item in report['results']), 2)

    def test_alternate_host_requires_its_own_complete_payload_on_every_route(self):
        def runner(command, **kwargs):
            primary = command[-1] == traffic.URL
            Path(command[command.index('--output') + 1]).write_bytes(png()[:-12] if primary else png())
            return subprocess.CompletedProcess(command, 0, '200', '')
        report = traffic.qualify(runner)
        self.assertEqual(report['status'], 'pass')
        for result in report['results']:
            self.assertEqual(result['url'], traffic.URLS[1])
            self.assertEqual(len(result['attempts']), 2)
            self.assertFalse(result['attempts'][0]['pass'])

    def test_green_identity_cannot_hide_failed_payload(self):
        output = io.StringIO()
        with patch.object(verifier, 'verify_app_bundle', return_value={}), \
             patch.object(verifier, 'verify_installed_app', return_value={'attestation': {'launchd_pid': 123}}), \
             patch.object(verifier, 'qualify_traffic', return_value={'status': 'fail'}), \
             patch.object(verifier, 'verify_status_v2') as status, contextlib.redirect_stdout(output):
            code = verifier.main(['--app-bundle', '/tmp/app', '--installed-app', '/tmp/app', '--qualify-traffic'])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.getvalue())['overall'], 'fail')
        self.assertEqual(status.call_args.kwargs['expected_pid'], 123)

    def test_daemon_change_invalidates_payload_proof(self):
        with patch.object(verifier, 'verify_app_bundle', return_value={}), \
             patch.object(verifier, 'verify_installed_app', return_value={'attestation': {'launchd_pid': 123}}), \
             patch.object(verifier, 'qualify_traffic', return_value={'status': 'pass'}), \
             patch.object(verifier, 'verify_status_v2', side_effect=verifier.VerificationError('PID changed')):
            with self.assertRaisesRegex(verifier.VerificationError, 'PID changed'):
                verifier.main(['--app-bundle', '/tmp/app', '--installed-app', '/tmp/app', '--qualify-traffic'])
