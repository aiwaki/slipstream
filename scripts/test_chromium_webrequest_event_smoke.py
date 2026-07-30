from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import chromium_semantic_packaged_smoke as semantic
import chromium_webrequest_event_smoke as smoke


def _signal_payload() -> dict[str, object]:
    return {
        "category": "incomplete_response",
        "confidence_bps": 10_000,
        "host": semantic.INCOMPLETE_FIXTURE_HOST,
        "observed_at_unix_ms": 1_722_345_678_901,
        "schema_version": 2,
        "signal_id": "0123456789abcdef0123456789abcdef",
        "source": "browser_extension",
        "top_level": True,
    }


class ChromiumWebRequestEventSmokeTests(unittest.TestCase):
    def test_native_stub_uses_chromium_framing_and_records_exact_signal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            signal_path = root / "signal.json"
            trace_path = root / "trace.jsonl"
            trace_path.write_bytes(b"")
            trace_path.chmod(0o600)
            stub_path = root / "native-stub.py"
            stub_path.write_bytes(
                smoke._native_stub_source(signal_path, trace_path)
            )
            payload = json.dumps(
                _signal_payload(),
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            completed = subprocess.run(
                [sys.executable, str(stub_path)],
                input=struct.pack("<I", len(payload)) + payload,
                check=True,
                capture_output=True,
            )

            response_size = struct.unpack("<I", completed.stdout[:4])[0]
            response = json.loads(completed.stdout[4:].decode("utf-8"))
            self.assertEqual(response_size, len(completed.stdout) - 4)
            self.assertEqual(
                response,
                {
                    "accepted": True,
                    "action": "confirm_exact_host_geo_exit",
                    "schema_version": 1,
                },
            )
            self.assertEqual(
                json.loads(signal_path.read_text(encoding="utf-8")),
                _signal_payload(),
            )
            self.assertEqual(trace_path.read_bytes(), b"")

    def test_native_stub_records_ci_trace_without_accepting_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            signal_path = root / "signal.json"
            trace_path = root / "trace.jsonl"
            trace_path.write_bytes(b"")
            trace_path.chmod(0o600)
            stub_path = root / "native-stub.py"
            stub_path.write_bytes(
                smoke._native_stub_source(signal_path, trace_path)
            )
            payload = json.dumps(
                {
                    "schema_version": 0,
                    "source": "ci_webrequest_trace",
                    "phase": "before_request",
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            completed = subprocess.run(
                [sys.executable, str(stub_path)],
                input=struct.pack("<I", len(payload)) + payload,
                check=True,
                capture_output=True,
            )

            response = json.loads(completed.stdout[4:].decode("utf-8"))
            self.assertEqual(
                response,
                {
                    "accepted": False,
                    "action": "none",
                    "schema_version": 1,
                },
            )
            self.assertFalse(signal_path.exists())
            self.assertEqual(
                smoke._read_trace(trace_path, os.getuid()),
                [
                    {
                        "schema_version": 0,
                        "source": "ci_webrequest_trace",
                        "phase": "before_request",
                    }
                ],
            )

    def test_diagnostic_worker_is_fixture_scoped_and_sanitized(self) -> None:
        worker = smoke._diagnostic_worker_source(
            semantic.INCOMPLETE_FIXTURE_HOST
        ).decode("utf-8")
        self.assertIn(semantic.INCOMPLETE_FIXTURE_HOST, worker)
        self.assertIn('"before_request"', worker)
        self.assertIn('"headers_received"', worker)
        self.assertIn('"completed"', worker)
        self.assertIn('"error"', worker)
        self.assertIn('"slipstream.qualification_warmup"', worker)
        self.assertIn('"ci_worker_ready"', worker)
        self.assertIn('"worker_ready"', worker)
        self.assertNotIn("url:", worker)
        self.assertNotIn("host,", worker)

    def test_diagnostic_extension_warms_worker_before_fixture_navigation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            destination = root / "destination"
            source.mkdir()
            (source / "service-worker.js").write_text(
                'const NATIVE_HOST = "dev.slipstream.semantic";\n',
                encoding="utf-8",
            )
            target = "https://example.net:443/?slipstream-webrequest=1"
            smoke._copy_diagnostic_extension(
                source,
                destination,
                host="example.net",
                target_url=target,
                uid=os.getuid(),
                gid=os.getgid(),
            )

            warmup = (destination / "qualification-warmup.js").read_text(
                encoding="utf-8"
            )
            self.assertIn("chrome.runtime.sendMessage", warmup)
            self.assertIn("response?.ready === true", warmup)
            self.assertIn("location.replace(target)", warmup)
            self.assertIn("const maxAttempts = 40", warmup)
            self.assertIn("setTimeout(warmWorker, 250)", warmup)
            self.assertIn(target, warmup)
            self.assertEqual(
                (destination / "qualification-warmup.js").stat().st_mode
                & 0o777,
                0o600,
            )

    def test_validate_signal_accepts_only_the_privacy_bounded_v2_contract(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            signal_path = Path(temporary) / "signal.json"
            signal_path.write_text(
                json.dumps(_signal_payload(), sort_keys=True),
                encoding="utf-8",
            )
            signal_path.chmod(0o600)
            self.assertEqual(
                smoke._validate_signal(signal_path, os.getuid()),
                _signal_payload(),
            )

    def test_validate_signal_rejects_expanded_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            signal_path = Path(temporary) / "signal.json"
            payload = _signal_payload()
            payload["url"] = "https://fixture.invalid/private"
            signal_path.write_text(json.dumps(payload), encoding="utf-8")
            signal_path.chmod(0o600)
            with self.assertRaisesRegex(
                semantic.QualificationError,
                "expanded signal",
            ):
                smoke._validate_signal(signal_path, os.getuid())


if __name__ == "__main__":
    unittest.main()
