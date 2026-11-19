from __future__ import annotations

import io
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

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
    def test_automatic_retry_qualification_runs_without_extension(self) -> None:
        fixture = mock.Mock()
        snapshot = semantic.FixtureSnapshot(2, 1, 1, 1, 1)
        with (
            mock.patch.object(
                smoke.semantic,
                "SemanticHttpsFixture",
                return_value=fixture,
            ) as fixture_type,
            mock.patch.object(
                smoke.semantic,
                "_run_chrome",
                return_value=snapshot,
            ) as run_chrome,
            mock.patch.object(
                smoke.semantic,
                "_assert_fixture_complete",
            ) as assert_complete,
        ):
            result = smoke._qualify_automatic_original_navigation_retry(
                Path("/Applications/Google Chrome for Testing"),
                501,
                20,
            )

        fixture_type.assert_called_once_with(
            semantic.PENDING_NAVIGATION_FIXTURE_HOST,
            semantic.AUTOMATIC_RETRY_SCENARIO,
        )
        fixture.start.assert_called_once_with()
        run_chrome.assert_called_once_with(
            501,
            20,
            None,
            fixture,
            Path("/Applications/Google Chrome for Testing"),
            None,
            None,
            headless=True,
        )
        assert_complete.assert_called_once_with(
            snapshot,
            semantic.AUTOMATIC_RETRY_SCENARIO,
        )
        fixture.close.assert_called_once_with()
        self.assertFalse(result["browser_extension_loaded"])
        self.assertEqual(result["root_requests"], 2)
        self.assertEqual(result["ready_callbacks"], 1)

    def _exercise_webrequest_outer_cli(self, failure, *, cleanup_error=True, retry_case=False):
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            root = Path(temporary)
            fixture = mock.Mock(host=semantic.INCOMPLETE_FIXTURE_HOST)
            fixture.close.side_effect = semantic.QualificationError("outer cleanup refusal") if cleanup_error and not retry_case else None
            retry_fixture = mock.Mock(host=semantic.PENDING_NAVIGATION_FIXTURE_HOST)
            retry_fixture.close.side_effect = semantic.QualificationError("retry cleanup refusal") if cleanup_error else None
            for owner, name, value in (
                (semantic, "_require_disposable_ci", (501, 20)),
                (semantic, "_validate_chrome_for_testing", root / "chrome"),
                (semantic, "_validate_extension", root / "extension"),
                (semantic, "SemanticHttpsFixture", fixture),
                (smoke.tempfile, "mkdtemp", str(root)),
                (smoke.os, "chown", None),
                (smoke, "_write_owner_file", None),
                (smoke, "_copy_diagnostic_extension", root / "extension"),
                (smoke, "_read_trace", []),
            ):
                stack.enter_context(mock.patch.object(owner, name, return_value=value))
            if retry_case:
                stack.enter_context(mock.patch.object(semantic, "SemanticHttpsFixture", side_effect=(fixture, retry_fixture)))
                stack.enter_context(mock.patch.object(smoke, "_validate_signal", return_value={"schema_version": 2}))
                stack.enter_context(mock.patch.object(smoke, "_validate_headless_performance", return_value={}))
                chrome = stack.enter_context(mock.patch.object(semantic, "_run_chrome",
                    side_effect=(semantic.FixtureSnapshot(2, 1, 1, 1, 1), failure)))
            else:
                chrome = stack.enter_context(mock.patch.object(semantic, "_run_chrome", side_effect=failure))
                retry = stack.enter_context(mock.patch.object(smoke, "_qualify_automatic_original_navigation_retry"))
            removal = stack.enter_context(mock.patch.object(smoke.shutil, "rmtree"))
            output, errors = io.StringIO(), io.StringIO()
            with redirect_stdout(output), redirect_stderr(errors):
                status = smoke.main(["--chrome-executable", str(root / "chrome")])
            self.assertEqual(status, 1)
            self.assertEqual(output.getvalue(), "")
            self.assertEqual(chrome.call_count, 2 if retry_case else 1)
            fixture.start.assert_called_once_with()
            fixture.close.assert_called_once_with()
            removal.assert_called_once_with(root)
            if retry_case:
                retry_fixture.start.assert_called_once_with()
                retry_fixture.close.assert_called_once_with()
            else:
                retry.assert_not_called()
            return errors.getvalue()

    def test_webrequest_cli_preserves_liveness_through_outer_cleanup(self):
        import test_chromium_semantic_packaged_smoke as semantic_tests
        case = semantic_tests.ChromiumSemanticPackagedSmokeTests()
        for inner_cleanup in (False, True):
            with self.subTest(inner_cleanup=inner_cleanup):
                query = subprocess.CompletedProcess((), 113, "PRIVATE_QUERY_SENTINEL", "PRIVATE_STDERR_SENTINEL")
                _, failure, _ = case._exercise_liveness_observation(launch_pid=None, launch_query=query,
                                                                   cleanup_error=inner_cleanup)
                expected = case._liveness_detail(failure.__cause__ if inner_cleanup else failure)
                failure.args = (str(failure) + " PRIVATE_PRIMARY_SENTINEL https://private.invalid/",)
                output = self._exercise_webrequest_outer_cli(failure)
                self.assertIn("outer cleanup refusal", output)
                self.assertIn("; liveness=", output, "outer webRequest cleanup discarded liveness evidence")
                self.assertEqual(json.loads(output.split("; liveness=", 1)[1]), expected)
                self.assertEqual(output.count("; liveness="), 1)
                self.assertNotIn("PRIVATE", output)
                self.assertNotIn("https://", output)

    def test_webrequest_cli_liveness_without_outer_cleanup_is_not_duplicated(self):
        import test_chromium_semantic_packaged_smoke as semantic_tests
        case = semantic_tests.ChromiumSemanticPackagedSmokeTests()
        _, failure, _ = case._exercise_liveness_observation(launch_pid=None)
        expected = case._liveness_detail(failure)
        output = self._exercise_webrequest_outer_cli(failure, cleanup_error=False)
        self.assertEqual(json.loads(output.split("; liveness=", 1)[1].split("; sanitized webRequest trace:", 1)[0]), expected)
        self.assertEqual(output.count("; liveness="), 1)

    def test_webrequest_cli_cleanup_does_not_expand_an_untyped_cause(self):
        import test_chromium_semantic_packaged_smoke as semantic_tests
        case = semantic_tests.ChromiumSemanticPackagedSmokeTests()
        _, cause, _ = case._exercise_liveness_observation(launch_pid=None)
        failure = semantic.QualificationError("PRIVATE_PRIMARY_SENTINEL https://private.invalid/")
        failure.liveness_json = "PRIVATE_ATTRIBUTE_SENTINEL"
        failure.__cause__ = cause
        output = self._exercise_webrequest_outer_cli(failure)
        self.assertIn("outer cleanup refusal", output)
        self.assertNotIn("; liveness=", output)
        self.assertNotIn("PRIVATE", output)
        self.assertNotIn("https://", output)

    def test_webrequest_retry_cli_preserves_liveness_when_close_also_fails(self):
        import test_chromium_semantic_packaged_smoke as semantic_tests
        case = semantic_tests.ChromiumSemanticPackagedSmokeTests()
        for inner_cleanup in (False, True):
            with self.subTest(inner_cleanup=inner_cleanup):
                _, failure, _ = case._exercise_liveness_observation(launch_pid=None, cleanup_error=inner_cleanup)
                expected = case._liveness_detail(failure.__cause__ if inner_cleanup else failure)
                failure.args = (str(failure) + " PRIVATE_PRIMARY_SENTINEL https://private.invalid/",)
                output = self._exercise_webrequest_outer_cli(failure, retry_case=True)
                self.assertIn("retry cleanup refusal", output)
                self.assertIn("; liveness=", output, "automatic retry cleanup discarded liveness evidence")
                self.assertEqual(json.loads(output.split("; liveness=", 1)[1]), expected)
                self.assertEqual(output.count("; liveness="), 1)
                self.assertNotIn("PRIVATE", output)
                self.assertNotIn("https://", output)

    def test_automatic_retry_cleanup_keeps_untyped_exception_identity(self):
        for primary in (None, semantic.QualificationError("PRIVATE_PRIMARY_SENTINEL")):
            for cleanup in (OSError("cleanup refusal"), KeyboardInterrupt("cleanup interrupt")):
                with self.subTest(primary=type(primary).__name__, cleanup=type(cleanup).__name__):
                    fixture = mock.Mock()
                    fixture.close.side_effect = cleanup
                    with mock.patch.object(semantic, "SemanticHttpsFixture", return_value=fixture), \
                            mock.patch.object(semantic, "_run_chrome", side_effect=primary,
                                              return_value=semantic.FixtureSnapshot(2, 1, 1, 1, 1)):
                        with self.assertRaises(type(cleanup)) as raised:
                            smoke._qualify_automatic_original_navigation_retry(Path("/fixture/chrome"), 501, 20)
                    self.assertIs(raised.exception, cleanup)
                    fixture.close.assert_called_once_with()

    def test_native_stub_manifest_is_complete_and_exact(self) -> None:
        stub_path = Path("/tmp/native-stub")
        self.assertEqual(
            smoke._native_stub_manifest(stub_path),
            {
                "allowed_origins": [semantic.NATIVE_HOST_ORIGIN],
                "description": "Slipstream Browser Companion Qualification",
                "name": semantic.NATIVE_HOST_NAME,
                "path": str(stub_path),
                "type": "stdio",
            },
        )

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
        self.assertNotIn("qualification_warmup", worker)
        self.assertNotIn("url:", worker)
        self.assertNotIn("host,", worker)

    def test_diagnostic_extension_only_appends_the_fixture_observer(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            destination = root / "destination"
            source.mkdir()
            (source / "service-worker.js").write_text(
                (
                    'const NATIVE_HOST = "dev.slipstream.semantic";\n'
                    "globalThis.__slipstreamWorkerReadyV1 = true;\n"
                ),
                encoding="utf-8",
            )
            smoke._copy_diagnostic_extension(
                source,
                destination,
                host="example.net",
                uid=os.getuid(),
                gid=os.getgid(),
            )

            worker = (destination / "service-worker.js").read_text(
                encoding="utf-8"
            )
            self.assertIn('const NATIVE_HOST = "dev.slipstream.semantic"', worker)
            self.assertIn("slipstreamCiWebRequestTrace", worker)
            self.assertLess(
                worker.index("slipstreamCiWebRequestTrace"),
                worker.index("globalThis.__slipstreamWorkerReadyV1 = true"),
            )
            self.assertFalse(
                (destination / "qualification-warmup.html").exists()
            )
            self.assertFalse(
                (destination / "qualification-warmup.js").exists()
            )
            self.assertEqual(
                (destination / "service-worker.js").stat().st_mode
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

    def test_headless_performance_requires_bounded_launch_and_memory(self) -> None:
        metrics = {
            "launch_to_worker_ready_ms": 1_200,
            "launch_to_semantic_ready_ms": 1_800,
            "physical_footprint_kib": 180_000,
            "peak_rss_kib": 245_000,
            "rss_samples": 3,
        }
        result = smoke._validate_headless_performance(metrics)
        self.assertEqual(result["launch_to_worker_ready_ms"], 1_200)
        self.assertEqual(result["launch_to_semantic_ready_ms"], 1_800)
        self.assertEqual(result["physical_footprint_kib"], 180_000)
        self.assertEqual(result["peak_aggregate_rss_kib"], 245_000)
        self.assertEqual(
            result["physical_footprint_budget_kib"],
            smoke.HEADLESS_PHYSICAL_FOOTPRINT_BUDGET_KIB,
        )

    def test_headless_performance_rejects_missing_samples_and_overruns(
        self,
    ) -> None:
        baseline = {
            "launch_to_worker_ready_ms": 1_200,
            "launch_to_semantic_ready_ms": 1_800,
            "physical_footprint_kib": 180_000,
            "peak_rss_kib": 245_000,
            "rss_samples": 3,
        }
        for key, value in (
            ("rss_samples", 1),
            (
                "launch_to_worker_ready_ms",
                smoke.HEADLESS_WORKER_READY_BUDGET_MS + 1,
            ),
            (
                "launch_to_semantic_ready_ms",
                smoke.HEADLESS_SEMANTIC_READY_BUDGET_MS + 1,
            ),
            (
                "physical_footprint_kib",
                smoke.HEADLESS_PHYSICAL_FOOTPRINT_BUDGET_KIB + 1,
            ),
        ):
            with self.subTest(key=key), self.assertRaises(
                semantic.QualificationError
            ):
                smoke._validate_headless_performance(
                    {**baseline, key: value}
                )


if __name__ == "__main__":
    unittest.main()
