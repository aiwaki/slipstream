from __future__ import annotations

import http.client
import io
import json
import os
import ssl
import struct
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import chromium_semantic_packaged_smoke as smoke


ROOT = Path(__file__).resolve().parents[1]


def _fake_chrome_for_testing(root: Path) -> Path:
    bundle = root / "Google Chrome for Testing.app"
    executable = bundle / "Contents" / "MacOS" / "Google Chrome for Testing"
    executable.parent.mkdir(parents=True)
    executable.write_text("binary", encoding="utf-8")
    executable.chmod(0o700)
    (bundle / "Contents" / "Info.plist").write_text("plist", encoding="utf-8")
    return executable


def _fake_extensionless_chrome_for_testing(root: Path) -> Path:
    bundle = root / "arm64"
    executable = bundle / "Contents" / "MacOS" / "Google Chrome for Testing"
    executable.parent.mkdir(parents=True)
    executable.write_text("binary", encoding="utf-8")
    executable.chmod(0o700)
    (bundle / "Contents" / "Info.plist").write_text("plist", encoding="utf-8")
    return executable


class ChromiumSemanticPackagedSmokeTests(unittest.TestCase):
    @staticmethod
    def _pending_navigation_signal(host: str) -> dict[str, object]:
        return {
            "category": smoke.PENDING_NAVIGATION_SCENARIO,
            "confidence_bps": smoke.PENDING_NAVIGATION_CONFIDENCE_BPS,
            "host": host,
            "observed_at_unix_ms": (
                1_000_000 + smoke.PENDING_NAVIGATION_MIN_DELAY_MS
            ),
            "request_started_at_unix_ms": 1_000_000,
            "schema_version": 3,
            "signal_id": "0123456789abcdef0123456789abcdef",
            "source": "browser_extension",
            "top_level": True,
        }

    def test_extension_validator_accepts_the_reviewed_webrequest_manifest(self) -> None:
        extension = ROOT / "browser-companion" / "chromium"
        self.assertEqual(smoke._validate_extension(extension), extension.resolve())

    def test_disposable_guard_requires_root_macos_and_original_user(self) -> None:
        environment = {
            "CI": "true",
            "GITHUB_ACTIONS": "true",
            "SLIPSTREAM_DISPOSABLE_CI": "1",
            "SUDO_UID": "501",
            "SUDO_GID": "20",
        }
        with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(
            smoke.sys, "platform", "darwin"
        ), mock.patch("os.geteuid", return_value=0):
            self.assertEqual(smoke._require_disposable_ci(), (501, 20))

        with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(
            smoke.sys, "platform", "darwin"
        ), mock.patch("os.geteuid", return_value=501):
            with self.assertRaisesRegex(smoke.QualificationError, "requires sudo"):
                smoke._require_disposable_ci()

        invalid = dict(environment)
        invalid["SUDO_UID"] = "0"
        with mock.patch.dict(os.environ, invalid, clear=True), mock.patch.object(
            smoke.sys, "platform", "darwin"
        ), mock.patch("os.geteuid", return_value=0):
            with self.assertRaisesRegex(smoke.QualificationError, "non-root"):
                smoke._require_disposable_ci()

    def test_fixture_transitions_once_then_requires_all_styled_assets(self) -> None:
        status, content_type, denial = smoke._fixture_response("/", root_visit=1)
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "text/html; charset=utf-8")
        self.assertIn(b"no longer available in your area", denial)

        _, _, success = smoke._fixture_response("/", root_visit=2)
        self.assertIn(b"/style.css", success)
        self.assertIn(b"/app.js", success)
        self.assertIn(b"/proof.svg", success)

        _, _, script = smoke._fixture_response("/app.js", root_visit=2)
        self.assertIn(smoke.STYLED_MARKER.encode(), script)
        self.assertIn(b"fetch('/ready'", script)
        ready_status, _, ready = smoke._fixture_response("/ready", root_visit=2)
        self.assertEqual((ready_status, ready), (204, b""))
        smoke._assert_fixture_complete(
            smoke.FixtureSnapshot(2, 1, 1, 1, 1)
        )
        with self.assertRaisesRegex(smoke.QualificationError, "exactly once"):
            smoke._assert_fixture_complete(
                smoke.FixtureSnapshot(3, 1, 1, 1, 1)
            )
        with self.assertRaisesRegex(smoke.QualificationError, "mandatory resource"):
            smoke._assert_fixture_complete(
                smoke.FixtureSnapshot(2, 1, 0, 1, 1)
            )
        with self.assertRaisesRegex(smoke.QualificationError, "ready callback"):
            smoke._assert_fixture_complete(
                smoke.FixtureSnapshot(2, 1, 1, 1, 0)
            )

    def test_incomplete_fixture_declares_more_bytes_only_on_first_root(self) -> None:
        _, _, incomplete = smoke._fixture_response(
            "/",
            root_visit=1,
            scenario=smoke.INCOMPLETE_RESPONSE_SCENARIO,
        )
        self.assertNotIn(b"no longer available in your area", incomplete)
        self.assertEqual(
            smoke._fixture_content_length(
                "/",
                root_visit=1,
                scenario=smoke.INCOMPLETE_RESPONSE_SCENARIO,
                body=incomplete,
            ),
            len(incomplete) + 4096,
        )

        _, _, success = smoke._fixture_response(
            "/",
            root_visit=2,
            scenario=smoke.INCOMPLETE_RESPONSE_SCENARIO,
        )
        self.assertEqual(
            smoke._fixture_content_length(
                "/",
                root_visit=2,
                scenario=smoke.INCOMPLETE_RESPONSE_SCENARIO,
                body=success,
            ),
            len(success),
        )

    def test_incomplete_fixture_closes_keep_alive_connection_after_partial_body(
        self,
    ) -> None:
        fixture = smoke.SemanticHttpsFixture(
            smoke.INCOMPLETE_FIXTURE_HOST,
            smoke.INCOMPLETE_RESPONSE_SCENARIO,
        )
        connection: http.client.HTTPSConnection | None = None
        try:
            fixture.start()
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            connection = http.client.HTTPSConnection(
                "127.0.0.1",
                fixture.port,
                timeout=1.0,
                context=context,
            )
            connection.request(
                "GET",
                "/",
                headers={
                    "Connection": "keep-alive",
                    "Host": fixture.host,
                },
            )
            response = connection.getresponse()
            with self.assertRaises(http.client.IncompleteRead) as raised:
                response.read()

            _, _, expected = smoke._fixture_response(
                "/",
                root_visit=1,
                scenario=smoke.INCOMPLETE_RESPONSE_SCENARIO,
            )
            self.assertEqual(raised.exception.partial, expected)
        finally:
            if connection is not None:
                connection.close()
            fixture.close()

    def test_pending_navigation_signal_is_strict_and_privacy_bounded(self) -> None:
        payload = self._pending_navigation_signal(
            smoke.PENDING_NAVIGATION_FIXTURE_HOST
        )
        smoke._validate_pending_navigation_signal(
            payload,
            smoke.PENDING_NAVIGATION_FIXTURE_HOST,
        )
        payload["url"] = "https://example.edu/private?token=secret"
        with self.assertRaisesRegex(smoke.QualificationError, "non-contract"):
            smoke._validate_pending_navigation_signal(
                payload,
                smoke.PENDING_NAVIGATION_FIXTURE_HOST,
            )

    def test_pending_navigation_tap_is_owner_private_and_exact_origin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            profile = root / "profile"
            home.mkdir()
            profile.mkdir()
            target = profile / "packaged-native-host"
            target.write_text(
                "#!/usr/bin/python3\n"
                "import sys\n"
                "sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
                encoding="utf-8",
            )
            target.chmod(0o700)
            tap = smoke._create_pending_navigation_tap(
                home,
                profile,
                os.getuid(),
                os.getgid(),
                target,
            )
            manifest = json.loads(tap.manifest.read_text(encoding="utf-8"))
            self.assertTrue(smoke._is_exact_native_host(manifest, tap.executable))
            self.assertEqual(
                manifest["description"], smoke.NATIVE_HOST_DESCRIPTION
            )
            missing_description = dict(manifest)
            missing_description.pop("description")
            self.assertFalse(
                smoke._is_exact_native_host(
                    missing_description,
                    tap.executable,
                )
            )
            self.assertFalse(tap.executable.is_relative_to(profile))
            self.assertTrue(tap.executable.is_relative_to(home))
            self.assertEqual(tap.runtime_directory.stat().st_mode & 0o777, 0o700)
            self.assertEqual(tap.executable.stat().st_mode & 0o777, 0o700)
            self.assertEqual(tap.manifest.stat().st_mode & 0o777, 0o600)
            self.assertGreaterEqual(len(tap.created_directories), 1)
            self.assertIs(tap.created_directories[-1], tap.runtime_directory)
            compile(
                tap.executable.read_text(encoding="utf-8"),
                str(tap.executable),
                "exec",
            )
            ready_body = json.dumps(
                {
                    "phase": "native_ready",
                    "schema_version": 0,
                    "source": "qualification_worker_ready",
                },
                sort_keys=True,
            ).encode("utf-8")
            ready_frame = struct.pack("=I", len(ready_body)) + ready_body
            ready = subprocess.run(
                (str(tap.executable),),
                input=ready_frame,
                capture_output=True,
                check=True,
            )
            self.assertEqual(ready.stdout, ready_frame)
            self.assertFalse(tap.capture.exists())
            self.assertEqual(
                json.loads(tap.status.read_text(encoding="utf-8"))["stage"],
                "response_forwarded",
            )

            body = json.dumps(
                self._pending_navigation_signal(
                    smoke.PENDING_NAVIGATION_FIXTURE_HOST
                ),
                sort_keys=True,
            ).encode("utf-8")
            framed = struct.pack("=I", len(body)) + body
            forwarded = subprocess.run(
                (str(tap.executable),),
                input=framed,
                capture_output=True,
                check=True,
            )
            self.assertEqual(forwarded.stdout, framed)
            self.assertEqual(tap.capture.read_bytes(), body)
            self.assertEqual(
                json.loads(tap.status.read_text(encoding="utf-8"))["stage"],
                "ack_published",
            )
            runtime_directory = tap.runtime_directory
            smoke._remove_native_message_tap(tap, os.getuid())
            smoke._remove_native_message_tap(tap, os.getuid())
            self.assertFalse(runtime_directory.exists())
            self.assertTrue(profile.exists())

    def test_pending_navigation_tap_marks_launch_before_reading_stdin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            profile = root / "profile"
            home.mkdir()
            profile.mkdir()
            target = profile / "unused-native-host"
            target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            target.chmod(0o700)
            tap = smoke._create_pending_navigation_tap(
                home,
                profile,
                os.getuid(),
                os.getgid(),
                target,
            )
            launched = subprocess.run(
                (str(tap.executable),),
                input=b"",
                capture_output=True,
                check=False,
            )
            self.assertEqual(launched.returncode, 2)
            self.assertEqual(
                json.loads(tap.status.read_text(encoding="utf-8")),
                {
                    "argv_count": 0,
                    "attempts": 1,
                    "stage": "host_started",
                    "stage_rank": 0,
                },
            )

    def test_pending_navigation_tap_status_never_regresses_across_attempts(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            profile = root / "profile"
            home.mkdir()
            profile.mkdir()
            target = profile / "echo-native-host"
            target.write_text(
                "#!/usr/bin/python3\n"
                "import sys\n"
                "sys.stdout.buffer.write(sys.stdin.buffer.read())\n",
                encoding="utf-8",
            )
            target.chmod(0o700)
            tap = smoke._create_pending_navigation_tap(
                home,
                profile,
                os.getuid(),
                os.getgid(),
                target,
            )
            body = b'{"source":"qualification_worker_ready"}'
            framed = struct.pack("=I", len(body)) + body
            first = subprocess.run(
                (str(tap.executable),),
                input=framed,
                capture_output=True,
                check=True,
            )
            self.assertEqual(first.stdout, framed)
            second = subprocess.run(
                (str(tap.executable),),
                input=b"",
                capture_output=True,
                check=False,
            )
            self.assertEqual(second.returncode, 2)
            status = json.loads(tap.status.read_text(encoding="utf-8"))
            self.assertEqual(status["attempts"], 2)
            self.assertEqual(status["stage"], "response_forwarded")
            self.assertEqual(status["stage_rank"], 4)

    def test_pending_navigation_fixture_closes_only_after_v3_signal(self) -> None:
        fixture = smoke.SemanticHttpsFixture(
            smoke.PENDING_NAVIGATION_FIXTURE_HOST,
            smoke.PENDING_NAVIGATION_SCENARIO,
        )
        first: http.client.HTTPSConnection | None = None
        second: http.client.HTTPSConnection | None = None
        try:
            fixture.start()
            assert fixture.directory is not None
            capture = fixture.directory / "pending-navigation-signal.json"
            smoke._write_owner_private_file(
                capture,
                json.dumps(
                    self._pending_navigation_signal(fixture.host),
                    sort_keys=True,
                ).encode("utf-8"),
                os.getuid(),
                os.getgid(),
            )
            fixture.arm_pending_navigation_tap(capture, os.getuid())
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            first = http.client.HTTPSConnection(
                "127.0.0.1", fixture.port, timeout=1.0, context=context
            )
            first.request("GET", "/", headers={"Host": fixture.host})
            with self.assertRaises(http.client.RemoteDisconnected):
                first.getresponse()

            second = http.client.HTTPSConnection(
                "127.0.0.1", fixture.port, timeout=1.0, context=context
            )
            second.request("GET", "/", headers={"Host": fixture.host})
            response = second.getresponse()
            self.assertIn(b"/style.css", response.read())
            snapshot = fixture.snapshot()
            self.assertEqual(snapshot.root_visits, 2)
            self.assertEqual(snapshot.pending_navigation_signals, 1)
            self.assertIsNone(snapshot.pending_navigation_error)
        finally:
            if first is not None:
                first.close()
            if second is not None:
                second.close()
            fixture.close()

    def test_pending_navigation_tap_does_not_ack_failed_native_forward(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            profile = root / "profile"
            home.mkdir()
            profile.mkdir()
            target = profile / "failing-native-host"
            target.write_text("#!/bin/sh\nexit 7\n", encoding="utf-8")
            target.chmod(0o700)
            tap = smoke._create_pending_navigation_tap(
                home,
                profile,
                os.getuid(),
                os.getgid(),
                target,
            )
            body = json.dumps(
                self._pending_navigation_signal(
                    smoke.PENDING_NAVIGATION_FIXTURE_HOST
                ),
                sort_keys=True,
            ).encode("utf-8")
            forwarded = subprocess.run(
                (str(tap.executable),),
                input=struct.pack("=I", len(body)) + body,
                capture_output=True,
                check=False,
            )
            self.assertEqual(forwarded.returncode, 7)
            self.assertFalse(tap.capture.exists())
            status = json.loads(tap.status.read_text(encoding="utf-8"))
            self.assertEqual(status["stage"], "child_completed")
            self.assertEqual(status["child_returncode"], 7)

    def test_pending_navigation_tap_rejects_empty_native_response(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            profile = root / "profile"
            home.mkdir()
            profile.mkdir()
            target = profile / "empty-native-host"
            target.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            target.chmod(0o700)
            tap = smoke._create_pending_navigation_tap(
                home,
                profile,
                os.getuid(),
                os.getgid(),
                target,
            )
            body = json.dumps(
                self._pending_navigation_signal(
                    smoke.PENDING_NAVIGATION_FIXTURE_HOST
                ),
                sort_keys=True,
            ).encode("utf-8")
            forwarded = subprocess.run(
                (str(tap.executable),),
                input=struct.pack("=I", len(body)) + body,
                capture_output=True,
                check=False,
            )
            self.assertEqual(forwarded.returncode, 6)
            self.assertFalse(tap.capture.exists())
            status = json.loads(tap.status.read_text(encoding="utf-8"))
            self.assertEqual(status["stage"], "empty_child_response")

    def test_chrome_command_loads_only_the_companion_in_a_fresh_profile(self) -> None:
        command = smoke._chrome_command(
            Path("/Applications/Google Chrome"),
            Path("/tmp/profile"),
            Path("/repo/browser-companion/chromium"),
            18443,
        )
        self.assertNotIn("--headless=new", command)
        self.assertNotIn("--dump-dom", command)
        self.assertNotIn("--no-sandbox", command)
        self.assertIn("--new-window", command)
        self.assertIn(
            "--disable-extensions-except=/repo/browser-companion/chromium",
            command,
        )
        self.assertIn("--load-extension=/repo/browser-companion/chromium", command)
        self.assertNotIn("--disable-extensions", command)
        self.assertIn(
            f"--host-resolver-rules=MAP {smoke.FIXTURE_HOST} 127.0.0.1, EXCLUDE localhost",
            command,
        )
        self.assertIn("--remote-debugging-port=0", command)
        self.assertEqual(command[-1], "about:blank")

    def test_chrome_command_uses_unified_headless_without_disabling_sandbox(
        self,
    ) -> None:
        command = smoke._chrome_command(
            Path("/Applications/Google Chrome for Testing"),
            Path("/tmp/profile"),
            Path("/repo/browser-companion/chromium"),
            18443,
            headless=True,
        )
        self.assertIn("--headless", command)
        self.assertNotIn("--headless=new", command)
        self.assertNotIn("--new-window", command)
        self.assertNotIn("--no-sandbox", command)
        self.assertEqual(command[-1], "about:blank")

    def test_chrome_command_can_qualify_retry_without_any_extension(
        self,
    ) -> None:
        command = smoke._chrome_command(
            Path("/Applications/Google Chrome for Testing"),
            Path("/tmp/profile"),
            None,
            18443,
            smoke.PENDING_NAVIGATION_FIXTURE_HOST,
            headless=True,
        )
        self.assertIn("--headless", command)
        self.assertIn("--disable-extensions", command)
        self.assertFalse(
            any(argument.startswith("--load-extension=") for argument in command)
        )
        self.assertFalse(
            any(
                argument.startswith("--disable-extensions-except=")
                for argument in command
            )
        )
        self.assertIn(
            "--host-resolver-rules=MAP "
            f"{smoke.PENDING_NAVIGATION_FIXTURE_HOST} 127.0.0.1, "
            "EXCLUDE localhost",
            command,
        )

    def test_chrome_command_maps_the_selected_fixture_host(self) -> None:
        command = smoke._chrome_command(
            Path("/Applications/Google Chrome"),
            Path("/tmp/profile"),
            Path("/repo/browser-companion/chromium"),
            18443,
            smoke.INCOMPLETE_FIXTURE_HOST,
        )
        self.assertIn(
            "--host-resolver-rules=MAP "
            f"{smoke.INCOMPLETE_FIXTURE_HOST} 127.0.0.1, EXCLUDE localhost",
            command,
        )
        self.assertEqual(command[-1], "about:blank")

    def test_devtools_active_port_requires_an_exact_local_endpoint(self) -> None:
        self.assertEqual(
            smoke._parse_devtools_active_port(
                b"49152\n/devtools/browser/qualified-browser\n"
            ),
            49152,
        )
        for payload in (
            b"0\n/devtools/browser/id\n",
            b"65536\n/devtools/browser/id\n",
            b"49152\n/devtools/page/id\n",
            b"not-a-port\n/devtools/browser/id\n",
            b"49152\n/devtools/browser/id\nextra\n",
        ):
            with self.subTest(payload=payload), self.assertRaises(
                smoke.QualificationError
            ):
                smoke._parse_devtools_active_port(payload)

    def test_owner_bounded_file_rejects_group_writable_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / smoke.DEVTOOLS_ACTIVE_PORT
            path.write_bytes(b"49152\n/devtools/browser/id\n")
            path.chmod(0o620)
            with self.assertRaisesRegex(
                smoke.QualificationError,
                "owner-controlled",
            ):
                smoke._read_owner_bounded_file(path, os.getuid())

    def test_extension_worker_gate_requires_the_exact_worker_target(self) -> None:
        targets = [
            [],
            [
                {
                    "type": "service_worker",
                    "url": f"{smoke.NATIVE_HOST_ORIGIN}service-worker.js",
                    "webSocketDebuggerUrl": (
                        "ws://127.0.0.1:49152/devtools/page/worker"
                    ),
                }
            ],
        ]
        with mock.patch.object(
            smoke,
            "_wait_for_devtools_port",
            return_value=49152,
        ), mock.patch.object(
            smoke,
            "_devtools_json",
            side_effect=targets,
        ) as request, mock.patch.object(
            smoke,
            "_worker_runtime_probe",
            return_value=(True, "native_response_received"),
        ) as runtime_probe, mock.patch.object(
            smoke.time,
            "sleep",
        ):
            self.assertEqual(
                smoke._wait_for_extension_worker(
                    Path("/tmp/profile"),
                    501,
                    timeout=1.0,
                ),
                49152,
            )
        self.assertEqual(
            request.call_args_list,
            [
                mock.call(49152, "/json/list"),
                mock.call(49152, "/json/list"),
            ],
        )
        runtime_probe.assert_called_once_with(
            "ws://127.0.0.1:49152/devtools/page/worker",
            49152,
        )

    def test_worker_debugger_path_is_bound_to_the_exact_loopback_port(self) -> None:
        self.assertEqual(
            smoke._worker_debugger_path(
                "ws://127.0.0.1:49152/devtools/page/worker",
                49152,
            ),
            "/devtools/page/worker",
        )
        for url in (
            "ws://localhost:49152/devtools/page/worker",
            "ws://127.0.0.1:49153/devtools/page/worker",
            "wss://127.0.0.1:49152/devtools/page/worker",
            "ws://127.0.0.1:49152/other/worker",
        ):
            with self.subTest(url=url), self.assertRaises(
                smoke.QualificationError
            ):
                smoke._worker_debugger_path(url, 49152)

    def test_worker_runtime_gate_requires_the_terminal_structured_marker(self) -> None:
        with mock.patch.object(
            smoke,
            "_devtools_command",
            return_value={
                "result": {
                    "type": "object",
                    "value": {
                        "ready": True,
                        "stage": "native_response_received",
                    },
                },
            },
        ) as command:
            self.assertTrue(
                smoke._worker_runtime_ready(
                    "ws://127.0.0.1:49152/devtools/page/worker",
                    49152,
                )
            )
        command.assert_called_once_with(
            "ws://127.0.0.1:49152/devtools/page/worker",
            49152,
            "Runtime.evaluate",
            {
                "expression": smoke.WORKER_READY_EXPRESSION,
                "returnByValue": True,
                "awaitPromise": True,
            },
        )

    def test_worker_runtime_probe_rejects_unbounded_stage_values(self) -> None:
        with mock.patch.object(
            smoke,
            "_devtools_command",
            return_value={
                "result": {
                    "type": "object",
                    "value": {
                        "ready": False,
                        "stage": "/Users/example/private/native-host-error",
                    },
                },
            },
        ):
            self.assertEqual(
                smoke._worker_runtime_probe(
                    "ws://127.0.0.1:49152/devtools/page/worker",
                    49152,
                ),
                (False, "invalid_devtools_result"),
            )

    def test_devtools_command_waits_for_its_bounded_response(self) -> None:
        connection = mock.Mock()
        with mock.patch.object(
            smoke,
            "_connect_worker_debugger",
            return_value=connection,
        ), mock.patch.object(
            smoke,
            "_send_websocket_json",
        ) as send, mock.patch.object(
            smoke,
            "_receive_websocket_json",
            side_effect=[
                {"method": "Runtime.consoleAPICalled"},
                {"id": 1, "result": {"frameId": "frame-1"}},
            ],
        ):
            self.assertEqual(
                smoke._devtools_command(
                    "ws://127.0.0.1:49152/devtools/page/owned",
                    49152,
                    "Page.navigate",
                    {"url": "https://example.net:18443/"},
                    response_timeout=12.0,
                ),
                {"frameId": "frame-1"},
            )
        connection.settimeout.assert_called_once_with(12.0)
        send.assert_called_once_with(
            connection,
            {
                "id": 1,
                "method": "Page.navigate",
                "params": {"url": "https://example.net:18443/"},
            },
        )
        connection.close.assert_called_once_with()

    def test_worker_runtime_gate_proves_an_address_free_native_roundtrip(self) -> None:
        self.assertIn("qualification_worker_ready", smoke.WORKER_READY_EXPRESSION)
        self.assertIn("sendNativeMessage", smoke.WORKER_READY_EXPRESSION)
        self.assertNotIn("http://", smoke.WORKER_READY_EXPRESSION)
        self.assertNotIn("https://", smoke.WORKER_READY_EXPRESSION)
        self.assertNotIn("return {ready: false, message", smoke.WORKER_READY_EXPRESSION)
        self.assertIn("native_host_not_found", smoke.WORKER_READY_EXPRESSION)

    def test_fixture_navigation_uses_page_navigate_for_the_exact_url(self) -> None:
        fixture = mock.Mock(host="example.net", port=18443)
        target = (
            "https://example.net:18443/"
            "?slipstream-semantic=1"
        )
        with mock.patch.object(
            smoke,
            "_devtools_json",
            return_value=[
                {
                    "type": "page",
                    "url": "about:blank",
                    "webSocketDebuggerUrl": (
                        "ws://127.0.0.1:49152/devtools/page/owned"
                    ),
                }
            ],
        ) as request, mock.patch.object(
            smoke,
            "_devtools_command",
            return_value={"frameId": "frame-1", "loaderId": "loader-1"},
        ) as command:
            smoke._open_fixture_with_devtools(49152, fixture)
        request.assert_called_once_with(49152, "/json/list")
        command.assert_called_once_with(
            "ws://127.0.0.1:49152/devtools/page/owned",
            49152,
            "Page.navigate",
            {"url": target},
        )

    def test_pending_navigation_allows_its_bounded_signal_delay(self) -> None:
        fixture = mock.Mock(
            host="example.edu",
            port=18443,
            scenario=smoke.PENDING_NAVIGATION_SCENARIO,
        )
        with mock.patch.object(
            smoke,
            "_devtools_json",
            return_value=[
                {
                    "type": "page",
                    "url": "about:blank",
                    "webSocketDebuggerUrl": (
                        "ws://127.0.0.1:49152/devtools/page/owned"
                    ),
                }
            ],
        ), mock.patch.object(
            smoke,
            "_devtools_command",
            return_value={
                "frameId": "frame-1",
                "errorText": "net::ERR_EMPTY_RESPONSE",
            },
        ) as command:
            smoke._open_fixture_with_devtools(49152, fixture)
        command.assert_called_once_with(
            "ws://127.0.0.1:49152/devtools/page/owned",
            49152,
            "Page.navigate",
            {
                "url": (
                    "https://example.edu:18443/"
                    "?slipstream-semantic=1"
                )
            },
            response_timeout=smoke.PENDING_NAVIGATION_DEVTOOLS_TIMEOUT,
        )

    def test_non_pending_navigation_rejects_empty_response(self) -> None:
        fixture = mock.Mock(
            host="example.net",
            port=18443,
            scenario=smoke.INCOMPLETE_RESPONSE_SCENARIO,
        )
        with mock.patch.object(
            smoke,
            "_devtools_json",
            return_value=[
                {
                    "type": "page",
                    "url": "about:blank",
                    "webSocketDebuggerUrl": (
                        "ws://127.0.0.1:49152/devtools/page/owned"
                    ),
                }
            ],
        ), mock.patch.object(
            smoke,
            "_devtools_command",
            return_value={
                "frameId": "frame-1",
                "errorText": "net::ERR_EMPTY_RESPONSE",
            },
        ):
            with self.assertRaisesRegex(
                smoke.QualificationError,
                "ERR_EMPTY_RESPONSE",
            ):
                smoke._open_fixture_with_devtools(49152, fixture)

    def test_launch_agent_payload_uses_launchservices_in_the_aqua_domain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            executable = _fake_chrome_for_testing(Path(tmp))
            payload = smoke._chrome_launch_agent_payload(
                "dev.slipstream.chromium-semantic.4242",
                {"HOME": "/Users/runner", "USER": "runner"},
                Path("/Users/runner"),
                Path("/tmp/profile/chrome.stdout"),
                Path("/tmp/profile/chrome.stderr"),
                Path("/tmp/profile/launcher.stdout"),
                Path("/tmp/profile/launcher.stderr"),
                executable,
                Path("/tmp/profile"),
                Path("/repo/browser-companion/chromium"),
                18443,
            )
        command = payload["ProgramArguments"]
        self.assertEqual(
            payload["Label"],
            "dev.slipstream.chromium-semantic.4242",
        )
        self.assertEqual(payload["LimitLoadToSessionType"], "Aqua")
        self.assertNotIn("SessionCreate", payload)
        self.assertEqual(payload["ProcessType"], "Interactive")
        self.assertTrue(payload["RunAtLoad"])
        self.assertFalse(payload["AbandonProcessGroup"])
        self.assertEqual(payload["WorkingDirectory"], "/Users/runner")
        self.assertEqual(command[0], "/usr/bin/open")
        self.assertIn("-W", command)
        self.assertIn("-n", command)
        self.assertIn("--args", command)
        self.assertIn(str(executable.parents[2]), command)
        self.assertNotIn("--no-sandbox", command)
        self.assertNotIn("/bin/sh", command)
        self.assertNotIn("/usr/bin/sudo", command)
        self.assertNotIn("/bin/launchctl", command)

    def test_headless_launch_agent_uses_launchservices_without_a_window(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            executable = _fake_chrome_for_testing(Path(tmp))
            payload = smoke._chrome_launch_agent_payload(
                "dev.slipstream.chromium-semantic.4242",
                {"HOME": "/Users/runner", "USER": "runner"},
                Path("/Users/runner"),
                Path("/tmp/profile/chrome.stdout"),
                Path("/tmp/profile/chrome.stderr"),
                Path("/tmp/profile/launcher.stdout"),
                Path("/tmp/profile/launcher.stderr"),
                executable,
                Path("/tmp/profile"),
                Path("/repo/browser-companion/chromium"),
                18443,
                headless=True,
            )

        command = payload["ProgramArguments"]
        self.assertEqual(payload["ProcessType"], "Interactive")
        self.assertEqual(payload["LimitLoadToSessionType"], "Aqua")
        self.assertEqual(command[0], "/usr/bin/open")
        self.assertIn("-W", command)
        self.assertIn("-j", command)
        self.assertIn("--headless", command)
        self.assertNotIn("--new-window", command)
        self.assertNotIn("--no-sandbox", command)

    def test_owned_chrome_rss_sums_only_enumerated_processes(self) -> None:
        processes = (
            smoke.ChromeProcess(101, 101, "/tmp/chrome --user-data-dir=/tmp/p"),
            smoke.ChromeProcess(102, 101, "/tmp/chrome-helper"),
        )
        completed = smoke.subprocess.CompletedProcess(
            ("/bin/ps",),
            0,
            stdout="12000\n8000\n",
            stderr="",
        )
        with mock.patch.object(
            smoke,
            "_owned_chrome_processes",
            return_value=processes,
        ), mock.patch.object(smoke, "_run", return_value=completed) as run:
            resident_kib = smoke._owned_chrome_rss_kib(
                501,
                Path("/tmp/chrome"),
                Path("/tmp/p"),
            )

        self.assertEqual(resident_kib, 20_000)
        run.assert_called_once_with(
            ("/bin/ps", "-p", "101,102", "-o", "rss="),
            check=False,
        )

    def test_physical_footprint_parser_uses_the_deduplicated_total(self) -> None:
        payload = json.dumps(
            {
                "processes": [
                    {"pid": 101, "footprint": 400_000_000},
                    {"pid": 102, "footprint": 300_000_000},
                ],
                "total footprint": 524_288_001,
                "unit": "bytes",
            }
        ).encode("utf-8")
        self.assertEqual(
            smoke._parse_physical_footprint_kib(
                payload,
                Path("/tmp/footprint.json"),
            ),
            512_001,
        )

    def test_physical_footprint_parser_rejects_missing_total(self) -> None:
        with self.assertRaisesRegex(
            smoke.QualificationError,
            "physical footprint total",
        ):
            smoke._parse_physical_footprint_kib(
                b'{"unit":"bytes"}',
                Path("/tmp/footprint.json"),
            )

    def test_launchservices_copies_an_extensionless_bundle_into_the_profile(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable = _fake_extensionless_chrome_for_testing(root)
            profile = root / "profile"
            profile.mkdir(mode=0o700)
            wrapper = smoke._launchservices_app_bundle(
                executable,
                profile,
                os.getuid(),
                os.getgid(),
            )

            self.assertTrue(wrapper.is_dir())
            self.assertFalse(wrapper.is_symlink())
            self.assertEqual(wrapper.parent, profile)
            self.assertEqual(wrapper.suffix, ".app")
            self.assertFalse((wrapper / "Contents").is_symlink())
            copied_executable = smoke._launchservices_executable(
                executable,
                wrapper,
            )
            self.assertEqual(
                copied_executable,
                wrapper / "Contents" / "MacOS" / "Google Chrome for Testing",
            )
            self.assertEqual(copied_executable.read_bytes(), executable.read_bytes())
            self.assertNotEqual(
                copied_executable.resolve(),
                executable.resolve(),
            )

            payload = smoke._chrome_launch_agent_payload(
                "dev.slipstream.chromium-semantic.4242",
                {"HOME": "/Users/runner", "USER": "runner"},
                Path("/Users/runner"),
                profile / "chrome.stdout",
                profile / "chrome.stderr",
                profile / "launcher.stdout",
                profile / "launcher.stderr",
                copied_executable,
                profile,
                Path("/repo/browser-companion/chromium"),
                18443,
                wrapper,
            )

        command = payload["ProgramArguments"]
        self.assertEqual(command[command.index("-a") + 1], str(wrapper))

    def test_launchservices_uses_an_existing_app_bundle_without_an_alias(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable = _fake_chrome_for_testing(root)
            profile = root / "profile"
            profile.mkdir(mode=0o700)
            bundle = smoke._launchservices_app_bundle(
                executable,
                profile,
                os.getuid(),
                os.getgid(),
            )

            self.assertEqual(bundle, executable.parents[2].resolve())
            self.assertFalse((profile / "Chrome for Testing.app").exists())
            self.assertEqual(
                smoke._launchservices_executable(executable, bundle),
                executable.resolve(),
            )

    def test_owner_private_capture_is_exact_and_tail_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "capture"
            smoke._write_owner_private_file(
                path,
                b"0123456789",
                os.getuid(),
                os.getgid(),
            )
            self.assertEqual(smoke._read_owner_private_tail(path, os.getuid(), 4), b"6789")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_chrome_process_ownership_requires_uid_bundle_and_exact_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable = _fake_chrome_for_testing(root)
            resolved_executable = executable.resolve()
            bundle = resolved_executable.parents[2]
            profile = root / "profile"
            profile_argument = f"--user-data-dir={profile}"
            helper = (
                bundle
                / "Contents"
                / "Frameworks"
                / "Chrome Framework.framework"
                / "Helpers"
                / "Chrome Helper"
            )
            result = smoke.subprocess.CompletedProcess(
                (),
                0,
                stdout="\n".join(
                    (
                        f"410 501 410 {resolved_executable} {profile_argument}",
                        f"411 501 410 {helper} --type=network",
                        f"412 502 412 {resolved_executable} {profile_argument}",
                        f"413 501 413 {resolved_executable} --user-data-dir=/tmp/foreign",
                        f"414 501 414 /tmp/foreign-browser {profile_argument}",
                        f"415 501 415 {helper} --type=utility",
                        f"416 501 416 {helper} --type=utility {profile_argument}",
                        f"417 501 410 {resolved_executable} --guest",
                    )
                ),
                stderr="",
            )
            with mock.patch.object(smoke, "_run", return_value=result):
                processes = smoke._owned_chrome_processes(
                    501,
                    executable,
                    profile,
                )

        self.assertEqual(
            tuple(process.pid for process in processes),
            (410, 411),
        )

    def test_chrome_ownership_retains_helpers_after_main_exit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable = _fake_chrome_for_testing(root)
            resolved_executable = executable.resolve()
            bundle = resolved_executable.parents[2]
            profile = root / "profile"
            profile_argument = f"--user-data-dir={profile}"
            helper = (
                bundle
                / "Contents"
                / "Frameworks"
                / "Chrome Framework.framework"
                / "Helpers"
                / "Chrome Helper"
            )
            initial = smoke.subprocess.CompletedProcess(
                (),
                0,
                stdout="\n".join(
                    (
                        f"410 501 410 {resolved_executable} {profile_argument}",
                        f"411 501 410 {helper} --type=network",
                    )
                ),
                stderr="",
            )
            helper_only = smoke.subprocess.CompletedProcess(
                (),
                0,
                stdout=f"411 501 410 {helper} --type=network",
                stderr="",
            )
            ownership = smoke.ChromeOwnership(set())
            with mock.patch.object(
                smoke,
                "_run",
                side_effect=(initial, helper_only),
            ):
                first = smoke._owned_chrome_processes(
                    501,
                    executable,
                    profile,
                    ownership,
                )
                second = smoke._owned_chrome_processes(
                    501,
                    executable,
                    profile,
                    ownership,
                )

        self.assertEqual(tuple(process.pid for process in first), (410, 411))
        self.assertEqual(tuple(process.pid for process in second), (411,))
        self.assertEqual(ownership.process_groups, {410})

    def test_chrome_cleanup_signals_only_exact_owned_profile_processes(self) -> None:
        processes = (
            smoke.ChromeProcess(410, 410, "browser"),
            smoke.ChromeProcess(411, 410, "helper"),
        )
        with mock.patch.object(
            smoke,
            "_owned_chrome_processes",
            return_value=processes,
        ), mock.patch.object(smoke.os, "kill") as kill:
            smoke._signal_owned_chrome_processes(
                501,
                Path("/tmp/Chrome.app/Contents/MacOS/Chrome"),
                Path("/tmp/profile"),
                smoke.signal.SIGTERM,
            )

        self.assertEqual(
            tuple(call.args for call in kill.call_args_list),
            (
                (411, smoke.signal.SIGTERM),
                (410, smoke.signal.SIGTERM),
            ),
        )

    def test_chrome_cleanup_revalidates_identity_before_signal(self) -> None:
        expected = smoke.ChromeProcess(410, 410, "browser")
        replacement = smoke.ChromeProcess(410, 999, "foreign")
        with mock.patch.object(
            smoke,
            "_owned_chrome_processes",
            side_effect=((expected,), (replacement,)),
        ), mock.patch.object(smoke.os, "kill") as kill:
            smoke._signal_owned_chrome_processes(
                501,
                Path("/tmp/Chrome.app/Contents/MacOS/Chrome"),
                Path("/tmp/profile"),
                smoke.signal.SIGTERM,
            )

        kill.assert_not_called()

    def test_owned_chrome_absence_requires_a_stable_quiet_window(self) -> None:
        delayed = smoke.ChromeProcess(410, 410, "browser")
        with mock.patch.object(
            smoke,
            "_owned_chrome_processes",
            side_effect=((), (delayed,), (), ()),
        ) as processes, mock.patch.object(
            smoke.time,
            "monotonic",
            side_effect=(0.0, 0.0, 0.2, 0.3, 0.6),
        ), mock.patch.object(
            smoke.time,
            "sleep",
        ):
            self.assertTrue(
                smoke._wait_for_owned_chrome_absence(
                    501,
                    Path("/tmp/Chrome.app/Contents/MacOS/Chrome"),
                    Path("/tmp/profile"),
                    timeout=1.0,
                    settle_time=0.25,
                )
            )

        self.assertEqual(processes.call_count, 4)

    def test_bootstrap_targets_the_exact_gui_domain_and_verifies_uid(self) -> None:
        absent = smoke.subprocess.CompletedProcess((), 113, "", "not found")
        success = smoke.subprocess.CompletedProcess((), 0, "", "")
        with mock.patch.object(
            smoke,
            "_run",
            side_effect=(absent, success),
        ) as run, mock.patch.object(
            smoke,
            "_launch_agent_pid",
            return_value=4242,
        ), mock.patch.object(
            smoke,
            "_process_identity",
            return_value=(501, 4242),
        ):
            launch = smoke._bootstrap_chrome_launch_agent(
                501,
                "dev.slipstream.chromium-semantic.4242",
                Path("/tmp/profile/chrome-launch-agent.plist"),
            )

        self.assertEqual(
            launch,
            smoke.ChromeLaunch(
                "gui/501/dev.slipstream.chromium-semantic.4242",
                4242,
                4242,
            ),
        )
        self.assertEqual(
            run.call_args_list[1].args[0],
            (
                "/bin/launchctl",
                "bootstrap",
                "gui/501",
                "/tmp/profile/chrome-launch-agent.plist",
            ),
        )

    def test_bootstrap_rejects_a_launchd_identity_mismatch(self) -> None:
        absent = smoke.subprocess.CompletedProcess((), 113, "", "not found")
        success = smoke.subprocess.CompletedProcess((), 0, "", "")
        with mock.patch.object(
            smoke,
            "_run",
            side_effect=(absent, success, success, success),
        ) as run, mock.patch.object(
            smoke,
            "_launch_agent_pid",
            return_value=4242,
        ), mock.patch.object(
            smoke,
            "_process_identity",
            return_value=(0, 4242),
        ), mock.patch.object(
            smoke,
            "_wait_for_launch_agent_absence",
        ):
            with self.assertRaisesRegex(smoke.QualificationError, "wrong identity"):
                smoke._bootstrap_chrome_launch_agent(
                    501,
                    "dev.slipstream.chromium-semantic.4242",
                    Path("/tmp/profile/chrome-launch-agent.plist"),
                )
        self.assertEqual(
            tuple(call.args[0] for call in run.call_args_list[-2:]),
            (
                (
                    "/bin/launchctl",
                    "kill",
                    "SIGKILL",
                    "gui/501/dev.slipstream.chromium-semantic.4242",
                ),
                (
                    "/bin/launchctl",
                    "bootout",
                    "gui/501/dev.slipstream.chromium-semantic.4242",
                ),
            ),
        )

    def test_bootstrap_failure_still_kills_and_boots_out_the_exact_target(self) -> None:
        absent = smoke.subprocess.CompletedProcess((), 113, "", "not found")
        success = smoke.subprocess.CompletedProcess((), 0, "", "")
        bootstrap_error = smoke.QualificationError("bootstrap returned an error")
        with mock.patch.object(
            smoke,
            "_run",
            side_effect=(absent, bootstrap_error, success, success),
        ) as run, mock.patch.object(
            smoke,
            "_wait_for_launch_agent_absence",
        ) as wait_absent:
            with self.assertRaisesRegex(
                smoke.QualificationError,
                "bootstrap returned an error",
            ):
                smoke._bootstrap_chrome_launch_agent(
                    501,
                    "dev.slipstream.chromium-semantic.4242",
                    Path("/tmp/profile/chrome-launch-agent.plist"),
                )

        self.assertEqual(
            tuple(call.args[0] for call in run.call_args_list),
            (
                (
                    "/bin/launchctl",
                    "print",
                    "gui/501/dev.slipstream.chromium-semantic.4242",
                ),
                (
                    "/bin/launchctl",
                    "bootstrap",
                    "gui/501",
                    "/tmp/profile/chrome-launch-agent.plist",
                ),
                (
                    "/bin/launchctl",
                    "kill",
                    "SIGKILL",
                    "gui/501/dev.slipstream.chromium-semantic.4242",
                ),
                (
                    "/bin/launchctl",
                    "bootout",
                    "gui/501/dev.slipstream.chromium-semantic.4242",
                ),
            ),
        )
        wait_absent.assert_called_once_with(
            "gui/501/dev.slipstream.chromium-semantic.4242"
        )

    def test_launch_agent_cleanup_targets_only_the_exact_job_and_group(self) -> None:
        launch = smoke.ChromeLaunch(
            "gui/501/dev.slipstream.chromium-semantic.4242",
            4242,
            4242,
        )
        success = smoke.subprocess.CompletedProcess((), 0, "", "")
        executable = Path("/tmp/Chrome.app/Contents/MacOS/Chrome")
        profile = Path("/tmp/profile")
        with mock.patch.object(
            smoke,
            "_run",
            return_value=success,
        ) as run, mock.patch.object(
            smoke,
            "_wait_for_launch_agent_absence",
        ) as wait_absent, mock.patch.object(
            smoke.lifecycle,
            "_chrome_process_group_members",
            return_value=(),
        ), mock.patch.object(
            smoke.lifecycle,
            "_signal_owned_chrome_processes",
        ) as signal_owned:
            with mock.patch.object(
                smoke,
                "_signal_owned_chrome_processes",
            ) as signal_chrome, mock.patch.object(
                smoke,
                "_wait_for_owned_chrome_absence",
                return_value=True,
            ), mock.patch.object(
                smoke,
                "_owned_chrome_processes",
                return_value=(),
            ):
                smoke._stop_chrome_launch_agent(
                    launch,
                    uid=501,
                    gid=20,
                    supplementary_groups=(12, 61),
                    executable=executable,
                    profile=profile,
                )

        self.assertEqual(
            tuple(call.args[0] for call in run.call_args_list),
            (
                (
                    "/bin/launchctl",
                    "kill",
                    "SIGTERM",
                    "gui/501/dev.slipstream.chromium-semantic.4242",
                ),
                (
                    "/bin/launchctl",
                    "bootout",
                    "gui/501/dev.slipstream.chromium-semantic.4242",
                ),
            ),
        )
        wait_absent.assert_called_once_with(launch.target)
        signal_owned.assert_not_called()
        signal_chrome.assert_called_once_with(
            501,
            executable,
            profile,
            smoke.signal.SIGTERM,
            mock.ANY,
        )

    def test_launch_agent_cleanup_rechecks_quiet_window_after_bootout(self) -> None:
        launch = smoke.ChromeLaunch(
            "gui/501/dev.slipstream.chromium-semantic.4242",
            4242,
            4242,
        )
        success = smoke.subprocess.CompletedProcess((), 0, "", "")
        executable = Path("/tmp/Chrome.app/Contents/MacOS/Chrome")
        profile = Path("/tmp/profile")
        ownership = smoke.ChromeOwnership(set())
        with mock.patch.object(
            smoke,
            "_run",
            return_value=success,
        ), mock.patch.object(
            smoke,
            "_wait_for_launch_agent_absence",
        ), mock.patch.object(
            smoke.lifecycle,
            "_chrome_process_group_members",
            return_value=(),
        ), mock.patch.object(
            smoke,
            "_stop_owned_chrome_processes",
        ) as stop_browser, mock.patch.object(
            smoke,
            "_owned_chrome_processes",
            return_value=(),
        ):
            smoke._stop_chrome_launch_agent(
                launch,
                uid=501,
                gid=20,
                supplementary_groups=(12, 61),
                executable=executable,
                profile=profile,
                ownership=ownership,
                post_bootout_settle_time=5.0,
            )

        self.assertEqual(
            stop_browser.call_args_list,
            [
                mock.call(501, executable, profile, ownership),
                mock.call(
                    501,
                    executable,
                    profile,
                    ownership,
                    timeout=10.0,
                    settle_time=5.0,
                ),
            ],
        )

    def test_launch_agent_cleanup_retries_bootout_before_reporting_failure(self) -> None:
        launch = smoke.ChromeLaunch(
            "gui/501/dev.slipstream.chromium-semantic.4242",
            4242,
            4242,
        )
        success = smoke.subprocess.CompletedProcess((), 0, "", "")
        executable = Path("/tmp/Chrome.app/Contents/MacOS/Chrome")
        profile = Path("/tmp/profile")
        with mock.patch.object(
            smoke,
            "_run",
            return_value=success,
        ) as run, mock.patch.object(
            smoke,
            "_wait_for_launch_agent_absence",
            side_effect=(
                smoke.QualificationError("transient bootout failure"),
                None,
            ),
        ) as wait_absent, mock.patch.object(
            smoke.lifecycle,
            "_chrome_process_group_members",
            return_value=(),
        ), mock.patch.object(
            smoke.lifecycle,
            "_signal_owned_chrome_processes",
        ) as signal_owned:
            with mock.patch.object(
                smoke,
                "_signal_owned_chrome_processes",
            ), mock.patch.object(
                smoke,
                "_wait_for_owned_chrome_absence",
                return_value=True,
            ), mock.patch.object(
                smoke,
                "_owned_chrome_processes",
                return_value=(),
            ):
                smoke._stop_chrome_launch_agent(
                    launch,
                    uid=501,
                    gid=20,
                    supplementary_groups=(12, 61),
                    executable=executable,
                    profile=profile,
                )

        self.assertEqual(
            tuple(call.args[0] for call in run.call_args_list),
            (
                (
                    "/bin/launchctl",
                    "kill",
                    "SIGTERM",
                    "gui/501/dev.slipstream.chromium-semantic.4242",
                ),
                (
                    "/bin/launchctl",
                    "bootout",
                    "gui/501/dev.slipstream.chromium-semantic.4242",
                ),
                (
                    "/bin/launchctl",
                    "kill",
                    "SIGKILL",
                    "gui/501/dev.slipstream.chromium-semantic.4242",
                ),
                (
                    "/bin/launchctl",
                    "bootout",
                    "gui/501/dev.slipstream.chromium-semantic.4242",
                ),
            ),
        )
        self.assertEqual(wait_absent.call_count, 2)
        signal_owned.assert_not_called()

    def test_launch_agent_cleanup_boots_out_after_browser_enumeration_failure(
        self,
    ) -> None:
        launch = smoke.ChromeLaunch(
            "gui/501/dev.slipstream.chromium-semantic.4242",
            4242,
            4242,
        )
        success = smoke.subprocess.CompletedProcess((), 0, "", "")
        executable = Path("/tmp/Chrome.app/Contents/MacOS/Chrome")
        profile = Path("/tmp/profile")
        with mock.patch.object(
            smoke,
            "_run",
            return_value=success,
        ) as run, mock.patch.object(
            smoke,
            "_wait_for_launch_agent_absence",
        ) as wait_absent, mock.patch.object(
            smoke.lifecycle,
            "_chrome_process_group_members",
            return_value=(),
        ), mock.patch.object(
            smoke,
            "_signal_owned_chrome_processes",
            side_effect=smoke.QualificationError("cannot enumerate"),
        ), mock.patch.object(
            smoke,
            "_owned_chrome_processes",
            return_value=(),
        ):
            with self.assertRaisesRegex(
                smoke.QualificationError,
                "process cleanup could not be verified",
            ):
                smoke._stop_chrome_launch_agent(
                    launch,
                    uid=501,
                    gid=20,
                    supplementary_groups=(12, 61),
                    executable=executable,
                    profile=profile,
                )

        self.assertEqual(
            tuple(call.args[0] for call in run.call_args_list),
            (
                (
                    "/bin/launchctl",
                    "kill",
                    "SIGTERM",
                    "gui/501/dev.slipstream.chromium-semantic.4242",
                ),
                (
                    "/bin/launchctl",
                    "bootout",
                    "gui/501/dev.slipstream.chromium-semantic.4242",
                ),
            ),
        )
        wait_absent.assert_called_once_with(launch.target)

    def test_launch_agent_cleanup_verifies_group_after_bootout_failure(self) -> None:
        launch = smoke.ChromeLaunch(
            "gui/501/dev.slipstream.chromium-semantic.4242",
            4242,
            4242,
        )
        success = smoke.subprocess.CompletedProcess((), 0, "", "")
        executable = Path("/tmp/Chrome.app/Contents/MacOS/Chrome")
        profile = Path("/tmp/profile")
        with mock.patch.object(
            smoke,
            "_run",
            return_value=success,
        ), mock.patch.object(
            smoke,
            "_wait_for_launch_agent_absence",
            side_effect=smoke.QualificationError("persistent bootout failure"),
        ), mock.patch.object(
            smoke.lifecycle,
            "_chrome_process_group_members",
            return_value=(),
        ) as members:
            with mock.patch.object(
                smoke,
                "_signal_owned_chrome_processes",
            ), mock.patch.object(
                smoke,
                "_wait_for_owned_chrome_absence",
                return_value=True,
            ), mock.patch.object(
                smoke,
                "_owned_chrome_processes",
                return_value=(),
            ):
                with self.assertRaisesRegex(
                    smoke.QualificationError,
                    "LaunchAgent survived exact cleanup",
                ):
                    smoke._stop_chrome_launch_agent(
                        launch,
                        uid=501,
                        gid=20,
                        supplementary_groups=(12, 61),
                        executable=executable,
                        profile=profile,
                    )

        self.assertGreaterEqual(members.call_count, 1)

    def test_run_chrome_uses_an_exact_temporary_launch_agent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable = _fake_chrome_for_testing(root)
            profile = root / "profile"
            profile.mkdir()
            launch = smoke.ChromeLaunch(
                "gui/501/dev.slipstream.chromium-semantic.4242",
                4242,
                4242,
            )
            browser = smoke.ChromeProcess(
                4343,
                4343,
                f"{executable} --user-data-dir={profile}",
            )
            fixture = mock.Mock(
                port=18443,
                snapshot=mock.Mock(
                    return_value=smoke.FixtureSnapshot(2, 1, 1, 1, 1)
                ),
            )
            with mock.patch.object(
                smoke.lifecycle,
                "_user_environment",
                return_value=({"HOME": str(root)}, root),
            ), mock.patch.object(
                smoke.lifecycle,
                "_user_supplementary_groups",
                return_value=(12, 61),
            ), mock.patch.object(
                smoke,
                "_install_profile_native_host",
            ), mock.patch.object(
                smoke,
                "_install_chrome_for_testing_native_host",
                return_value=smoke.NativeHostRegistration(
                    Path("/tmp/chrome-for-testing-native-host.json"),
                    (),
                ),
            ), mock.patch.object(
                smoke,
                "_remove_chrome_for_testing_native_host",
            ), mock.patch.object(
                smoke,
                "_remove_owned_profile",
            ), mock.patch.object(
                smoke.tempfile,
                "mkdtemp",
                return_value=str(profile),
            ), mock.patch.object(
                smoke.os,
                "chown",
            ), mock.patch.object(
                smoke,
                "_write_owner_private_file",
            ) as write_private, mock.patch.object(
                smoke,
                "_bootstrap_chrome_launch_agent",
                return_value=launch,
            ), mock.patch.object(
                smoke,
                "_wait_for_owned_chrome_process",
                return_value=browser,
            ), mock.patch.object(
                smoke,
                "_wait_for_extension_worker",
                return_value=49152,
            ) as wait_for_worker, mock.patch.object(
                smoke,
                "_open_fixture_with_devtools",
            ) as open_fixture, mock.patch.object(
                smoke,
                "_owned_chrome_process_alive",
                return_value=True,
            ), mock.patch.object(
                smoke,
                "_launch_agent_pid",
                return_value=4242,
            ), mock.patch.object(
                smoke,
                "_stop_chrome_launch_agent",
            ) as stop, mock.patch.object(
                smoke,
                "_read_owner_private_tail",
                return_value=b"",
            ), mock.patch.object(smoke.subprocess, "Popen") as popen:
                snapshot = smoke._run_chrome(
                    501,
                    20,
                    Path("/repo/browser-companion/chromium"),
                    fixture,
                    executable,
                    Path("/tmp/native-host.json"),
                    Path("/tmp/Slipstream.app/Contents/MacOS/slipstream"),
                )

            self.assertEqual(snapshot.ready_requests, 1)
            popen.assert_not_called()
            wait_for_worker.assert_called_once_with(profile, 501)
            open_fixture.assert_called_once_with(49152, fixture)
            stop.assert_called_once_with(
                launch,
                uid=501,
                gid=20,
                supplementary_groups=(12, 61),
                executable=executable.resolve(),
                profile=profile,
                ownership=mock.ANY,
                post_bootout_settle_time=0.0,
            )
            plist_payload = smoke.plistlib.loads(
                write_private.call_args_list[4].args[1]
            )
            self.assertEqual(plist_payload["LimitLoadToSessionType"], "Aqua")
            self.assertEqual(
                plist_payload["ProgramArguments"][0],
                "/usr/bin/open",
            )
            self.assertNotIn("--no-sandbox", plist_payload["ProgramArguments"])
            self.assertEqual(
                plist_payload["Label"],
                f"{smoke.CHROME_JOB_PREFIX}.{os.getpid()}",
            )

    def test_run_chrome_uses_quiet_window_after_admission_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable = _fake_chrome_for_testing(root)
            profile = root / "profile"
            profile.mkdir()
            launch = smoke.ChromeLaunch(
                "gui/501/dev.slipstream.chromium-semantic.4242",
                4242,
                4242,
            )
            fixture = mock.Mock(port=18443)
            with mock.patch.object(
                smoke.lifecycle,
                "_user_environment",
                return_value=({"HOME": str(root)}, root),
            ), mock.patch.object(
                smoke.lifecycle,
                "_user_supplementary_groups",
                return_value=(12, 61),
            ), mock.patch.object(
                smoke,
                "_install_profile_native_host",
            ), mock.patch.object(
                smoke,
                "_install_chrome_for_testing_native_host",
                return_value=smoke.NativeHostRegistration(
                    Path("/tmp/chrome-for-testing-native-host.json"),
                    (),
                ),
            ), mock.patch.object(
                smoke,
                "_remove_chrome_for_testing_native_host",
            ), mock.patch.object(
                smoke,
                "_remove_owned_profile",
            ) as remove_profile, mock.patch.object(
                smoke.tempfile,
                "mkdtemp",
                return_value=str(profile),
            ), mock.patch.object(
                smoke.os,
                "chown",
            ), mock.patch.object(
                smoke,
                "_write_owner_private_file",
            ), mock.patch.object(
                smoke,
                "_bootstrap_chrome_launch_agent",
                return_value=launch,
            ), mock.patch.object(
                smoke,
                "_wait_for_owned_chrome_process",
                side_effect=smoke.QualificationError("browser admission timed out"),
            ), mock.patch.object(
                smoke,
                "_stop_chrome_launch_agent",
            ) as stop, mock.patch.object(
                smoke,
                "_read_owner_private_tail",
                return_value=b"",
            ):
                with self.assertRaisesRegex(
                    smoke.QualificationError,
                    "browser admission timed out",
                ):
                    smoke._run_chrome(
                        501,
                        20,
                        Path("/repo/browser-companion/chromium"),
                        fixture,
                        executable,
                        Path("/tmp/native-host.json"),
                        Path("/tmp/Slipstream.app/Contents/MacOS/slipstream"),
                    )

            stop.assert_called_once_with(
                launch,
                uid=501,
                gid=20,
                supplementary_groups=(12, 61),
                executable=executable.resolve(),
                profile=profile,
                ownership=mock.ANY,
                post_bootout_settle_time=5.0,
            )
            remove_profile.assert_called_once_with(profile)

    def test_run_chrome_retains_profile_until_launch_agent_is_absent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable = _fake_chrome_for_testing(root)
            profile = root / "profile"
            profile.mkdir()
            launch = smoke.ChromeLaunch(
                "gui/501/dev.slipstream.chromium-semantic.4242",
                4242,
                4242,
            )
            browser = smoke.ChromeProcess(
                4343,
                4343,
                f"{executable} --user-data-dir={profile}",
            )
            fixture = mock.Mock(
                port=18443,
                snapshot=mock.Mock(
                    return_value=smoke.FixtureSnapshot(2, 1, 1, 1, 1)
                ),
            )
            with mock.patch.object(
                smoke.lifecycle,
                "_user_environment",
                return_value=({"HOME": str(root)}, root),
            ), mock.patch.object(
                smoke.lifecycle,
                "_user_supplementary_groups",
                return_value=(12, 61),
            ), mock.patch.object(
                smoke,
                "_install_profile_native_host",
            ), mock.patch.object(
                smoke,
                "_install_chrome_for_testing_native_host",
                return_value=smoke.NativeHostRegistration(
                    Path("/tmp/chrome-for-testing-native-host.json"),
                    (),
                ),
            ), mock.patch.object(
                smoke,
                "_remove_chrome_for_testing_native_host",
            ), mock.patch.object(
                smoke,
                "_remove_owned_profile",
            ) as remove_profile, mock.patch.object(
                smoke.tempfile,
                "mkdtemp",
                return_value=str(profile),
            ), mock.patch.object(
                smoke.os,
                "chown",
            ), mock.patch.object(
                smoke,
                "_write_owner_private_file",
            ), mock.patch.object(
                smoke,
                "_bootstrap_chrome_launch_agent",
                return_value=launch,
            ), mock.patch.object(
                smoke,
                "_wait_for_owned_chrome_process",
                return_value=browser,
            ), mock.patch.object(
                smoke,
                "_wait_for_extension_worker",
                return_value=49152,
            ), mock.patch.object(
                smoke,
                "_open_fixture_with_devtools",
            ), mock.patch.object(
                smoke,
                "_owned_chrome_process_alive",
                return_value=True,
            ), mock.patch.object(
                smoke,
                "_launch_agent_pid",
                return_value=4242,
            ), mock.patch.object(
                smoke,
                "_stop_chrome_launch_agent",
                side_effect=smoke.QualificationError("job still loaded"),
            ), mock.patch.object(
                smoke,
                "_read_owner_private_tail",
                return_value=b"",
            ):
                with self.assertRaisesRegex(
                    smoke.QualificationError,
                    "profile retained until LaunchAgent cleanup",
                ):
                    smoke._run_chrome(
                        501,
                        20,
                        Path("/repo/browser-companion/chromium"),
                        fixture,
                        executable,
                        Path("/tmp/native-host.json"),
                        Path("/tmp/Slipstream.app/Contents/MacOS/slipstream"),
                    )

            remove_profile.assert_not_called()

    def test_run_chrome_cleans_exact_profile_after_partial_bootstrap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable = _fake_chrome_for_testing(root)
            profile = root / "profile"
            profile.mkdir()
            fixture = mock.Mock(port=18443)

            def diagnostic_tail(path: Path, _uid: int) -> bytes:
                if path.name == "launcher.stderr":
                    return b"LaunchServices refused the request"
                return b""

            with mock.patch.object(
                smoke.lifecycle,
                "_user_environment",
                return_value=({"HOME": str(root)}, root),
            ), mock.patch.object(
                smoke.lifecycle,
                "_user_supplementary_groups",
                return_value=(12, 61),
            ), mock.patch.object(
                smoke,
                "_install_profile_native_host",
            ), mock.patch.object(
                smoke,
                "_install_chrome_for_testing_native_host",
                return_value=smoke.NativeHostRegistration(
                    Path("/tmp/chrome-for-testing-native-host.json"),
                    (),
                ),
            ), mock.patch.object(
                smoke,
                "_remove_chrome_for_testing_native_host",
            ), mock.patch.object(
                smoke,
                "_remove_owned_profile",
            ) as remove_profile, mock.patch.object(
                smoke.tempfile,
                "mkdtemp",
                return_value=str(profile),
            ), mock.patch.object(
                smoke.os,
                "chown",
            ), mock.patch.object(
                smoke,
                "_write_owner_private_file",
            ), mock.patch.object(
                smoke,
                "_bootstrap_chrome_launch_agent",
                side_effect=smoke.QualificationError("identity polling failed"),
            ), mock.patch.object(
                smoke,
                "_wait_for_launch_agent_absence",
            ) as wait_absent, mock.patch.object(
                smoke,
                "_stop_owned_chrome_processes",
            ) as stop_browser, mock.patch.object(
                smoke,
                "_read_owner_private_tail",
                side_effect=diagnostic_tail,
            ):
                with self.assertRaisesRegex(
                    smoke.QualificationError,
                    "identity polling failed",
                ) as raised:
                    smoke._run_chrome(
                        501,
                        20,
                        Path("/repo/browser-companion/chromium"),
                        fixture,
                        executable,
                        Path("/tmp/native-host.json"),
                        Path("/tmp/Slipstream.app/Contents/MacOS/slipstream"),
                    )

            self.assertIn(
                "LaunchServices stderr:\nLaunchServices refused the request",
                str(raised.exception),
            )
            wait_absent.assert_called_once_with(
                f"gui/501/{smoke.CHROME_JOB_PREFIX}.{os.getpid()}"
            )
            stop_browser.assert_called_once_with(
                501,
                executable.resolve(),
                profile,
                mock.ANY,
                timeout=10.0,
                settle_time=5.0,
            )
            remove_profile.assert_called_once_with(profile)

    def test_run_chrome_retains_profile_when_partial_bootstrap_cleanup_fails(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable = _fake_chrome_for_testing(root)
            profile = root / "profile"
            profile.mkdir()
            fixture = mock.Mock(port=18443)
            with mock.patch.object(
                smoke.lifecycle,
                "_user_environment",
                return_value=({"HOME": str(root)}, root),
            ), mock.patch.object(
                smoke.lifecycle,
                "_user_supplementary_groups",
                return_value=(12, 61),
            ), mock.patch.object(
                smoke,
                "_install_profile_native_host",
            ), mock.patch.object(
                smoke,
                "_install_chrome_for_testing_native_host",
                return_value=smoke.NativeHostRegistration(
                    Path("/tmp/chrome-for-testing-native-host.json"),
                    (),
                ),
            ), mock.patch.object(
                smoke,
                "_remove_chrome_for_testing_native_host",
            ), mock.patch.object(
                smoke,
                "_remove_owned_profile",
            ) as remove_profile, mock.patch.object(
                smoke.tempfile,
                "mkdtemp",
                return_value=str(profile),
            ), mock.patch.object(
                smoke.os,
                "chown",
            ), mock.patch.object(
                smoke,
                "_write_owner_private_file",
            ), mock.patch.object(
                smoke,
                "_bootstrap_chrome_launch_agent",
                side_effect=smoke.QualificationError("identity polling failed"),
            ), mock.patch.object(
                smoke,
                "_wait_for_launch_agent_absence",
            ), mock.patch.object(
                smoke,
                "_stop_owned_chrome_processes",
                side_effect=smoke.QualificationError("Chrome survived"),
            ), mock.patch.object(
                smoke,
                "_read_owner_private_tail",
                return_value=b"",
            ):
                with self.assertRaisesRegex(
                    smoke.QualificationError,
                    "profile retained until LaunchAgent cleanup",
                ):
                    smoke._run_chrome(
                        501,
                        20,
                        Path("/repo/browser-companion/chromium"),
                        fixture,
                        executable,
                        Path("/tmp/native-host.json"),
                        Path("/tmp/Slipstream.app/Contents/MacOS/slipstream"),
                    )

            remove_profile.assert_not_called()

    def test_partial_bootstrap_stops_browser_after_launcher_absence_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable = _fake_chrome_for_testing(root)
            profile = root / "profile"
            profile.mkdir()
            fixture = mock.Mock(port=18443)
            with mock.patch.object(
                smoke.lifecycle,
                "_user_environment",
                return_value=({"HOME": str(root)}, root),
            ), mock.patch.object(
                smoke.lifecycle,
                "_user_supplementary_groups",
                return_value=(12, 61),
            ), mock.patch.object(
                smoke,
                "_install_profile_native_host",
            ), mock.patch.object(
                smoke,
                "_install_chrome_for_testing_native_host",
                return_value=smoke.NativeHostRegistration(
                    Path("/tmp/chrome-for-testing-native-host.json"),
                    (),
                ),
            ), mock.patch.object(
                smoke,
                "_remove_chrome_for_testing_native_host",
            ), mock.patch.object(
                smoke,
                "_remove_owned_profile",
            ) as remove_profile, mock.patch.object(
                smoke.tempfile,
                "mkdtemp",
                return_value=str(profile),
            ), mock.patch.object(
                smoke.os,
                "chown",
            ), mock.patch.object(
                smoke,
                "_write_owner_private_file",
            ), mock.patch.object(
                smoke,
                "_bootstrap_chrome_launch_agent",
                side_effect=smoke.QualificationError("identity polling failed"),
            ), mock.patch.object(
                smoke,
                "_wait_for_launch_agent_absence",
                side_effect=smoke.QualificationError("job still loaded"),
            ), mock.patch.object(
                smoke,
                "_stop_owned_chrome_processes",
            ) as stop_browser, mock.patch.object(
                smoke,
                "_read_owner_private_tail",
                return_value=b"",
            ):
                with self.assertRaisesRegex(
                    smoke.QualificationError,
                    "profile retained until LaunchAgent cleanup",
                ):
                    smoke._run_chrome(
                        501,
                        20,
                        Path("/repo/browser-companion/chromium"),
                        fixture,
                        executable,
                        Path("/tmp/native-host.json"),
                        Path("/tmp/Slipstream.app/Contents/MacOS/slipstream"),
                    )

            stop_browser.assert_called_once_with(
                501,
                executable.resolve(),
                profile,
                mock.ANY,
                timeout=10.0,
                settle_time=5.0,
            )
            remove_profile.assert_not_called()

    def test_chrome_for_testing_validation_rejects_branded_chrome(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            executable = Path(tmp) / "Google Chrome"
            executable.write_text("binary", encoding="utf-8")
            executable.chmod(0o700)
            with mock.patch.object(
                smoke,
                "_run",
                return_value=smoke.subprocess.CompletedProcess(
                    (str(executable), "--version"),
                    0,
                    stdout="Google Chrome 148.0.0.0\n",
                    stderr="",
                ),
            ):
                with self.assertRaisesRegex(
                    smoke.QualificationError,
                    "requires Google Chrome for Testing",
                ):
                    smoke._validate_chrome_for_testing(executable)

    def test_profile_native_host_is_exact_private_owner_copy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile = root / "profile"
            profile.mkdir()
            source = root / "native-host.json"
            expected_executable = root / "Slipstream.app/Contents/MacOS/slipstream"
            payload = json.dumps(
                {
                    "name": smoke.NATIVE_HOST_NAME,
                    "description": "Slipstream Browser Companion",
                    "path": str(expected_executable),
                    "type": "stdio",
                    "allowed_origins": [smoke.NATIVE_HOST_ORIGIN],
                },
                separators=(",", ":"),
            ).encode()
            source.write_bytes(payload)
            source.chmod(0o600)
            real_write = os.write
            writes = 0

            def partial_write(fd: int, data: bytes | memoryview) -> int:
                nonlocal writes
                writes += 1
                return real_write(fd, data[:3])

            with mock.patch.object(smoke.os, "write", side_effect=partial_write):
                destination = smoke._install_profile_native_host(
                    profile,
                    source,
                    os.getuid(),
                    os.getgid(),
                    expected_executable,
                )
            self.assertEqual(destination.read_bytes(), payload)
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
            self.assertGreater(writes, 1)
            self.assertEqual(
                destination.relative_to(profile),
                smoke.PROFILE_NATIVE_HOST_RELATIVE_PATH,
            )

            source.unlink()
            foreign = root / "foreign.json"
            foreign.write_bytes(payload)
            foreign.chmod(0o600)
            source.symlink_to(foreign)
            second_profile = root / "second-profile"
            second_profile.mkdir()
            with self.assertRaises(OSError):
                smoke._install_profile_native_host(
                    second_profile,
                    source,
                    os.getuid(),
                    os.getgid(),
                    expected_executable,
                )

    def test_chrome_for_testing_native_host_uses_exact_current_location(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            home.mkdir(mode=0o700)
            expected_executable = root / "native-host"
            expected_executable.write_bytes(b"host")
            source = root / "native-host.json"
            payload = json.dumps(
                {
                    "name": smoke.NATIVE_HOST_NAME,
                    "description": "Slipstream Browser Companion",
                    "path": str(expected_executable),
                    "type": "stdio",
                    "allowed_origins": [smoke.NATIVE_HOST_ORIGIN],
                },
                separators=(",", ":"),
            ).encode()
            source.write_bytes(payload)
            source.chmod(0o600)

            registration = smoke._install_chrome_for_testing_native_host(
                home,
                source,
                os.getuid(),
                os.getgid(),
                expected_executable,
            )

            self.assertEqual(
                registration.path.relative_to(home),
                smoke.CHROME_FOR_TESTING_NATIVE_HOST_RELATIVE_PATH,
            )
            self.assertEqual(registration.path.read_bytes(), payload)
            self.assertEqual(registration.path.stat().st_mode & 0o777, 0o600)
            self.assertTrue(registration.created_directories)

            smoke._remove_chrome_for_testing_native_host(
                registration,
                expected_executable,
                os.getuid(),
            )
            self.assertFalse(registration.path.exists())
            self.assertTrue(home.exists())
            for directory in registration.created_directories:
                self.assertFalse(directory.exists())

    def test_chrome_for_testing_cleanup_preserves_nonempty_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            home = root / "home"
            home.mkdir(mode=0o700)
            expected_executable = root / "native-host"
            expected_executable.write_bytes(b"host")
            source = root / "native-host.json"
            source.write_text(
                json.dumps(
                    {
                        "name": smoke.NATIVE_HOST_NAME,
                        "description": "Slipstream Browser Companion",
                        "path": str(expected_executable),
                        "type": "stdio",
                        "allowed_origins": [smoke.NATIVE_HOST_ORIGIN],
                    }
                ),
                encoding="utf-8",
            )
            source.chmod(0o600)
            registration = smoke._install_chrome_for_testing_native_host(
                home,
                source,
                os.getuid(),
                os.getgid(),
                expected_executable,
            )
            google_directory = (
                home / "Library/Application Support/Google"
            )
            independent = google_directory / "independent"
            independent.write_bytes(b"preserve")

            smoke._remove_chrome_for_testing_native_host(
                registration,
                expected_executable,
                os.getuid(),
            )

            self.assertFalse(registration.path.exists())
            self.assertEqual(independent.read_bytes(), b"preserve")
            self.assertTrue(google_directory.exists())
            self.assertFalse(
                google_directory.joinpath("ChromeForTesting").exists()
            )

    def test_native_manifest_must_be_private_exact_origin_and_packaged_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            executable = home / "Slipstream.app/Contents/MacOS/slipstream"
            executable.parent.mkdir(parents=True)
            executable.write_text("binary", encoding="utf-8")
            manifest = home / smoke.NATIVE_HOST_RELATIVE_PATH
            manifest.parent.mkdir(parents=True)
            manifest.write_text(
                json.dumps(
                    {
                        "name": smoke.NATIVE_HOST_NAME,
                        "description": "Slipstream Browser Companion",
                        "path": str(executable),
                        "type": "stdio",
                        "allowed_origins": [smoke.NATIVE_HOST_ORIGIN],
                    }
                ),
                encoding="utf-8",
            )
            manifest.chmod(0o600)
            self.assertEqual(
                smoke._wait_for_native_host(
                    home,
                    executable,
                    os.getuid(),
                    timeout=0.1,
                ),
                manifest,
            )
            smoke._remove_exact_native_host(
                manifest,
                executable,
                os.getuid(),
            )
            self.assertFalse(manifest.exists())

            manifest.write_text(
                json.dumps(
                    {
                        "name": smoke.NATIVE_HOST_NAME,
                        "path": str(executable),
                        "type": "stdio",
                        "allowed_origins": ["chrome-extension://foreign/"],
                    }
                ),
                encoding="utf-8",
            )
            manifest.chmod(0o600)
            with self.assertRaisesRegex(
                smoke.QualificationError,
                "foreign native host",
            ):
                smoke._remove_exact_native_host(
                    manifest,
                    executable,
                    os.getuid(),
                )
            self.assertTrue(manifest.exists())

            manifest.chmod(0o644)
            with self.assertRaises(smoke.QualificationError):
                smoke._wait_for_native_host(
                    home,
                    executable,
                    os.getuid(),
                    timeout=0.01,
                )

    def test_learned_route_state_requires_root_private_future_expiry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "auto-geph.json"
            learned = {smoke.FIXTURE_HOST: smoke.time.time() + 60}
            with mock.patch.object(smoke, "AUTO_GEPH_STATE", state), mock.patch.object(
                smoke,
                "_read_private_json",
                return_value=learned,
            ) as read:
                expiry = smoke._wait_for_learned_host(
                    smoke.FIXTURE_HOST,
                    timeout=0.1,
                )
            self.assertGreater(expiry, smoke.time.time())
            read.assert_called_once_with(state, 0)

    def test_automatic_navigation_runtime_restarts_with_exact_environment(
        self,
    ) -> None:
        system = mock.Mock()
        browser_environment = {
            key: f"value-{index}"
            for index, key in enumerate(
                sorted(
                    smoke.composed.DISPOSABLE_QUALIFICATION_ENVIRONMENT_KEYS
                )
            )
        }
        with mock.patch.object(
            smoke.composed,
            "require_disposable_ci",
        ) as require_ci, mock.patch.object(
            smoke.lifecycle,
            "_wait_for_status",
            side_effect=({"pid": 41}, {"pid": 42}),
        ) as wait_status, mock.patch.object(
            smoke.lifecycle,
            "_wait_for_path",
        ) as wait_path, mock.patch.object(
            smoke.lifecycle,
            "_patch_launchd_for_qualification",
        ) as patch_launchd:
            active = smoke._restart_daemon_for_automatic_navigation(
                system,
                browser_environment,
            )

        self.assertEqual(active, {"pid": 42})
        require_ci.assert_called_once_with()
        self.assertEqual(
            system.run.call_args_list,
            [
                mock.call(
                    (
                        "/bin/launchctl",
                        "bootout",
                        "system",
                        str(smoke.lifecycle.LAUNCHD_PLIST),
                    )
                ),
                mock.call(
                    (
                        "/bin/launchctl",
                        "bootstrap",
                        "system",
                        str(smoke.lifecycle.LAUNCHD_PLIST),
                    )
                ),
            ],
        )
        wait_path.assert_called_once_with(
            smoke.lifecycle.STATUS_PATH,
            present=False,
        )
        patch_launchd.assert_called_once_with(
            smoke.lifecycle.LAUNCHD_PLIST,
            browser_environment,
        )
        self.assertEqual(
            wait_status.call_args_list,
            [
                mock.call("active"),
                mock.call("active", previous_pid=41, timeout=60),
            ],
        )

    def test_fresh_chrome_profile_cleanup_is_mandatory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp) / "profile"
            profile.mkdir()
            smoke._remove_owned_profile(profile)
            self.assertFalse(profile.exists())

            profile.mkdir()
            with mock.patch.object(smoke.shutil, "rmtree"):
                with self.assertRaisesRegex(
                    smoke.QualificationError,
                    "profile survived cleanup",
                ):
                    smoke._remove_owned_profile(profile)

    def test_dry_run_describes_real_composition_without_production_override(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(smoke.main(["--dry-run"]), 0)
        payload = json.loads(output.getvalue())
        self.assertIn("packaged native host", payload["path"])
        self.assertIn("Chrome for Testing", payload["browser"])
        self.assertIn(
            "disposable browser profile",
            payload["native_host_registration"],
        )
        self.assertEqual(payload["production_overrides"], "none")
        self.assertEqual(payload["chrome_sandbox"], "enabled")
        self.assertIn("LaunchServices", payload["browser_launch"])

        source = (
            ROOT / "scripts/chromium_semantic_packaged_smoke.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("SLIP_GEPH_PORT", source)
        self.assertNotIn("Math.random", source)

    def test_cli_keeps_the_launchservices_browser_sandboxed(self) -> None:
        output = io.StringIO()
        with mock.patch.object(
            smoke,
            "run_qualification",
            return_value={"result": "pass"},
        ) as qualify, redirect_stdout(output):
            self.assertEqual(
                smoke.main(
                    [
                        "--app-bundle",
                        "/tmp/Slipstream.app",
                        "--chrome-executable",
                        "/tmp/Chrome for Testing",
                    ]
                ),
                0,
            )

        qualify.assert_called_once_with(
            Path("/tmp/Slipstream.app"),
            Path("/tmp/Chrome for Testing"),
            smoke.DEFAULT_EXTENSION,
        )
        self.assertEqual(json.loads(output.getvalue()), {"result": "pass"})

    def test_protected_workflow_composes_geph_and_semantic_gates_without_secret_leak(self) -> None:
        workflow = (
            ROOT / ".github/workflows/owned-geph-qualification.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("geph_owned_lifecycle_smoke.py", workflow)
        self.assertIn("chromium_semantic_packaged_smoke.py", workflow)
        self.assertIn(
            "browser-actions/setup-chrome@2e1d749697dd1612b833dba4a722266286fbefcd",
            workflow,
        )
        self.assertIn("chrome-version: 151.0.7922.77", workflow)
        source = (
            ROOT / "scripts/chromium_semantic_packaged_smoke.py"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "automatic_fixture = composed.ComposedHttpsFixture()",
            source,
        )
        self.assertIn(
            '--chrome-executable "${{ steps.chrome-for-testing.outputs.chrome-path }}"',
            workflow,
        )
        self.assertNotIn("--ci-disable-chrome-sandbox", workflow)
        self.assertIn("env -u SLIPSTREAM_GEPH_ACCOUNT_SECRET", workflow)
        self.assertIn("env -u SLIPSTREAM_GEPH_ACCOUNT_SECRET sudo -E", workflow)
        self.assertEqual(
            workflow.count("secrets.SLIPSTREAM_GEPH_ACCOUNT_SECRET"),
            1,
        )
        self.assertIn("test ! -e /var/run/slipstream-autogeph.json", workflow)
        self.assertIn("test ! -e /var/run/slipstream-semantic.sock", workflow)
        self.assertIn(
            "Google/Chrome/NativeMessagingHosts/dev.slipstream.semantic.json",
            workflow,
        )


if __name__ == "__main__":
    unittest.main()
