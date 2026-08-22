from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import live_site_browser_diagnostic as diagnostic


class LiveSiteBrowserDiagnosticTests(unittest.TestCase):
    def _executable(self, root: Path) -> Path:
        executable = root / "chrome"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o700)
        return executable

    def _chrome_evidence(self, *, same_host: bool = True) -> dict[str, object]:
        return {
            "result": {
                "value": {
                    "evidence": {
                        "challenge_detected": False,
                        "denial_detected": False,
                        "document_bytes": 1_000,
                        "signals": {
                            "app_text_length": 100,
                            "body_text_length": 1_000,
                            "https": True,
                            "main_text_length": 1_000,
                            "next_hop_protocol": "h2",
                            "preloader_visible": False,
                            "ready_state": "complete",
                            "secure_context": True,
                            "title": "Aikido Security",
                            "visible_app": True,
                            "visible_body": True,
                            "visible_challenge_marker": False,
                        },
                    },
                    "same_host": same_host,
                }
            }
        }

    def test_direct_environment_drops_proxy_variables_and_ci_secrets(self) -> None:
        profile = Path("/tmp/slipstream-diagnostic-profile")
        with mock.patch.dict(
            os.environ,
            {
                "HTTP_PROXY": "http://example.invalid",
                "https_proxy": "http://example.invalid",
                "GITHUB_TOKEN": "token",
                "AWS_SECRET_ACCESS_KEY": "secret",
                "LANG": "C",
            },
            clear=True,
        ):
            environment = diagnostic._direct_environment(profile)

        self.assertNotIn("HTTP_PROXY", environment)
        self.assertNotIn("https_proxy", environment)
        self.assertNotIn("GITHUB_TOKEN", environment)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", environment)
        self.assertEqual(environment["LANG"], "C")
        self.assertEqual(environment["HOME"], str(profile))
        self.assertEqual(environment["TMPDIR"], str(profile))

    def test_direct_environment_uses_only_the_temporary_home(self) -> None:
        profile = Path("/tmp/slipstream-diagnostic-profile")

        environment = diagnostic._direct_environment(profile)

        self.assertEqual(environment["HOME"], str(profile))

    def test_cross_origin_evidence_fails_closed(self) -> None:
        envelope = self._chrome_evidence(same_host=False)["result"]["value"]

        self.assertEqual(
            diagnostic._classify_diagnostic_evidence("app.aikido.dev", envelope),
            ("terminal_error", "origin_mismatch"),
        )

    def test_diagnostic_expression_exposes_only_a_same_host_boolean(self) -> None:
        expression = diagnostic._diagnostic_evidence_expression("weather.com")

        self.assertIn("location.hostname.toLowerCase()", expression)
        self.assertIn('"weather.com"', expression)
        self.assertNotIn("location.href", expression)

    def test_chrome_command_is_headless_and_does_not_use_a_proxy(self) -> None:
        command = diagnostic._chrome_command(Path("/tmp/chrome"), Path("/tmp/profile"))

        self.assertIn("--headless=new", command)
        self.assertIn("--no-proxy-server", command)
        self.assertIn("--disable-extensions", command)
        self.assertNotIn("--no-sandbox", command)
        self.assertIn("--user-data-dir=/tmp/profile", command)

    def test_one_host_diagnostic_is_explicitly_non_release_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable = self._executable(Path(temporary))
            process = mock.Mock(pid=1234)
            targets = [
                {
                    "type": "page",
                    "url": "about:blank",
                    "webSocketDebuggerUrl": "ws://127.0.0.1:9222/devtools/page/1",
                }
            ]
            with (
                mock.patch.object(
                    diagnostic.subprocess, "Popen", return_value=process
                ) as popen,
                mock.patch.object(
                    diagnostic.release.chromium,
                    "_wait_for_devtools_port",
                    return_value=9222,
                ),
                mock.patch.object(
                    diagnostic.release.chromium,
                    "_devtools_json",
                    return_value=targets,
                ),
                mock.patch.object(
                    diagnostic.release.chromium,
                    "_devtools_command",
                    side_effect=[{}, self._chrome_evidence()],
                ),
                mock.patch.object(diagnostic, "_terminate_process", return_value=True),
            ):
                report = diagnostic.run_diagnostic("app.aikido.dev", executable)

        self.assertTrue(report["diagnostic_only"])
        self.assertFalse(report["release_eligible"])
        self.assertEqual(report["host"], "app.aikido.dev")
        self.assertEqual(report["result"]["outcome"], "usable")
        self.assertEqual(
            report["result"]["route"], "unverified_local_environment"
        )
        command = popen.call_args.args[0]
        self.assertIn("--headless=new", command)
        self.assertIn("--no-proxy-server", command)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertTrue(popen.call_args.kwargs["close_fds"])
        self.assertNotIn("GITHUB_TOKEN", popen.call_args.kwargs["env"])

    def test_termination_signals_the_original_group_before_reaping_its_leader(self) -> None:
        process = mock.Mock(pid=1234)
        process.poll.return_value = 0
        with mock.patch.object(
            diagnostic.os,
            "killpg",
            side_effect=(None, None, ProcessLookupError()),
        ) as killpg:
            self.assertTrue(diagnostic._terminate_process(process))

        self.assertEqual(
            killpg.call_args_list,
            [
                mock.call(1234, 0),
                mock.call(1234, diagnostic.signal.SIGTERM),
                mock.call(1234, 0),
            ],
        )
        process.wait.assert_called_once_with(
            timeout=diagnostic.TEARDOWN_TIMEOUT_SECONDS
        )

    def test_termination_does_not_signal_a_group_that_survives_reaping(self) -> None:
        process = mock.Mock(pid=1234)
        process.poll.return_value = 0
        with mock.patch.object(
            diagnostic.os,
            "killpg",
            side_effect=(None, None),
        ) as killpg:
            with mock.patch.object(
                diagnostic, "_wait_for_process_group_absence", return_value=False
            ):
                self.assertFalse(diagnostic._terminate_process(process))

        self.assertEqual(
            killpg.call_args_list,
            [
                mock.call(1234, 0),
                mock.call(1234, diagnostic.signal.SIGTERM),
            ],
        )
        process.wait.assert_called_once_with(
            timeout=diagnostic.TEARDOWN_TIMEOUT_SECONDS
        )

    def test_termination_kills_a_timed_out_owned_group_before_reaping(self) -> None:
        process = mock.Mock(pid=1234)
        process.poll.return_value = 0
        process.wait.side_effect = (
            diagnostic.subprocess.TimeoutExpired(["chrome"], 10),
            None,
        )
        with mock.patch.object(
            diagnostic.os,
            "killpg",
            side_effect=(None, None, None),
        ) as killpg:
            with mock.patch.object(
                diagnostic, "_wait_for_process_group_absence", return_value=True
            ):
                self.assertTrue(diagnostic._terminate_process(process))

        self.assertEqual(
            killpg.call_args_list,
            [
                mock.call(1234, 0),
                mock.call(1234, diagnostic.signal.SIGTERM),
                mock.call(1234, diagnostic.signal.SIGKILL),
            ],
        )
        self.assertEqual(
            process.wait.call_args_list,
            [
                mock.call(timeout=diagnostic.TEARDOWN_TIMEOUT_SECONDS),
                mock.call(timeout=diagnostic.TEARDOWN_TIMEOUT_SECONDS),
            ],
        )

    def test_unknown_host_is_rejected_before_a_browser_starts(self) -> None:
        with self.assertRaisesRegex(ValueError, "fixed diagnostic allowlist"):
            diagnostic.run_diagnostic("example.com", Path("/does-not-matter"))

    def test_diagnostic_source_cannot_be_mistaken_for_a_privileged_gate(self) -> None:
        source = Path(diagnostic.__file__).read_text(encoding="utf-8")

        for forbidden in (
            "pfctl",
            "launchctl",
            "SLIPSTREAM_GEPH_ACCOUNT_SECRET",
            "SLIPSTREAM_RELEASE_READINESS",
            "sudo",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
