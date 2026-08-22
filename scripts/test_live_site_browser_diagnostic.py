from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import live_site_browser_diagnostic as diagnostic


class LiveSiteBrowserDiagnosticTests(unittest.TestCase):
    def _executable(self, root: Path) -> Path:
        executable = root / "chrome-headless-shell"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o700)
        return executable

    def _chrome_evidence(
        self, *, host_state: str = "same_host"
    ) -> dict[str, object]:
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
                    "host_state": host_state,
                }
            }
        }

    def _report(
        self,
        *,
        outcome: str,
        reason: str,
        diagnostic_completed: bool,
    ) -> dict[str, object]:
        return {
            "browser": "chrome-headless",
            "diagnostic_completed": diagnostic_completed,
            "diagnostic_only": True,
            "host": "app.aikido.dev",
            "release_eligible": False,
            "result": {
                "browser": "chrome-headless",
                "deadline_ms": 30_000,
                "elapsed_ms": 1_000,
                "outcome": outcome,
                "reason": reason,
                "route": "unverified_local_environment",
            },
            "schema_version": diagnostic.SCHEMA_VERSION,
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
        envelope = self._chrome_evidence(host_state="other_host")["result"]["value"]

        self.assertEqual(
            diagnostic._classify_diagnostic_evidence("app.aikido.dev", envelope),
            ("terminal_error", "origin_mismatch"),
        )

    def test_uncommitted_navigation_remains_pending(self) -> None:
        envelope = self._chrome_evidence(host_state="not_committed")["result"][
            "value"
        ]

        self.assertEqual(
            diagnostic._classify_diagnostic_evidence("app.aikido.dev", envelope),
            ("terminal_error", "navigation_pending"),
        )

    def test_diagnostic_expression_exposes_only_a_fixed_host_state(self) -> None:
        expression = diagnostic._diagnostic_evidence_expression("weather.com")

        self.assertIn("location.hostname.toLowerCase()", expression)
        self.assertIn('"weather.com"', expression)
        self.assertIn('"same_host"', expression)
        self.assertIn('"not_committed"', expression)
        self.assertIn('"other_host"', expression)
        self.assertNotIn("location.href", expression)

    def test_target_host_state_exposes_no_raw_target_url(self) -> None:
        debugger = "ws://127.0.0.1:9222/devtools/page/1"
        target = {
            "type": "page",
            "url": "https://app.aikido.dev/private/path?secret=value",
            "webSocketDebuggerUrl": debugger,
        }

        self.assertEqual(
            diagnostic._target_host_state([target], debugger, "app.aikido.dev"),
            "same_host",
        )
        target["url"] = "about:blank"
        self.assertEqual(
            diagnostic._target_host_state([target], debugger, "app.aikido.dev"),
            "not_committed",
        )
        target["url"] = "https://example.com/private"
        self.assertEqual(
            diagnostic._target_host_state([target], debugger, "app.aikido.dev"),
            "other_host",
        )
        target["url"] = "http://app.aikido.dev/insecure"
        self.assertEqual(
            diagnostic._target_host_state([target], debugger, "app.aikido.dev"),
            "other_host",
        )

    def test_chrome_command_is_headless_and_does_not_use_a_proxy(self) -> None:
        command = diagnostic._chrome_command(Path("/tmp/chrome"), Path("/tmp/profile"))

        self.assertIn("--headless=new", command)
        self.assertIn("--no-proxy-server", command)
        self.assertIn("--disable-extensions", command)
        self.assertIn("--use-mock-keychain", command)
        self.assertNotIn("--no-sandbox", command)
        self.assertIn("--user-data-dir=/tmp/profile", command)

    def test_consumer_google_chrome_is_rejected_before_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "Google Chrome"
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o700)
            with mock.patch.object(diagnostic.subprocess, "Popen") as popen:
                with self.assertRaisesRegex(ValueError, "Chrome for Testing"):
                    diagnostic.run_diagnostic("app.aikido.dev", executable)

        popen.assert_not_called()

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
        self.assertTrue(report["diagnostic_completed"])
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

    def test_navigation_timeout_continues_bounded_semantic_observation(self) -> None:
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
                ),
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
                    side_effect=[TimeoutError(), self._chrome_evidence()],
                ) as command,
                mock.patch.object(diagnostic, "_terminate_process", return_value=True),
            ):
                report = diagnostic.run_diagnostic("app.aikido.dev", executable)

        self.assertEqual(report["result"]["outcome"], "usable")
        self.assertEqual(command.call_args_list[0].args[2], "Page.navigate")
        self.assertEqual(command.call_args_list[1].args[2], "Runtime.evaluate")

    def test_navigation_timeout_without_commit_ends_as_pending(self) -> None:
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

            def command(
                _debugger: str,
                _port: int,
                method: str,
                _params: dict[str, object],
                **_kwargs: object,
            ) -> dict[str, object]:
                if method == "Page.navigate":
                    raise TimeoutError
                return self._chrome_evidence(host_state="not_committed")

            site = dict(diagnostic.release.SITES["app.aikido.dev"])
            site["deadline_ms"] = 20
            with (
                mock.patch.object(
                    diagnostic.subprocess, "Popen", return_value=process
                ),
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
                    side_effect=command,
                ),
                mock.patch.object(diagnostic, "_terminate_process", return_value=True),
                mock.patch.dict(
                    diagnostic.release.SITES,
                    {"app.aikido.dev": site},
                ),
            ):
                report = diagnostic.run_diagnostic("app.aikido.dev", executable)

        self.assertTrue(report["diagnostic_completed"])
        self.assertEqual(
            (report["result"]["outcome"], report["result"]["reason"]),
            ("terminal_error", "navigation_pending"),
        )

    def test_navigation_timeout_without_evidence_is_a_harness_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable = self._executable(Path(temporary))
            process = mock.Mock(pid=1234)
            targets = [
                {
                    "type": "page",
                    "url": "about:blank",
                    "webSocketDebuggerUrl": (
                        "ws://127.0.0.1:9222/devtools/page/1"
                    ),
                }
            ]

            def command(
                _debugger: str,
                _port: int,
                method: str,
                _params: dict[str, object],
                **_kwargs: object,
            ) -> dict[str, object]:
                if method == "Page.navigate":
                    raise TimeoutError
                raise diagnostic.release.chromium.QualificationError(
                    "no valid evidence"
                )

            site = dict(diagnostic.release.SITES["app.aikido.dev"])
            site["deadline_ms"] = 20
            with (
                mock.patch.object(
                    diagnostic.subprocess, "Popen", return_value=process
                ),
                mock.patch.object(
                    diagnostic.release.chromium,
                    "_wait_for_devtools_port",
                    return_value=9222,
                ),
                mock.patch.object(
                    diagnostic.release.chromium,
                    "_devtools_json",
                    side_effect=(
                        targets,
                        diagnostic.release.chromium.QualificationError(
                            "target list unavailable"
                        ),
                    ),
                ),
                mock.patch.object(
                    diagnostic.release.chromium,
                    "_devtools_command",
                    side_effect=command,
                ),
                mock.patch.object(diagnostic, "_terminate_process", return_value=True),
                mock.patch.dict(
                    diagnostic.release.SITES,
                    {"app.aikido.dev": site},
                ),
            ):
                report = diagnostic.run_diagnostic("app.aikido.dev", executable)

        self.assertFalse(report["diagnostic_completed"])
        self.assertEqual(
            (report["result"]["outcome"], report["result"]["reason"]),
            ("terminal_error", "browser_observation_failed"),
        )

    def test_navigation_timeout_accepts_a_valid_target_state_observation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable = self._executable(Path(temporary))
            process = mock.Mock(pid=1234)
            debugger = "ws://127.0.0.1:9222/devtools/page/1"
            initial_targets = [
                {
                    "type": "page",
                    "url": "about:blank",
                    "webSocketDebuggerUrl": debugger,
                }
            ]
            observed_targets = [
                {
                    "type": "page",
                    "url": "https://app.aikido.dev/private/path",
                    "webSocketDebuggerUrl": debugger,
                }
            ]

            def command(
                _debugger: str,
                _port: int,
                method: str,
                _params: dict[str, object],
                **_kwargs: object,
            ) -> dict[str, object]:
                if method == "Page.navigate":
                    raise TimeoutError
                raise diagnostic.release.chromium.QualificationError(
                    "execution context pending"
                )

            site = dict(diagnostic.release.SITES["app.aikido.dev"])
            site["deadline_ms"] = 20
            with (
                mock.patch.object(
                    diagnostic.subprocess, "Popen", return_value=process
                ),
                mock.patch.object(
                    diagnostic.release.chromium,
                    "_wait_for_devtools_port",
                    return_value=9222,
                ),
                mock.patch.object(
                    diagnostic.release.chromium,
                    "_devtools_json",
                    side_effect=(initial_targets, observed_targets),
                ),
                mock.patch.object(
                    diagnostic.release.chromium,
                    "_devtools_command",
                    side_effect=command,
                ),
                mock.patch.object(diagnostic, "_terminate_process", return_value=True),
                mock.patch.dict(
                    diagnostic.release.SITES,
                    {"app.aikido.dev": site},
                ),
            ):
                report = diagnostic.run_diagnostic("app.aikido.dev", executable)

        self.assertTrue(report["diagnostic_completed"])
        self.assertEqual(
            (report["result"]["outcome"], report["result"]["reason"]),
            ("terminal_error", "navigation_pending"),
        )

    def test_navigation_error_text_remains_rejected(self) -> None:
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
                ),
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
                    return_value={"errorText": "net::ERR_FAILED"},
                ),
                mock.patch.object(diagnostic, "_terminate_process", return_value=True),
            ):
                report = diagnostic.run_diagnostic("app.aikido.dev", executable)

        self.assertEqual(
            (report["result"]["outcome"], report["result"]["reason"]),
            ("terminal_error", "navigation_rejected"),
        )

    def test_navigation_harness_failures_are_not_completed_findings(self) -> None:
        failures = (
            (
                "navigation protocol",
                diagnostic.release.chromium.QualificationError("protocol failure"),
            ),
            ("navigation transport", OSError("transport failure")),
            (
                "post-timeout transport",
                [TimeoutError(), OSError("evaluation transport failure")],
            ),
        )
        for name, failure in failures:
            with (
                self.subTest(failure=name),
                tempfile.TemporaryDirectory() as temporary,
            ):
                executable = self._executable(Path(temporary))
                process = mock.Mock(pid=1234)
                targets = [
                    {
                        "type": "page",
                        "url": "about:blank",
                        "webSocketDebuggerUrl": (
                            "ws://127.0.0.1:9222/devtools/page/1"
                        ),
                    }
                ]
                with (
                    mock.patch.object(
                        diagnostic.subprocess, "Popen", return_value=process
                    ),
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
                        side_effect=failure,
                    ),
                    mock.patch.object(
                        diagnostic, "_terminate_process", return_value=True
                    ),
                ):
                    report = diagnostic.run_diagnostic(
                        "app.aikido.dev", executable
                    )

            self.assertFalse(report["diagnostic_completed"])
            self.assertEqual(
                (report["result"]["outcome"], report["result"]["reason"]),
                ("terminal_error", "browser_observation_failed"),
            )

    def test_termination_signals_group_before_reaping_leader(self) -> None:
        events: list[str] = []
        process = mock.Mock(pid=1234, returncode=None)
        process.wait.side_effect = lambda **_kwargs: events.append("reap")
        with (
            mock.patch.object(
                diagnostic.os, "getpgid", return_value=1234
            ),
            mock.patch.object(
                diagnostic,
                "_owned_live_process_group_pids",
                side_effect=((1234, 1235), (), ()),
            ),
            mock.patch.object(
                diagnostic,
                "_signal_owned_process_group",
                side_effect=lambda *_args: events.append("term"),
            ) as send_signal,
            mock.patch.object(
                diagnostic,
                "_wait_for_process_group_absence",
                side_effect=lambda *_args: events.append("verify") or True,
            ) as wait_for_absence,
        ):
            self.assertTrue(diagnostic._terminate_process(process))

        send_signal.assert_called_once_with(1234, (1234, 1235), signal.SIGTERM)
        self.assertEqual(events, ["term", "reap", "verify"])
        wait_for_absence.assert_called_once_with(
            1234,
            diagnostic.TEARDOWN_TIMEOUT_SECONDS,
        )

    def test_group_signal_uses_one_atomic_killpg(self) -> None:
        with (
            mock.patch.object(diagnostic.os, "killpg") as killpg,
            mock.patch.object(diagnostic.os, "kill") as kill_process,
            mock.patch.object(diagnostic.os, "getpgid") as get_process_group,
        ):
            diagnostic._signal_owned_process_group(
                1234,
                (1234, 1235),
                signal.SIGKILL,
            )

        killpg.assert_called_once_with(1234, signal.SIGKILL)
        kill_process.assert_not_called()
        get_process_group.assert_not_called()

    def test_group_signal_accepts_zombie_only_macos_permission_result(self) -> None:
        with (
            mock.patch.object(
                diagnostic.os,
                "killpg",
                side_effect=PermissionError("zombie-only group"),
            ),
            mock.patch.object(
                diagnostic,
                "_owned_live_process_group_pids",
                return_value=(),
            ),
        ):
            diagnostic._signal_owned_process_group(
                1234,
                (1234,),
                signal.SIGKILL,
            )

    def test_group_signal_permission_failure_with_live_member_is_fatal(self) -> None:
        with (
            mock.patch.object(
                diagnostic.os,
                "killpg",
                side_effect=PermissionError("live group denied"),
            ),
            mock.patch.object(
                diagnostic,
                "_owned_live_process_group_pids",
                return_value=(1235,),
            ),
            self.assertRaises(PermissionError),
        ):
            diagnostic._signal_owned_process_group(
                1234,
                (1235,),
                signal.SIGKILL,
            )

    def test_profile_removal_retries_a_transient_filesystem_race(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "slipstream-diagnostic-chrome-test"
            profile.mkdir(mode=0o700)
            (profile / "DevToolsActivePort").write_text("test", encoding="utf-8")
            real_rmtree = diagnostic.shutil.rmtree
            attempts = 0

            def flaky_rmtree(path: Path) -> None:
                nonlocal attempts
                attempts += 1
                if attempts == 1:
                    raise OSError("transient removal race")
                real_rmtree(path)

            with (
                mock.patch.object(
                    diagnostic.shutil, "rmtree", side_effect=flaky_rmtree
                ),
                mock.patch.object(diagnostic.time, "sleep"),
            ):
                self.assertTrue(diagnostic._remove_owned_profile(profile))

            self.assertFalse(profile.exists())
            self.assertEqual(attempts, 2)

    def test_profile_removal_rejects_a_replaced_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target"
            target.mkdir()
            profile = root / "slipstream-diagnostic-chrome-test"
            profile.symlink_to(target, target_is_directory=True)

            self.assertFalse(diagnostic._remove_owned_profile(profile))
            self.assertTrue(profile.is_symlink())
            self.assertTrue(target.is_dir())

    def test_termination_fails_closed_when_group_inspection_fails(self) -> None:
        process = mock.Mock(pid=1234, returncode=None)
        with (
            mock.patch.object(
                diagnostic.os, "getpgid", return_value=1234
            ),
            mock.patch.object(
                diagnostic,
                "_owned_live_process_group_pids",
                side_effect=diagnostic.release.lifecycle.LifecycleError(
                    "cleanup failed"
                ),
            ),
            mock.patch.object(
                diagnostic, "_wait_for_process_group_absence"
            ) as wait_for_absence,
        ):
            self.assertFalse(diagnostic._terminate_process(process))

        process.kill.assert_called_once_with()
        process.wait.assert_called_once_with(
            timeout=diagnostic.TEARDOWN_TIMEOUT_SECONDS
        )
        wait_for_absence.assert_not_called()

    def test_termination_fails_closed_if_a_group_survives_after_reaping(self) -> None:
        process = mock.Mock(pid=1234, returncode=None)
        with (
            mock.patch.object(
                diagnostic.os, "getpgid", return_value=1234
            ),
            mock.patch.object(
                diagnostic,
                "_owned_live_process_group_pids",
                side_effect=((), (), ()),
            ),
            mock.patch.object(
                diagnostic, "_wait_for_process_group_absence", return_value=False
            ),
        ):
            self.assertFalse(diagnostic._terminate_process(process))

    @unittest.skipUnless(hasattr(os, "killpg"), "requires POSIX process groups")
    def test_live_termination_removes_lingering_helper_and_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "slipstream-diagnostic-chrome-live"
            profile.mkdir(mode=0o700)
            child_pid_path = profile / "child.pid"
            leader_source = """
import pathlib
import signal
import subprocess
import sys
import time

child = subprocess.Popen(
    [
        sys.executable,
        "-c",
        "import signal,time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "time.sleep(30)",
    ]
)
pathlib.Path(sys.argv[1]).write_text(str(child.pid), encoding="ascii")
time.sleep(30)
"""
            process = subprocess.Popen(
                (sys.executable, "-c", leader_source, str(child_pid_path)),
                start_new_session=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            child_pid: int | None = None
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if child_pid_path.exists():
                        child_pid = int(child_pid_path.read_text(encoding="ascii"))
                        break
                    if process.poll() is not None:
                        self.fail("synthetic process-group leader exited early")
                    time.sleep(0.05)
                self.assertIsNotNone(child_pid)

                self.assertTrue(diagnostic._terminate_process(process))
                self.assertFalse(diagnostic._process_group_exists(process.pid))
                with self.assertRaises(ProcessLookupError):
                    os.kill(child_pid, 0)
                self.assertTrue(diagnostic._remove_owned_profile(profile))
                self.assertFalse(profile.exists())
            finally:
                if child_pid is not None:
                    try:
                        if os.getpgid(child_pid) == process.pid:
                            os.kill(child_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)

    def test_unknown_host_is_rejected_before_a_browser_starts(self) -> None:
        with self.assertRaisesRegex(ValueError, "fixed diagnostic allowlist"):
            diagnostic.run_diagnostic("example.com", Path("/does-not-matter"))

    def test_main_accepts_a_completed_nonusable_diagnostic_by_default(self) -> None:
        report = self._report(
            outcome="terminal_error",
            reason="navigation_pending",
            diagnostic_completed=True,
        )
        with (
            mock.patch.object(diagnostic, "run_diagnostic", return_value=report),
            mock.patch.object(diagnostic, "_write_report"),
        ):
            result = diagnostic.main(
                [
                    "--host",
                    "app.aikido.dev",
                    "--chrome-executable",
                    "/tmp/chrome-headless-shell",
                ]
            )

        self.assertEqual(result, 0)

    def test_main_can_require_a_usable_target(self) -> None:
        report = self._report(
            outcome="terminal_error",
            reason="navigation_pending",
            diagnostic_completed=True,
        )
        with (
            mock.patch.object(diagnostic, "run_diagnostic", return_value=report),
            mock.patch.object(diagnostic, "_write_report"),
        ):
            result = diagnostic.main(
                [
                    "--host",
                    "app.aikido.dev",
                    "--chrome-executable",
                    "/tmp/chrome-headless-shell",
                    "--require-usable",
                ]
            )

        self.assertEqual(result, 1)

    def test_main_returns_harness_failure_for_incomplete_diagnostic(self) -> None:
        report = self._report(
            outcome="terminal_error",
            reason="browser_cleanup_failed",
            diagnostic_completed=False,
        )
        with (
            mock.patch.object(diagnostic, "run_diagnostic", return_value=report),
            mock.patch.object(diagnostic, "_write_report"),
        ):
            result = diagnostic.main(
                [
                    "--host",
                    "app.aikido.dev",
                    "--chrome-executable",
                    "/tmp/chrome-headless-shell",
                ]
            )

        self.assertEqual(result, 2)

    def test_main_returns_zero_for_usable_target(self) -> None:
        report = self._report(
            outcome="usable",
            reason="",
            diagnostic_completed=True,
        )
        with (
            mock.patch.object(diagnostic, "run_diagnostic", return_value=report),
            mock.patch.object(diagnostic, "_write_report"),
        ):
            result = diagnostic.main(
                [
                    "--host",
                    "app.aikido.dev",
                    "--chrome-executable",
                    "/tmp/chrome-headless-shell",
                ]
            )

        self.assertEqual(result, 0)

    def test_main_returns_harness_failure_when_report_write_fails(self) -> None:
        report = self._report(
            outcome="usable",
            reason="",
            diagnostic_completed=True,
        )
        with (
            mock.patch.object(diagnostic, "run_diagnostic", return_value=report),
            mock.patch.object(diagnostic, "_write_report", side_effect=OSError),
        ):
            result = diagnostic.main(
                [
                    "--host",
                    "app.aikido.dev",
                    "--chrome-executable",
                    "/tmp/chrome-headless-shell",
                ]
            )

        self.assertEqual(result, 2)

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
