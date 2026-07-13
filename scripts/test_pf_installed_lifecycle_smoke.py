from __future__ import annotations

import io
import json
import os
import plistlib
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import pf_installed_lifecycle_smoke as lifecycle


class PfInstalledLifecycleSmokeTests(unittest.TestCase):
    def test_command_guard_accepts_only_exact_lifecycle_commands(self) -> None:
        target = lifecycle.script_target()
        accepted = (
            target.install_command,
            target.uninstall_command,
            (
                "/bin/launchctl",
                "bootout",
                "system",
                str(lifecycle.LAUNCHD_PLIST),
            ),
            (
                "/bin/launchctl",
                "bootstrap",
                "system",
                str(lifecycle.LAUNCHD_PLIST),
            ),
            ("/bin/launchctl", "kickstart", "-k", lifecycle.LAUNCHD_LABEL),
        )
        for command in accepted:
            lifecycle.validate_system_command(command, target)

    def test_command_guard_rejects_shell_and_unowned_paths(self) -> None:
        rejected = (
            ("/bin/sh", "-c", "pfctl -d"),
            ("/bin/rm", "-rf", "/"),
            ("/bin/launchctl", "bootout", "system", "/tmp/other.plist"),
            (sys.executable, str(lifecycle.SOURCE_DAEMON), "--uninstall"),
        )
        for command in rejected:
            with self.subTest(command=command):
                with self.assertRaises(lifecycle.LifecycleError):
                    lifecycle.validate_system_command(command)

    def test_packaged_target_accepts_only_its_embedded_and_installed_daemon(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = Path(tmp) / "Slipstream.app"
            daemon = app / "Contents" / "Resources" / "slipstreamd" / "slipstreamd"
            daemon.parent.mkdir(parents=True)
            daemon.write_bytes(b"packaged-daemon")
            daemon.chmod(0o755)
            tray = app / "Contents" / "MacOS" / "slipstream"
            tray.parent.mkdir(parents=True)
            tray.write_bytes(b"packaged-tray")
            tray.chmod(0o755)

            target = lifecycle.packaged_app_target(app)

            self.assertEqual(target.name, "packaged-app")
            self.assertEqual(target.tray_executable, tray.resolve())
            lifecycle.validate_system_command(target.install_command, target)
            lifecycle.validate_system_command(target.uninstall_command, target)
            with self.assertRaises(lifecycle.LifecycleError):
                lifecycle.validate_system_command(
                    lifecycle.script_target().install_command,
                    target,
                )

    def test_packaged_target_rejects_missing_or_non_executable_daemon(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = Path(tmp) / "Slipstream.app"
            with self.assertRaises(lifecycle.LifecycleError):
                lifecycle.packaged_app_target(app)

            daemon = app / "Contents" / "Resources" / "slipstreamd" / "slipstreamd"
            daemon.parent.mkdir(parents=True)
            daemon.write_bytes(b"packaged-daemon")
            daemon.chmod(0o644)
            with self.assertRaises(lifecycle.LifecycleError):
                lifecycle.packaged_app_target(app)

    def test_packaged_target_requires_an_executable_tray(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            app = Path(tmp) / "Slipstream.app"
            daemon = app / "Contents" / "Resources" / "slipstreamd" / "slipstreamd"
            daemon.parent.mkdir(parents=True)
            daemon.write_bytes(b"packaged-daemon")
            daemon.chmod(0o755)

            with self.assertRaisesRegex(lifecycle.LifecycleError, "executable tray"):
                lifecycle.packaged_app_target(app)

            tray = app / "Contents" / "MacOS" / "slipstream"
            tray.parent.mkdir(parents=True)
            tray.write_bytes(b"packaged-tray")
            tray.chmod(0o644)
            with self.assertRaisesRegex(lifecycle.LifecycleError, "executable tray"):
                lifecycle.packaged_app_target(app)

    def test_plist_patch_enables_local_only_mode_and_disables_voice(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "daemon.plist"
            data = {
                "EnvironmentVariables": {"PATH": "/usr/bin"},
                "ProgramArguments": ["python", "tproxy.py"],
            }
            with path.open("wb") as handle:
                plistlib.dump(data, handle)

            lifecycle._patch_launchd_for_local_only(path)

            with path.open("rb") as handle:
                updated = plistlib.load(handle)
            self.assertEqual(updated["EnvironmentVariables"]["SLIP_GEPH"], "0")
            self.assertEqual(
                updated["EnvironmentVariables"]["SLIP_RUNTIME_WAKE_GAP_SECONDS"],
                "6",
            )
            self.assertIn("--no-voice", updated["ProgramArguments"])
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_disposable_guard_requires_every_ci_marker(self) -> None:
        environment = {
            "CI": "true",
            "GITHUB_ACTIONS": "true",
            "SLIPSTREAM_DISPOSABLE_CI": "1",
        }
        with mock.patch.dict(os.environ, environment, clear=True), mock.patch(
            "os.geteuid", return_value=0
        ):
            lifecycle._require_disposable_ci()
        for missing in environment:
            partial = {key: value for key, value in environment.items() if key != missing}
            with self.subTest(missing=missing), mock.patch.dict(
                os.environ, partial, clear=True
            ), mock.patch("os.geteuid", return_value=0):
                with self.assertRaises(lifecycle.LifecycleError):
                    lifecycle._require_disposable_ci()

    def test_pf_rule_port_parser_accepts_macos_output(self) -> None:
        self.assertTrue(lifecycle._rule_has_port("to any port = 443", 443))
        self.assertTrue(lifecycle._rule_has_port("port 1080", 1080))
        self.assertFalse(lifecycle._rule_has_port("port = 4430", 443))

    def test_status_daemon_view_accepts_v1_and_v2(self) -> None:
        v1 = {"state": "active", "pid": 11, "ts": 100.0}
        v2 = {
            "schema_version": 2,
            "daemon": {"state": "active", "pid": 22, "updated_at": 200.0},
        }

        self.assertEqual(lifecycle._daemon_status(v1), v1)
        self.assertEqual(lifecycle._daemon_status(v2), v2["daemon"])
        self.assertIsNone(lifecycle._daemon_status({"schema_version": 2}))

    def test_recovery_view_and_wait_require_same_fresh_daemon(self) -> None:
        status = {
            "schema_version": 2,
            "daemon": {
                "state": "active",
                "pid": 42,
                "updated_at": 500.0,
            },
            "recovery": {
                "last_action": "network_change",
                "count": 3,
            },
        }
        with mock.patch.object(lifecycle, "_read_status", return_value=status), mock.patch(
            "time.time", return_value=501.0
        ):
            observed = lifecycle._wait_for_rearm(
                "network_change",
                expected_pid=42,
                previous_count=2,
                timeout=1,
            )

        self.assertIs(observed, status)
        self.assertEqual(lifecycle._recovery_count(status), 3)
        self.assertIsNone(lifecycle._recovery_status({"state": "active"}))

    def test_wait_for_same_daemon_requires_a_new_status_update(self) -> None:
        stale = {
            "schema_version": 2,
            "daemon": {"state": "active", "pid": 42, "updated_at": 500.0},
        }
        fresh = {
            "schema_version": 2,
            "daemon": {"state": "active", "pid": 42, "updated_at": 502.0},
        }
        with mock.patch.object(
            lifecycle,
            "_read_status",
            side_effect=[stale, fresh],
        ), mock.patch("time.time", return_value=503.0), mock.patch("time.sleep"):
            observed = lifecycle._wait_for_same_daemon(
                "active",
                expected_pid=42,
                updated_after=500.0,
                timeout=1,
            )

        self.assertEqual(observed["pid"], 42)
        self.assertEqual(lifecycle._daemon_updated_at(fresh), 502.0)

    def test_daemon_signal_guard_accepts_only_exact_installed_command(self) -> None:
        target = lifecycle.script_target()
        command = " ".join((*target.installed_program_prefix, "--no-voice"))
        with mock.patch.object(
            lifecycle, "_process_command_for_pid", return_value=command
        ), mock.patch("os.kill") as kill:
            lifecycle._signal_owned_daemon(target, 42, lifecycle.RUNTIME_REARM_SIGNAL)
        kill.assert_called_once_with(42, lifecycle.RUNTIME_REARM_SIGNAL)

        with mock.patch.object(
            lifecycle,
            "_process_command_for_pid",
            return_value="/tmp/not-slipstream --no-voice",
        ), mock.patch("os.kill") as kill:
            with self.assertRaisesRegex(lifecycle.LifecycleError, "unowned pid"):
                lifecycle._signal_owned_daemon(
                    target,
                    42,
                    lifecycle.RUNTIME_REARM_SIGNAL,
                )
        kill.assert_not_called()

    def test_daemon_signal_guard_accepts_resolved_interpreter_alias(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            real_python = Path(tmp) / "Python"
            venv_python = Path(tmp) / "python3"
            script = Path(tmp) / "tproxy.py"
            real_python.write_text("python")
            venv_python.symlink_to(real_python)
            script.write_text("daemon")
            target = lifecycle.LifecycleTarget(
                name="alias-test",
                install_command=(),
                uninstall_command=(),
                installed_program_prefix=(str(venv_python), str(script)),
                required_installed_paths=(),
            )
            command = f"{real_python} {script} --no-voice"

            with mock.patch.object(
                lifecycle,
                "_process_command_for_pid",
                return_value=command,
            ), mock.patch("os.kill") as kill:
                lifecycle._signal_owned_daemon(
                    target,
                    42,
                    lifecycle.RUNTIME_REARM_SIGNAL,
                )

        kill.assert_called_once_with(42, lifecycle.RUNTIME_REARM_SIGNAL)

    def test_daemon_signal_guard_accepts_harness_base_interpreter(self) -> None:
        target = lifecycle.script_target()
        daemon_command = (
            "/Library/Frameworks/Python.framework/Versions/3.13/Resources/"
            "Python.app/Contents/MacOS/Python "
            f"{lifecycle.INSTALLED_DAEMON} --port 1080 --no-voice"
        )
        harness_command = (
            "/Library/Frameworks/Python.framework/Versions/3.13/Resources/"
            "Python.app/Contents/MacOS/Python "
            f"{Path(__file__)}"
        )
        with mock.patch.object(
            lifecycle,
            "_process_command_for_pid",
            side_effect=[daemon_command, harness_command],
        ), mock.patch("os.kill") as kill:
            lifecycle._signal_owned_daemon(
                target,
                42,
                lifecycle.RUNTIME_REARM_SIGNAL,
            )

        kill.assert_called_once_with(42, lifecycle.RUNTIME_REARM_SIGNAL)

    def test_tray_signal_guard_requires_exact_uid_and_executable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            executable = Path(tmp) / "Slipstream.app" / "Contents" / "MacOS" / "slipstream"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"tray")
            executable.chmod(0o755)
            expected = str(executable.resolve())

            with mock.patch.object(
                lifecycle,
                "_process_identity_for_pid",
                return_value=(501, expected),
            ):
                lifecycle._assert_owned_tray_pid(executable, 42, 501)

            for identity in ((502, expected), (501, "/tmp/not-slipstream"), None):
                with self.subTest(identity=identity), mock.patch.object(
                    lifecycle,
                    "_process_identity_for_pid",
                    return_value=identity,
                ):
                    with self.assertRaisesRegex(lifecycle.LifecycleError, "unowned tray"):
                        lifecycle._assert_owned_tray_pid(executable, 42, 501)

    def test_packaged_tray_crash_signals_only_the_verified_process(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            executable = Path(tmp) / "Slipstream.app" / "Contents" / "MacOS" / "slipstream"
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b"tray")
            executable.chmod(0o755)
            tray = lifecycle.PackagedTrayProcess(executable, 501, 20)
            process = mock.Mock(pid=42)
            tray.process = process
            tray.log = tempfile.TemporaryFile()

            with mock.patch.object(
                lifecycle,
                "_process_identity_for_pid",
                return_value=(501, str(executable.resolve())),
            ), mock.patch("os.kill") as kill:
                tray.crash()

        kill.assert_called_once_with(42, lifecycle.signal.SIGKILL)
        process.wait.assert_called_once_with(timeout=5)
        self.assertIsNone(tray.process)

    def test_user_environment_does_not_forward_proxy_or_ci_secrets(self) -> None:
        account = mock.Mock(pw_dir="/Users/runner", pw_name="runner")
        inherited = {
            "HTTPS_PROXY": "http://external-proxy.invalid",
            "GH_TOKEN": "secret",
            "TMPDIR": "/tmp/runner/",
            "LANG": "en_US.UTF-8",
        }
        with mock.patch.dict(os.environ, inherited, clear=True), mock.patch.object(
            lifecycle.pwd,
            "getpwuid",
            return_value=account,
        ):
            environment, home = lifecycle._user_environment(501)

        self.assertEqual(home, Path("/Users/runner"))
        self.assertNotIn("HTTPS_PROXY", environment)
        self.assertNotIn("GH_TOKEN", environment)
        self.assertEqual(environment["HOME"], "/Users/runner")
        self.assertEqual(environment["TMPDIR"], "/tmp/runner/")

    def test_https_probe_is_fresh_non_proxy_ipv4_client(self) -> None:
        command = lifecycle._https_probe_command("After Tray Crash")

        self.assertEqual(command[0], "/usr/bin/curl")
        self.assertIn("--ipv4", command)
        self.assertIn("--http1.1", command)
        self.assertEqual(command[command.index("--noproxy") + 1], "*")
        self.assertEqual(
            command[-1],
            "https://github.com/robots.txt?slipstream-lifecycle=after-tray-crash",
        )

    def test_chrome_probe_uses_a_clean_profile_and_tcp_without_proxy(self) -> None:
        executable = Path(
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        )
        profile = Path("/tmp/slipstream-chrome-test")
        command = lifecycle._chrome_probe_command(
            executable,
            profile,
            "After Tray Crash",
        )

        self.assertEqual(command[0], str(executable))
        self.assertIn("--headless=new", command)
        self.assertIn("--disable-quic", command)
        self.assertIn("--no-proxy-server", command)
        self.assertIn(f"--user-data-dir={profile}", command)
        self.assertEqual(
            command[-1],
            "https://github.com/robots.txt?slipstream-chrome=after-tray-crash",
        )

    def test_run_chrome_probe_drops_privileges_and_removes_profile(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            executable = Path(tmp) / "Google Chrome"
            executable.write_bytes(b"chrome")
            executable.chmod(0o755)
            completed = mock.Mock(
                returncode=0,
                stdout=(
                    lifecycle.CHROME_PROBE_MARKER
                    + b"x" * lifecycle.CHROME_PROBE_MIN_BYTES
                ),
                stderr=b"",
            )

            observed_profile_mode = None

            def run_probe(command, **_kwargs):
                nonlocal observed_profile_mode
                profile_argument = next(
                    argument
                    for argument in command
                    if argument.startswith("--user-data-dir=")
                )
                profile = Path(profile_argument.split("=", 1)[1])
                observed_profile_mode = profile.stat().st_mode & 0o777
                return completed

            with mock.patch.object(
                lifecycle,
                "_user_environment",
                return_value=({"HOME": tmp}, Path(tmp)),
            ), mock.patch.object(lifecycle.os, "chown") as chown, mock.patch.object(
                lifecycle.subprocess,
                "run",
                side_effect=run_probe,
            ) as run:
                size = lifecycle._run_chrome_probe(
                    501,
                    20,
                    "After Tray Crash",
                    executable,
                )

        self.assertEqual(size, len(completed.stdout))
        self.assertEqual(observed_profile_mode, 0o700)
        chown.assert_called_once()
        command = run.call_args.args[0]
        profile_argument = next(
            argument for argument in command if argument.startswith("--user-data-dir=")
        )
        profile = Path(profile_argument.split("=", 1)[1])
        self.assertFalse(profile.exists())
        self.assertEqual(run.call_args.kwargs["user"], 501)
        self.assertEqual(run.call_args.kwargs["group"], 20)
        self.assertEqual(run.call_args.kwargs["extra_groups"], ())

    def test_run_chrome_probe_rejects_an_unavailable_executable(self) -> None:
        with self.assertRaisesRegex(lifecycle.LifecycleError, "unavailable"):
            lifecycle._run_chrome_probe(
                501,
                20,
                "missing",
                Path("/definitely/not/chrome"),
            )

    def test_run_chrome_probe_rejects_a_browser_error_page(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            executable = Path(tmp) / "Google Chrome"
            executable.write_bytes(b"chrome")
            executable.chmod(0o755)
            completed = mock.Mock(
                returncode=0,
                stdout=b"<html>ERR_CONNECTION_CLOSED</html>",
                stderr=b"",
            )
            with mock.patch.object(
                lifecycle,
                "_user_environment",
                return_value=({"HOME": tmp}, Path(tmp)),
            ), mock.patch.object(lifecycle.os, "chown"), mock.patch.object(
                lifecycle.subprocess,
                "run",
                return_value=completed,
            ):
                with self.assertRaisesRegex(
                    lifecycle.LifecycleError,
                    "expected page",
                ):
                    lifecycle._run_chrome_probe(
                        501,
                        20,
                        "error-page",
                        executable,
                    )

    def test_private_raw_log_requires_regular_owner_only_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "slipstream.log"
            log.write_text("private\n")
            log.chmod(0o600)

            lifecycle._assert_private_raw_log(log, expected_uid=os.getuid())

            log.chmod(0o640)
            with self.assertRaisesRegex(lifecycle.LifecycleError, "not 0600"):
                lifecycle._assert_private_raw_log(log, expected_uid=os.getuid())

    def test_private_raw_log_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "target"
            target.write_text("not the log\n")
            log = Path(tmp) / "slipstream.log"
            log.symlink_to(target)

            with self.assertRaisesRegex(lifecycle.LifecycleError, "not a regular file"):
                lifecycle._assert_private_raw_log(log, expected_uid=os.getuid())

    def test_dry_run_never_executes_privileged_work(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            result = lifecycle.main(["--dry-run"])

        self.assertEqual(result, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["result"], "dry-run")
        self.assertEqual(report["target"], "script")
        self.assertFalse(report["workstation_allowed"])

        packaged = lifecycle.dry_run("packaged-app")
        self.assertIn("crash", packaged["packaged_tray"])
        self.assertIn("HTTPS client", packaged["https_client_probes"])
        self.assertIn("Chrome", packaged["chrome_probes"])


if __name__ == "__main__":
    unittest.main()
