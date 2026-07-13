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

            target = lifecycle.packaged_app_target(app)

            self.assertEqual(target.name, "packaged-app")
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


if __name__ == "__main__":
    unittest.main()
