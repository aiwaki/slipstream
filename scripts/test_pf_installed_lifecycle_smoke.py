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
        accepted = (
            (sys.executable, str(lifecycle.SOURCE_DAEMON), "--install"),
            (
                str(lifecycle.INSTALLED_PYTHON),
                str(lifecycle.INSTALLED_DAEMON),
                "--uninstall",
            ),
            (
                "/bin/launchctl",
                "bootout",
                "system",
                str(lifecycle.LAUNCHD_PLIST),
            ),
            ("/bin/launchctl", "kickstart", "-k", lifecycle.LAUNCHD_LABEL),
        )
        for command in accepted:
            lifecycle.validate_system_command(command)

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

    def test_dry_run_never_executes_privileged_work(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            result = lifecycle.main(["--dry-run"])

        self.assertEqual(result, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["result"], "dry-run")
        self.assertFalse(report["workstation_allowed"])


if __name__ == "__main__":
    unittest.main()
