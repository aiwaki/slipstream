from __future__ import annotations

import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from scripts.download_github_release_assets import download_release_assets, parse_args


class DownloadGithubReleaseAssetsTests(unittest.TestCase):
    def test_each_download_attempt_has_a_finite_process_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
                self.assertIsInstance(kwargs.get("timeout"), (float, int))
                self.assertGreater(kwargs["timeout"], 0)
                destination = Path(command[command.index("--dir") + 1])
                (destination / "asset").write_text("exact", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "", "")

            download_release_assets(
                repository="aiwaki/slipstream", tag="pinned", output=Path(root_name) / "assets",
                patterns=("asset",), attempts=1, runner=runner,
            )

    def test_timeout_discards_partial_attempt_and_retries(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            destinations: list[Path] = []

            def runner(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
                destination = Path(command[command.index("--dir") + 1])
                destinations.append(destination)
                if len(destinations) == 1:
                    (destination / "partial").write_text("discard", encoding="utf-8")
                    raise subprocess.TimeoutExpired(command, 1)
                self.assertFalse(destinations[0].exists())
                (destination / "asset").write_text("exact", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "", "")

            download_release_assets(
                repository="aiwaki/slipstream", tag="pinned", output=root / "assets",
                patterns=("asset",), attempts=2, delay_seconds=0, runner=runner,
            )
            self.assertEqual(len(destinations), 2)
            self.assertEqual(list(root.glob(".assets.download.*")), [])
            self.assertFalse((root / "assets" / "partial").exists())

    def test_real_hung_process_is_reaped_before_partial_directory_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            pids: list[int] = []

            def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
                destination = command[command.index("--dir") + 1]
                pid_file = root / f"child-{len(pids)}"
                script = (
                    "import os, pathlib, sys, time; "
                    "pathlib.Path(sys.argv[1], 'partial').write_text('incomplete'); "
                    "pathlib.Path(sys.argv[2]).write_text(str(os.getpid())); time.sleep(60)"
                )
                try:
                    return subprocess.run(
                        [sys.executable, "-c", script, destination, str(pid_file)], **kwargs)
                finally:
                    if pid_file.exists():
                        pids.append(int(pid_file.read_text()))

            started = time.monotonic()
            with self.assertRaisesRegex(RuntimeError, "after 2 attempts: .*timed out"):
                download_release_assets(
                    repository="aiwaki/slipstream", tag="pinned", output=root / "assets",
                    patterns=("asset",), attempts=2, delay_seconds=0,
                    timeout_seconds=0.25, runner=runner,
                )
            self.assertLess(time.monotonic() - started, 5)
            self.assertEqual(len(pids), 2)
            if sys.platform != "win32":
                import os
                for pid in pids:
                    with self.assertRaises(ChildProcessError):
                        os.waitpid(pid, os.WNOHANG)
            self.assertFalse((root / "assets").exists())
            self.assertEqual(list(root.glob(".assets.download.*")), [])

    def test_timeout_configuration_is_finite_positive_and_cli_configurable(self) -> None:
        args = parse_args([
            "--repo", "aiwaki/slipstream", "--tag", "pinned", "--output", "assets",
            "--pattern", "asset", "--timeout-seconds", "30",
        ])
        self.assertEqual(args.timeout_seconds, 30)
        with tempfile.TemporaryDirectory() as root_name:
            for timeout in (0, -1, float("inf"), float("nan")):
                with self.subTest(timeout=timeout), self.assertRaisesRegex(ValueError, "bounds"):
                    download_release_assets(
                        repository="aiwaki/slipstream", tag="pinned",
                        output=Path(root_name) / "assets", patterns=("asset",),
                        timeout_seconds=timeout,
                    )

    def test_retries_into_fresh_directories_and_publishes_only_success(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            output = root / "assets"
            commands: list[list[str]] = []
            delays: list[float] = []

            def runner(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
                commands.append(command)
                destination = Path(command[command.index("--dir") + 1])
                if len(commands) == 1:
                    (destination / "partial").write_text("discard", encoding="utf-8")
                    return subprocess.CompletedProcess(command, 0, "", "")
                (destination / "geph5-client").write_text("exact", encoding="utf-8")
                (destination / "SHA256SUMS").write_text("exact", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "", "")

            download_release_assets(
                repository="aiwaki/slipstream",
                tag="geph-vendor-0.3.0-r1",
                output=output,
                patterns=("geph5-client", "SHA256SUMS"),
                attempts=3,
                delay_seconds=0.25,
                runner=runner,
                sleeper=delays.append,
            )

            self.assertEqual((output / "geph5-client").read_text(), "exact")
            self.assertFalse((output / "partial").exists())
            self.assertEqual(delays, [0.25])
            self.assertEqual(len(commands), 2)
            self.assertIn("geph-vendor-0.3.0-r1", commands[0])
            self.assertEqual(commands[0].count("--pattern"), 2)

    def test_exhaustion_leaves_no_output_or_partial_directory(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            root = Path(root_name)
            output = root / "assets"

            def runner(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
                destination = Path(command[command.index("--dir") + 1])
                (destination / "partial").write_text("discard", encoding="utf-8")
                return subprocess.CompletedProcess(command, 1, "", "HTTP 503")

            with self.assertRaisesRegex(RuntimeError, "after 2 attempts: HTTP 503"):
                download_release_assets(
                    repository="aiwaki/slipstream",
                    tag="geph-vendor-0.3.0-r1",
                    output=output,
                    patterns=("geph5-client",),
                    attempts=2,
                    delay_seconds=0,
                    runner=runner,
                    sleeper=lambda _: None,
                )

            self.assertFalse(output.exists())
            self.assertEqual(list(root.glob(".assets.download.*")), [])

    def test_existing_output_is_never_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as root_name:
            output = Path(root_name) / "assets"
            output.mkdir()

            with self.assertRaisesRegex(ValueError, "must not already exist"):
                download_release_assets(
                    repository="aiwaki/slipstream",
                    tag="geph-vendor-0.3.0-r1",
                    output=output,
                    patterns=("geph5-client",),
                )


if __name__ == "__main__":
    unittest.main()
