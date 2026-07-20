from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.download_github_release_assets import download_release_assets


class DownloadGithubReleaseAssetsTests(unittest.TestCase):
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
