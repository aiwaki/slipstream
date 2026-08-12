from pathlib import Path
from unittest import mock
import os
import subprocess
import tempfile
import unittest

from scripts import composed_pending_navigation_smoke as smoke


def _ci_environment() -> dict[str, str]:
    return {
        "CI": "true",
        "GITHUB_ACTIONS": "true",
        "SLIPSTREAM_DISPOSABLE_CI": "1",
    }


class ComposedPendingNavigationSmokeTests(unittest.TestCase):
    def test_disposable_guard_requires_all_three_markers(self) -> None:
        with mock.patch.object(smoke.os, "environ", _ci_environment()):
            smoke.require_disposable_ci()

        with mock.patch.object(smoke.os, "environ", {"CI": "true"}):
            with self.assertRaisesRegex(smoke.ComposedQualificationError, "missing"):
                smoke.require_disposable_ci()

    def test_original_navigation_command_is_extension_free_and_targets_public_ip(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            command = smoke.original_navigation_command(
                Path("/tmp/Chrome"),
                Path(raw_directory),
            )

        self.assertEqual(command[0], "/tmp/Chrome")
        self.assertIn("--disable-extensions", command)
        self.assertIn("--disable-quic", command)
        self.assertIn("--ignore-certificate-errors", command)
        self.assertTrue(any(smoke.FIXTURE_PUBLIC_IP in value for value in command))
        self.assertEqual(command[-1], f"https://{smoke.FIXTURE_HOST}/")

    def test_qualification_environment_is_exact_and_keeps_production_socket(
        self,
    ) -> None:
        with mock.patch.object(smoke.os, "environ", _ci_environment()):
            with tempfile.TemporaryDirectory() as raw_directory:
                root = Path(raw_directory)
                chrome = root / "Chrome"
                chrome.write_bytes(b"chrome")
                chrome.chmod(0o755)
                fixture = smoke.ComposedHttpsFixture()
                fixture._worker_port = 18443
                fixture._original_port = 19443
                try:
                    environment = fixture.qualification_environment(chrome)
                finally:
                    fixture.close()

        self.assertEqual(
            set(environment),
            smoke.DISPOSABLE_QUALIFICATION_ENVIRONMENT_KEYS,
        )
        self.assertNotIn("SLIPSTREAM_BROWSER_PROBE_SOCKET", environment)
        self.assertEqual(
            environment["SLIPSTREAM_BROWSER_PROBE_ORIGIN"],
            f"https://{smoke.FIXTURE_HOST}:18443/",
        )
        self.assertEqual(environment[smoke.DAEMON_FIXTURE_PORT_ENV], "19443")

    def test_report_requires_original_worker_original_timing_and_resources(
        self,
    ) -> None:
        fixture = smoke.ComposedHttpsFixture()
        try:
            fixture._records = [
                {"channel": "original", "path": "/", "count": 1, "elapsed_ms": 100},
                {"channel": "worker", "path": "/", "count": 2, "elapsed_ms": 8_100},
                {
                    "channel": "original",
                    "path": "/",
                    "count": 3,
                    "elapsed_ms": 16_100,
                },
            ]
            fixture._counts.update(
                {"root": 3, "css": 1, "js": 1, "image": 1, "ready": 1}
            )
            fixture._ready.set()

            report = fixture.report()

            self.assertEqual(
                report["root_channels"],
                ["original", "worker", "original"],
            )
            self.assertEqual(report["ready_callbacks"], 1)
            fixture._records[1]["elapsed_ms"] = 7_000
            with self.assertRaisesRegex(
                smoke.ComposedQualificationError,
                "observation windows",
            ):
                fixture.report()
        finally:
            fixture.close()

    def test_cpu_time_parser(self) -> None:
        for value, expected in (
            ("01:02", 62.0),
            ("01:02:03", 3723.0),
            ("00:00.50", 0.5),
        ):
            with self.subTest(value=value):
                self.assertEqual(smoke._cpu_seconds(value), expected)

    def test_worker_diagnostics_is_bounded_to_owned_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            root = Path(raw_directory)
            runtime = root / "runtime"
            runtime.mkdir(mode=0o700)
            launch = runtime / "dev.slipstream.browser-probe.0123456789abcdef"
            launch.mkdir(mode=0o700)
            for name in ("worker.plist", "worker.stdout.log", "worker.stderr.log"):
                (launch / name).write_bytes(b"private")
            profile = root / ("slipstream-browser-probe-" + "a" * 32)
            profile.mkdir()
            with (
                mock.patch.object(smoke, "PRODUCTION_WORKER_RUNTIME", runtime),
                mock.patch.object(smoke, "_worker_processes", return_value=(123,)),
                mock.patch.object(smoke, "_worker_profiles", return_value=(profile,)),
            ):
                diagnostic = smoke.worker_diagnostics(os.getuid())

        self.assertEqual(diagnostic["processes"], (123,))
        self.assertEqual(diagnostic["profiles"], (profile.name,))
        self.assertEqual(
            diagnostic["runtime"],
            ({
                "name": launch.name,
                "owner": os.getuid(),
                "mode": "0700",
                "entries": (
                    "worker.plist",
                    "worker.stderr.log",
                    "worker.stdout.log",
                ),
            },),
        )

    def test_active_worker_requires_one_matching_loaded_launchagent(self) -> None:
        uid = os.getuid()
        label = "dev.slipstream.browser-probe.0123456789abcdef"
        diagnostic = {
            "processes": (4242,),
            "profiles": ("slipstream-browser-probe-" + "a" * 32,),
            "runtime": ({
                "name": label,
                "owner": uid,
                "mode": "0700",
                "entries": (
                    "worker.plist",
                    "worker.stderr.log",
                    "worker.stdout.log",
                ),
            },),
        }
        profile = Path("/var/folders/test/slipstream-browser-probe-" + "a" * 32)
        completed = subprocess.CompletedProcess((), 0, "pid = 4242\n", "")
        with (
            mock.patch.object(smoke.os, "environ", _ci_environment()),
            mock.patch.object(smoke, "worker_diagnostics", return_value=diagnostic),
            mock.patch.object(
                smoke,
                "_active_worker_chrome_profiles",
                return_value=(profile,),
            ),
            mock.patch.object(smoke.subprocess, "run", return_value=completed),
        ):
            self.assertEqual(
                smoke.assert_worker_active(uid, timeout=0.1),
                (
                    {
                        "worker_processes": 1,
                        "worker_profiles": 1,
                        "worker_runtime_directories": 1,
                        "launchagent": "loaded",
                    },
                    (profile,),
                ),
            )

            diagnostic["processes"] = (4243,)
            with self.assertRaisesRegex(
                smoke.ComposedQualificationError,
                "not provably active",
            ):
                smoke.assert_worker_active(uid, timeout=0.01)

    def test_live_worker_profile_comes_from_exact_owned_chrome_argument(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            root = Path(raw_directory)
            profile = root / ("slipstream-browser-probe-" + "b" * 32)
            profile.mkdir(mode=0o700)
            completed = subprocess.CompletedProcess(
                (),
                0,
                f"{os.getuid()} /tmp/Chrome --user-data-dir={profile} --headless\n"
                f"{os.getuid()} /tmp/Chrome --user-data-dir=/tmp/unowned --headless\n",
                "",
            )
            with mock.patch.object(smoke.subprocess, "run", return_value=completed):
                observed = smoke._active_worker_chrome_profiles(os.getuid())

            self.assertEqual(observed, (profile,))


if __name__ == "__main__":
    unittest.main()
