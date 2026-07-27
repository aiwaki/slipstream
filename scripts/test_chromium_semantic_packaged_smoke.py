from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import chromium_semantic_packaged_smoke as smoke


ROOT = Path(__file__).resolve().parents[1]


class ChromiumSemanticPackagedSmokeTests(unittest.TestCase):
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

    def test_chrome_command_loads_only_the_companion_in_a_fresh_profile(self) -> None:
        command = smoke._chrome_command(
            Path("/Applications/Google Chrome"),
            Path("/tmp/profile"),
            Path("/repo/browser-companion/chromium"),
            18443,
        )
        self.assertNotIn("--headless=new", command)
        self.assertNotIn("--dump-dom", command)
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
        self.assertTrue(command[-1].startswith(f"https://{smoke.FIXTURE_HOST}:18443/"))

    def test_launch_agent_payload_requires_the_aqua_user_domain(self) -> None:
        payload = smoke._chrome_launch_agent_payload(
            "dev.slipstream.chromium-semantic.4242",
            {"HOME": "/Users/runner", "USER": "runner"},
            Path("/Users/runner"),
            Path("/tmp/profile/chrome.stdout"),
            Path("/tmp/profile/chrome.stderr"),
            Path("/Applications/Google Chrome for Testing"),
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
        self.assertEqual(payload["ProcessType"], "Interactive")
        self.assertTrue(payload["RunAtLoad"])
        self.assertFalse(payload["AbandonProcessGroup"])
        self.assertEqual(payload["WorkingDirectory"], "/Users/runner")
        self.assertEqual(
            command[0],
            "/Applications/Google Chrome for Testing",
        )
        self.assertNotIn("/bin/sh", command)
        self.assertNotIn("/usr/bin/sudo", command)
        self.assertNotIn("/bin/launchctl", command)

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
            smoke._stop_chrome_launch_agent(
                launch,
                uid=501,
                gid=20,
                supplementary_groups=(12, 61),
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

    def test_launch_agent_cleanup_retries_bootout_before_reporting_failure(self) -> None:
        launch = smoke.ChromeLaunch(
            "gui/501/dev.slipstream.chromium-semantic.4242",
            4242,
            4242,
        )
        success = smoke.subprocess.CompletedProcess((), 0, "", "")
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
            smoke._stop_chrome_launch_agent(
                launch,
                uid=501,
                gid=20,
                supplementary_groups=(12, 61),
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

    def test_launch_agent_cleanup_verifies_group_after_bootout_failure(self) -> None:
        launch = smoke.ChromeLaunch(
            "gui/501/dev.slipstream.chromium-semantic.4242",
            4242,
            4242,
        )
        success = smoke.subprocess.CompletedProcess((), 0, "", "")
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
            with self.assertRaisesRegex(
                smoke.QualificationError,
                "LaunchAgent survived exact cleanup",
            ):
                smoke._stop_chrome_launch_agent(
                    launch,
                    uid=501,
                    gid=20,
                    supplementary_groups=(12, 61),
                )

        self.assertGreaterEqual(members.call_count, 1)

    def test_run_chrome_uses_an_exact_temporary_launch_agent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable = root / "Google Chrome for Testing"
            executable.write_text("binary", encoding="utf-8")
            executable.chmod(0o700)
            profile = root / "profile"
            profile.mkdir()
            launch = smoke.ChromeLaunch(
                "gui/501/dev.slipstream.chromium-semantic.4242",
                4242,
                4242,
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
            stop.assert_called_once_with(
                launch,
                uid=501,
                gid=20,
                supplementary_groups=(12, 61),
            )
            plist_payload = smoke.plistlib.loads(
                write_private.call_args_list[2].args[1]
            )
            self.assertEqual(plist_payload["LimitLoadToSessionType"], "Aqua")
            self.assertEqual(
                plist_payload["Label"],
                f"{smoke.CHROME_JOB_PREFIX}.{os.getpid()}",
            )

    def test_run_chrome_retains_profile_until_launch_agent_is_absent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            executable = root / "Google Chrome for Testing"
            executable.write_text("binary", encoding="utf-8")
            executable.chmod(0o700)
            profile = root / "profile"
            profile.mkdir()
            launch = smoke.ChromeLaunch(
                "gui/501/dev.slipstream.chromium-semantic.4242",
                4242,
                4242,
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

        source = (
            ROOT / "scripts/chromium_semantic_packaged_smoke.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("SLIP_GEPH_PORT", source)
        self.assertNotIn("Math.random", source)

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
        self.assertIn("chrome-version: stable", workflow)
        self.assertIn(
            '--chrome-executable "${{ steps.chrome-for-testing.outputs.chrome-path }}"',
            workflow,
        )
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
