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
        smoke._assert_fixture_complete(
            smoke.FixtureSnapshot(2, 1, 1, 1)
        )
        with self.assertRaisesRegex(smoke.QualificationError, "exactly once"):
            smoke._assert_fixture_complete(
                smoke.FixtureSnapshot(3, 1, 1, 1)
            )
        with self.assertRaisesRegex(smoke.QualificationError, "mandatory resource"):
            smoke._assert_fixture_complete(
                smoke.FixtureSnapshot(2, 1, 0, 1)
            )

    def test_chrome_command_loads_only_the_companion_in_a_fresh_profile(self) -> None:
        command = smoke._chrome_command(
            Path("/Applications/Google Chrome"),
            Path("/tmp/profile"),
            Path("/repo/browser-companion/chromium"),
            18443,
        )
        self.assertIn("--headless=new", command)
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
