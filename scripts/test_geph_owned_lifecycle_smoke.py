from __future__ import annotations

import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import geph_owned_lifecycle_smoke as smoke


ROOT = Path(__file__).resolve().parents[1]


class GephOwnedLifecycleSmokeTests(unittest.TestCase):
    def test_disposable_guard_requires_every_marker_macos_and_non_root(self) -> None:
        environment = {
            "CI": "true",
            "GITHUB_ACTIONS": "true",
            "SLIPSTREAM_DISPOSABLE_CI": "1",
        }
        with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(
            smoke.sys, "platform", "darwin"
        ), mock.patch("os.geteuid", return_value=501):
            smoke._require_disposable_ci()

        for missing in environment:
            partial = {key: value for key, value in environment.items() if key != missing}
            with self.subTest(missing=missing), mock.patch.dict(
                os.environ, partial, clear=True
            ), mock.patch.object(smoke.sys, "platform", "darwin"), mock.patch(
                "os.geteuid", return_value=501
            ):
                with self.assertRaises(smoke.QualificationError):
                    smoke._require_disposable_ci()

        with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(
            smoke.sys, "platform", "linux"
        ), mock.patch("os.geteuid", return_value=501):
            with self.assertRaisesRegex(smoke.QualificationError, "requires macOS"):
                smoke._require_disposable_ci()

        with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(
            smoke.sys, "platform", "darwin"
        ), mock.patch("os.geteuid", return_value=0):
            with self.assertRaisesRegex(smoke.QualificationError, "login user"):
                smoke._require_disposable_ci()

    def test_secret_is_required_and_removed_from_child_environment(self) -> None:
        with mock.patch.dict(
            os.environ,
            {smoke.GEPH_SECRET_ENV: "  disposable-secret  "},
            clear=True,
        ):
            self.assertEqual(smoke._take_secret(), "disposable-secret")
            self.assertNotIn(smoke.GEPH_SECRET_ENV, os.environ)

        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(smoke.QualificationError, "missing protected"):
                smoke._take_secret()

    def test_paths_are_scoped_to_the_app_config_and_user_launch_agent(self) -> None:
        home = Path("/Users/runner")
        paths = smoke.geph_paths(home)
        self.assertEqual(
            paths.config_dir,
            home / "Library/Application Support/dev.slipstream.tray",
        )
        self.assertEqual(paths.executable, paths.config_dir / "runtime/geph5-client")
        self.assertEqual(paths.launcher, paths.config_dir / "runtime/geph-launcher")
        self.assertEqual(paths.settings, paths.config_dir / "geph.json")
        self.assertEqual(paths.config, paths.config_dir / "geph-active.yaml")
        self.assertEqual(paths.cache, paths.config_dir / "geph-cache.db")
        self.assertEqual(paths.ownership, paths.config_dir / "geph-owned.json")
        self.assertEqual(
            paths.plist,
            home / "Library/LaunchAgents/dev.slipstream.geph.plist",
        )

    def test_private_json_is_atomic_owner_only_and_string_typed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config" / "geph.json"
            smoke._write_private_json(path, {"enabled": "1", "exit": "auto"})
            self.assertEqual(
                json.loads(path.read_text(encoding="utf-8")),
                {"enabled": "1", "exit": "auto"},
            )
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
            self.assertEqual(list(path.parent.glob(f".{path.name}.*")), [])

    def test_owned_state_requires_exact_uid_label_paths_and_private_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            paths = smoke.geph_paths(home)
            paths.ownership.parent.mkdir(parents=True)
            payload = {
                "pid": 4242,
                "uid": os.getuid(),
                "executable": str(paths.executable),
                "config": str(paths.config),
                "launchd_label": smoke.GEPH_LABEL,
            }
            paths.ownership.write_text(json.dumps(payload), encoding="utf-8")
            paths.ownership.chmod(0o600)

            state = smoke._read_owned_state(paths, os.getuid())
            self.assertEqual(state.pid, 4242)

            for key, value in (
                ("uid", os.getuid() + 1),
                ("launchd_label", "external.geph"),
                ("executable", "/tmp/geph5-client"),
                ("config", "/tmp/geph.yaml"),
            ):
                with self.subTest(key=key):
                    changed = dict(payload)
                    changed[key] = value
                    paths.ownership.write_text(json.dumps(changed), encoding="utf-8")
                    paths.ownership.chmod(0o600)
                    with self.assertRaises(smoke.QualificationError):
                        smoke._read_owned_state(paths, os.getuid())

            paths.ownership.write_text(json.dumps(payload), encoding="utf-8")
            paths.ownership.chmod(0o644)
            with self.assertRaisesRegex(smoke.QualificationError, "owner-private"):
                smoke._read_owned_state(paths, os.getuid())

    def test_socks_connect_request_is_domain_scoped_and_deterministic(self) -> None:
        request = smoke._socks_connect_request("store.steampowered.com", 443)
        host = b"store.steampowered.com"
        self.assertEqual(request[:5], b"\x05\x01\x00\x03" + bytes((len(host),)))
        self.assertEqual(request[5:-2], host)
        self.assertEqual(request[-2:], b"\x01\xbb")
        with self.assertRaises(smoke.QualificationError):
            smoke._socks_connect_request("x" * 256, 443)

    def test_launchd_disabled_parser_requires_the_exact_label(self) -> None:
        completed = mock.Mock(
            returncode=0,
            stdout='disabled services = {\n  "dev.slipstream.tproxy" => disabled\n}\n',
        )
        with mock.patch.object(smoke, "_run", return_value=completed):
            self.assertTrue(smoke._daemon_is_disabled())
        completed.stdout = '"dev.slipstream.other" => disabled\n'
        with mock.patch.object(smoke, "_run", return_value=completed):
            self.assertFalse(smoke._daemon_is_disabled())

    def test_owned_geph_kill_targets_only_the_revalidated_launchd_job(self) -> None:
        paths = smoke.geph_paths(Path("/Users/runner"))
        state = smoke.OwnedGephState(
            pid=4242,
            uid=501,
            executable=paths.executable,
            config=paths.config,
            launchd_label=smoke.GEPH_LABEL,
        )
        completed = mock.Mock(returncode=0)
        with mock.patch.object(smoke, "_assert_owned_geph") as validate, mock.patch.object(
            smoke, "_run", return_value=completed
        ) as run:
            smoke._kill_owned_geph(paths, 501, state)
        validate.assert_called_once_with(paths, 501, state)
        run.assert_called_once_with(
            (
                "/bin/launchctl",
                "kill",
                "SIGKILL",
                "gui/501/dev.slipstream.geph",
            ),
            check=False,
        )

    def test_dry_run_is_non_mutating_and_describes_the_real_gate(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(smoke.main(["--dry-run"]), 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["result"], "dry-run")
        self.assertIn("KeepAlive", payload["owned_geph"])
        self.assertIn("read-only", payload["system_network_state"])

    def test_harness_has_no_pf_or_root_daemon_mutation_commands(self) -> None:
        source = (ROOT / "scripts/geph_owned_lifecycle_smoke.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("pfctl", source)
        self.assertNotIn('"disable", "system/', source)
        self.assertNotIn("DAEMON_PLIST.unlink", source)
        self.assertNotIn("os.kill(initial.pid", source)

    def test_protected_workflow_is_manual_main_only_and_not_pr_secreted(self) -> None:
        workflow = (
            ROOT / ".github/workflows/owned-geph-qualification.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("environment: geph-qualification", workflow)
        self.assertEqual(
            workflow.count("secrets.SLIPSTREAM_GEPH_ACCOUNT_SECRET"),
            1,
        )
        self.assertIn("geph_owned_lifecycle_smoke.py", workflow)


if __name__ == "__main__":
    unittest.main()
