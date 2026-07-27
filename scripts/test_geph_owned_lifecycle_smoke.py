from __future__ import annotations

import io
import json
import os
import stat
import tempfile
import threading
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

    def test_coordination_requires_distinct_absent_sibling_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ready = root / "ready"
            release = root / "release"
            coordination = smoke._validate_coordination_paths(ready, release)
            self.assertEqual(
                coordination,
                smoke.CoordinationPaths(
                    ready=ready.resolve(),
                    release=release.resolve(),
                ),
            )
            with self.assertRaisesRegex(smoke.QualificationError, "used together"):
                smoke._validate_coordination_paths(ready, None)
            with self.assertRaisesRegex(smoke.QualificationError, "distinct siblings"):
                smoke._validate_coordination_paths(ready, ready)
            ready.write_text("occupied", encoding="utf-8")
            with self.assertRaisesRegex(smoke.QualificationError, "must not already"):
                smoke._validate_coordination_paths(ready, release)

    def test_coordination_wait_revalidates_geph_after_private_release(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            coordination = smoke.CoordinationPaths(
                ready=root / "ready",
                release=root / "release",
            )
            paths = smoke.geph_paths(root / "home")
            state = smoke.OwnedGephState(
                pid=4242,
                uid=os.getuid(),
                executable=paths.executable,
                config=paths.config,
                launchd_label=smoke.GEPH_LABEL,
            )

            def release() -> None:
                for _ in range(100):
                    if coordination.ready.exists():
                        coordination.release.write_text("done\n", encoding="utf-8")
                        coordination.release.chmod(0o600)
                        return
                    smoke.time.sleep(0.01)

            worker = threading.Thread(target=release)
            worker.start()
            with mock.patch.object(smoke, "_assert_owned_geph") as validate:
                smoke._publish_ready_and_wait(
                    coordination,
                    paths,
                    os.getuid(),
                    state,
                    timeout=2,
                )
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(stat.S_IMODE(coordination.ready.stat().st_mode), 0o600)
            validate.assert_called_once_with(paths, os.getuid(), state)

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
        self.assertEqual(
            smoke._native_host_path(home),
            home
            / "Library/Application Support/Google/Chrome/NativeMessagingHosts"
            / "dev.slipstream.semantic.json",
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

    def test_payload_probe_rotates_canaries_until_real_https_payload_succeeds(
        self,
    ) -> None:
        targets = (
            smoke.PayloadTarget("first.example", "/", 512),
            smoke.PayloadTarget("second.example", "/health", 1024),
        )
        expected = {
            "bytes": 4096,
            "canary": "second.example",
            "protocol": "TLSv1.3",
            "status": "HTTP/1.1 200 OK",
        }
        with mock.patch.object(
            smoke,
            "_payload_probe",
            side_effect=[TimeoutError("first timed out"), expected],
        ) as probe:
            self.assertEqual(
                smoke._wait_for_payload(timeout=1, targets=targets),
                expected,
            )
        self.assertEqual(
            [call.args for call in probe.call_args_list],
            [(targets[0],), (targets[1],)],
        )

    def test_native_host_cleanup_removes_only_the_exact_packaged_manifest(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            executable = home / "Slipstream.app/Contents/MacOS/slipstream"
            path = smoke._native_host_path(home)
            path.parent.mkdir(parents=True)
            payload = {
                "name": smoke.NATIVE_HOST_NAME,
                "description": "Slipstream Browser Companion",
                "path": str(executable),
                "type": "stdio",
                "allowed_origins": [smoke.NATIVE_HOST_ORIGIN],
            }
            path.write_text(json.dumps(payload), encoding="utf-8")
            path.chmod(0o600)

            smoke._remove_exact_native_host(home, executable, os.getuid())
            self.assertFalse(path.exists())

            payload["path"] = "/Applications/Foreign.app/Contents/MacOS/foreign"
            path.write_text(json.dumps(payload), encoding="utf-8")
            path.chmod(0o600)
            with self.assertRaisesRegex(
                smoke.QualificationError,
                "foreign native host",
            ):
                smoke._remove_exact_native_host(home, executable, os.getuid())
            self.assertTrue(path.exists())

    def test_launchd_disabled_parser_accepts_current_and_legacy_states(self) -> None:
        completed = mock.Mock(
            returncode=0,
            stdout='disabled services = {\n  "dev.slipstream.tproxy" => true\n}\n',
        )
        with mock.patch.object(smoke, "_run", return_value=completed):
            self.assertTrue(smoke._daemon_is_disabled())

        completed.stdout = '"dev.slipstream.tproxy" => disabled\n'
        with mock.patch.object(smoke, "_run", return_value=completed):
            self.assertTrue(smoke._daemon_is_disabled())

    def test_launchd_disabled_parser_rejects_enabled_or_other_labels(self) -> None:
        completed = mock.Mock(
            returncode=0,
            stdout='"dev.slipstream.tproxy" => false\n',
        )
        with mock.patch.object(smoke, "_run", return_value=completed):
            self.assertFalse(smoke._daemon_is_disabled())

        completed.stdout = '"dev.slipstream.tproxy" => enabled\n'
        with mock.patch.object(smoke, "_run", return_value=completed):
            self.assertFalse(smoke._daemon_is_disabled())

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

    def test_cleanup_continues_after_keychain_delete_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "runner"
            app_bundle = Path(tmp) / "Slipstream.app"
            app_bundle.mkdir()
            paths = smoke.geph_paths(home)
            sentinel = mock.Mock()
            tray = mock.Mock()
            tray.start.side_effect = smoke.QualificationError("startup failed")

            with mock.patch.object(smoke, "_require_disposable_ci"), mock.patch.object(
                smoke, "_take_secret", return_value="secret"
            ), mock.patch.object(smoke.Path, "home", return_value=home), mock.patch.object(
                smoke.os, "getuid", return_value=501
            ), mock.patch.object(
                smoke, "_preflight", return_value=Path(tmp) / "slipstream"
            ), mock.patch.object(
                smoke, "ExternalListenerSentinel", return_value=sentinel
            ), mock.patch.object(
                smoke, "PackagedTray", return_value=tray
            ), mock.patch.object(
                smoke, "_keychain_add"
            ), mock.patch.object(
                smoke, "_bootout_owned_geph"
            ), mock.patch.object(
                smoke, "_wait_for_listener_gone"
            ), mock.patch.object(
                smoke, "_keychain_delete", side_effect=RuntimeError("security timeout")
            ) as keychain_delete, mock.patch.object(
                smoke, "_keychain_exists", return_value=False
            ), mock.patch.object(
                smoke, "_listener_pids", return_value=()
            ), mock.patch.object(
                smoke, "_daemon_is_disabled", return_value=True
            ), mock.patch.object(
                smoke, "DAEMON_PLIST", Path(tmp) / "daemon.plist"
            ):
                with self.assertRaisesRegex(
                    smoke.QualificationError,
                    "Keychain cleanup: security timeout",
                ):
                    smoke.run_qualification(app_bundle)

            keychain_delete.assert_called_once_with()
            tray.close.assert_called_once_with()
            sentinel.close.assert_called_once_with()
            self.assertFalse(paths.config_dir.exists())

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
