"""Offline observer and containment checks; native proof runs on disposable CI."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest import mock

import stop_quit_ui_smoke as smoke


class StopQuitObserverTests(unittest.TestCase):
    def test_workstation_refusal_precedes_every_command(self):
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(smoke, "run") as run:
            with self.assertRaisesRegex(smoke.QualificationError, "disposable"):
                smoke.require_disposable()
            run.assert_not_called()

    def test_status_requires_fresh_settled_heartbeat(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "status"
            base = {"schema_version": 2, "daemon": {"pid": 4242, "heartbeat_seq": 8,
                    "state": "dormant", "phase": "active", "updated_at": time.time()}}
            with mock.patch.object(smoke, "STATUS", path):
                path.write_text(json.dumps(base))
                self.assertEqual(smoke.status_observation(), (4242, 8))
                for key, value in [("phase", "recovering"), ("heartbeat_seq", 0), ("updated_at", 0), ("pid", 0)]:
                    changed = json.loads(json.dumps(base))
                    changed["daemon"][key] = value
                    path.write_text(json.dumps(changed))
                    self.assertIsNone(smoke.status_observation(), (key, value))

    def test_root_absence_requires_exact_job_disabled_listener_and_process_proof(self):
        result = lambda code, out=b"", err=b"": subprocess.CompletedProcess([], code, out, err)
        missing = result(113, err=b'Could not find service "dev.slipstream.tproxy" in domain for system')
        disabled = result(0, b'"dev.slipstream.tproxy" => true')
        no_listener = result(1)
        clear = result(0, b"501 123 /usr/bin/python observer\n")
        for disabled_value in (b'true', b'disabled'):
            with mock.patch.object(smoke, "run", side_effect=[missing, result(0, b'"dev.slipstream.tproxy" => ' + disabled_value), no_listener, clear]), \
                 mock.patch.object(smoke, "routing_residue_clear", return_value=True):
                self.assertTrue(smoke.root_stopped())
        for responses in [
            [result(1, err=b"permission denied")],
            [missing, result(0, b'"dev.slipstream.tproxy" => false')],
            [missing, disabled, result(1, err=b"query failed")],
            [missing, disabled, result(0, b"4242\n")],
            [missing, disabled, no_listener, result(0, b"0 4242 /usr/local/slipstream/slipstreamd\n")],
            [missing, disabled, no_listener, result(0, b"501 4242 /candidate/Slipstream.app/Contents/MacOS/slipstream --pending-navigation-browser-probe\n")],
            [missing, disabled, no_listener, result(1)],
        ]:
            with mock.patch.object(smoke, "run", side_effect=responses):
                self.assertFalse(smoke.root_stopped())

    def test_stop_requires_empty_pf_and_absent_owned_residue(self):
        clean = subprocess.CompletedProcess([], 0, b"", b"No ALTQ support in kernel\nALTQ related functions disabled\n")
        with tempfile.TemporaryDirectory() as temp:
            residue = Path(temp) / "owned-worker"
            with mock.patch.object(smoke, "STOP_RESIDUE", (residue,)), mock.patch.object(smoke, "run", return_value=clean) as run:
                self.assertTrue(smoke.routing_residue_clear())
                self.assertEqual(run.call_count, 2)
                residue.touch()
                run.reset_mock()
                self.assertFalse(smoke.routing_residue_clear())
                run.assert_not_called()
                residue.unlink()
                for code, out, err in [(0, b"rdr pass on lo0", b""), (1, b"", b""), (0, b"", b"unknown query failure")]:
                    run.return_value = subprocess.CompletedProcess([], code, out, err)
                    self.assertFalse(smoke.routing_residue_clear())

    def test_failed_stop_cannot_claim_continuation_after_root_restart(self):
        with mock.patch.object(smoke, "wait_progress", return_value=(42, 9)):
            with self.assertRaisesRegex(smoke.QualificationError, "restarted"):
                smoke.continued_root((41, 8))
        with mock.patch.object(smoke, "wait_progress", return_value=(41, 9)):
            self.assertEqual(smoke.continued_root((41, 8)), (41, 9))

    def test_native_host_restores_previous_bytes_and_mode_without_removing_unowned_file(self):
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            executable = Path("/candidate/Slipstream.app/Contents/MacOS/slipstream")
            first = smoke.NativeHostSnapshot(home, executable)
            first.path.parent.mkdir(parents=True)
            previous = b'{"name":"dev.slipstream.semantic","path":"/prior/app"}\n'
            first.path.write_bytes(previous)
            first.path.chmod(0o640)
            snapshot = smoke.NativeHostSnapshot(home, executable)
            snapshot.path.write_text(json.dumps({"name": "dev.slipstream.semantic", "path": str(executable)}))
            snapshot.path.chmod(0o600)
            snapshot.restore()
            self.assertEqual(snapshot.path.read_bytes(), previous)
            self.assertEqual(snapshot.path.stat().st_mode & 0o777, 0o640)
            snapshot.path.write_text('{"name":"external"}')
            with self.assertRaisesRegex(smoke.QualificationError, "not this fixture"):
                snapshot.restore()
            self.assertTrue(snapshot.path.exists())

    def test_owned_fixture_refuses_existing_private_files_before_compiling_or_spawning(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            directory.chmod(0o700)
            (directory / "runtime").mkdir(mode=0o700)
            fixture = smoke.OwnedPrelistenerFixture(directory)
            for path in (fixture.executable, fixture.config, fixture.record):
                with self.subTest(path=path.name):
                    path.write_bytes(b"must preserve")
                    with mock.patch.object(smoke, "require_disposable"), mock.patch.object(smoke, "run") as run, \
                         mock.patch.object(smoke.subprocess, "Popen") as popen:
                        with self.assertRaisesRegex(smoke.QualificationError, "replace existing"):
                            fixture.start()
                        run.assert_not_called()
                        popen.assert_not_called()
                    self.assertEqual(path.read_bytes(), b"must preserve")
                    path.unlink()

    def test_owned_fixture_cleanup_does_not_signal_changed_identity(self):
        fixture = smoke.OwnedPrelistenerFixture(Path("/private-fixture"))
        fixture.process = mock.Mock()
        fixture.process.poll.return_value = None
        with mock.patch.object(fixture, "identity", return_value=False):
            with self.assertRaisesRegex(smoke.QualificationError, "unowned inert"):
                fixture.close()
        fixture.process.terminate.assert_not_called()
        fixture.process.kill.assert_not_called()

    def test_owned_fixture_quit_proof_requires_signal_and_absence_without_signalling(self):
        with tempfile.TemporaryDirectory() as temp:
            fixture = smoke.OwnedPrelistenerFixture(Path(temp))
            fixture.process = mock.Mock()
            fixture.process.pid = 4242
            fixture.process.wait.return_value = -smoke.signal.SIGTERM
            with mock.patch.object(smoke, "run", return_value=subprocess.CompletedProcess([], 1, b"", b"")):
                fixture.assert_stopped()
                fixture.record.touch()
                with self.assertRaisesRegex(smoke.QualificationError, "absence"):
                    fixture.assert_stopped()
                fixture.record.unlink()
                fixture.process.wait.return_value = 0
                with self.assertRaisesRegex(smoke.QualificationError, "real stop signal"):
                    fixture.assert_stopped()
            fixture.process.terminate.assert_not_called()
            fixture.process.kill.assert_not_called()

    def test_heartbeat_progress_resets_after_missing_proof_and_pid_change(self):
        observations = iter([(41, 8), None, (41, 9), (42, 10), (42, 11)])
        def bounded_wait(predicate, message, timeout):
            for _ in range(5):
                if value := predicate():
                    return value
            self.fail(message)
        with mock.patch.object(smoke, "status_observation", side_effect=lambda: next(observations)), \
             mock.patch.object(smoke, "wait", side_effect=bounded_wait), \
             mock.patch.object(smoke, "run", return_value=subprocess.CompletedProcess([], 0, b"pid = 42", b"")):
            self.assertEqual(smoke.wait_progress(), (42, 11))

    def test_root_heartbeat_does_not_accept_another_launchd_pid_with_same_prefix(self):
        def one_observation(predicate, message, timeout):
            self.assertFalse(predicate())
            raise smoke.QualificationError(message)
        with mock.patch.object(smoke, "status_observation", return_value=(42, 9)), \
             mock.patch.object(smoke, "wait", side_effect=one_observation), \
             mock.patch.object(smoke, "run", return_value=subprocess.CompletedProcess([], 0, b"\tpid = 4242\n", b"")):
            with self.assertRaises(smoke.QualificationError):
                smoke.wait_progress((42, 8))

    def test_private_fixture_failure_never_echoes_secret_or_command(self):
        secret = "fixture-secret-must-not-escape"
        with mock.patch.object(smoke.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, secret.encode(), secret.encode())):
            with self.assertRaises(smoke.QualificationError) as error:
                smoke.run(["/usr/sbin/sysadminctl", "-password", secret], sensitive=True)
            self.assertNotIn(secret, str(error.exception))
        with mock.patch.object(smoke.subprocess, "run", side_effect=subprocess.TimeoutExpired(["sysadminctl", secret], 1)):
            with self.assertRaises(smoke.QualificationError) as error:
                smoke.run(["sysadminctl", secret], sensitive=True)
            self.assertNotIn(secret, str(error.exception))

    def test_native_cancel_and_confirmation_are_distinct_results(self):
        with mock.patch.object(smoke, "applescript", return_value="cancelled") as apple:
            self.assertEqual(smoke.auth_action(smoke.STOP_PROMPT, cancel=True), "cancelled")
            script = apple.call_args.args[0]
            self.assertIn(smoke.STOP_PROMPT, script)
            self.assertIn('click item 1 of cancelButtons', script)
            self.assertNotIn('set value of item 1 of secretFields', script)
        with mock.patch.object(smoke, "applescript", return_value="confirmed") as apple:
            self.assertEqual(smoke.auth_action(smoke.STOP_PROMPT, username="fixture", password="secret"), "confirmed")
            self.assertTrue(apple.call_args.kwargs["sensitive"])

    def test_auth_action_uses_the_observed_snapshot_traversal_before_unique_prompt_action(self):
        # CI observed the exact prompt in one window while the old direct-repeat
        # observer returned absent. Keep both generated AX readers identical.
        with mock.patch.object(smoke, "applescript", return_value="cancelled") as apple:
            smoke.auth_action(smoke.STOP_PROMPT, cancel=True)
            action = apple.call_args.args[0]
        with mock.patch.object(smoke, "applescript", return_value="process=SecurityAgent|present=1|windows=1") as apple:
            smoke.auth_snapshot(smoke.STOP_PROMPT)
            snapshot = apple.call_args.args[0]
        for script in (action, snapshot):
            self.assertIn(smoke.AUTH_WINDOW_ELEMENTS, script)
            self.assertIn(smoke.AUTH_PROMPT_COLLECTION, script)
            self.assertIn("set e to item elementIndex of elements", script)
            self.assertNotIn("repeat with elementRef in entire contents", script)
        click = action.index("click item 1 of cancelButtons")
        for guard in ('if windowCount is not 1', 'if (count of cancelButtons) is not 1',
                      'if readErrors is not 0', f'valueText contains "{smoke.STOP_PROMPT}"',
                      f'nameText contains "{smoke.STOP_PROMPT}"'):
            self.assertLess(action.index(guard), click)

    def test_disabled_native_menu_is_not_reported_as_a_successful_click(self):
        with mock.patch.object(smoke, "applescript", return_value="disabled:Stop Slipstream and Quit"):
            with self.assertRaisesRegex(smoke.QualificationError, "disabled before click"):
                smoke.menu_action(4242, smoke.STOP_LABELS)

    def test_auth_snapshot_accepts_only_known_processes_and_numeric_diagnostics(self):
        raw = "process=SecurityAgent|present=1|windows=0\nprocess=SecurityAgentHelper-arm64|window=1|static=3|secure=1|prompt_value=0|prompt_name=1"
        with mock.patch.object(smoke, "applescript", return_value=raw) as apple:
            observed = smoke.auth_snapshot(smoke.STOP_PROMPT)
            self.assertEqual(observed[1]["prompt_name"], 1)
            self.assertEqual(observed[0]["windows"], 0)
            self.assertTrue(apple.call_args.kwargs["sensitive"])
            self.assertNotIn("click ", apple.call_args.args[0])
            self.assertNotIn("set value of", apple.call_args.args[0])
        for private in ["process=external-private-title|present=1", "process=SecurityAgent|secure=private-value", "process=SecurityAgent|field_value=0"]:
            with mock.patch.object(smoke, "applescript", return_value=private):
                with self.assertRaises(smoke.QualificationError):
                    smoke.auth_snapshot(smoke.STOP_PROMPT)

    def test_bounded_tray_diagnostics_redact_credentials_before_truncating(self):
        secret = "unique-fixture-password"
        raw = ("unrelated private output\n" + "error: " + "x" * 390 + secret + "\n"
               + "error: password = unknown-secret with spaces\n"
               + "execution error: administrator action failed\n")
        excerpt = smoke.redacted_error_excerpt(raw, (secret,))
        self.assertNotIn(secret, excerpt)
        self.assertNotIn("unknown-secret", excerpt)
        self.assertNotIn("unrelated private output", excerpt)
        self.assertIn("administrator action failed", excerpt)
        self.assertLessEqual(len(excerpt), 2000)

    def test_owned_operation_diagnostics_never_return_process_arguments(self):
        secret = "sensitive-command-argument"
        uid = os.getuid()
        raw = (f'{uid} 40 1 unrelated {secret}\n'
               f'{uid} 42 41 /usr/bin/osascript -e do shell script --stop with prompt {smoke.STOP_PROMPT} {secret}\n')
        with mock.patch.object(smoke, "run", return_value=subprocess.CompletedProcess([], 0, raw.encode(), b"")):
            observed = smoke.owned_operation_snapshot(41, smoke.STOP_PROMPT)
        self.assertEqual(observed["operation_prompt_children"], 1)
        self.assertEqual(observed["children"], 1)
        self.assertNotIn(secret, json.dumps(observed))

    def test_failure_snapshot_retains_operation_boundary_when_ax_is_unavailable(self):
        with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryFile() as log:
            intent = Path(temp) / "intent"
            intent.write_bytes(b"v1 stopping\n")
            secret = "private-fixture-password"
            log.write(f"Slipstream service lifecycle: administrator action failed {secret}\n".encode())
            log.flush()
            tray = mock.Mock(log=log)
            tray.alive.return_value = True
            tray.process.pid = 42
            tray.process.poll.return_value = None
            with mock.patch.object(smoke, "owned_operation_snapshot", return_value={"operation_prompt_children": 0}), \
                 mock.patch.object(smoke, "auth_snapshot", side_effect=smoke.QualificationError(f"AX failed {secret}")):
                observed = smoke.failure_snapshot(tray, intent, smoke.STOP_PROMPT, (secret,))
            self.assertEqual(observed["intent"], "stopping")
            self.assertEqual(observed["authorization_ui"]["observation"], "unavailable")
            self.assertTrue(observed["tray_alive_owned"])
            self.assertNotIn(secret, json.dumps(observed))

    def test_temporary_admin_cleanup_runs_on_failure_and_targets_created_user(self):
        calls = []
        accounts = {"root"}
        def record(args, **kwargs):
            calls.append(args)
            if "-addUser" in args:
                accounts.add(args[args.index("-addUser") + 1])
            if "-deleteUser" in args:
                accounts.remove(args[args.index("-deleteUser") + 1])
            return subprocess.CompletedProcess(args, 0, b"yes fixture is a member", b"")
        with mock.patch.object(smoke, "run", side_effect=record), \
             mock.patch.object(smoke, "require_disposable"), \
             mock.patch.object(smoke, "account_names", side_effect=lambda: accounts.copy()):
            with self.assertRaisesRegex(RuntimeError, "test failure"):
                with smoke.fixture_admin() as (username, _password):
                    raise RuntimeError("test failure")
        self.assertEqual(calls[-1][-2:], ["-deleteUser", username])
        self.assertTrue(username.startswith("slipstop"))


    def test_unknown_admin_creation_outcome_still_cleans_created_account(self):
        accounts = {"root"}
        deleted = []
        def record(args, **kwargs):
            if "-addUser" in args:
                username = args[args.index("-addUser") + 1]
                accounts.add(username)
                raise smoke.QualificationError("creation result unknown")
            if "-deleteUser" in args:
                username = args[args.index("-deleteUser") + 1]
                accounts.remove(username)
                deleted.append(username)
            return subprocess.CompletedProcess(args, 0, b"", b"")
        with mock.patch.object(smoke, "run", side_effect=record), \
             mock.patch.object(smoke, "require_disposable"), \
             mock.patch.object(smoke, "account_names", side_effect=lambda: accounts.copy()):
            with self.assertRaisesRegex(smoke.QualificationError, "unknown"):
                with smoke.fixture_admin():
                    self.fail("unknown result cannot authorize fixture")
        self.assertEqual(accounts, {"root"})
        self.assertEqual(len(deleted), 1)

    def test_new_error_observation_does_not_accept_old_cancel_log(self):
        with tempfile.TemporaryFile() as log:
            log.write(b"administrator action failed: old\n")
            log.flush()
            tray = smoke.Tray(Path("/candidate/slipstream"), log)
            offset = tray.checkpoint()
            self.assertFalse(tray.error_since(offset, "administrator action failed"))
            log.write(b"administrator action failed: new\n")
            log.flush()
            self.assertTrue(tray.error_since(offset, "administrator action failed"))

    def test_cleanup_refuses_unowned_tray_pid(self):
        tray = smoke.Tray(Path("/candidate/slipstream"), None)
        tray.process = mock.Mock()
        tray.process.poll.return_value = None
        with mock.patch.object(tray, "identity", return_value=False), mock.patch.object(smoke.os, "killpg") as kill:
            with self.assertRaisesRegex(smoke.QualificationError, "unowned"):
                tray.close()
            kill.assert_not_called()


if __name__ == "__main__":
    unittest.main()
