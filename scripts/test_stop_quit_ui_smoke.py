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
    def test_actual_geph_disable_block_survives_crash_and_retries_disabled_cleanup(self):
        # Compile the production arm and startup branch with inert file/process adapters.
        # This catches effects ordering and crash behavior without a native app build.
        source_dir = Path(__file__).resolve().parents[1] / "app-tauri/src-tauri/src"
        source = (source_dir / "lib.rs").read_text()
        enabled_write = source.index('geph_config_set(app, "enabled", "1");', source.index('ID_GEPH_ENABLE => {'))
        marker = '                            } else {'
        start = source.index(marker, enabled_write) + len(marker)
        end = source.index('\n                            }\n                        }\n                        ID_LAUNCH', start)
        disable = source[start:end]
        start = source.index('    if !geph_enabled(app) {', source.index('fn ensure_geph_launch_agent('))
        startup = source[start:source.index('    let Some(secret)', start)]
        config = (source_dir / "geph_config.rs").read_text()
        start = config.index('fn resolve_geph_enabled_state(')
        resolver = config[start:config.index('/// Whether Slipstream', start)]
        fixture = r"""
use std::cell::{Cell, RefCell};
use std::sync::atomic::{AtomicUsize, Ordering};
#[derive(Clone, Copy, PartialEq)] enum GephSecretAvailability { Present, Missing }
struct App { path: std::path::PathBuf, save_ok: Cell<bool>, cleanup: Cell<u8>, calls: Cell<usize>, alive: Cell<bool>, notes: RefCell<Vec<String>> }
impl App { fn new() -> Self {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = std::path::PathBuf::from(std::env::var_os("GEPH_TEST_ROOT").unwrap()).join(format!("enabled-{}", NEXT.fetch_add(1, Ordering::Relaxed)));
    std::fs::write(&path, "1").unwrap();
    Self { path, save_ok: Cell::new(true), cleanup: Cell::new(0), calls: Cell::new(0), alive: Cell::new(true), notes: RefCell::new(vec![]) }
} }
struct Check(Cell<bool>);
impl Check { fn set_checked(&self, value: bool) -> Result<(), ()> { self.0.set(value); Ok(()) } }
fn geph_config_set(app: &App, key: &str, value: &str) {
    assert_eq!(key, "enabled"); if app.save_ok.get() { std::fs::write(&app.path, value).unwrap(); }
}
fn geph_field(app: &App, key: &str) -> Option<String> { assert_eq!(key,"enabled"); std::fs::read_to_string(&app.path).ok() }
fn geph_launch_agent_disable(app: &App) -> Result<(), String> {
    app.calls.set(app.calls.get()+1);
    match app.cleanup.get() {
        1 => Err("injected cleanup failure".into()),
        2 => { app.alive.set(false); panic!("injected crash after cleanup"); },
        _ => { app.alive.set(false); Ok(()) }
    }
}
fn notify(app: &App, text: &str) { app.notes.borrow_mut().push(text.into()); }
fn tr(text: &str) -> String { text.into() }
fn geph_enabled(app: &App) -> bool { resolve_geph_enabled_state(geph_field(app,"enabled").as_deref(), true, GephSecretAvailability::Present).0 }
fn startup(app: &App) -> Result<bool, String> { STARTUP panic!("disabled preference must not reach bootstrap"); }
fn disable(app: &App, enable_h: &Check) { DISABLE }
#[test] fn crash_after_cleanup_retains_disabled_preference_and_reopen_cleans_only() {
    let app=App::new(); let check=Check(Cell::new(true)); app.cleanup.set(2);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| disable(&app,&check))).is_err());
    assert_eq!(geph_field(&app,"enabled").as_deref(), Some("0"));
    app.cleanup.set(0); app.alive.set(true);
    assert_eq!(startup(&app),Ok(false)); assert_eq!(app.calls.get(),2); assert!(!app.alive.get());
}
#[test] fn failed_persistence_does_not_begin_cleanup_or_claim_stopped() {
    let app=App::new(); let check=Check(Cell::new(true)); app.save_ok.set(false); disable(&app,&check);
    assert_eq!(app.calls.get(),0); assert!(app.alive.get()); assert!(check.0.get());
    assert_eq!(geph_field(&app,"enabled").as_deref(), Some("1"));
    assert!(!app.notes.borrow().is_empty()); assert!(app.notes.borrow().iter().all(|s| !s.contains("Geph stopped")));
}
#[test] fn cleanup_failure_retains_off_and_reports_possible_running_process() {
    let app=App::new(); let check=Check(Cell::new(true)); app.cleanup.set(1); disable(&app,&check);
    assert_eq!(geph_field(&app,"enabled").as_deref(), Some("0")); assert!(!check.0.get()); assert!(app.alive.get());
    assert!(app.notes.borrow().iter().any(|s| s.contains("may still be running")));
}
#[test] fn successful_disable_persists_off_and_stops() {
    let app=App::new(); let check=Check(Cell::new(true)); disable(&app,&check);
    assert_eq!(geph_field(&app,"enabled").as_deref(), Some("0")); assert!(!check.0.get()); assert!(!app.alive.get());
    assert!(app.notes.borrow().is_empty());
}
"""
        with tempfile.TemporaryDirectory() as temp:
            test_source = Path(temp) / "geph_disable.rs"
            binary = Path(temp) / "geph_disable_test"
            test_source.write_text(resolver + fixture.replace("STARTUP", startup).replace("DISABLE", disable))
            compiled = subprocess.run(["rustc", "--test", "--edition=2021", str(test_source), "-o", str(binary)],
                                      capture_output=True, text=True, timeout=60)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10,
                                    env={**os.environ, "GEPH_TEST_ROOT": temp})
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

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

    def test_native_cancel_and_submission_are_distinct_results(self):
        with mock.patch.object(smoke, "applescript", return_value="cancelled") as apple:
            self.assertEqual(smoke.auth_action(smoke.STOP_PROMPT, cancel=True), "cancelled")
            script = apple.call_args.args[0]
            self.assertIn(smoke.STOP_PROMPT, script)
            self.assertIn('click item 1 of cancelButtons', script)
            self.assertNotIn('set value of item 1 of secretFields', script)
        with mock.patch.object(smoke, "applescript", return_value="submitted") as apple:
            self.assertEqual(smoke.auth_action(smoke.STOP_PROMPT, username="fixture", password="secret"), "submitted")
            self.assertTrue(apple.call_args.kwargs["sensitive"])
            self.assertIn('return "submitted"', apple.call_args.args[0])
            self.assertNotIn('return "confirmed"', apple.call_args.args[0])

    def test_pending_authorization_observer_never_focuses_writes_or_clicks(self):
        with mock.patch.object(smoke, "applescript", return_value="pending") as apple:
            self.assertEqual(smoke.auth_action(smoke.STOP_PROMPT, submit=False,
                username="private-fixture-user", password="private-fixture-secret"), "pending")
        script = apple.call_args.args[0]
        for forbidden in ("set frontmost", "set value of", "click ",
                          "private-fixture-user", "private-fixture-secret"):
            self.assertNotIn(forbidden, script)
        self.assertIn('return "pending"', script)
        self.assertTrue(apple.call_args.kwargs["sensitive"])

    def test_explicit_rejection_is_classified_before_submission_without_text_output(self):
        with mock.patch.object(smoke, "applescript", return_value="rejected") as apple:
            self.assertEqual(smoke.auth_action(smoke.STOP_PROMPT,
                username="private-user", password="private-secret"), "rejected")
        script = apple.call_args.args[0]
        self.assertLess(script.index('then return "rejected"'), script.index('set value of item 1 of userFields'))
        self.assertNotIn("return rejectionText", script)
        self.assertNotIn("return valueText", script)

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
                      'set authStage to "element_read"', f'valueText contains "{smoke.STOP_PROMPT}"',
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
                 mock.patch.object(smoke, "root_readiness_snapshot", return_value={}), \
                 mock.patch.object(smoke, "auth_snapshot", side_effect=smoke.QualificationError(f"AX failed {secret}")):
                observed = smoke.failure_snapshot(tray, intent, smoke.STOP_PROMPT, (secret,))
            self.assertEqual(observed["intent"], "stopping")
            self.assertEqual(observed["authorization_ui"]["observation"], "unavailable")
            self.assertTrue(observed["tray_alive_owned"])
            self.assertNotIn(secret, json.dumps(observed))

    def test_root_failure_snapshot_is_bounded_allowlisted_and_keeps_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            status, evidence = Path(temp) / "status", Path(temp) / "attestation"
            status.write_text(json.dumps({"daemon": {"state":"active", "phase":"private-secret", "pid":42, "heartbeat_seq":9}, "secret":"private-secret"}))
            evidence.write_text(json.dumps({"state":"dormant", "pf_active":False, "launchd":{"pid":42}, "private_path":"private-secret"}))
            witness = Path(str(evidence) + ".daemon")
            witness.write_bytes(b"unread private payload")
            with mock.patch.object(smoke, "STATUS", status), mock.patch.object(smoke, "ATTESTATION", evidence):
                observed = smoke.root_readiness_snapshot()
                self.assertEqual(observed["status"]["heartbeat_seq"], 9)
                self.assertEqual(observed["status"]["phase"], "unknown")
                self.assertFalse(observed["attestation"]["pf_active"])
                self.assertNotIn("private", json.dumps(observed))
                self.assertIn("nlink", observed["witness"])
                evidence.write_text("invalid json")
                self.assertIn("metadata", smoke.root_readiness_snapshot()["attestation"])
                evidence.write_bytes(b"x" * 4097)
                self.assertEqual(smoke.root_readiness_snapshot()["attestation"]["observation"], "unavailable")

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
            log.write(b"Slipstream service lifecycle: Resume: old failure\n")
            log.flush()
            tray = smoke.Tray(Path("/candidate/slipstream"), log)
            offset = tray.checkpoint()
            self.assertFalse(tray.error_since(offset, "administrator action failed"))
            self.assertFalse(tray.error_since(offset, "Slipstream service lifecycle: Resume:"))
            log.write(b"administrator action failed: new\n")
            log.flush()
            self.assertTrue(tray.error_since(offset, "administrator action failed"))
            log.write(b"Slipstream service lifecycle: Resume: current readiness failure\n")
            log.flush()
            self.assertTrue(tray.error_since(offset, "Slipstream service lifecycle: Resume:"))

    def test_cleanup_refuses_unowned_tray_pid(self):
        tray = smoke.Tray(Path("/candidate/slipstream"), None)
        tray.process = mock.Mock()
        tray.process.poll.return_value = None
        with mock.patch.object(tray, "identity", return_value=False), mock.patch.object(smoke.os, "killpg") as kill:
            with self.assertRaisesRegex(smoke.QualificationError, "unowned"):
                tray.close()
            kill.assert_not_called()


class AuthorizationProgressTests(unittest.TestCase):
    def exercise(self, observations, done=None, *, require_submission=False):
        # A deterministic native-dialog adapter: only submit=True writes fields
        # and presses OK. Read-only observations never touch fixture credentials.
        now = [0.0]
        submits = []
        reads = []
        states = iter(observations)
        last = ["pending"]
        def observe(prompt, *, submit=True, timeout=15):
            if submit:
                submits.append(now[0])
                return "submitted"
            reads.append(now[0])
            last[0] = next(states, last[0])
            return last[0]
        def sleep(seconds):
            now[0] += seconds
        result = {}
        with mock.patch.object(smoke.time, "monotonic", side_effect=lambda: now[0]), \
             mock.patch.object(smoke.time, "sleep", side_effect=sleep):
            try:
                value = smoke.authorize_until(done or (lambda: False), observe,
                    result=result, require_submission=require_submission)
                error = None
            except smoke.QualificationError as caught:
                value, error = None, caught
        return value, error, submits, reads, now[0], result

    def test_pending_prompt_submits_once_until_original_deadline(self):
        _, error, submits, reads, elapsed, result = self.exercise(["pending"])
        self.assertIsInstance(error, smoke.QualificationError)
        self.assertEqual(len(submits), 1, "pending authorization must not rewrite credentials or press OK again")
        self.assertGreater(len(reads), 1)
        self.assertGreaterEqual(elapsed, 90)
        self.assertLess(elapsed, 90.21)
        self.assertEqual(result["authorization_attempts"][-1]["state"], "pending")
        self.assertNotIn("confirmed", json.dumps(result))

    def test_rejected_prompt_fails_without_resubmission(self):
        _, error, submits, reads, elapsed, result = self.exercise(["pending", "rejected"])
        self.assertRegex(str(error), "authorization was rejected")
        self.assertEqual(len(submits), 1)
        self.assertLess(elapsed, 90)
        self.assertEqual(result["authorization_attempts"][-1]["state"], "rejected")

    def test_disappearance_requires_operation_completion(self):
        _, error, submits, _, elapsed, result = self.exercise(["absent"])
        self.assertIsInstance(error, smoke.QualificationError)
        self.assertEqual(len(submits), 1)
        self.assertGreaterEqual(elapsed, 90)
        attempt = result["authorization_attempts"][-1]
        self.assertTrue(attempt["prompt_disappeared"])
        self.assertFalse(attempt["operation_completed"])

    def test_pending_prompt_does_not_accept_stale_done(self):
        done = mock.Mock(return_value=True)
        _, error, submits, _, _, _ = self.exercise(["pending"], done, require_submission=True)
        self.assertIsInstance(error, smoke.QualificationError)
        self.assertEqual(len(submits), 1)
        done.assert_not_called()

    def test_disappeared_prompt_and_completed_operation_pass(self):
        done = mock.Mock(side_effect=[False, True])
        value, error, submits, reads, _, result = self.exercise(["pending", "absent"], done, require_submission=True)
        self.assertIsNone(error)
        self.assertTrue(value)
        self.assertEqual(len(submits), 1)
        self.assertEqual(done.call_count, 2)
        self.assertGreaterEqual(len(reads), 3)
        self.assertTrue(result["authorization_attempts"][-1]["operation_completed"])

    def test_reappearing_prompt_is_not_resubmitted(self):
        _, error, submits, _, _, result = self.exercise(["absent", "pending"])
        self.assertIsInstance(error, smoke.QualificationError)
        self.assertEqual(len(submits), 1)
        self.assertTrue(result["authorization_attempts"][-1]["prompt_disappeared"])
        self.assertEqual(result["authorization_attempts"][-1]["state"], "pending")

    def test_unknown_observation_does_not_leak_text_or_qualify(self):
        private = "private-authentication-detail"
        result = {}
        with self.assertRaisesRegex(smoke.QualificationError, "unexpected native authorization observation") as caught:
            smoke.authorize_until(lambda: True, lambda *a, **k: private, result=result)
        self.assertNotIn(private, str(caught.exception))
        self.assertNotIn(private, json.dumps(result))

    def test_no_prompt_allows_cached_authorization_only_when_not_required(self):
        for required in (False, True):
            with self.subTest(required=required):
                now = [0.0]
                def sleep(seconds):
                    now[0] += seconds
                with mock.patch.object(smoke.time, "monotonic", side_effect=lambda: now[0]), \
                     mock.patch.object(smoke.time, "sleep", side_effect=sleep):
                    if required:
                        with self.assertRaises(smoke.QualificationError):
                            smoke.authorize_until(lambda: True, lambda *a, **k: "absent",
                                result={}, require_submission=True)
                    else:
                        self.assertFalse(smoke.authorize_until(lambda: True,
                            lambda *a, **k: "absent", result={}))


class AuthorizationObservationTests(unittest.TestCase):
    def drive(self, observations, *, done=None, require_submission=False, timeout=90):
        now, calls, result = [0.0], [], {}
        states = iter(observations)
        done = done if done is not None else mock.Mock(return_value=True)

        def apple(script, **kwargs):
            calls.append((script, kwargs))
            response = next(states, "pending")
            if isinstance(response, tuple):
                response, elapsed = response
                now[0] += elapsed
            if isinstance(response, Exception):
                raise response
            return response

        def sleep(seconds):
            now[0] += seconds

        with mock.patch.object(smoke, "applescript", side_effect=apple), \
             mock.patch.object(smoke.time, "monotonic", side_effect=lambda: now[0]), \
             mock.patch.object(smoke.time, "sleep", side_effect=sleep):
            try:
                value = smoke.authorize_until(done, smoke.auth_action, result=result,
                    require_submission=require_submission, timeout=timeout)
                error = None
            except smoke.QualificationError as caught:
                value, error = None, caught
        return value, error, calls, result, done, now[0]

    def test_transient_preclick_error_recovers_without_losing_stage_or_code(self):
        value, error, calls, result, _, _ = self.drive([
            "ax_error|inventory|-1728", "ax_error|write_username|-25204",
            "submitted", "pending", "absent"], require_submission=True)
        self.assertIsNone(error)
        self.assertTrue(value)
        attempt = result["authorization_attempts"][-1]
        self.assertEqual(attempt["transient_errors"], 2)
        self.assertEqual(attempt["last_error"], {"stage": "write_username", "code": -25204})
        self.assertTrue(attempt["submission_attempted"])
        self.assertFalse(attempt["submission_uncertain"])
        self.assertTrue(all("click item 1 of confirmButtons" not in call[0] for call in calls[3:]))

    def test_click_error_is_uncertain_and_never_resubmitted_or_qualified(self):
        for required in (False, True):
            with self.subTest(require_submission=required):
                value, error, calls, result, done, _ = self.drive([
                    "ax_error|confirm|-25204", "pending", "absent"], require_submission=required)
                self.assertIsNone(value)
                self.assertRegex(str(error), r"stage=confirm code=-25204")
                attempt = result["authorization_attempts"][-1]
                self.assertFalse(attempt["submitted"])
                self.assertTrue(attempt["submission_attempted"])
                self.assertTrue(attempt["submission_uncertain"])
                self.assertTrue(attempt["operation_completed"])
                self.assertTrue(attempt["prompt_disappeared"])
                self.assertEqual(done.call_count, 1)
                self.assertEqual(len(calls), 3)
                for script, _ in calls[1:]:
                    self.assertNotIn("click ", script)
                    self.assertNotIn("set value of", script)
                    self.assertNotIn("set frontmost", script)

    def test_confirmed_submission_stays_readonly_after_transient_observer_error(self):
        value, error, calls, result, _, _ = self.drive([
            "submitted", "ax_error|element_read|-1728", "absent"])
        self.assertIsNone(error)
        self.assertTrue(value)
        self.assertEqual(len(calls), 3)
        self.assertTrue(result["authorization_attempts"][-1]["submitted"])
        self.assertTrue(all("click " not in call[0] for call in calls[1:]))

    def test_permission_unknown_and_structural_errors_fail_closed(self):
        for observation in ("ax_error|inventory|-10005", "ax_error|inventory|-1743",
                            "ax_error|inventory|-2700", "ax_error|inventory|-1712",
                            "ax_error|form_shape|-1728", "ax_error|window_shape|-25204"):
            with self.subTest(observation=observation):
                _, error, calls, result, done, elapsed = self.drive([observation])
                self.assertIsInstance(error, smoke.QualificationError)
                self.assertEqual(len(calls), 1)
                self.assertEqual(elapsed, 0)
                self.assertFalse(result["authorization_attempts"][-1]["submitted"])
                done.assert_not_called()

    def test_unknown_script_outcome_never_retries_or_exposes_private_text(self):
        private = "private-authentication-detail"
        for observation in (private, "ax_error|" + private + "|-1728",
                            "ax_error|inventory|" + private,
                            "ax_error|confirm|-25204|" + private,
                            smoke.QualificationError("osascript failed (1): " + private)):
            with self.subTest(kind=type(observation).__name__):
                _, error, calls, result, done, _ = self.drive([observation])
                self.assertIsInstance(error, smoke.QualificationError)
                self.assertNotIn(private, str(error))
                self.assertNotIn(private, json.dumps(result))
                self.assertEqual(len(calls), 1)
                self.assertEqual(result["authorization_attempts"][-1]["last_error"],
                                 {"stage": "script", "code": None})
                done.assert_not_called()

    def test_remaining_budget_limits_subprocess_and_rejects_late_submission(self):
        observations = [("ax_error|inventory|-1728", 14.9)] * 5
        observations += [("ax_error|inventory|-1728", 14.2), ("submitted", .2)]
        _, error, calls, result, done, elapsed = self.drive(observations)
        self.assertIsInstance(error, smoke.QualificationError)
        self.assertEqual(len(calls), 7)
        self.assertLess(calls[-1][1]["timeout"], .11)
        self.assertGreater(calls[-1][1]["timeout"], 0)
        self.assertTrue(all(call[1]["timeout"] <= 15 for call in calls))
        self.assertLess(elapsed, 90.11)
        self.assertTrue(result["authorization_attempts"][-1]["submitted"])
        self.assertFalse(result["authorization_attempts"][-1]["operation_completed"])
        done.assert_not_called()

    def test_late_absence_cannot_accept_cached_authorization(self):
        _, error, _, result, done, _ = self.drive([("absent", .3)], timeout=.25)
        self.assertIsInstance(error, smoke.QualificationError)
        self.assertFalse(result["authorization_attempts"][-1]["operation_completed"])
        done.assert_not_called()

    def test_transient_errors_do_not_extend_deadline(self):
        _, error, calls, result, done, elapsed = self.drive(
            ["ax_error|inventory|-1728"] * 10, timeout=.25)
        self.assertIsInstance(error, smoke.QualificationError)
        self.assertEqual(len(calls), 2)
        self.assertAlmostEqual(elapsed, .25)
        self.assertFalse(result["authorization_attempts"][-1]["submission_attempted"])
        done.assert_not_called()

    def test_action_marks_stage_before_click_and_checks_form_before_writes(self):
        with mock.patch.object(smoke, "applescript", return_value="submitted") as apple:
            smoke.auth_action(smoke.STOP_PROMPT, username="fixture", password="secret", timeout=.5)
        script = apple.call_args.args[0]
        self.assertEqual(apple.call_args.kwargs["timeout"], .5)
        self.assertLess(script.index('set authStage to "confirm"'), script.index("click item 1 of confirmButtons"))
        self.assertLess(script.index("if (count of confirmButtons) is not 1"), script.index("set value of item 1 of userFields"))
        self.assertIn("on error number errorCode", script)
        self.assertIn('return "ax_error|" & authStage & "|" & errorCode', script)
        self.assertNotIn("set readErrors to readErrors + 1", script)


if __name__ == "__main__":
    unittest.main()
