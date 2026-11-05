from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import live_site_release_smoke as smoke
import live_site_runtime_observation as runtime


class RuntimeObservationTests(unittest.TestCase):
    def test_status_keeps_only_allowlisted_scalars(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "status"
            path.write_text(json.dumps({
                "schema_version": 2,
                "daemon": {"pid": 23, "state": "active", "updated_at": 10},
                "backends": {"geph": {"state": "down", "owned": True,
                    "restart_recommended": True, "port_conflict": False,
                    "active_sessions": 0, "account": "private-secret"}},
                "recovery": {"state": "recovering", "reason": "owned_geph_restart_pending"},
                "browsing_history": "private-secret",
            }))
            value = runtime._status(path, 11.5)
            self.assertEqual(value["status_age_ms"], 1500)
            self.assertEqual(value["recovery_reason"], "owned_geph_restart_pending")
            self.assertNotIn("private", json.dumps(value))
            self.assertEqual(value["geph_state"], "down")

    def test_invalid_status_does_not_publish_untrusted_values(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "status"
            for text in ('{}', 'private-secret', '[]', '{"schema_version":2,"daemon":[]}'):
                path.write_text(text)
                self.assertEqual(runtime._status(path, 10), {"state": "unavailable"})

    def test_json_reader_refuses_symlink_size_and_nonprivate_ownership(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "status"
            path.write_text('{}')
            alias = Path(temporary) / "alias"
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                runtime._json_file(alias)
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                runtime._json_file(path, owner=os.getuid())
            path.chmod(0o600)
            self.assertEqual(runtime._json_file(path, owner=os.getuid()), {})
            path.write_bytes(b' ' * (runtime.MAX_JSON_BYTES + 1))
            with self.assertRaises(ValueError):
                runtime._json_file(path)

    def test_capture_distinguishes_missing_listener_and_successor_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            uid = os.getuid()
            paths = runtime.geph.geph_paths(home)
            paths.config_dir.mkdir(parents=True)
            paths.ownership.write_text(json.dumps({
                "pid": 100, "uid": uid, "launchd_label": runtime.geph.GEPH_LABEL,
                "executable": str(paths.executable), "config": str(paths.config),
            }))
            paths.ownership.chmod(0o600)
            for code, listeners, stderr, expected in (
                (1, b'', b'', 'absent'), (0, b'200\n', b'', 'present'),
                (2, b'private-secret', b'', 'unavailable'),
                (1, b'', b'private-secret', 'unavailable'),
            ):
                with (
                    self.subTest(expected=expected),
                    mock.patch.object(runtime.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir=temporary)),
                    mock.patch.object(runtime.subprocess, "run", side_effect=[
                        SimpleNamespace(returncode=0, stdout=b' pid = 200\n state = running\n secret = private-secret\n', stderr=b''),
                        SimpleNamespace(returncode=code, stdout=listeners, stderr=stderr),
                    ]) as run,
                ):
                    value = runtime.capture(uid, home / "missing-status")
                self.assertEqual(value["listener"], expected)
                self.assertEqual(value["record_pid"], 100)
                self.assertEqual(value["launchd_pid"], 200)
                self.assertIs(value["record_matches_launchd"], False)
                self.assertNotIn("private-secret", json.dumps(value))
                self.assertEqual(len(run.call_args_list), 2)
                self.assertEqual(run.call_args_list[0].args[0][:2], ("/bin/launchctl", "print"))
                self.assertIn("-sTCP:LISTEN", run.call_args_list[1].args[0])

    def test_command_timeout_is_not_listener_absence_and_never_retries(self):
        with mock.patch.object(runtime.subprocess, "run", side_effect=subprocess.TimeoutExpired('private', 1)) as run:
            self.assertIsNone(runtime._command(("/bin/launchctl", "print"), runtime.time.monotonic() + 1))
        run.assert_called_once()
        with mock.patch.object(runtime.subprocess, "run") as run:
            self.assertIsNone(runtime._command(("/bin/launchctl", "print"), runtime.time.monotonic() - 1))
        run.assert_not_called()

    def test_diagnostic_failure_cannot_replace_primary_failure(self):
        observation = {"net_error": "net::ERR_CONNECTION_CLOSED"}
        smoke._observe_runtime(observation, mock.Mock(side_effect=RuntimeError('private-secret')))
        self.assertEqual(observation, {"net_error": "net::ERR_CONNECTION_CLOSED", "runtime": {"state": "unavailable"}})

    def test_chrome_samples_failure_before_cleanup_without_another_navigation(self):
        from test_live_site_release_smoke import LiveSiteReleaseSmokeTests
        factory = LiveSiteReleaseSmokeTests()
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            lifecycle = factory._enter_chrome_lifecycle(stack, Path(temporary))
            stack.enter_context(mock.patch.object(smoke.chromium, "_wait_for_devtools_port", return_value=9222))
            stack.enter_context(mock.patch.object(smoke.chromium, "_devtools_json", return_value=[{
                "type": "page", "url": "about:blank", "webSocketDebuggerUrl": "ws://127.0.0.1/devtools/page/1",
            }]))
            navigate = stack.enter_context(mock.patch.object(smoke.chromium, "_devtools_command", return_value={"errorText": "net::ERR_CONNECTION_CLOSED"}))
            def sample():
                lifecycle.stop.assert_not_called()
                return {"listener": "absent"}
            observer = mock.Mock(side_effect=sample)
            evidence = {}
            result = smoke._run_chrome("xpersonatoy.com", lifecycle.executable, 501, 20,
                                       failure_observation=evidence, runtime_observer=observer)
        self.assertEqual(result["reason"], "navigation_rejected")
        self.assertEqual(evidence["runtime"]["listener"], "absent")
        observer.assert_called_once()
        navigate.assert_called_once()
        lifecycle.stop.assert_called_once()

    def test_control_samples_after_its_only_attempt_and_keeps_result(self):
        evidence = {}
        with mock.patch.object(smoke.subprocess, "run", return_value=SimpleNamespace(
            returncode=7, stdout=b'\n__SLIPSTREAM_STATUS__:000', stderr=b'private-secret',
        )) as request:
            def sample():
                request.assert_called_once()
                return {"listener": "absent"}
            result = smoke._control_route("xpersonatoy.com", "owned_geph", failure_observation=evidence,
                                          runtime_observer=sample)
        self.assertEqual(result, "unavailable")
        self.assertEqual(evidence["runtime"]["listener"], "absent")
        self.assertNotIn("private", json.dumps(evidence))

    def test_safari_samples_only_failure_before_cleanup(self):
        from test_live_site_release_smoke import LiveSiteReleaseSmokeTests
        factory = LiveSiteReleaseSmokeTests()
        for failed in (False, True):
            with self.subTest(failed=failed):
                events = []
                def webdriver(_base, method, path, _payload=None, **_kwargs):
                    events.append((method, path))
                    if path == "/session":
                        return {"value": {"sessionId": "session-id"}}
                    if path.endswith("/url") and failed:
                        raise smoke.lifecycle.LifecycleError("private-secret")
                    if path.endswith("/execute/sync"):
                        return {"value": json.dumps(factory._browser_evidence())}
                    return {}
                def sample():
                    self.assertFalse(any(method == "DELETE" for method, _ in events))
                    return {"listener": "absent"}
                with (
                    mock.patch.object(smoke, "_wait_for_safaridriver_ready"),
                    mock.patch.object(smoke.lifecycle, "_assert_no_safari_process"),
                    mock.patch.object(smoke.lifecycle, "_wait_for_safari_process", return_value=4321),
                    mock.patch.object(smoke.lifecycle, "_stop_owned_safari_process") as stop,
                    mock.patch.object(smoke.lifecycle, "_webdriver_request", side_effect=webdriver),
                ):
                    observation = {}
                    observer = mock.Mock(side_effect=sample)
                    result = smoke._run_safari("app.aikido.dev", "http://127.0.0.1:1", 501,
                                               failure_observation=observation, runtime_observer=observer)
                self.assertEqual(result["outcome"], "terminal_error" if failed else "usable")
                self.assertEqual(observer.call_count, int(failed))
                self.assertEqual(sum(path.endswith("/url") for _, path in events), 1)
                self.assertEqual(sum(method == "DELETE" for method, _ in events), 1)
                stop.assert_called_once()


if __name__ == "__main__":
    unittest.main()
