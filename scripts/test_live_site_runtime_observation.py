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

    def test_heartbeat_does_not_make_cached_health_fresh(self):
        status = {
            "schema_version": 2,
            "daemon": {"updated_at": 1793933700, "heartbeat_at": "2026-11-06T02:55:00Z",
                       "health_updated_at": "2026-11-06T02:54:40+00:00"},
            "backends": {"geph": {}},
            "recovery": {"last_action": "geph_restart", "updated_at": 1793933698, "count": 2},
        }
        with mock.patch.object(runtime, "_json_file", return_value=status):
            value = runtime._status(Path("unused"), 1793933700.5)
        self.assertEqual(value["status_age_ms"], 500)
        self.assertEqual(value["heartbeat_age_ms"], 500)
        self.assertEqual(value["health_age_ms"], 20500)
        self.assertEqual(value["health_updated_at"], 1793933680)
        self.assertEqual(value["recovery_last_action"], "geph_restart")
        self.assertEqual(value["recovery_updated_at"], 1793933698)
        self.assertEqual(value["recovery_count"], 2)

    def test_malformed_health_and_recovery_fields_stay_unknown(self):
        for invalid in (None, True, "private-secret", "2026-11-06T02:54:40",
                        "2026-11-06T02:54:40+0060", float("nan"), float("inf"), -1, 10**500):
            with self.subTest(value_type=type(invalid).__name__):
                status = {"schema_version": 2,
                          "daemon": {"updated_at": 10, "health_updated_at": invalid},
                          "backends": {"geph": {}},
                          "recovery": {"last_action": "private-secret", "updated_at": invalid, "count": True}}
                with mock.patch.object(runtime, "_json_file", return_value=status):
                    value = runtime._status(Path("unused"), 11)
                self.assertEqual(value["heartbeat_age_ms"], 1000)
                self.assertIsNone(value["health_age_ms"])
                self.assertIsNone(value["health_updated_at"])
                self.assertIsNone(value["recovery_updated_at"])
                self.assertIsNone(value["recovery_count"])
                self.assertEqual(value["recovery_last_action"], "unknown")
                self.assertNotIn("private-secret", json.dumps(value, allow_nan=False))

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


class DaemonLogObservationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.log = self.home / "slipstream.log"
        patcher = mock.patch.object(runtime, "DAEMON_LOG_PATH", self.log)
        patcher.start()
        self.addCleanup(patcher.stop)

    @staticmethod
    def line(message, second=0):
        return f"2026-11-06T02:55:{second:02d}+0000 >> {message}\n".encode()

    def observe(self, host="xpersonatoy.com"):
        return runtime._daemon_log(host, runtime.time.monotonic() + 2)

    def test_only_exact_host_markers_and_daemon_restart_are_exported(self):
        self.assertEqual(runtime.FIXED_LOG_HOSTS, frozenset(smoke.SITES))
        self.log.write_bytes(b"".join([
            self.line("geph route retry for xpersonatoy.com: SOCKS connect failed", 1),
            self.line("geph route retry for xpersonatoy.com: first payload timeout", 2),
            self.line("geph route retry for xpersonatoy.com: remote closed without response", 3),
            self.line("owned Geph LaunchAgent restarted after routing became idle", 4),
            self.line("geph route retry for private-secret.example: first payload timeout"),
            self.line("geph route retry for xpersonatoy.com.evil: first payload timeout"),
            self.line("geph route retry for xpersonatoy.com: SOCKS connect failed private-secret"),
            self.line("owned Geph recovery unavailable: https://private-secret.example/path"),
            b"2026-99-99T02:55:00+0000 >> geph route retry for xpersonatoy.com: first payload timeout\n",
            b"2026-11-06T02:55:00+0060 >> geph route retry for xpersonatoy.com: first payload timeout\n",
            b"private-secret\n\x00\xff\n",
        ]))
        value = self.observe()
        self.assertEqual(value["state"], "sampled")
        self.assertEqual(value["counts"], {"connect_failed": 1, "first_payload_timeout": 1,
                                         "remote_closed": 1, "owned_restart": 1})
        self.assertEqual([event["at"] for event in value["events"]],
                         [1793933701, 1793933702, 1793933703, 1793933704])
        self.assertEqual([event["scope"] for event in value["events"]], ["host"] * 3 + ["daemon"])
        encoded = json.dumps(value, allow_nan=False)
        for forbidden in ("private-secret", "xpersonatoy", "https://", str(self.home)):
            self.assertNotIn(forbidden, encoded)
        self.assertFalse(value["request_window_scoped"])
        self.assertFalse(value["absence_proves_no_dial"])
        self.assertTrue(value["rate_limited"])
        self.assertFalse(value["rotation_atomic"])

    def test_none_and_nonallowlisted_hosts_do_not_open_files(self):
        for host in (None, "private-secret", "XPERSONATOY.COM", "xpersonatoy.com/", [], True):
            with self.subTest(host_type=type(host).__name__), mock.patch.object(runtime.os, "open") as opened:
                value = self.observe(host)
            opened.assert_not_called()
            self.assertEqual(value["state"], "not_requested" if host is None else "unavailable")
            self.assertEqual(value["events"], [])
            self.assertNotIn("private-secret", json.dumps(value))

    def test_missing_logs_are_not_proof_of_no_dial(self):
        value = self.observe()
        self.assertEqual(value["state"], "missing")
        self.assertEqual([part["state"] for part in value["sources"].values()], ["missing", "missing"])
        self.assertFalse(value["absence_proves_no_dial"])

    def test_refuses_symlink_directory_and_fifo(self):
        target = self.home / "target"
        target.write_bytes(self.line("owned Geph LaunchAgent restarted after routing became idle"))
        for kind in ("symlink", "directory", "fifo"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    self.log.symlink_to(target)
                elif kind == "directory":
                    self.log.mkdir()
                else:
                    os.mkfifo(self.log)
                try:
                    value = self.observe()
                finally:
                    self.log.rmdir() if kind == "directory" else self.log.unlink()
                self.assertEqual(value["sources"]["current"]["state"], "unavailable")
                self.assertEqual(value["events"], [])

    def test_tail_reads_have_fixed_byte_bounds_and_discard_fragments(self):
        valid = self.line("geph route retry for xpersonatoy.com: SOCKS connect failed")
        fragment = self.line("geph route retry for xpersonatoy.com: first payload timeout")
        self.log.write_bytes(b"private-secret" * 800 + fragment + valid + fragment.rstrip(b"\n"))
        with (mock.patch.object(runtime, "MAX_LOG_TAIL_BYTES", 512),
              mock.patch.object(runtime.os, "read", wraps=os.read) as read):
            value = self.observe()
        self.assertEqual([call.args[1] for call in read.call_args_list], [512])
        self.assertTrue(value["tail_truncated"])
        self.assertTrue(value["sources"]["current"]["partial_line_discarded"])
        self.assertEqual(value["sources"]["current"]["bytes_read"], 512)
        self.assertEqual(value["counts"]["connect_failed"], 1)
        self.assertEqual(value["counts"]["first_payload_timeout"], 0)

    def test_reads_only_dot_one_archive_and_deduplicates_rotation_inode(self):
        self.log.write_bytes(self.line("owned Geph LaunchAgent restarted after routing became idle"))
        os.link(self.log, Path(f"{self.log}.1"))
        Path(f"{self.log}.2").write_bytes(self.line("geph route retry for xpersonatoy.com: first payload timeout"))
        with mock.patch.object(runtime.os, "open", wraps=os.open) as opened:
            value = self.observe()
        self.assertEqual([call.args[0] for call in opened.call_args_list],
                         [self.log, Path(f"{self.log}.1")])
        for call in opened.call_args_list:
            self.assertTrue(call.args[1] & os.O_NOFOLLOW)
            self.assertTrue(call.args[1] & os.O_NONBLOCK)
        self.assertEqual(value["archive_limit"], 1)
        self.assertEqual(value["sources"]["archive"]["state"], "duplicate")
        self.assertEqual(value["state"], "partial")
        self.assertEqual(value["counts"]["owned_restart"], 1)
        self.assertEqual(value["counts"]["first_payload_timeout"], 0)

    def test_archive_events_are_bounded_and_sorted_with_current(self):
        Path(f"{self.log}.1").write_bytes(b"".join(
            self.line("geph route retry for xpersonatoy.com: SOCKS connect failed", second)
            for second in range(40)
        ))
        self.log.write_bytes(self.line("owned Geph LaunchAgent restarted after routing became idle", 50))
        value = self.observe()
        self.assertEqual(value["counts"]["connect_failed"], 40)
        self.assertEqual(len(value["events"]), runtime.MAX_LOG_EVENTS)
        self.assertTrue(value["events_truncated"])
        self.assertEqual(value["events"][-1]["kind"], "owned_restart")
        self.assertEqual(value["events"][0]["at"], 1793933709)

    def test_deadline_prevents_open_and_discards_a_late_read(self):
        self.log.write_bytes(self.line("owned Geph LaunchAgent restarted after routing became idle"))
        with (mock.patch.object(runtime.time, "monotonic", return_value=2),
              mock.patch.object(runtime.os, "open") as opened):
            value = runtime._daemon_log("xpersonatoy.com", 1)
        opened.assert_not_called()
        self.assertTrue(value["time_limited"])
        self.assertEqual(value["events"], [])
        with mock.patch.object(runtime.time, "monotonic", side_effect=[0, 0, 2]):
            source, raw = runtime._log_tail(self.log, 1, set())
        self.assertEqual(source["state"], "timed_out")
        self.assertGreater(source["bytes_read"], 0)
        self.assertEqual(raw, b"")

    def test_read_error_does_not_escape_or_publish_exception_text(self):
        self.log.write_bytes(b"private-secret")
        with mock.patch.object(runtime.os, "read", side_effect=OSError("private-secret")):
            value = self.observe()
        self.assertEqual(value["sources"]["current"]["state"], "unavailable")
        self.assertNotIn("private-secret", json.dumps(value))

    def test_capture_keeps_status_when_log_inspection_is_unavailable(self):
        self.log.mkdir()
        with (mock.patch.object(runtime, "_status", return_value={"state": "sampled", "geph_state": "up"}),
              mock.patch.object(runtime.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir=str(self.home))),
              mock.patch.object(runtime, "_command", return_value=None)):
            value = runtime.capture(os.getuid(), self.home / "status", host="xpersonatoy.com")
        self.assertEqual(value["status"]["geph_state"], "up")
        self.assertEqual(value["daemon_log"]["sources"]["current"]["state"], "unavailable")


if __name__ == "__main__":
    unittest.main()
