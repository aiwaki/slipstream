from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

import safari_session_smoke as smoke


class SafariSessionSmokeTests(unittest.TestCase):
    def clean_report(self):
        return {
            "strategy": "none", "stage": "complete", "status": "passed",
            "error": smoke.lifecycle.webdriver_failure_details(None),
            "elapsed_ms": 50, "session_id_observed": True,
            "pid_observed": True, "blank_verified": True,
            "cleanup_verified": True, "cleanup_errors": [],
        }

    def probe_mocks(self, stack):
        stack.enter_context(mock.patch.object(smoke.live, "_wait_for_safaridriver_ready"))
        absent = stack.enter_context(mock.patch.object(smoke.lifecycle, "_assert_no_safari_process"))
        pid = stack.enter_context(mock.patch.object(smoke.lifecycle, "_wait_for_safari_process", return_value=1234))
        stop = stack.enter_context(mock.patch.object(smoke.lifecycle, "_stop_owned_safari_process"))
        request = stack.enter_context(mock.patch.object(smoke.lifecycle, "_webdriver_request", side_effect=[
            {"value": {"sessionId": "PRIVATE-SESSION"}}, {"value": None},
            {"value": "about:blank"}, {"value": None},
        ]))
        return absent, pid, stop, request

    def test_both_capabilities_use_one_session_and_only_blank_document(self):
        for strategy in sorted(smoke.STRATEGIES):
            with self.subTest(strategy=strategy), ExitStack() as stack:
                absent, pid, stop, request = self.probe_mocks(stack)
                result = smoke.session_probe(strategy, "http://127.0.0.1:12345", 501)
                self.assertEqual(result["status"], "passed")
                self.assertTrue(result["blank_verified"])
                self.assertTrue(result["cleanup_verified"])
                self.assertEqual(absent.call_count, 2)
                stop.assert_called_once_with(1234, 501, "session-smoke")
                calls = request.call_args_list
                self.assertEqual(calls[0].args[1:3], ("POST", "/session"))
                self.assertEqual(calls[0].args[3]["capabilities"]["alwaysMatch"],
                                 {"browserName": "safari", "pageLoadStrategy": strategy})
                self.assertEqual(calls[1].args[3], {"url": "about:blank"})
                self.assertEqual(calls[2].args[1], "GET")
                self.assertEqual(calls[3].args[1], "DELETE")
                self.assertNotIn("PRIVATE-SESSION", json.dumps(result))
                self.assertNotIn("127.0.0.1", json.dumps(result))

    def test_failed_creation_records_safe_code_and_unowned_residue_without_kill(self):
        with ExitStack() as stack:
            absent, pid, stop, request = self.probe_mocks(stack)
            request.side_effect = smoke.lifecycle.WebDriverRequestError(
                "PRIVATE-SESSION https://private.test/?token=secret", http_status=500,
                webdriver_error="session not created")
            absent.side_effect = [None, smoke.lifecycle.LifecycleError("PRIVATE-PID residue")]
            result = smoke.session_probe("none", "http://127.0.0.1:12345", 501)
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["stage"], "session_create")
            self.assertEqual(result["error"]["http_status"], 500)
            self.assertEqual(result["error"]["webdriver_error"], "session not created")
            self.assertFalse(result["cleanup_verified"])
            self.assertFalse(result["session_id_observed"])
            self.assertEqual(absent.call_count, 2)
            pid.assert_not_called()
            stop.assert_not_called()
            self.assertEqual(request.call_count, 1)
            for secret in ("PRIVATE", "private.test", "token=secret"):
                self.assertNotIn(secret, json.dumps(result))

    def test_creation_failure_with_proven_absence_still_fails(self):
        with ExitStack() as stack:
            absent, pid, stop, request = self.probe_mocks(stack)
            request.side_effect = TimeoutError("private timeout detail")
            result = smoke.session_probe("normal", "http://127.0.0.1:12345", 501)
            self.assertEqual(result["status"], "failed")
            self.assertTrue(result["cleanup_verified"])
            self.assertEqual(result["error"]["exception_class"], "TimeoutError")
            self.assertEqual(request.call_count, 1)
            stop.assert_not_called()

    def test_missing_session_and_conflicting_pid_are_not_adopted(self):
        for case in ("missing-session", "pid-conflict"):
            with self.subTest(case=case), ExitStack() as stack:
                absent, pid, stop, request = self.probe_mocks(stack)
                if case == "missing-session":
                    request.side_effect = [{"value": {"message": "PRIVATE"}}]
                else:
                    pid.side_effect = smoke.lifecycle.LifecycleError("multiple PRIVATE PIDs")
                    request.side_effect = [{"value": {"sessionId": "PRIVATE"}}, {}]
                result = smoke.session_probe("none", "http://127.0.0.1:12345", 501)
                self.assertEqual(result["status"], "failed")
                stop.assert_not_called()
                self.assertEqual(absent.call_count, 2)
                self.assertNotIn("PRIVATE", json.dumps(result))

    def test_cleanup_error_and_wrong_document_cannot_pass(self):
        for case in ("delete", "stop", "absence", "document"):
            with self.subTest(case=case), ExitStack() as stack:
                absent, pid, stop, request = self.probe_mocks(stack)
                if case == "delete":
                    request.side_effect = [{"sessionId": "id"}, {}, {"value": "about:blank"}, TimeoutError("private")]
                elif case == "stop":
                    stop.side_effect = smoke.lifecycle.LifecycleError("identity changed")
                elif case == "absence":
                    absent.side_effect = [None, smoke.lifecycle.LifecycleError("leftover")]
                else:
                    request.side_effect = [{"sessionId": "id"}, {}, {"value": "https://private.test"}, {}]
                result = smoke.session_probe("none", "http://127.0.0.1:12345", 501)
                self.assertEqual(result["status"], "failed")
                self.assertNotIn("private", json.dumps(result))
                self.assertEqual(absent.call_count, 2)

    def test_client_report_rejects_contradictory_success_and_private_nested_data(self):
        changes = [
            {"blank_verified": False}, {"cleanup_verified": False},
            {"session_id_observed": False}, {"pid_observed": False},
            {"stage": "session_create"}, {"elapsed_ms": -1},
            {"error": {"exception_class": "PRIVATE", "http_status": 500, "webdriver_error": "secret"}},
            {"cleanup_errors": [{"message": "SECRET"}]},
        ]
        for change in changes:
            with self.subTest(change=change):
                report = self.clean_report() | change
                result = subprocess.CompletedProcess([], 0, json.dumps(report).encode(), b"PRIVATE STDERR")
                with mock.patch.object(smoke.subprocess, "run", return_value=result):
                    with self.assertRaises(smoke.lifecycle.LifecycleError):
                        smoke._run_client("none", "http://127.0.0.1:12345", 501)

    def test_clean_client_report_and_single_bounded_root_client(self):
        result = subprocess.CompletedProcess([], 0, json.dumps(self.clean_report()).encode(), b"PRIVATE")
        with mock.patch.object(smoke.subprocess, "run", return_value=result) as run:
            self.assertEqual(smoke._run_client("none", "http://127.0.0.1:12345", 501), self.clean_report())
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.kwargs["timeout"], smoke.CLIENT_TIMEOUT)
        self.assertEqual(run.call_args.args[0][:3], ["/usr/bin/sudo", "-n", "-E"])

    def test_no_native_action_after_disposable_guard_refusal(self):
        with mock.patch.object(smoke, "_runtime_identity", return_value={}), \
             mock.patch.object(smoke, "_require_ci", side_effect=smoke.lifecycle.LifecycleError("not CI")), \
             mock.patch.object(smoke.lifecycle, "_assert_no_safari_process") as absence, \
             mock.patch.object(smoke.subprocess, "run") as run:
            report = smoke.run_smoke("none")
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["release_qualified"])
        absence.assert_not_called()
        run.assert_not_called()

    def test_coordinator_retains_refused_session_and_stops_only_its_driver(self):
        for case in ("success", "session-failure", "client-timeout", "enable", "driver-start", "driver-stop"):
            with self.subTest(case=case), ExitStack() as stack:
                stack.enter_context(mock.patch.object(smoke, "_runtime_identity", return_value={}))
                stack.enter_context(mock.patch.object(smoke, "_require_ci"))
                stack.enter_context(mock.patch.object(smoke.os, "geteuid", return_value=501))
                absence = stack.enter_context(mock.patch.object(smoke.lifecycle, "_assert_no_safari_process"))
                enable = stack.enter_context(mock.patch.object(smoke.subprocess, "run"))
                sock = stack.enter_context(mock.patch.object(smoke.socket, "socket"))
                sock.return_value.__enter__.return_value.getsockname.return_value = ("127.0.0.1", 12345)
                start = stack.enter_context(mock.patch.object(smoke.subprocess, "Popen"))
                driver = start.return_value
                driver.poll.return_value = None
                client = stack.enter_context(mock.patch.object(smoke, "_run_client", return_value=self.clean_report()))
                if case == "session-failure":
                    client.return_value = self.clean_report() | {"status": "failed", "stage": "session_create"}
                elif case == "client-timeout":
                    client.side_effect = subprocess.TimeoutExpired(["PRIVATE"], smoke.CLIENT_TIMEOUT, output=b"SECRET")
                elif case == "enable":
                    enable.side_effect = subprocess.CalledProcessError(1, ["PRIVATE"], stderr=b"SECRET")
                elif case == "driver-start":
                    start.side_effect = OSError("PRIVATE")
                elif case == "driver-stop":
                    driver.wait.side_effect = subprocess.TimeoutExpired(["PRIVATE"], 5)
                report = smoke.run_smoke("none")
                self.assertEqual(report["status"], "passed" if case == "success" else "failed")
                self.assertFalse(report["release_qualified"])
                self.assertEqual(absence.call_count, 2)
                if case not in {"enable", "driver-start"}:
                    driver.terminate.assert_called_once()
                    driver.wait.assert_called_once_with(timeout=5)
                if case == "enable":
                    start.assert_not_called()
                    client.assert_not_called()
                self.assertNotIn("PRIVATE", json.dumps(report))
                self.assertNotIn("SECRET", json.dumps(report))

    def test_client_boundary_refuses_invalid_status_types_and_private_errors(self):
        malformed = [
            self.clean_report() | {"error": {"exception_class": None, "http_status": True, "webdriver_error": None}},
            self.clean_report() | {"session_id_observed": 1},
            self.clean_report() | {"elapsed_ms": True},
            self.clean_report() | {"error": {"exception_class": None, "http_status": 500, "webdriver_error": None}},
            self.clean_report() | {"extra_private": "secret"},
        ]
        for body in malformed:
            with self.subTest(body=body), mock.patch.object(smoke.subprocess, "run", return_value=
                    subprocess.CompletedProcess([], 0, json.dumps(body).encode(), b"PRIVATE")):
                with self.assertRaises(smoke.lifecycle.LifecycleError):
                    smoke._run_client("none", "http://127.0.0.1:12345", 501)

    def test_driver_exit_even_zero_cannot_be_successful_session_evidence(self):
        for when in ("before", "after"):
            with self.subTest(when=when), ExitStack() as stack:
                stack.enter_context(mock.patch.object(smoke, "_runtime_identity", return_value={}))
                stack.enter_context(mock.patch.object(smoke, "_require_ci"))
                stack.enter_context(mock.patch.object(smoke.os, "geteuid", return_value=501))
                stack.enter_context(mock.patch.object(smoke.lifecycle, "_assert_no_safari_process"))
                stack.enter_context(mock.patch.object(smoke.subprocess, "run"))
                sock = stack.enter_context(mock.patch.object(smoke.socket, "socket"))
                sock.return_value.__enter__.return_value.getsockname.return_value = ("127.0.0.1", 12345)
                start = stack.enter_context(mock.patch.object(smoke.subprocess, "Popen"))
                start.return_value.poll.side_effect = [0, 0] if when == "before" else [None, 0, 0]
                start.return_value.wait.return_value = 0
                client = stack.enter_context(mock.patch.object(smoke, "_run_client", return_value=self.clean_report()))
                result = smoke.run_smoke("none")
                self.assertEqual(result["status"], "failed")
                self.assertFalse(result["release_qualified"])
                if when == "before":
                    client.assert_not_called()

    def test_main_writes_failed_structured_report_and_returns_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "nested/report.json"
            refused = {"status": "failed", "release_qualified": False,
                       "error": smoke.lifecycle.webdriver_failure_details(TimeoutError("SECRET"))}
            with mock.patch.object(smoke.sys, "argv", ["smoke", "--strategy", "none", "--output", str(output)]), \
                 mock.patch.object(smoke, "run_smoke", return_value=refused):
                self.assertEqual(smoke.main(), 1)
            self.assertEqual(json.loads(output.read_text()), refused)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertNotIn("SECRET", output.read_text())

    def test_runtime_metadata_does_not_admit_arbitrary_environment_strings(self):
        with mock.patch.dict(smoke.os.environ, {"ImageOS": "private user/token secret", "ImageVersion": "SECRET",
                                               "GITHUB_SHA": "PRIVATE", "GITHUB_RUN_ID": "bad"}), \
             mock.patch.object(smoke.platform, "mac_ver", return_value=("SECRET", "", "")):
            value = smoke._runtime_identity()
        for key in ("image_os", "image_version", "source_sha", "run_id", "macos_version"):
            self.assertIsNone(value[key])

    def test_workflow_is_unprotected_two_fresh_jobs_and_only_safe_artifacts(self):
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/safari-session-smoke.yml").read_text()
        self.assertIn("strategy: [normal, none]", workflow)
        self.assertIn("runs-on: macos-15", workflow)
        self.assertIn("fail-fast: false", workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("python-version: '3.13.14'", workflow)
        self.assertIn("if: always()", workflow)
        self.assertIn("safari-session/report.json", workflow)
        for forbidden in ("secrets.", "environment:", "geph", "pfctl", "app-bundle", ".log", "retry"):
            self.assertNotIn(forbidden, workflow)
        readiness = (root / ".github/workflows/release-readiness.yml").read_text()
        self.assertIn('--safari-startup-report "$safari_startup_report"', readiness)
        self.assertIn("dist-readiness/live-site-safari-startup.json", readiness)
        self.assertNotIn('cat "$driver_log"', readiness)


if __name__ == "__main__":
    unittest.main()
