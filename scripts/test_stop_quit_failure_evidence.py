"""Failure evidence must describe the operation before fixture teardown."""
from contextlib import contextmanager
import json
import subprocess
import unittest
from unittest import mock

import stop_quit_ui_smoke as smoke
import test_stop_quit_ui_smoke as existing


class StopQuitFailureEvidenceTests(unittest.TestCase):
    def test_private_timeout_retains_only_its_safe_kind(self):
        secret = "fixture-private-value"
        timeout = subprocess.TimeoutExpired(["osascript", secret], 1,
                                           output=secret.encode(), stderr=secret.encode())
        with mock.patch.object(smoke.subprocess, "run", side_effect=timeout):
            with self.assertRaises(smoke.PrivateOperationTimeout) as caught:
                smoke.run(["/usr/bin/osascript", secret], sensitive=True)
        self.assertNotIn(secret, str(caught.exception))
        self.assertNotIn(secret, repr(caught.exception.args))
        self.assertIsInstance(caught.exception, smoke.QualificationError)

    def test_confirmed_submission_deadline_is_not_an_unclassified_script_error(self):
        driver = existing.AuthorizationObservationTests()
        value, error, calls, result, done, elapsed = driver.drive([
            "submitted", ("pending", 89.1), (smoke.PrivateOperationTimeout("timeout"), .5),
        ], require_submission=True)
        self.assertIsNone(value)
        self.assertRegex(str(error), "authorization deadline expired")
        attempt = result["authorization_attempts"][-1]
        self.assertEqual(attempt["failure_kind"], "authorization_deadline")
        self.assertEqual(attempt["last_state"], "pending")
        self.assertEqual(attempt["elapsed_ms"], 90000)
        self.assertEqual(attempt["remaining_ms"], 0)
        self.assertTrue(attempt["submitted"])
        self.assertFalse(attempt["submission_uncertain"])
        self.assertEqual(len(calls), 3)
        self.assertEqual(elapsed, 90)
        self.assertTrue(all("click " not in script for script, _ in calls[1:]))
        done.assert_not_called()

    def test_early_timeout_and_unknown_output_fail_without_replay(self):
        for observation, kind in ((smoke.PrivateOperationTimeout("private"), "observer_timeout"),
                                  (smoke.QualificationError("private"), "observer_unavailable")):
            for submitted in (False, True):
                with self.subTest(kind=kind, submitted=submitted):
                    sequence = (["submitted"] if submitted else []) + [(observation, 1)]
                    _, error, calls, result, done, elapsed = existing.AuthorizationObservationTests().drive(sequence)
                    attempt = result["authorization_attempts"][-1]
                    self.assertEqual(attempt["failure_kind"], kind)
                    self.assertEqual(attempt["submission_uncertain"], not submitted)
                    self.assertNotIn("private", str(error) + json.dumps(result))
                    self.assertEqual(len(calls), 2 if submitted else 1)
                    self.assertLess(elapsed, 2)
                    done.assert_not_called()

    def test_nested_failure_capture_precedes_account_and_lock_cleanup(self):
        active, order, result = set(), [], {"phase": "root_lock_failure"}
        @contextmanager
        def resource(name):
            active.add(name)
            try:
                yield
            finally:
                active.remove(name)
                order.append("cleanup:" + name)
        def capture():
            order.append("snapshot")
            return {"active": sorted(active)}
        failure = RuntimeError("operation failed")
        with self.assertRaises(RuntimeError) as caught:
            with resource("account"), smoke.capture_failure_before_cleanup(result, capture):
                with resource("lock"), smoke.capture_failure_before_cleanup(result, capture):
                    raise failure
        self.assertIs(caught.exception, failure)
        self.assertEqual(order, ["snapshot", "cleanup:lock", "cleanup:account"])
        self.assertEqual(result["diagnostics"]["active"], ["account", "lock"])
        self.assertEqual(result["diagnostics_capture"],
                         {"stage": "before_fixture_cleanup", "phase": "root_lock_failure"})
        smoke.record_failure_snapshot(result, lambda: {"active": []}, "after_fixture_cleanup")
        self.assertEqual(result["diagnostics"]["active"], ["account", "lock"])

    def test_capture_failure_does_not_hide_original_or_skip_cleanup(self):
        result, cleaned = {}, []
        original = RuntimeError("original operation")
        with self.assertRaises(RuntimeError) as caught:
            try:
                with smoke.capture_failure_before_cleanup(result, mock.Mock(side_effect=ValueError("private"))):
                    raise original
            finally:
                cleaned.append(True)
        self.assertIs(caught.exception, original)
        self.assertEqual(cleaned, [True])
        self.assertEqual(result["diagnostics"], {"observation": "unavailable"})
        self.assertNotIn("private", json.dumps(result))

    def test_cleanup_failure_preserves_redacted_primary_failure(self):
        result = {"phase": "root_lock_failure"}
        secret = "private-fixture-secret"
        @contextmanager
        def broken_cleanup():
            try:
                yield
            finally:
                raise RuntimeError("cleanup failed\n" + secret)
        try:
            with broken_cleanup(), smoke.capture_failure_before_cleanup(
                    result, lambda: {"active": True}, secrets_to_hide=(secret,)):
                raise smoke.QualificationError("authorization failed\n" + secret)
        except RuntimeError as error:
            smoke.record_failure(result, error, (secret,))
            smoke.record_failure_snapshot(result, lambda: {"active": False}, "after_fixture_cleanup")
        self.assertEqual(result["failure"], "authorization failed\n[redacted]")
        self.assertEqual(result["fixture_unwind_failure"], "cleanup failed\n[redacted]")
        self.assertEqual(result["diagnostics"], {"active": True})
        self.assertNotIn(secret, json.dumps(result))

    def test_admin_credentials_are_checked_before_use_and_failed_check_cleans_account(self):
        for accepted in (False, True):
            with self.subTest(accepted=accepted):
                accounts, calls = {"root"}, []
                def run(args, **kwargs):
                    calls.append((args, kwargs))
                    if "-addUser" in args:
                        accounts.add(args[args.index("-addUser") + 1])
                    if "-deleteUser" in args:
                        accounts.remove(args[-1])
                    if "-authonly" in args and not accepted:
                        raise smoke.QualificationError("fixture credential rejected")
                    return subprocess.CompletedProcess(args, 0, b"yes member", b"")
                with mock.patch.object(smoke, "require_disposable"), \
                     mock.patch.object(smoke, "account_names", side_effect=lambda: accounts.copy()), \
                     mock.patch.object(smoke, "run", side_effect=run), \
                     mock.patch.object(smoke.Path, "exists", return_value=False), \
                     mock.patch.object(smoke.Path, "is_symlink", return_value=False):
                    if accepted:
                        with smoke.fixture_admin() as (username, password):
                            self.assertEqual(calls[-1][0], ["/usr/bin/dscl", ".", "-authonly", username, password])
                            self.assertTrue(calls[-1][1]["sensitive"])
                    else:
                        with self.assertRaisesRegex(smoke.QualificationError, "credential rejected"):
                            with smoke.fixture_admin():
                                self.fail("unverified credentials reached native UI")
                self.assertEqual(accounts, {"root"})
                self.assertIn("-deleteUser", calls[-1][0])
                self.assertEqual(sum("-authonly" in args for args, _ in calls), 1)


if __name__ == "__main__":
    unittest.main()
