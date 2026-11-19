"""Offline fixture-account failure contracts; no real account command is allowed."""

from contextlib import ExitStack, contextmanager
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock

import stop_quit_ui_smoke as smoke


class FixtureAdminDiagnosticsTests(unittest.TestCase):
    USER = "slipstopdeadbeef"
    PASSWORD = "PRIVATE_PASSWORD_SENTINEL"
    PRIVATE = "PRIVATE_ARGUMENT_STDERR_SENTINEL"
    SETUP = ["inventory_before", "create", "membership", "inventory_after", "authenticate"]
    CLEANUP = ["cleanup_inventory_before", "delete", "cleanup_inventory_after"]

    @contextmanager
    def fixture(self, stages, *, failures=None, outputs=None, initially_present=False,
                delete_retains_account=False):
        """Run actual fixture/account_names/run with only subprocess.run replaced."""
        remaining = list(stages)
        failures, outputs = failures or {}, outputs or {}
        accounts = {"root", self.USER} if initially_present else {"root"}
        calls = []
        commands = {
            "create": ["/usr/bin/sudo", "-n", "/usr/sbin/sysadminctl", "-addUser",
                       self.USER, "-password", self.PASSWORD, "-admin"],
            "membership": ["/usr/sbin/dseditgroup", "-o", "checkmember", "-m", self.USER, "admin"],
            "authenticate": ["/usr/bin/dscl", ".", "-authonly", self.USER, self.PASSWORD],
            "delete": ["/usr/bin/sudo", "-n", "/usr/sbin/sysadminctl", "-deleteUser", self.USER],
        }

        def fake_run(args, **kwargs):
            self.assertTrue(remaining, "unexpected account command or retry")
            stage = remaining.pop(0)
            expected = commands.get(stage, ["/usr/bin/dscl", ".", "-list", "/Users"])
            self.assertEqual(args, expected)
            self.assertEqual(kwargs, {"input": None, "stdout": subprocess.PIPE,
                                     "stderr": subprocess.PIPE,
                                     "timeout": 60 if stage in ("create", "delete") else
                                                15 if stage == "authenticate" else 30})
            calls.append(stage)
            # Unknown creation results may already have created the account.
            if stage == "create":
                accounts.add(self.USER)
            failure = failures.get(stage)
            if isinstance(failure, BaseException):
                raise failure
            if failure is not None:
                return subprocess.CompletedProcess(args, failure, b"", self.PRIVATE.encode())
            if stage == "delete" and not delete_retains_account:
                accounts.discard(self.USER)
            stdout = ("\n".join(sorted(accounts)) + "\n").encode()
            if stage == "membership":
                stdout = b"yes member\n"
            elif stage in commands:
                stdout = b""
            return subprocess.CompletedProcess(args, 0, outputs.get(stage, stdout), b"")

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(smoke, "require_disposable"))
            stack.enter_context(mock.patch.object(smoke.secrets, "token_hex", return_value="deadbeef"))
            stack.enter_context(mock.patch.object(smoke.secrets, "token_urlsafe", return_value=self.PASSWORD))
            stack.enter_context(mock.patch.object(Path, "exists", return_value=False))
            stack.enter_context(mock.patch.object(Path, "is_symlink", return_value=False))
            stack.enter_context(mock.patch.object(smoke.subprocess, "Popen",
                                                  side_effect=AssertionError("native process forbidden")))
            subprocess_mock = stack.enter_context(mock.patch.object(smoke.subprocess, "run", side_effect=fake_run))
            sensitive_mock = stack.enter_context(mock.patch.object(smoke, "run", wraps=smoke.run))
            yield SimpleNamespace(accounts=accounts, calls=calls)
            self.assertEqual(remaining, [])
            self.assertEqual(subprocess_mock.call_count, len(stages))
            self.assertTrue(all(call.kwargs.get("sensitive") is True
                                for call in sensitive_mock.call_args_list))

    def diagnostic(self, error, primary, cleanup):
        # Inspect the caught original failure first: baseline must expose lost
        # primary/cleanup evidence, not merely fail to import a new class.
        self.assertTrue(hasattr(error, "diagnostic"), "fixture failure lost its stage/cleanup diagnostic")
        self.assertIsInstance(error, smoke.FixtureAdminError)
        expected = {"primary": primary, "cleanup": cleanup}
        self.assertEqual(error.diagnostic, expected)
        message = str(error)
        self.assertTrue(message.startswith("fixture_admin "))
        self.assertEqual(json.loads(message[len("fixture_admin "):]), expected)
        self.assertLessEqual(len(message.encode()), 512, "public reason[:512] must retain both outcomes")
        self.assertTrue(error.__suppress_context__)
        for private in (self.USER, self.PASSWORD, self.PRIVATE, "RuntimeError", "PermissionError"):
            self.assertNotIn(private, message)

    @staticmethod
    def failed(stage, kind="command_failed", code=10):
        return {"stage": stage, "kind": kind, "code": code}

    def test_happy_path_keeps_exact_sensitive_command_order(self):
        stages = self.SETUP + self.CLEANUP
        with self.fixture(stages) as fixture:
            with smoke.fixture_admin() as credentials:
                self.assertEqual(credentials, (self.USER, self.PASSWORD))
                self.assertEqual(fixture.calls, self.SETUP)
            self.assertEqual(fixture.accounts, {"root"})
            self.assertEqual(fixture.calls, stages)

    def test_each_setup_command_failure_identifies_stage_and_cleanup(self):
        for index, stage in enumerate(self.SETUP):
            with self.subTest(stage=stage):
                stages = self.SETUP[:index + 1] + (self.CLEANUP if index else [])
                with self.fixture(stages, failures={stage: 10}) as fixture:
                    with self.assertRaises(smoke.QualificationError) as caught:
                        with smoke.fixture_admin():
                            self.fail("body must not run after setup failure")
                    self.diagnostic(caught.exception, self.failed(stage),
                                    {"status": "confirmed" if index else "not_needed"})
                    self.assertEqual(fixture.accounts, {"root"})

    def test_primary_authentication_failure_survives_cleanup_inventory_failure(self):
        with self.fixture(self.SETUP + ["cleanup_inventory_before"],
                          failures={"authenticate": 10, "cleanup_inventory_before": 11}):
            with self.assertRaises(smoke.QualificationError) as caught:
                with smoke.fixture_admin():
                    self.fail("authentication failed")
            self.diagnostic(caught.exception, self.failed("authenticate"),
                            {"status": "failed", **self.failed("cleanup_inventory_before", code=11)})
            report = {}
            smoke.record_failure(report, caught.exception, ())
            self.assertEqual(report["fixture_admin"], caught.exception.diagnostic)
            self.assertNotIn(self.PRIVATE, json.dumps(report))

    def test_each_cleanup_command_failure_is_distinct_without_primary(self):
        for index, stage in enumerate(self.CLEANUP):
            with self.subTest(stage=stage):
                with self.fixture(self.SETUP + self.CLEANUP[:index + 1], failures={stage: 10}):
                    with self.assertRaises(smoke.QualificationError) as caught:
                        with smoke.fixture_admin():
                            pass
                    self.diagnostic(caught.exception, None, {"status": "failed", **self.failed(stage)})

    def test_unknown_create_timeout_still_checks_and_deletes_created_account(self):
        timeout = subprocess.TimeoutExpired([self.PASSWORD], 60,
                                            output=self.PRIVATE, stderr=self.PRIVATE)
        with self.fixture(self.SETUP[:2] + self.CLEANUP, failures={"create": timeout}) as fixture:
            with self.assertRaises(smoke.QualificationError) as caught:
                with smoke.fixture_admin():
                    self.fail("unknown create cannot authorize body")
            self.diagnostic(caught.exception, self.failed("create", "timeout", None),
                            {"status": "confirmed"})
            self.assertEqual(fixture.accounts, {"root"})

    def test_os_error_does_not_expose_private_exception_details(self):
        with self.fixture(self.SETUP + self.CLEANUP,
                          failures={"authenticate": PermissionError(13, self.PRIVATE)}):
            with self.assertRaises(smoke.QualificationError) as caught:
                with smoke.fixture_admin():
                    self.fail("failed authentication cannot authorize body")
            self.diagnostic(caught.exception, self.failed("authenticate", "os_error", 13),
                            {"status": "confirmed"})

    def test_membership_and_inventory_refusals_keep_order_and_logical_stage(self):
        for output_stage, output, expected_stage in (
            ("inventory_before", b"missing_root\n", "inventory_before"),
            ("inventory_after", b"root\n", "inventory_after"),
            ("membership", b"no member\n", "membership"),
        ):
            with self.subTest(stage=expected_stage):
                stages = (["inventory_before"] if output_stage == "inventory_before"
                          else self.SETUP[:4] + self.CLEANUP)
                with self.fixture(stages, outputs={output_stage: output}):
                    with self.assertRaises(smoke.QualificationError) as caught:
                        with smoke.fixture_admin():
                            self.fail("validation failure cannot authorize body")
                    self.diagnostic(caught.exception, self.failed(expected_stage, "refused", None),
                                    {"status": "not_needed" if output_stage == "inventory_before" else "confirmed"})

    def test_existing_identity_refused_without_create_or_cleanup(self):
        with self.fixture(["inventory_before"], initially_present=True) as fixture:
            with self.assertRaises(smoke.QualificationError) as caught:
                with smoke.fixture_admin():
                    self.fail("existing identity cannot be used")
            self.diagnostic(caught.exception, self.failed("inventory_before", "refused", None),
                            {"status": "not_needed"})
            self.assertIn(self.USER, fixture.accounts)

    def test_retained_account_is_failed_cleanup_not_confirmed(self):
        with self.fixture(self.SETUP + self.CLEANUP, delete_retains_account=True):
            with self.assertRaises(smoke.QualificationError) as caught:
                with smoke.fixture_admin():
                    pass
            self.diagnostic(caught.exception, None,
                            {"status": "failed", **self.failed("cleanup_inventory_after", "refused", None)})

    def test_body_error_identity_survives_confirmed_cleanup(self):
        original = RuntimeError(self.PRIVATE)
        with self.fixture(self.SETUP + self.CLEANUP) as fixture:
            with self.assertRaises(RuntimeError) as caught:
                with smoke.fixture_admin():
                    raise original
            self.assertIs(caught.exception, original)
            self.assertEqual(fixture.accounts, {"root"})
            self.assertIs(getattr(original, "_fixture_admin_cleanup_confirmed", None), True)
            report = {}
            smoke.record_failure(report, original, (self.PRIVATE,))
            self.assertEqual(report["fixture_admin"], {
                "primary": self.failed("body", "operation_failed", None),
                "cleanup": {"status": "confirmed"},
            })
            self.assertNotIn(self.PRIVATE, json.dumps(report))

    def test_body_and_cleanup_error_are_compact_safe_and_separate(self):
        original = RuntimeError(self.PRIVATE + self.PASSWORD + self.USER)
        with self.fixture(self.SETUP + self.CLEANUP[:2], failures={"delete": 10}):
            with self.assertRaises(smoke.QualificationError) as caught:
                with smoke.fixture_admin():
                    raise original
            self.diagnostic(caught.exception, self.failed("body", "operation_failed", None),
                            {"status": "failed", **self.failed("delete")})
            self.assertIsNot(caught.exception, original)

    def test_sensitive_run_retains_safe_exit_code_without_arguments_or_stderr(self):
        args = ["/usr/bin/dscl", self.USER, self.PASSWORD]
        result = subprocess.CompletedProcess(args, 10, b"", self.PRIVATE.encode())
        with mock.patch.object(smoke.subprocess, "run", return_value=result) as native:
            with self.assertRaises(smoke.QualificationError) as caught:
                smoke.run(args, sensitive=True)
        native.assert_called_once()
        self.assertIsInstance(caught.exception, smoke.PrivateOperationError)
        self.assertEqual(caught.exception.returncode, 10)
        self.assertEqual(str(caught.exception), "dscl failed (10): ")
        for private in (self.USER, self.PASSWORD, self.PRIVATE):
            self.assertNotIn(private, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
