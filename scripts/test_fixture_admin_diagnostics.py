"""Offline fixture-account failure contracts; no real account command is allowed."""

from contextlib import ExitStack, contextmanager
import json
from pathlib import Path
import subprocess
import traceback
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
            if stage == "delete" and failure is None and not delete_retains_account:
                accounts.discard(self.USER)
            stdout = ("\n".join(sorted(accounts)) + "\n").encode()
            if stage == "membership":
                stdout = b"yes member\n"
            elif stage in commands:
                stdout = b""
            default = (b"", self.PRIVATE.encode()) if failure is not None else (stdout, b"")
            output = outputs.get(stage, default)
            stdout, stderr = output if isinstance(output, tuple) else (output, b"")
            return subprocess.CompletedProcess(args, failure or 0, stdout, stderr)

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
        expected = {"primary": dict(primary) if primary is not None else None, "cleanup": cleanup}
        if primary and primary["stage"] in ("create", "authenticate") and primary["kind"] == "command_failed":
            expected["primary"]["native"] = {"status": "unrecognized", "error": None, "code": None}
        if primary is None or primary["stage"] in ("membership", "inventory_after", "authenticate", "body"):
            expected["create_native"] = {"status": "absent", "error": None, "code": None}
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
            for secret in (self.USER, self.PASSWORD, self.PRIVATE):
                self.assertNotIn(secret, json.dumps(report))

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
        original = RuntimeError(self.PRIVATE + self.USER + self.PASSWORD)
        with self.fixture(self.SETUP + self.CLEANUP) as fixture:
            with self.assertRaises(RuntimeError) as caught:
                with smoke.fixture_admin():
                    raise original
            self.assertIs(caught.exception, original)
            self.assertEqual(fixture.accounts, {"root"})
            self.assertIs(getattr(original, "_fixture_admin_cleanup_confirmed", None), True)
            report = {}
            smoke.record_failure(report, original, (self.PRIVATE, self.USER, self.PASSWORD))
            self.assertEqual(report["fixture_admin"], {
                "primary": self.failed("body", "operation_failed", None),
                "cleanup": {"status": "confirmed"},
                "create_native": {"status": "absent", "error": None, "code": None},
            })
            for secret in (self.USER, self.PASSWORD, self.PRIVATE):
                self.assertNotIn(secret, json.dumps(report))

    def test_body_and_cleanup_error_are_compact_safe_and_separate(self):
        original = RuntimeError(self.PRIVATE + self.PASSWORD + self.USER)
        with self.fixture(self.SETUP + self.CLEANUP[:2], failures={"delete": 10}):
            with self.assertRaises(smoke.QualificationError) as caught:
                with smoke.fixture_admin():
                    raise original
            self.diagnostic(caught.exception, self.failed("body", "operation_failed", None),
                            {"status": "failed", **self.failed("delete")})
            self.assertIsNot(caught.exception, original)

    def test_process_control_is_not_converted_to_a_qualification_failure(self):
        for control_type in (KeyboardInterrupt, SystemExit):
            for stage in ("inventory_before", "create", "authenticate", "body", "delete"):
                control = SystemExit(42) if control_type is SystemExit else KeyboardInterrupt()
                with self.subTest(control=control_type.__name__, stage=stage):
                    if stage in self.SETUP:
                        index = self.SETUP.index(stage)
                        stages = self.SETUP[:index + 1] + (self.CLEANUP if index else [])
                    elif stage == "delete":
                        stages = self.SETUP + self.CLEANUP[:2]
                    else:
                        stages = self.SETUP + self.CLEANUP
                    with self.fixture(stages, failures={} if stage == "body" else {stage: control}):
                        with self.assertRaises(type(control)) as caught:
                            with smoke.fixture_admin():
                                if stage == "body":
                                    raise control
                                if stage != "delete":
                                    self.fail("control must prevent body")
                        self.assertIs(caught.exception, control)
                        self.assertFalse(isinstance(caught.exception, smoke.FixtureAdminError))

    def test_setup_interrupt_preserves_failed_cleanup_as_a_safe_note(self):
        original = KeyboardInterrupt()
        with self.fixture(self.SETUP + self.CLEANUP[:2],
                          failures={"authenticate": original, "delete": 10}):
            with self.assertRaises(KeyboardInterrupt) as caught:
                with smoke.fixture_admin():
                    self.fail("interrupted authentication must prevent body")
            self.assertIs(caught.exception, original)
            note = caught.exception.__notes__[-1]
            expected = {"primary": self.failed("authenticate", "operation_failed", None),
                        "cleanup": {"status": "failed", **self.failed("delete")},
                        "create_native": {"status": "absent", "error": None, "code": None}}
            self.assertEqual(json.loads(note[len("fixture_admin "):]), expected)
            self.assertLessEqual(len(note.encode()), 512)
            for secret in (self.USER, self.PASSWORD, self.PRIVATE):
                self.assertNotIn(secret, note)

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


class FixtureAdminNativeOutputTests(unittest.TestCase):
    USER = FixtureAdminDiagnosticsTests.USER
    PASSWORD = FixtureAdminDiagnosticsTests.PASSWORD
    PRIVATE = FixtureAdminDiagnosticsTests.PRIVATE
    SETUP = FixtureAdminDiagnosticsTests.SETUP
    CLEANUP = FixtureAdminDiagnosticsTests.CLEANUP
    fixture = FixtureAdminDiagnosticsTests.fixture

    @staticmethod
    def native(status, error=None, code=None):
        return {"status": status, "error": error, "code": code}

    def assert_private(self, error, report=None):
        rendered = str(error) + "".join(traceback.format_exception(error)) + json.dumps(report or {})
        for secret in (self.USER, self.PASSWORD, self.PRIVATE):
            self.assertNotIn(secret, rendered)
        self.assertLessEqual(len(str(error).encode()), 512)
        self.assertEqual(str(error)[:512], str(error))

    def test_create_exit_zero_error_survives_later_auth_failure(self):
        create = (f"sysadminctl[42] New account password error. {self.PRIVATE} "
                  f"{self.USER} {self.PASSWORD} (5402)\n").encode()
        auth = b"<dscl_cmd> DS Error: -14090 (eDSAuthFailed)\n"
        with self.fixture(self.SETUP + self.CLEANUP, failures={"authenticate": 10},
                          outputs={"create": (b"", create), "authenticate": (b"", auth)}) as fixture:
            try:
                with smoke.fixture_admin():
                    self.fail("failed auth cannot yield")
            except smoke.FixtureAdminError as error:
                self.assertEqual(error.diagnostic.get("create_native"),
                                 self.native("recognized", "sysadminctl_password_error", 5402))
                self.assertEqual(error.diagnostic["primary"].get("native"),
                                 self.native("recognized", "eDSAuthFailed", -14090))
                self.assertEqual(error.diagnostic["primary"]["code"], 10)
                self.assertEqual(error.diagnostic["cleanup"], {"status": "confirmed"})
                report = {}
                smoke.record_failure(report, error, ())
                self.assertEqual(report["fixture_admin"], error.diagnostic)
                self.assert_private(error, report)
            self.assertEqual(fixture.accounts, {"root"})

    def test_auth_native_diagnostic_survives_cleanup_failure(self):
        auth = b"<dscl_cmd> DS Error: -14096 (eDSAuthBadPassword)\n"
        with self.fixture(self.SETUP + self.CLEANUP[:2],
                          failures={"authenticate": 10, "delete": 12},
                          outputs={"authenticate": (auth, self.PRIVATE.encode())}):
            try:
                with smoke.fixture_admin():
                    self.fail("failed auth cannot yield")
            except smoke.FixtureAdminError as error:
                self.assertEqual(error.diagnostic["primary"].get("native"),
                                 self.native("recognized", "eDSAuthBadPassword", -14096))
                self.assertEqual(error.diagnostic["cleanup"], {
                    "status": "failed", "stage": "delete", "kind": "command_failed", "code": 12})
                self.assert_private(error)

    def test_auth_output_closed_pairs_unknown_conflicting_and_bounds(self):
        cases = []
        for code, name in ((-14090, "eDSAuthFailed"), (-14096, "eDSAuthBadPassword"),
                           (-14098, "eDSAuthUnknownUser"), (-14120, "eDSPermissionError")):
            cases.append(((b"", f"<dscl_cmd> DS Error: {code} ({name})\n".encode()),
                          self.native("recognized", name, code)))
        valid = b"<dscl_cmd> DS Error: -14090 (eDSAuthFailed)\n"
        cases += [
            ((b"", b""), self.native("absent")),
            ((self.PRIVATE.encode(), b""), self.native("unrecognized")),
            ((b"", b"<dscl_cmd> DS Error: -14090 (eDSAuthBadPassword)\n"), self.native("unrecognized")),
            ((b"", b"<dscl_cmd> DS Error: -14090 (eDSUnknown)\n"), self.native("unrecognized")),
            ((b"\xff", valid), self.native("unrecognized")),
            ((b"x" * 8193, valid), self.native("oversized")),
            ((valid, b"<dscl_cmd> DS Error: -14098 (eDSAuthUnknownUser)\n"), self.native("conflicting")),
            ((valid, valid), self.native("recognized", "eDSAuthFailed", -14090)),
            ((valid, b"<dscl_cmd> DS Error: -1 (eDSAuthFailed)\n"), self.native("unrecognized")),
            ((None, valid), self.native("unrecognized")),
        ]
        for output, expected in cases:
            with self.subTest(expected=expected):
                with self.fixture(self.SETUP + self.CLEANUP, failures={"authenticate": 10},
                                  outputs={"authenticate": output}):
                    try:
                        with smoke.fixture_admin():
                            self.fail("failed auth cannot yield")
                    except smoke.FixtureAdminError as error:
                        self.assertEqual(error.diagnostic["primary"]["native"], expected)
                        self.assertEqual(error.diagnostic["primary"]["code"], 10)
                        report = {}
                        smoke.record_failure(report, error, ())
                        self.assert_private(error, report)

    def test_create_marker_closed_code_set_and_uninterpreted_domain(self):
        cases = []
        for code in range(5400, 5407):
            line = f"sysadminctl[7] New account password error. {self.PRIVATE} ({code})\n".encode()
            cases.append((line, self.native("recognized", "sysadminctl_password_error", code)))
        valid = b"New account password error. opaque (5402)\n"
        cases += [
            (b"", self.native("absent")),
            (b"New account password error. opaque (99)\n", self.native("unrecognized")),
            (b"New account password error. opaque (5402) private suffix\n", self.native("unrecognized")),
            (b"\xff" + valid, self.native("unrecognized")),
            (valid + b"x" * 8193, self.native("oversized")),
            (valid + b"New account password error. opaque (5403)\n", self.native("conflicting")),
        ]
        for output, expected in cases:
            with self.subTest(expected=expected):
                with self.fixture(self.SETUP[:2] + self.CLEANUP, failures={"create": 1},
                                  outputs={"create": (b"", output)}):
                    try:
                        with smoke.fixture_admin():
                            self.fail("failed create cannot yield")
                    except smoke.FixtureAdminError as error:
                        self.assertEqual(error.diagnostic["primary"]["native"], expected)
                        self.assertNotIn("create_native", error.diagnostic)
                        self.assertEqual(error.diagnostic["cleanup"], {"status": "confirmed"})
                        self.assert_private(error)

    def test_observation_does_not_change_success_or_add_a_command(self):
        outputs = {"create": b"New account password error. opaque (5402)\n",
                   "authenticate": b"<dscl_cmd> DS Error: -14090 (eDSAuthFailed)\n"}
        with self.fixture(self.SETUP + self.CLEANUP, outputs=outputs) as fixture:
            with smoke.fixture_admin() as credentials:
                self.assertEqual(credentials, (self.USER, self.PASSWORD))
            self.assertEqual(fixture.accounts, {"root"})
            self.assertEqual(fixture.calls.count("authenticate"), 1)

    def test_classifier_error_does_not_replace_command_outcome(self):
        for failed in (False, True):
            with self.subTest(failed=failed):
                with self.fixture(self.SETUP + self.CLEANUP,
                                  failures={"authenticate": 10} if failed else {}):
                    with mock.patch.object(smoke, "_fixture_admin_native", side_effect=ValueError(self.PRIVATE)) as classifier:
                        if failed:
                            try:
                                with smoke.fixture_admin():
                                    self.fail("failed auth cannot yield")
                            except smoke.FixtureAdminError as error:
                                self.assertEqual(error.diagnostic["primary"]["code"], 10)
                                self.assertEqual(error.diagnostic["primary"]["native"], self.native("unrecognized"))
                                self.assert_private(error)
                        else:
                            body_completed = False
                            with smoke.fixture_admin():
                                body_completed = True
                            self.assertTrue(body_completed)
                            self.assertEqual(classifier.call_args_list, [
                                mock.call("create", b"", b""), mock.call("authenticate", b"", b""),
                            ])

    def test_create_observation_survives_body_and_process_control_without_identity_change(self):
        create = b"New account password error. opaque (5402)\n"
        expected = self.native("recognized", "sysadminctl_password_error", 5402)
        for original in (RuntimeError("body failed"), KeyboardInterrupt(), SystemExit(42)):
            with self.subTest(kind=type(original).__name__):
                with self.fixture(self.SETUP + self.CLEANUP, outputs={"create": create}):
                    try:
                        with smoke.fixture_admin():
                            raise original
                    except BaseException as error:
                        self.assertIs(error, original)
                        if isinstance(error, Exception):
                            report = {}
                            smoke.record_failure(report, error, ())
                            self.assertEqual(report["fixture_admin"]["create_native"], expected)
                        else:
                            note = error.__notes__[-1]
                            self.assertEqual(json.loads(note[len("fixture_admin "):])["create_native"], expected)
                            self.assertLessEqual(len(note.encode()), 512)
                        self.assert_private(error)

    def test_worst_case_public_reason_contains_complete_both_outcomes(self):
        create = b"New account password error. opaque (5406)\n"
        auth = b"<dscl_cmd> DS Error: -14120 (eDSPermissionError)\n"
        with self.fixture(self.SETUP + ["cleanup_inventory_before"],
                          failures={"authenticate": -(2 ** 31), "cleanup_inventory_before": -(2 ** 31)},
                          outputs={"create": create, "authenticate": auth}):
            try:
                with smoke.fixture_admin():
                    self.fail("failed auth cannot yield")
            except smoke.FixtureAdminError as error:
                self.assert_private(error)
                self.assertEqual(json.loads(str(error)[:512][len("fixture_admin "):]), error.diagnostic)
                self.assertEqual(error.diagnostic["cleanup"]["stage"], "cleanup_inventory_before")


if __name__ == "__main__":
    unittest.main()
