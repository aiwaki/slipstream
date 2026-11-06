"""Isolated contracts for the system-without-Slipstream Safari comparison."""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace
import unittest
from unittest import mock

import live_site_release_smoke as smoke
import release_readiness as readiness


EMPTY_PROXY = b"<dictionary> {\n}\n"
ABSENT_JOB = 'Could not find service "dev.slipstream.tproxy" in domain for system\n'


def browser_result(host="xpersonatoy.com", browser="safari", outcome="usable"):
    return {
        "browser": browser, "deadline_ms": smoke.SITES[host]["deadline_ms"],
        "elapsed_ms": 100, "outcome": outcome,
        "reason": "" if outcome == "usable" else "readiness_document_pending",
        "route": "slipstream_selected",
    }


class SystemProxyControlTests(unittest.TestCase):
    def capture(self, raw=EMPTY_PROXY, *, code=0, stderr=b""):
        with mock.patch.object(smoke.subprocess, "run", return_value=SimpleNamespace(
            stdout=raw, stderr=stderr, returncode=code,
        )) as run:
            value, signature = smoke._system_proxy_control_snapshot()
        run.assert_called_once_with(
            ("/usr/sbin/scutil", "--proxy"), capture_output=True, check=False, timeout=3,
        )
        self.assertNotIn("private-secret", json.dumps(value))
        return value, signature

    def test_empty_and_missing_enable_keys_are_disabled(self):
        for raw in (EMPTY_PROXY, b"""<dictionary> {
  ExceptionsList : <array> {
    0 : private-secret.example
  }
  ExcludeSimpleHostnames : 0
  FTPPassive : 1
}
"""):
            with self.subTest(raw=raw):
                value, signature = self.capture(raw)
                self.assertEqual(value["state"], "disabled")
                self.assertEqual(signature, raw)
                self.assertEqual({v for k, v in value.items() if k != "state"}, {False})

    def test_each_enabled_proxy_flag_is_detected_globally_and_in_scopes(self):
        for flag in ("HTTPEnable", "HTTPSEnable", "SOCKSEnable",
                     "ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable"):
            for scoped in (False, True):
                with self.subTest(flag=flag, scoped=scoped):
                    content = f"  {flag} : 1\n  ProxyAutoConfigURLString : https://private-secret/\n"
                    if scoped:
                        content = "  __SCOPED__ : <dictionary> {\n    en0 : <dictionary> {\n" + content + "    }\n  }\n"
                    value, _ = self.capture(("<dictionary> {\n" + content + "}\n").encode())
                    self.assertEqual(value["state"], "enabled")

    def test_scoped_enable_cannot_be_overwritten_by_disabled_global_flag(self):
        value, _ = self.capture(b"""<dictionary> {
  __SCOPED__ : <dictionary> {
    en0 : <dictionary> {
      SOCKSEnable : 1
    }
  }
  SOCKSEnable : 0
}
""")
        self.assertTrue(value["socks"])
        self.assertEqual(value["state"], "enabled")

    def test_invalid_or_failed_inspection_is_unknown(self):
        for raw, code, stderr in (
            (b"", 0, b""), (b"private-secret", 0, b""),
            (EMPTY_PROXY, 1, b""), (EMPTY_PROXY, 0, b"private-secret"),
            (b"<dictionary> {\n  SOCKSEnable : true\n}\n", 0, b""),
            (b"<dictionary> {\n  SOCKSEnable : 2\n}\n", 0, b""),
            (b"<dictionary> {\n  __SCOPED__ : <dictionary> {\n}\n", 0, b""),
            (EMPTY_PROXY + b"}\n", 0, b""),
            (b"<dictionary> {\n  private-secret\n}\n", 0, b""),
            (b"x" * (16 * 1024 + 1), 0, b""), (b"\xff", 0, b""),
        ):
            with self.subTest(code=code, raw=raw[:60]):
                value, signature = self.capture(raw, code=code, stderr=stderr)
                self.assertEqual(value["state"], "unavailable")
                self.assertIsNone(signature)
                self.assertEqual({v for k, v in value.items() if k != "state"}, {None})

    def test_timeout_does_not_retry_or_change_environment(self):
        with mock.patch.object(smoke.subprocess, "run", side_effect=
                               subprocess.TimeoutExpired("private-secret", 3)) as run:
            value, signature = smoke._system_proxy_control_snapshot()
        self.assertEqual(value["state"], "unavailable")
        self.assertIsNone(signature)
        self.assertEqual(run.call_count, 1)
        self.assertNotIn("env", run.call_args.kwargs)


class OwnedAbsenceGuardTests(unittest.TestCase):
    def snapshot(self, *, code=113, stdout="", stderr=ABSENT_JOB,
                 owned_error=None, anchor_error=None, changed_pf=False, proxy=None):
        before = smoke.pf.PfSnapshot(False, "", "", False)
        after = smoke.pf.PfSnapshot(True, "", "", False) if changed_pf else before
        system = mock.Mock()
        system.run.return_value = SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)
        proxy = proxy or ({"state": "disabled"}, EMPTY_PROXY)
        with (
            mock.patch.object(smoke.subprocess, "run", side_effect=AssertionError("unexpected command")),
            mock.patch.object(smoke.lifecycle, "_assert_clean_install_state", side_effect=owned_error) as clean,
            mock.patch.object(smoke.pf, "_assert_empty_anchor", side_effect=anchor_error) as anchors,
            mock.patch.object(smoke.pf, "_pf_snapshot", return_value=after),
            mock.patch.object(smoke, "_system_proxy_control_snapshot", return_value=proxy) as proxy_call,
        ):
            value, signature = smoke._system_without_slipstream_snapshot(mock.Mock(), system, before)
        system.run.assert_called_once_with(
            ("/bin/launchctl", "print", smoke.lifecycle.LAUNCHD_LABEL), check=False, timeout=3,
        )
        self.assertNotIn("private-secret", json.dumps(value))
        return value, signature, clean, anchors, proxy_call

    def test_absent_job_clean_owned_state_and_disabled_proxy_are_required(self):
        for detail in (ABSENT_JOB, "Bad request.\n" + ABSENT_JOB, ABSENT_JOB.replace('"', '')):
            value, signature, clean, anchors, proxy = self.snapshot(stderr=detail)
            self.assertEqual(value["state"], "verified")
            self.assertEqual(value["daemon_job"], "absent")
            self.assertEqual(value["owned_anchors"], "empty")
            self.assertIs(value["pf_matches_preflight"], True)
            self.assertEqual(signature, EMPTY_PROXY)
            clean.assert_called_once()
            self.assertEqual(anchors.call_args.args[1], smoke.pf.SENTINEL_ANCHOR)
            proxy.assert_called_once()

    def test_failed_launchctl_is_not_absence(self):
        for code, detail in (
            (0, ""), (1, ""), (113, ""), (1, ABSENT_JOB),
            (113, "Operation not permitted: private-secret"),
            (113, ABSENT_JOB.replace("dev.slipstream.tproxy", "other.service")),
            (113, ABSENT_JOB + "private-secret"),
        ):
            with self.subTest(code=code, detail=detail):
                value, signature, clean, _, proxy = self.snapshot(code=code, stderr=detail)
                self.assertEqual(value["state"], "unavailable")
                self.assertIsNone(signature)
                clean.assert_not_called()
                proxy.assert_not_called()

    def test_owned_residue_anchor_pf_or_proxy_uncertainty_refuses_control(self):
        for changes in (
            {"owned_error": RuntimeError("private-secret")},
            {"anchor_error": RuntimeError("private-secret")},
            {"changed_pf": True},
            {"proxy": ({"state": "enabled", "socks": True}, b"private-secret")},
            {"proxy": ({"state": "unavailable"}, None)},
        ):
            with self.subTest(changes=list(changes)):
                value, signature, *_ = self.snapshot(**changes)
                self.assertEqual(value["state"], "unavailable")
                self.assertIsNone(signature)


class PairedBrowserControlTests(unittest.TestCase):
    @contextmanager
    def gate(self, *, baseline="usable", selected="usable", controls="usable",
             snapshots=None, browser_error=None, install_error=None):
        events = []
        installed = False
        before = smoke.pf.PfSnapshot(False, "", "", False)
        target = SimpleNamespace(install_command=("install",))
        system = mock.Mock()

        def install(command, **kwargs):
            nonlocal installed
            self.assertEqual(command, target.install_command)
            events.append("install")
            if install_error is not None:
                raise install_error
            installed = True

        system.run.side_effect = install
        answers = iter(snapshots or [({"state": "verified"}, EMPTY_PROXY)] * 2)

        def snapshot(*args):
            self.assertFalse(installed)
            events.append("guard")
            return next(answers)

        def safari(host, driver, uid, **kwargs):
            events.append("selected:" + host if installed else "baseline")
            if not installed and browser_error is not None:
                raise browser_error
            if "startup_diagnostics" in kwargs:
                kwargs["startup_diagnostics"].append({"cleanup_verified": True})
            return browser_result(host, outcome=selected if installed else baseline)

        with ExitStack() as stack:
            def patch(obj, name, **kwargs):
                return stack.enter_context(mock.patch.object(obj, name, **kwargs))
            patch(smoke.subprocess, "run", side_effect=AssertionError("unexpected system command"))
            patch(smoke.lifecycle, "_webdriver_request", side_effect=AssertionError("unexpected WebDriver request"))
            patch(smoke, "_require_protected_ci")
            patch(smoke.pf, "PfctlRunner", return_value=mock.Mock())
            patch(smoke.lifecycle, "_preflight", side_effect=lambda _: (events.append("preflight") or before, 501, 20))
            patch(smoke.lifecycle, "packaged_app_target", return_value=target)
            patch(smoke.lifecycle, "SystemRunner", return_value=system)
            patch(smoke.lifecycle, "_wait_for_status")
            patch(smoke.lifecycle, "_assert_anchor_active")
            snapshot_call = patch(smoke, "_system_without_slipstream_snapshot", side_effect=snapshot)
            safari_call = patch(smoke, "_run_safari", side_effect=safari)
            patch(smoke, "_run_chrome", side_effect=lambda host, *args, **kwargs: browser_result(host, "chrome", selected))
            patch(smoke, "_control_route", return_value=controls)
            fallback = patch(smoke.lifecycle, "_fallback_uninstall", side_effect=lambda *args: events.append("cleanup") or [])
            clean = patch(smoke.lifecycle, "_assert_clean_install_state")
            patch(smoke.pf, "_pf_snapshot", return_value=before)
            yield SimpleNamespace(events=events, safari=safari_call, snapshots=snapshot_call,
                                  fallback=fallback, clean=clean, system=system)

    def test_one_baseline_is_between_preflight_and_install_with_separate_startup(self):
        observations, startup = [], []
        with self.gate() as fixture:
            report, status = smoke.run_gate(Path("/app"), Path("/chrome"), "driver",
                                           failure_observations=observations, startup_diagnostics=startup)
        self.assertEqual(fixture.events[:5], ["preflight", "guard", "baseline", "guard", "install"])
        self.assertEqual(fixture.safari.call_count, 5)
        self.assertEqual(len(startup), 4)
        self.assertEqual(len(observations), 4)
        control = observations[0]["system_without_slipstream"]
        self.assertEqual(control["state"], "observed")
        self.assertEqual(control["browser"]["deadline_ms"], 20_000)
        self.assertNotIn("route", control["browser"])
        self.assertEqual(control["startup"], [{"cleanup_verified": True}])
        self.assertNotIn("system_without_slipstream", json.dumps(report))
        self.assertEqual(readiness.validate_live_report(report, status), "passed")

    def test_baseline_result_cannot_change_selected_gate_verdict(self):
        for baseline, selected, controls, expected in (
            ("terminal_error", "usable", "usable", "passed"),
            ("usable", "terminal_error", "usable", "failed"),
            ("usable", "terminal_error", "unavailable", "inconclusive"),
        ):
            with self.subTest(expected=expected), self.gate(
                baseline=baseline, selected=selected, controls=controls,
            ) as fixture:
                observations = []
                report, status = smoke.run_gate(Path("/app"), Path("/chrome"), "driver",
                                               failure_observations=observations)
            self.assertEqual(report["result"], expected)
            self.assertEqual(observations[0]["system_without_slipstream"]["browser"]["outcome"], baseline)
            fixture.fallback.assert_called_once()

    def test_unavailable_before_guard_skips_only_baseline(self):
        observations = []
        with self.gate(snapshots=[({"state": "unavailable"}, None)]) as fixture:
            report, _ = smoke.run_gate(Path("/app"), Path("/chrome"), "driver",
                                       failure_observations=observations)
        self.assertEqual(report["result"], "passed")
        self.assertNotIn("baseline", fixture.events)
        self.assertEqual(fixture.safari.call_count, 4)
        self.assertEqual(observations[0]["system_without_slipstream"]["reason"], "before_guard_unavailable")

    def test_changed_or_unknown_after_guard_invalidates_only_diagnostic(self):
        for final in (({"state": "unavailable"}, None),
                      ({"state": "verified"}, b"changed-private-secret")):
            with self.subTest(final=final), self.gate(snapshots=[
                ({"state": "verified"}, EMPTY_PROXY), final,
            ]) as fixture:
                observations = []
                report, _ = smoke.run_gate(Path("/app"), Path("/chrome"), "driver",
                                           failure_observations=observations)
            control = observations[0]["system_without_slipstream"]
            self.assertEqual(control["state"], "unavailable")
            self.assertEqual(control["reason"], "after_guard_unavailable")
            self.assertEqual(report["result"], "passed")
            self.assertNotIn("private-secret", json.dumps(observations))
            fixture.fallback.assert_called_once()

    def test_baseline_cleanup_error_still_runs_after_guard_and_gate_cleanup(self):
        observations = []
        with self.gate(browser_error=smoke.LiveSiteError("private-secret cleanup")) as fixture:
            with self.assertRaisesRegex(smoke.LiveSiteError,
                                        "system_without_slipstream:xpersonatoy.com \\(LiveSiteError\\)") as error:
                smoke.run_gate(Path("/app"), Path("/chrome"), "driver",
                               failure_observations=observations)
        self.assertEqual(fixture.events, ["preflight", "guard", "baseline", "guard", "cleanup"])
        fixture.system.run.assert_not_called()
        fixture.fallback.assert_called_once()
        fixture.clean.assert_called_once()
        self.assertNotIn("private-secret", str(error.exception) + json.dumps(observations))

    def test_install_failure_does_not_erase_completed_baseline(self):
        observations = []
        with self.gate(install_error=RuntimeError("private-secret")) as fixture:
            with self.assertRaisesRegex(smoke.LiveSiteError, "failed at install"):
                smoke.run_gate(Path("/app"), Path("/chrome"), "driver",
                               failure_observations=observations)
        self.assertEqual(observations[0]["system_without_slipstream"]["state"], "observed")
        self.assertEqual(fixture.safari.call_count, 1)
        fixture.fallback.assert_called_once()

    def test_no_sidecar_does_not_add_an_unrecorded_navigation(self):
        with self.gate() as fixture:
            report, _ = smoke.run_gate(Path("/app"), Path("/chrome"), "driver")
        self.assertEqual(report["result"], "passed")
        fixture.snapshots.assert_not_called()
        self.assertEqual(fixture.safari.call_count, 4)


class ActualSafariControlTests(unittest.TestCase):
    @contextmanager
    def isolated_safari(self, *, cleanup_error=None):
        from test_live_site_release_smoke import LiveSiteReleaseSmokeTests
        factory = LiveSiteReleaseSmokeTests()
        evidence = factory._browser_evidence(signals=factory._signals(title="StarrToy"))
        calls, events = [], []
        sessions = 0

        def webdriver(base, method, path, payload=None, **kwargs):
            nonlocal sessions
            calls.append((method, path, payload))
            if path == "/session":
                sessions += 1
                return {"value": {"sessionId": f"session-{sessions}"}}
            if path.endswith("/execute/sync"):
                return {"value": json.dumps(evidence)}
            if method == "DELETE":
                events.append("delete")
            return {}

        def stop(*args):
            events.append("stop")
            if cleanup_error is not None:
                raise cleanup_error

        def guard(*args):
            events.append("guard")
            return {"state": "verified"}, EMPTY_PROXY

        with (
            mock.patch.object(smoke.subprocess, "run", side_effect=AssertionError("unexpected command")),
            mock.patch.object(smoke, "_wait_for_safaridriver_ready"),
            mock.patch.object(smoke.lifecycle, "_assert_no_safari_process") as absent,
            mock.patch.object(smoke.lifecycle, "_wait_for_safari_process", side_effect=[1234, 5678]),
            mock.patch.object(smoke.lifecycle, "_stop_owned_safari_process", side_effect=stop) as stopped,
            mock.patch.object(smoke.lifecycle, "_webdriver_request", side_effect=webdriver),
            mock.patch.object(smoke, "_system_without_slipstream_snapshot", side_effect=guard),
        ):
            yield SimpleNamespace(calls=calls, events=events, absent=absent, stopped=stopped)

    def test_actual_control_and_selected_browser_use_separate_clean_sessions(self):
        observation = {}
        with self.isolated_safari() as fixture:
            smoke._run_system_without_slipstream_control(
                mock.Mock(), mock.Mock(), mock.Mock(), "driver", 501, observation,
            )
            selected = smoke._run_safari("xpersonatoy.com", "driver", 501)
        self.assertEqual(observation["state"], "observed")
        self.assertTrue(observation["startup"][0]["cleanup_verified"])
        self.assertEqual(selected["outcome"], "usable")
        self.assertEqual(fixture.events, ["guard", "delete", "stop", "guard", "delete", "stop"])
        self.assertEqual(fixture.stopped.call_args_list,
                         [mock.call(1234, 501, "xpersonatoy.com"), mock.call(5678, 501, "xpersonatoy.com")])
        self.assertEqual(fixture.absent.call_count, 4)
        navigations = [row for row in fixture.calls if row[1].endswith("/url")]
        self.assertEqual(navigations, [
            ("POST", f"/session/session-{n}/url", {"url": "https://xpersonatoy.com/"})
            for n in (1, 2)
        ])
        timeouts = [row[2] for row in fixture.calls if row[1].endswith("/timeouts")]
        self.assertEqual(timeouts, [{"pageLoad": 20_000, "script": 10_000}] * 2)
        expressions = [row[2] for row in fixture.calls if row[1].endswith("/execute/sync")]
        self.assertEqual(expressions[0], expressions[1])

    def test_actual_safari_cleanup_failure_is_not_swallowed_by_diagnostic(self):
        observation = {}
        with self.isolated_safari(cleanup_error=RuntimeError("private-secret")) as fixture:
            with self.assertRaisesRegex(smoke.LiveSiteError, "^Safari cleanup failed$"):
                smoke._run_system_without_slipstream_control(
                    mock.Mock(), mock.Mock(), mock.Mock(), "driver", 501, observation,
                )
        self.assertEqual(fixture.events, ["guard", "delete", "stop", "guard"])
        self.assertEqual(observation["state"], "unavailable")
        self.assertFalse(observation["startup"][0]["cleanup_verified"])
        self.assertNotIn("private-secret", json.dumps(observation))


if __name__ == "__main__":
    unittest.main()
