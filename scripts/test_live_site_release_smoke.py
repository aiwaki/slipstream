from __future__ import annotations

import tempfile
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest import mock

import live_site_release_smoke as smoke
import release_readiness as readiness


class LiveSiteReleaseSmokeTests(unittest.TestCase):
    def _signals(self, **changes: object) -> dict[str, object]:
        value = {
            "app_text_length": 100,
            "body_text_length": 1000,
            "https": True,
            "main_text_length": 1000,
            "next_hop_protocol": "h2",
            "preloader_visible": False,
            "ready_state": "complete",
            "secure_context": True,
            "title": "Aikido Security",
            "visible_app": True,
            "visible_body": True,
        }
        value.update(changes)
        return value

    def test_fixed_sites_have_explicit_deadlines(self) -> None:
        self.assertEqual(
            tuple(smoke.SITES),
            (
                "xpersonatoy.com",
                "app.aikido.dev",
                "weather.com",
                "capacitorjs.com",
            ),
        )
        self.assertTrue(all(site["deadline_ms"] > 0 for site in smoke.SITES.values()))

    def test_release_chrome_is_a_normal_headed_clean_profile(self) -> None:
        command = smoke._chrome_command(
            smoke.Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
            smoke.Path("/tmp/private-profile"),
        )
        self.assertFalse(any(argument.startswith("--headless") for argument in command))
        self.assertIn("--remote-debugging-port=0", command)
        self.assertIn("--user-data-dir=/tmp/private-profile", command)

    def test_chrome_navigation_error_becomes_bounded_terminal_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = smoke.Path(temporary)
            executable = root / "chrome"
            executable.touch()
            process = mock.Mock(pid=1234)
            with (
                mock.patch.object(
                    smoke.lifecycle,
                    "_user_environment",
                    return_value=({}, root),
                ),
                mock.patch.object(
                    smoke.lifecycle,
                    "_user_supplementary_groups",
                    return_value=(),
                ),
                mock.patch.object(smoke.os, "chown"),
                mock.patch.object(smoke.subprocess, "Popen", return_value=process),
                mock.patch.object(
                    smoke.chromium, "_wait_for_devtools_port", return_value=9222
                ),
                mock.patch.object(
                    smoke.chromium,
                    "_devtools_json",
                    return_value=[
                        {
                            "type": "page",
                            "url": "about:blank",
                            "webSocketDebuggerUrl": "ws://127.0.0.1/devtools/page/1",
                        }
                    ],
                ),
                mock.patch.object(
                    smoke.chromium,
                    "_devtools_command",
                    return_value={"errorText": "net::ERR_EMPTY_RESPONSE"},
                ),
                mock.patch.object(
                    smoke.lifecycle, "_stop_owned_chrome_process_group"
                ) as stop,
            ):
                result = smoke._run_chrome("app.aikido.dev", executable, 501, 20)

        self.assertEqual(result["outcome"], "terminal_error")
        self.assertEqual(result["reason"], "navigation_rejected")
        self.assertEqual(result["browser"], "chrome")
        self.assertEqual(result["route"], "slipstream_selected")
        stop.assert_called_once()

    def test_chrome_setup_failures_keep_exact_bounded_stages(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = smoke.Path(temporary)
            executable = root / "chrome"
            executable.touch()
            process = mock.Mock(pid=1234)

            def run(*patchers: object) -> dict[str, object]:
                with ExitStack() as stack:
                    stack.enter_context(
                        mock.patch.object(
                            smoke.lifecycle,
                            "_user_environment",
                            return_value=({}, root),
                        )
                    )
                    stack.enter_context(
                        mock.patch.object(
                            smoke.lifecycle,
                            "_user_supplementary_groups",
                            return_value=(),
                        )
                    )
                    stack.enter_context(mock.patch.object(smoke.os, "chown"))
                    for patcher in patchers:
                        stack.enter_context(patcher)
                    return smoke._run_chrome(
                        "app.aikido.dev", executable, 501, 20
                    )

            result = run(
                mock.patch.object(
                    smoke.subprocess,
                    "Popen",
                    side_effect=OSError("private process diagnostic"),
                )
            )
            self.assertEqual(result["reason"], "browser_start_failed")

            result = run(
                mock.patch.object(smoke.subprocess, "Popen", return_value=process),
                mock.patch.object(
                    smoke.chromium,
                    "_wait_for_devtools_port",
                    side_effect=smoke.chromium.QualificationError(
                        "private DevTools diagnostic"
                    ),
                ),
                mock.patch.object(
                    smoke.lifecycle, "_stop_owned_chrome_process_group"
                ),
            )
            self.assertEqual(result["reason"], "devtools_unavailable")

            result = run(
                mock.patch.object(smoke.subprocess, "Popen", return_value=process),
                mock.patch.object(
                    smoke.chromium, "_wait_for_devtools_port", return_value=9222
                ),
                mock.patch.object(smoke.chromium, "_devtools_json", return_value=[]),
                mock.patch.object(
                    smoke.lifecycle, "_stop_owned_chrome_process_group"
                ),
            )
            self.assertEqual(result["reason"], "target_unavailable")

    def test_chrome_retries_transient_execution_context_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = smoke.Path(temporary)
            executable = root / "chrome"
            executable.touch()
            process = mock.Mock(pid=1234)
            document = "<html><title>Aikido Security</title>" + "x" * 600
            commands = mock.Mock(
                side_effect=[
                    {},
                    smoke.chromium.QualificationError("context replaced"),
                    {"result": {"value": self._signals()}},
                    {"result": {"value": document}},
                ]
            )
            with (
                mock.patch.object(
                    smoke.lifecycle, "_user_environment", return_value=({}, root)
                ),
                mock.patch.object(
                    smoke.lifecycle, "_user_supplementary_groups", return_value=()
                ),
                mock.patch.object(smoke.os, "chown"),
                mock.patch.object(smoke.subprocess, "Popen", return_value=process),
                mock.patch.object(
                    smoke.chromium, "_wait_for_devtools_port", return_value=9222
                ),
                mock.patch.object(
                    smoke.chromium,
                    "_devtools_json",
                    return_value=[
                        {
                            "type": "page",
                            "url": "about:blank",
                            "webSocketDebuggerUrl": "ws://127.0.0.1/devtools/page/1",
                        }
                    ],
                ),
                mock.patch.object(smoke.chromium, "_devtools_command", commands),
                mock.patch.object(smoke.time, "sleep"),
                mock.patch.object(
                    smoke.lifecycle, "_stop_owned_chrome_process_group"
                ),
            ):
                result = smoke._run_chrome("app.aikido.dev", executable, 501, 20)

        self.assertEqual(result["outcome"], "usable")
        self.assertEqual(result["reason"], "")
        self.assertEqual(commands.call_count, 4)

    def test_safari_waits_for_the_ready_status_not_only_http_success(self) -> None:
        ready = mock.Mock(
            side_effect=[smoke.lifecycle.LifecycleError("not ready"), None]
        )
        with (
            mock.patch.object(smoke.lifecycle, "_assert_safaridriver_ready", ready),
            mock.patch.object(smoke.time, "sleep") as sleep,
        ):
            smoke._wait_for_safaridriver_ready("http://127.0.0.1:12345")

        self.assertEqual(ready.call_count, 2)
        sleep.assert_called_once_with(0.2)

    def test_safari_ready_wait_fails_after_the_deadline(self) -> None:
        clock = mock.Mock(side_effect=[0.0, 0.0, 0.3, 0.6])
        with (
            mock.patch.object(
                smoke.lifecycle,
                "_assert_safaridriver_ready",
                side_effect=smoke.lifecycle.LifecycleError("not ready"),
            ),
            mock.patch.object(smoke.time, "monotonic", clock),
            mock.patch.object(smoke.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(
                smoke.LiveSiteError, "SafariDriver did not become ready"
            ):
                smoke._wait_for_safaridriver_ready(
                    "http://127.0.0.1:12345", timeout=0.5
                )

        self.assertEqual(sleep.call_count, 2)

    def test_safari_setup_failures_keep_exact_bounded_stages(self) -> None:
        with (
            mock.patch.object(
                smoke,
                "_wait_for_safaridriver_ready",
                side_effect=smoke.LiveSiteError("private driver diagnostic"),
            ),
        ):
            result = smoke._run_safari(
                "app.aikido.dev", "http://127.0.0.1:12345", 501
            )
        self.assertEqual(result["reason"], "driver_unavailable")

        with (
            mock.patch.object(smoke, "_wait_for_safaridriver_ready"),
            mock.patch.object(
                smoke.lifecycle,
                "_assert_no_safari_process",
                side_effect=smoke.lifecycle.LifecycleError(
                    "private process diagnostic"
                ),
            ),
        ):
            result = smoke._run_safari(
                "app.aikido.dev", "http://127.0.0.1:12345", 501
            )
        self.assertEqual(result["reason"], "browser_process_conflict")

        with (
            mock.patch.object(smoke, "_wait_for_safaridriver_ready"),
            mock.patch.object(smoke.lifecycle, "_assert_no_safari_process"),
            mock.patch.object(
                smoke.lifecycle,
                "_webdriver_request",
                side_effect=smoke.lifecycle.LifecycleError(
                    "private session diagnostic"
                ),
            ),
        ):
            result = smoke._run_safari(
                "app.aikido.dev", "http://127.0.0.1:12345", 501
            )
        self.assertEqual(result["reason"], "session_create_failed")

        webdriver = mock.Mock(
            side_effect=[
                {"value": {"sessionId": "session-id"}},
                {},
            ]
        )
        with (
            mock.patch.object(smoke, "_wait_for_safaridriver_ready"),
            mock.patch.object(smoke.lifecycle, "_assert_no_safari_process"),
            mock.patch.object(smoke.lifecycle, "_webdriver_request", webdriver),
            mock.patch.object(
                smoke.lifecycle,
                "_wait_for_safari_process",
                side_effect=smoke.lifecycle.LifecycleError(
                    "private Safari startup diagnostic"
                ),
            ),
        ):
            result = smoke._run_safari(
                "app.aikido.dev", "http://127.0.0.1:12345", 501
            )
        self.assertEqual(result["reason"], "browser_process_unavailable")

        webdriver = mock.Mock(
            side_effect=[
                {"value": {"sessionId": "session-id"}},
                smoke.lifecycle.LifecycleError("private timeout diagnostic"),
                {},
            ]
        )
        with (
            mock.patch.object(smoke, "_wait_for_safaridriver_ready"),
            mock.patch.object(smoke.lifecycle, "_assert_no_safari_process"),
            mock.patch.object(smoke.lifecycle, "_webdriver_request", webdriver),
            mock.patch.object(
                smoke.lifecycle, "_wait_for_safari_process", return_value=4321
            ),
            mock.patch.object(smoke.lifecycle, "_stop_owned_safari_process"),
        ):
            result = smoke._run_safari(
                "app.aikido.dev", "http://127.0.0.1:12345", 501
            )
        self.assertEqual(result["reason"], "session_configuration_failed")

    def test_safari_clean_session_navigates_without_originless_cookie_delete(
        self,
    ) -> None:
        calls: list[tuple[str, str]] = []

        def webdriver(
            _base_url: str,
            method: str,
            path: str,
            _payload: dict | None = None,
            **_kwargs: object,
        ) -> dict:
            calls.append((method, path))
            if method == "POST" and path == "/session":
                return {"value": {"sessionId": "session-id"}}
            if method == "GET" and path.endswith("/source"):
                return {"value": "<html>" + "x" * 600}
            if method == "POST" and path.endswith("/execute/sync"):
                return {"value": smoke.json.dumps(self._signals())}
            if (method, path) in {
                ("POST", "/session/session-id/timeouts"),
                ("POST", "/session/session-id/url"),
                ("DELETE", "/session/session-id"),
            }:
                return {}
            self.fail(f"unexpected WebDriver call: {method} {path}")

        with (
            mock.patch.object(smoke, "_wait_for_safaridriver_ready"),
            mock.patch.object(smoke.lifecycle, "_assert_no_safari_process"),
            mock.patch.object(smoke.lifecycle, "_webdriver_request", webdriver),
            mock.patch.object(
                smoke.lifecycle, "_wait_for_safari_process", return_value=4321
            ),
            mock.patch.object(smoke.lifecycle, "_stop_owned_safari_process"),
        ):
            result = smoke._run_safari(
                "app.aikido.dev", "http://127.0.0.1:12345", 501
            )

        self.assertEqual(result["outcome"], "usable")
        self.assertNotIn(
            ("DELETE", "/session/session-id/cookie"),
            calls,
        )
        self.assertIn(("DELETE", "/session/session-id"), calls)

    def test_regional_and_edge_denials_are_not_usable(self) -> None:
        regional = "x" * 600 + "This content is no longer available in your area"
        edge = "x" * 600 + "Sorry, you have been blocked"
        self.assertEqual(
            smoke._classify_document("weather.com", regional),
            "regional_access_denied",
        )
        self.assertEqual(
            smoke._classify_document("capacitorjs.com", edge),
            "edge_access_denied",
        )

    def test_browser_reason_contract_is_bounded_and_shared(self) -> None:
        self.assertEqual(
            smoke.TERMINAL_BROWSER_REASONS,
            readiness.TERMINAL_BROWSER_REASONS,
        )
        self.assertEqual(
            smoke._classify_document_evidence("app.aikido.dev", "short"),
            ("terminal_error", "document_too_short"),
        )
        document = "<html>" + "x" * 600
        self.assertEqual(
            smoke._classify_document_evidence(
                "app.aikido.dev", document, self._signals()
            ),
            ("usable", ""),
        )

    def test_safari_readiness_signals_require_a_json_object_string(self) -> None:
        signals = self._signals()
        self.assertEqual(
            smoke._decode_safari_readiness_signals(smoke.json.dumps(signals)),
            signals,
        )
        for invalid in (None, signals, "not-json", "[]"):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(
                    smoke.LiveSiteError,
                    "^Safari returned invalid readiness signals$",
                ):
                    smoke._decode_safari_readiness_signals(invalid)

    def test_short_or_tls_warning_documents_fail(self) -> None:
        self.assertEqual(
            smoke._classify_document("app.aikido.dev", "short"),
            "terminal_error",
        )
        warning = "x" * 600 + "This Connection Is Not Secure"
        self.assertEqual(
            smoke._classify_document("xpersonatoy.com", warning),
            "terminal_error",
        )

    def test_aikido_static_shell_cannot_false_pass(self) -> None:
        document = (
            "<html><title>Aikido Security</title><div id='app'></div>" + "x" * 600
        )
        skeleton = self._signals(app_text_length=0, visible_app=False)
        self.assertEqual(
            smoke._classify_document("app.aikido.dev", document, skeleton),
            "terminal_error",
        )
        self.assertEqual(
            smoke._classify_document("app.aikido.dev", document, self._signals()),
            "usable",
        )

    def test_https_and_negotiated_transport_are_required(self) -> None:
        document = "<html>" + "x" * 600
        for changes in (
            {"https": False},
            {"secure_context": False},
            {"next_hop_protocol": ""},
        ):
            with self.subTest(changes=changes):
                self.assertEqual(
                    smoke._classify_document(
                        "app.aikido.dev", document, self._signals(**changes)
                    ),
                    "terminal_error",
                )

    def test_control_route_tolerates_non_utf8_document_bytes(self) -> None:
        response = mock.Mock(
            returncode=0,
            stdout=b"\xff" + (b"x" * 600) + b"\n__SLIPSTREAM_STATUS__:200",
        )
        with mock.patch.object(smoke.subprocess, "run", return_value=response) as run:
            self.assertEqual(smoke._control_route("weather.com", "direct"), "usable")

        self.assertNotIn("text", run.call_args.kwargs)

    def test_successful_sites_cannot_hide_cleanup_failure(self) -> None:
        browser_result = {
            "browser": "safari",
            "deadline_ms": 20_000,
            "elapsed_ms": 100,
            "outcome": "usable",
            "reason": "",
            "route": "slipstream_selected",
        }
        target = SimpleNamespace(install_command=("install",))
        system = mock.Mock()
        with (
            mock.patch.object(smoke, "_require_protected_ci"),
            mock.patch.object(smoke.pf, "PfctlRunner", return_value=mock.Mock()),
            mock.patch.object(
                smoke.lifecycle, "_preflight", return_value=("before", 501, 20)
            ),
            mock.patch.object(
                smoke.lifecycle, "packaged_app_target", return_value=target
            ),
            mock.patch.object(smoke.lifecycle, "SystemRunner", return_value=system),
            mock.patch.object(smoke.lifecycle, "_wait_for_status"),
            mock.patch.object(smoke.lifecycle, "_assert_anchor_active"),
            mock.patch.object(smoke, "_run_safari", return_value=browser_result),
            mock.patch.object(
                smoke,
                "_run_chrome",
                return_value={**browser_result, "browser": "chrome"},
            ),
            mock.patch.object(
                smoke.lifecycle,
                "_fallback_uninstall",
                return_value=["cleanup failed"],
            ),
            mock.patch.object(smoke.lifecycle, "_assert_clean_install_state"),
            mock.patch.object(smoke.pf, "_pf_snapshot", return_value="before"),
            mock.patch.object(smoke.pf, "_assert_same_snapshot"),
        ):
            with self.assertRaisesRegex(
                smoke.LiveSiteError, "^live-site cleanup failed$"
            ):
                smoke.run_gate(mock.Mock(), mock.Mock(), "http://127.0.0.1:1")

    def test_mid_matrix_exception_is_bounded_and_cleanup_still_runs(self) -> None:
        browser_result = {
            "browser": "safari",
            "deadline_ms": 20_000,
            "elapsed_ms": 100,
            "outcome": "usable",
            "reason": "",
            "route": "slipstream_selected",
        }
        target = SimpleNamespace(install_command=("install",))
        system = mock.Mock()
        fallback = mock.Mock(return_value=[])
        safari = mock.Mock(
            side_effect=[browser_result, RuntimeError("private raw diagnostic")]
        )
        with (
            mock.patch.object(smoke, "_require_protected_ci"),
            mock.patch.object(smoke.pf, "PfctlRunner", return_value=mock.Mock()),
            mock.patch.object(
                smoke.lifecycle, "_preflight", return_value=("before", 501, 20)
            ),
            mock.patch.object(
                smoke.lifecycle, "packaged_app_target", return_value=target
            ),
            mock.patch.object(smoke.lifecycle, "SystemRunner", return_value=system),
            mock.patch.object(smoke.lifecycle, "_wait_for_status"),
            mock.patch.object(smoke.lifecycle, "_assert_anchor_active"),
            mock.patch.object(smoke, "_run_safari", safari),
            mock.patch.object(
                smoke,
                "_run_chrome",
                return_value={**browser_result, "browser": "chrome"},
            ),
            mock.patch.object(smoke.lifecycle, "_fallback_uninstall", fallback),
            mock.patch.object(smoke.lifecycle, "_assert_clean_install_state"),
            mock.patch.object(smoke.pf, "_pf_snapshot", return_value="before"),
            mock.patch.object(smoke.pf, "_assert_same_snapshot"),
        ):
            with self.assertRaises(smoke.LiveSiteError) as raised:
                smoke.run_gate(mock.Mock(), mock.Mock(), "http://127.0.0.1:1")

        self.assertEqual(
            str(raised.exception),
            "live-site execution failed at safari:app.aikido.dev (RuntimeError)",
        )
        self.assertNotIn("private raw diagnostic", str(raised.exception))
        fallback.assert_called_once()

    def test_setup_exception_is_bounded_without_raw_diagnostic(self) -> None:
        with (
            mock.patch.object(smoke, "_require_protected_ci"),
            mock.patch.object(smoke.pf, "PfctlRunner", return_value=mock.Mock()),
            mock.patch.object(
                smoke.lifecycle,
                "_preflight",
                side_effect=RuntimeError("private raw diagnostic"),
            ),
        ):
            with self.assertRaises(smoke.LiveSiteError) as raised:
                smoke.run_gate(mock.Mock(), mock.Mock(), "http://127.0.0.1:1")

        self.assertEqual(
            str(raised.exception),
            "live-site execution failed at preflight (RuntimeError)",
        )
        self.assertNotIn("private raw diagnostic", str(raised.exception))

    def test_fallback_exception_cannot_skip_remaining_cleanup_proofs(self) -> None:
        target = SimpleNamespace(install_command=("install",))
        system = mock.Mock()
        clean_install = mock.Mock()
        same_snapshot = mock.Mock()
        with (
            mock.patch.object(smoke, "_require_protected_ci"),
            mock.patch.object(smoke.pf, "PfctlRunner", return_value=mock.Mock()),
            mock.patch.object(
                smoke.lifecycle, "_preflight", return_value=("before", 501, 20)
            ),
            mock.patch.object(
                smoke.lifecycle, "packaged_app_target", return_value=target
            ),
            mock.patch.object(smoke.lifecycle, "SystemRunner", return_value=system),
            mock.patch.object(smoke.lifecycle, "_wait_for_status"),
            mock.patch.object(smoke.lifecycle, "_assert_anchor_active"),
            mock.patch.object(
                smoke,
                "_run_safari",
                side_effect=RuntimeError("stop before browser side effects"),
            ),
            mock.patch.object(
                smoke.lifecycle,
                "_fallback_uninstall",
                side_effect=RuntimeError("private cleanup diagnostic"),
            ),
            mock.patch.object(
                smoke.lifecycle, "_assert_clean_install_state", clean_install
            ),
            mock.patch.object(smoke.pf, "_pf_snapshot", return_value="before"),
            mock.patch.object(smoke.pf, "_assert_same_snapshot", same_snapshot),
        ):
            with self.assertRaisesRegex(
                smoke.LiveSiteError, "^live-site cleanup failed$"
            ):
                smoke.run_gate(mock.Mock(), mock.Mock(), "http://127.0.0.1:1")

        clean_install.assert_called_once()
        same_snapshot.assert_called_once_with("before", "before")

    def test_every_returned_report_matches_the_readiness_contract(self) -> None:
        browser_result = {
            "browser": "safari",
            "deadline_ms": 20_000,
            "elapsed_ms": 100,
            "outcome": "usable",
            "reason": "",
            "route": "slipstream_selected",
        }
        target = SimpleNamespace(install_command=("install",))
        system = mock.Mock()

        def safari(host: str, _driver_url: str, _uid: int) -> dict[str, object]:
            return {
                **browser_result,
                "deadline_ms": smoke.SITES[host]["deadline_ms"],
            }

        def chrome(
            host: str, _path: smoke.Path, _uid: int, _gid: int
        ) -> dict[str, object]:
            return {
                **browser_result,
                "browser": "chrome",
                "deadline_ms": smoke.SITES[host]["deadline_ms"],
            }

        with (
            mock.patch.object(smoke, "_require_protected_ci"),
            mock.patch.object(smoke.pf, "PfctlRunner", return_value=mock.Mock()),
            mock.patch.object(
                smoke.lifecycle, "_preflight", return_value=("before", 501, 20)
            ),
            mock.patch.object(
                smoke.lifecycle, "packaged_app_target", return_value=target
            ),
            mock.patch.object(smoke.lifecycle, "SystemRunner", return_value=system),
            mock.patch.object(smoke.lifecycle, "_wait_for_status"),
            mock.patch.object(smoke.lifecycle, "_assert_anchor_active"),
            mock.patch.object(smoke, "_run_safari", side_effect=safari),
            mock.patch.object(smoke, "_run_chrome", side_effect=chrome),
            mock.patch.object(smoke.lifecycle, "_fallback_uninstall", return_value=[]),
            mock.patch.object(smoke.lifecycle, "_assert_clean_install_state"),
            mock.patch.object(smoke.pf, "_pf_snapshot", return_value="before"),
            mock.patch.object(smoke.pf, "_assert_same_snapshot"),
        ):
            report, status = smoke.run_gate(
                mock.Mock(), mock.Mock(), "http://127.0.0.1:1"
            )

        self.assertEqual(readiness.validate_live_report(report, status), "passed")

    def test_browser_terminal_result_still_returns_the_full_matrix(self) -> None:
        browser_result = {
            "browser": "safari",
            "deadline_ms": 20_000,
            "elapsed_ms": 100,
            "outcome": "usable",
            "reason": "",
            "route": "slipstream_selected",
        }
        target = SimpleNamespace(install_command=("install",))
        system = mock.Mock()

        def safari(host: str, _driver_url: str, _uid: int) -> dict[str, object]:
            return {
                **browser_result,
                "deadline_ms": smoke.SITES[host]["deadline_ms"],
            }

        def chrome(
            host: str, _path: smoke.Path, _uid: int, _gid: int
        ) -> dict[str, object]:
            return {
                **browser_result,
                "browser": "chrome",
                "deadline_ms": smoke.SITES[host]["deadline_ms"],
                "outcome": ("terminal_error" if host == "app.aikido.dev" else "usable"),
                "reason": ("readiness_timeout" if host == "app.aikido.dev" else ""),
            }

        with (
            mock.patch.object(smoke, "_require_protected_ci"),
            mock.patch.object(smoke.pf, "PfctlRunner", return_value=mock.Mock()),
            mock.patch.object(
                smoke.lifecycle, "_preflight", return_value=("before", 501, 20)
            ),
            mock.patch.object(
                smoke.lifecycle, "packaged_app_target", return_value=target
            ),
            mock.patch.object(smoke.lifecycle, "SystemRunner", return_value=system),
            mock.patch.object(smoke.lifecycle, "_wait_for_status"),
            mock.patch.object(smoke.lifecycle, "_assert_anchor_active"),
            mock.patch.object(smoke, "_run_safari", side_effect=safari),
            mock.patch.object(smoke, "_run_chrome", side_effect=chrome),
            mock.patch.object(smoke, "_control_route", return_value="usable"),
            mock.patch.object(smoke.lifecycle, "_fallback_uninstall", return_value=[]),
            mock.patch.object(smoke.lifecycle, "_assert_clean_install_state"),
            mock.patch.object(smoke.pf, "_pf_snapshot", return_value="before"),
            mock.patch.object(smoke.pf, "_assert_same_snapshot"),
        ):
            report, status = smoke.run_gate(
                mock.Mock(), mock.Mock(), "http://127.0.0.1:1"
            )

        self.assertEqual(len(report["sites"]), len(smoke.SITES))
        self.assertEqual(readiness.validate_live_report(report, status), "failed")


if __name__ == "__main__":
    unittest.main()
