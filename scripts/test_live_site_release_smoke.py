from __future__ import annotations

import tempfile
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest import mock

import live_site_release_smoke as smoke
import release_readiness as readiness

_DEFAULT_DOCUMENT_ACTIVATION_ID = object()


class LiveSiteReleaseSmokeTests(unittest.TestCase):
    DOCUMENT_ACTIVATION_ID = (1, 2, 3, 4)

    def _confirmation(
        self,
        since: float,
        document_activation_id: tuple[int, int, int, int] | None = None,
    ) -> smoke.InteractiveConfirmation:
        return (
            since,
            document_activation_id or self.DOCUMENT_ACTIVATION_ID,
        )

    def _signals(self, **changes: object) -> dict[str, object]:
        value = {
            "app_text_length": 100,
            "body_text_length": 1000,
            "dom_content_loaded": True,
            "host_matches": True,
            "https": True,
            "main_text_length": 1000,
            "next_hop_protocol": "h2",
            "preloader_visible": False,
            "ready_state": "complete",
            "secure_context": True,
            "title": "Aikido Security",
            "visible_app": True,
            "visible_body": True,
            "visible_challenge_marker": False,
        }
        value.update(changes)
        return value

    def _browser_evidence(
        self,
        *,
        document_bytes: int = 1_000,
        denial_detected: bool = False,
        challenge_detected: bool = False,
        document_activation_id: object = _DEFAULT_DOCUMENT_ACTIVATION_ID,
        signals: dict[str, object] | None = None,
    ) -> dict[str, object]:
        return {
            "challenge_detected": challenge_detected,
            "denial_detected": denial_detected,
            "document_activation_id": (
                list(self.DOCUMENT_ACTIVATION_ID)
                if document_activation_id is _DEFAULT_DOCUMENT_ACTIVATION_ID
                else document_activation_id
            ),
            "document_bytes": document_bytes,
            "signals": self._signals() if signals is None else signals,
        }

    def _chrome_evidence(self, **changes: object) -> dict[str, object]:
        return {"result": {"value": self._browser_evidence(**changes)}}

    def _safari_observation_timeout(self) -> smoke.lifecycle.LifecycleError:
        error = smoke.lifecycle.LifecycleError("private timeout diagnostic")
        error.__cause__ = TimeoutError("timed out")
        return error

    def _fake_chrome_for_testing(self, root: smoke.Path) -> smoke.Path:
        contents = root / "Google Chrome for Testing.app" / "Contents"
        executable = contents / "MacOS" / "Google Chrome for Testing"
        executable.parent.mkdir(parents=True, exist_ok=True)
        (contents / "Info.plist").touch()
        executable.touch()
        executable.chmod(0o755)
        return executable

    def _enter_chrome_lifecycle(
        self,
        stack: ExitStack,
        root: smoke.Path,
        *,
        bootstrap_error: BaseException | None = None,
        cleanup_events: list[str] | None = None,
    ) -> SimpleNamespace:
        executable = self._fake_chrome_for_testing(root)
        profile = root / "profile"
        profile.mkdir(exist_ok=True)
        launch = smoke.chromium.ChromeLaunch(
            "gui/501/dev.slipstream.chromium-semantic.live.test",
            4242,
            4242,
        )
        browser = smoke.chromium.ChromeProcess(
            4343,
            4343,
            f"{executable} --user-data-dir={profile}",
        )
        events = cleanup_events if cleanup_events is not None else []

        stack.enter_context(
            mock.patch.object(
                smoke.lifecycle,
                "_user_environment",
                return_value=({"HOME": str(root), "USER": "runner"}, root),
            )
        )
        stack.enter_context(
            mock.patch.object(
                smoke.lifecycle,
                "_user_supplementary_groups",
                return_value=(12, 61),
            )
        )
        stack.enter_context(
            mock.patch.object(smoke.tempfile, "mkdtemp", return_value=str(profile))
        )
        stack.enter_context(mock.patch.object(smoke.os, "chown"))
        write_private = stack.enter_context(
            mock.patch.object(smoke.chromium, "_write_owner_private_file")
        )
        bootstrap_options = (
            {"side_effect": bootstrap_error}
            if bootstrap_error is not None
            else {"return_value": launch}
        )
        bootstrap = stack.enter_context(
            mock.patch.object(
                smoke.chromium,
                "_bootstrap_chrome_launch_agent",
                **bootstrap_options,
            )
        )
        wait_for_browser = stack.enter_context(
            mock.patch.object(
                smoke.chromium,
                "_wait_for_owned_chrome_process",
                return_value=browser,
            )
        )
        stop = stack.enter_context(
            mock.patch.object(
                smoke.chromium,
                "_stop_chrome_launch_agent",
                side_effect=lambda *_args, **_kwargs: events.append("stop"),
            )
        )
        remove_profile = stack.enter_context(
            mock.patch.object(
                smoke.chromium,
                "_remove_owned_profile",
                side_effect=lambda *_args, **_kwargs: events.append("remove"),
            )
        )
        wait_for_absence = stack.enter_context(
            mock.patch.object(smoke.chromium, "_wait_for_launch_agent_absence")
        )
        stop_partial = stack.enter_context(
            mock.patch.object(smoke.chromium, "_stop_owned_chrome_processes")
        )
        popen = stack.enter_context(mock.patch.object(smoke.subprocess, "Popen"))
        return SimpleNamespace(
            bootstrap=bootstrap,
            browser=browser,
            events=events,
            executable=executable,
            launch=launch,
            popen=popen,
            profile=profile,
            remove_profile=remove_profile,
            stop=stop,
            stop_partial=stop_partial,
            wait_for_absence=wait_for_absence,
            wait_for_browser=wait_for_browser,
            write_private=write_private,
        )

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

    def test_readiness_expression_bounds_page_controlled_strings(self) -> None:
        self.assertIn("const boundedString", smoke.READINESS_EXPRESSION)
        self.assertIn(
            "boundedString(navigation.nextHopProtocol, 32)",
            smoke.READINESS_EXPRESSION,
        )
        self.assertIn(
            "boundedString(document.title, 512)", smoke.READINESS_EXPRESSION
        )
        self.assertIn("const visibleText", smoke.READINESS_EXPRESSION)
        self.assertIn("visible_challenge_marker", smoke.READINESS_EXPRESSION)
        self.assertIn("visibleChallengeWidget", smoke.READINESS_EXPRESSION)
        self.assertIn("challenges.cloudflare.com", smoke.READINESS_EXPRESSION)
        self.assertIn("data-sitekey", smoke.READINESS_EXPRESSION)
        self.assertIn("if (!visible(node)) return false;", smoke.READINESS_EXPRESSION)
        self.assertIn("node.hasAttribute('data-sitekey')", smoke.READINESS_EXPRESSION)
        self.assertIn("domContentLoadedEventEnd > 0", smoke.READINESS_EXPRESSION)
        host_expression = smoke._readiness_expression("weather.com")
        self.assertIn('const expectedHost = "weather.com"', host_expression)
        self.assertIn("location.hostname.toLowerCase()", host_expression)
        with self.assertRaisesRegex(ValueError, "fixed matrix"):
            smoke._readiness_expression("example.com")

    def test_chrome_navigation_error_becomes_bounded_terminal_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = smoke.Path(temporary)
            cleanup_events: list[str] = []
            with ExitStack() as stack:
                lifecycle = self._enter_chrome_lifecycle(
                    stack,
                    root,
                    cleanup_events=cleanup_events,
                )
                stack.enter_context(
                    mock.patch.object(
                    smoke.chromium, "_wait_for_devtools_port", return_value=9222
                    )
                )
                stack.enter_context(
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
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                    smoke.chromium,
                    "_devtools_command",
                    return_value={"errorText": "net::ERR_EMPTY_RESPONSE"},
                    )
                )
                result = smoke._run_chrome(
                    "app.aikido.dev", lifecycle.executable, 501, 20
                )

        self.assertEqual(result["outcome"], "terminal_error")
        self.assertEqual(result["reason"], "navigation_rejected")
        self.assertEqual(result["browser"], "chrome")
        self.assertEqual(result["route"], "slipstream_selected")
        lifecycle.popen.assert_not_called()
        lifecycle.wait_for_browser.assert_called_once_with(
            501,
            lifecycle.executable.resolve(),
            lifecycle.profile,
            mock.ANY,
        )
        lifecycle.stop.assert_called_once_with(
            lifecycle.launch,
            uid=501,
            gid=20,
            supplementary_groups=(12, 61),
            executable=lifecycle.executable.resolve(),
            profile=lifecycle.profile,
            ownership=mock.ANY,
            post_bootout_settle_time=0.0,
        )
        lifecycle.remove_profile.assert_called_once_with(lifecycle.profile)
        self.assertEqual(cleanup_events, ["stop", "remove"])
        self.assertEqual(lifecycle.write_private.call_count, 5)
        for call in lifecycle.write_private.call_args_list:
            self.assertEqual(call.args[-2:], (501, 20))
        payload = smoke.plistlib.loads(
            lifecycle.write_private.call_args_list[-1].args[1]
        )
        self.assertEqual(payload["ProcessType"], "Interactive")
        self.assertEqual(payload["LimitLoadToSessionType"], "Aqua")
        command = payload["ProgramArguments"]
        self.assertEqual(command[:4], ["/usr/bin/open", "-n", "-W", "-j"])
        self.assertIn(str(lifecycle.executable.parents[2].resolve()), command)
        self.assertIn("--args", command)
        self.assertFalse(any(argument.startswith("--headless") for argument in command))
        self.assertNotIn("--no-sandbox", command)

    def test_chrome_navigation_timeout_is_not_an_observation_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = smoke.Path(temporary)
            with ExitStack() as stack:
                lifecycle = self._enter_chrome_lifecycle(stack, root)
                stack.enter_context(
                    mock.patch.object(
                        smoke.chromium, "_wait_for_devtools_port", return_value=9222
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        smoke.chromium,
                        "_devtools_json",
                        return_value=[
                            {
                                "type": "page",
                                "url": "about:blank",
                                "webSocketDebuggerUrl": (
                                    "ws://127.0.0.1/devtools/page/1"
                                ),
                            }
                        ],
                    )
                )
                commands = stack.enter_context(
                    mock.patch.object(
                        smoke.chromium,
                        "_devtools_command",
                        side_effect=TimeoutError("timed out"),
                    )
                )
                result = smoke._run_chrome(
                    "app.aikido.dev", lifecycle.executable, 501, 20
                )

        self.assertEqual(
            (result["outcome"], result["reason"]),
            ("terminal_error", "navigation_rejected"),
        )
        commands.assert_called_once()

    def test_chrome_setup_failures_keep_exact_bounded_stages(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = smoke.Path(temporary)

            def run(
                *patchers: object,
                bootstrap_error: BaseException | None = None,
            ) -> tuple[dict[str, object], SimpleNamespace]:
                with ExitStack() as stack:
                    lifecycle = self._enter_chrome_lifecycle(
                        stack,
                        root,
                        bootstrap_error=bootstrap_error,
                    )
                    for patcher in patchers:
                        stack.enter_context(patcher)
                    result = smoke._run_chrome(
                        "app.aikido.dev", lifecycle.executable, 501, 20
                    )
                    lifecycle.popen.assert_not_called()
                    return result, lifecycle

            result, lifecycle = run(
                bootstrap_error=smoke.chromium.QualificationError(
                    "private launch diagnostic"
                )
            )
            self.assertEqual(result["reason"], "browser_start_failed")
            self.assertEqual(result["elapsed_ms"], 0)
            label = lifecycle.bootstrap.call_args.args[1]
            lifecycle.wait_for_absence.assert_called_once_with(f"gui/501/{label}")
            lifecycle.stop_partial.assert_called_once_with(
                501,
                lifecycle.executable.resolve(),
                lifecycle.profile,
                mock.ANY,
                timeout=10.0,
                settle_time=5.0,
            )
            lifecycle.stop.assert_not_called()
            lifecycle.remove_profile.assert_called_once_with(lifecycle.profile)

            result, lifecycle = run(
                mock.patch.object(
                    smoke.chromium,
                    "_wait_for_devtools_port",
                    side_effect=smoke.chromium.QualificationError(
                        "private DevTools diagnostic"
                    ),
                ),
            )
            self.assertEqual(result["reason"], "devtools_unavailable")
            self.assertEqual(result["elapsed_ms"], 0)
            lifecycle.stop.assert_called_once()
            lifecycle.remove_profile.assert_called_once_with(lifecycle.profile)

            result, lifecycle = run(
                mock.patch.object(
                    smoke.chromium, "_wait_for_devtools_port", return_value=9222
                ),
                mock.patch.object(smoke.chromium, "_devtools_json", return_value=[]),
            )
            self.assertEqual(result["reason"], "target_unavailable")
            self.assertEqual(result["elapsed_ms"], 0)
            lifecycle.stop.assert_called_once()
            lifecycle.remove_profile.assert_called_once_with(lifecycle.profile)

    def test_chrome_partial_bootstrap_cleanup_failure_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = smoke.Path(temporary)
            with ExitStack() as stack:
                lifecycle = self._enter_chrome_lifecycle(
                    stack,
                    root,
                    bootstrap_error=smoke.chromium.QualificationError(
                        "private launch diagnostic"
                    ),
                )
                lifecycle.wait_for_absence.side_effect = (
                    smoke.chromium.QualificationError("private cleanup diagnostic")
                )
                with self.assertRaisesRegex(
                    smoke.LiveSiteError,
                    "^Chrome cleanup failed$",
                ):
                    smoke._run_chrome(
                        "app.aikido.dev", lifecycle.executable, 501, 20
                    )

        lifecycle.popen.assert_not_called()
        label = lifecycle.bootstrap.call_args.args[1]
        lifecycle.wait_for_absence.assert_called_once_with(f"gui/501/{label}")
        lifecycle.stop_partial.assert_called_once()
        lifecycle.stop.assert_not_called()
        lifecycle.remove_profile.assert_not_called()

    def test_chrome_retries_transient_execution_context_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = smoke.Path(temporary)
            commands = mock.Mock(
                side_effect=[
                    {},
                    smoke.chromium.QualificationError("context replaced"),
                    self._chrome_evidence(),
                ]
            )
            with ExitStack() as stack:
                lifecycle = self._enter_chrome_lifecycle(stack, root)
                stack.enter_context(
                    mock.patch.object(
                    smoke.chromium, "_wait_for_devtools_port", return_value=9222
                    )
                )
                stack.enter_context(
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
                    )
                )
                stack.enter_context(
                    mock.patch.object(smoke.chromium, "_devtools_command", commands)
                )
                stack.enter_context(mock.patch.object(smoke.time, "sleep"))
                result = smoke._run_chrome(
                    "app.aikido.dev", lifecycle.executable, 501, 20
                )

        self.assertEqual(result["outcome"], "usable")
        self.assertEqual(result["reason"], "")
        self.assertEqual(commands.call_count, 3)
        lifecycle.popen.assert_not_called()
        lifecycle.stop.assert_called_once()
        lifecycle.remove_profile.assert_called_once_with(lifecycle.profile)

    def test_chrome_confirms_interactive_readiness_before_passing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = smoke.Path(temporary)
            clock = 0.0
            runtime_calls = 0
            evidence = self._chrome_evidence(
                signals=self._signals(ready_state="interactive")
            )

            def monotonic() -> float:
                nonlocal clock
                clock += 0.1
                return clock

            def command(
                _debugger: str,
                _port: int,
                method: str,
                _payload: dict[str, object],
                **_kwargs: object,
            ) -> dict:
                nonlocal runtime_calls
                if method == "Page.navigate":
                    return {}
                self.assertEqual(method, "Runtime.evaluate")
                runtime_calls += 1
                return evidence

            with ExitStack() as stack:
                lifecycle = self._enter_chrome_lifecycle(stack, root)
                stack.enter_context(
                    mock.patch.object(
                        smoke.chromium, "_wait_for_devtools_port", return_value=9222
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        smoke.chromium,
                        "_devtools_json",
                        return_value=[
                            {
                                "type": "page",
                                "url": "about:blank",
                                "webSocketDebuggerUrl": (
                                    "ws://127.0.0.1/devtools/page/1"
                                ),
                            }
                        ],
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        smoke.chromium, "_devtools_command", side_effect=command
                    )
                )
                stack.enter_context(
                    mock.patch.object(smoke.time, "monotonic", monotonic)
                )
                stack.enter_context(mock.patch.object(smoke.time, "sleep"))
                result = smoke._run_chrome(
                    "app.aikido.dev", lifecycle.executable, 501, 20
                )

        self.assertEqual((result["outcome"], result["reason"]), ("usable", ""))
        self.assertGreaterEqual(runtime_calls, 2)

    def test_chrome_response_latency_cannot_satisfy_interactive_settle(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = smoke.Path(temporary)
            clock = 0.0
            runtime_calls = 0
            interactive = self._chrome_evidence(
                signals=self._signals(ready_state="interactive")
            )
            complete = self._chrome_evidence()

            def monotonic() -> float:
                return clock

            def sleep(_seconds: float) -> None:
                nonlocal clock
                clock = 2.25 if runtime_calls == 1 else 4.5

            def command(
                _debugger: str,
                _port: int,
                method: str,
                _payload: dict[str, object],
                **_kwargs: object,
            ) -> dict:
                nonlocal clock, runtime_calls
                if method == "Page.navigate":
                    return {}
                runtime_calls += 1
                if runtime_calls == 1:
                    clock = 2.0
                    return interactive
                if runtime_calls == 2:
                    clock = 4.25
                    return interactive
                clock = 4.6
                return complete

            with ExitStack() as stack:
                lifecycle = self._enter_chrome_lifecycle(stack, root)
                stack.enter_context(
                    mock.patch.dict(
                        smoke.SITES["app.aikido.dev"], {"deadline_ms": 10_000}
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        smoke.chromium, "_wait_for_devtools_port", return_value=9222
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        smoke.chromium,
                        "_devtools_json",
                        return_value=[
                            {
                                "type": "page",
                                "url": "about:blank",
                                "webSocketDebuggerUrl": (
                                    "ws://127.0.0.1/devtools/page/1"
                                ),
                            }
                        ],
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        smoke.chromium, "_devtools_command", side_effect=command
                    )
                )
                stack.enter_context(
                    mock.patch.object(smoke.time, "monotonic", monotonic)
                )
                stack.enter_context(
                    mock.patch.object(smoke.time, "sleep", side_effect=sleep)
                )
                result = smoke._run_chrome(
                    "app.aikido.dev", lifecycle.executable, 501, 20
                )

        self.assertEqual(runtime_calls, 3)
        self.assertEqual((result["outcome"], result["reason"]), ("usable", ""))

    def test_chrome_document_replacement_restarts_interactive_settle(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = smoke.Path(temporary)
            clock = 0.0
            runtime_calls = 0
            first_id = [1, 2, 3, 4]
            replacement_id = [5, 6, 7, 8]
            signals = self._signals(ready_state="interactive")

            def monotonic() -> float:
                return clock

            def sleep(_seconds: float) -> None:
                nonlocal clock
                clock = 0.7 if runtime_calls == 1 else 1.3

            def command(
                _debugger: str,
                _port: int,
                method: str,
                _payload: dict[str, object],
                **_kwargs: object,
            ) -> dict:
                nonlocal clock, runtime_calls
                if method == "Page.navigate":
                    return {}
                runtime_calls += 1
                clock = {1: 0.1, 2: 0.8, 3: 1.31}[runtime_calls]
                return self._chrome_evidence(
                    document_activation_id=(
                        first_id if runtime_calls == 1 else replacement_id
                    ),
                    signals=signals,
                )

            with ExitStack() as stack:
                lifecycle = self._enter_chrome_lifecycle(stack, root)
                stack.enter_context(
                    mock.patch.dict(
                        smoke.SITES["app.aikido.dev"], {"deadline_ms": 10_000}
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        smoke.chromium, "_wait_for_devtools_port", return_value=9222
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        smoke.chromium,
                        "_devtools_json",
                        return_value=[
                            {
                                "type": "page",
                                "url": "about:blank",
                                "webSocketDebuggerUrl": (
                                    "ws://127.0.0.1/devtools/page/1"
                                ),
                            }
                        ],
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        smoke.chromium, "_devtools_command", side_effect=command
                    )
                )
                stack.enter_context(
                    mock.patch.object(smoke.time, "monotonic", monotonic)
                )
                stack.enter_context(
                    mock.patch.object(smoke.time, "sleep", side_effect=sleep)
                )
                result = smoke._run_chrome(
                    "app.aikido.dev", lifecycle.executable, 501, 20
                )

        self.assertEqual(runtime_calls, 3)
        self.assertEqual((result["outcome"], result["reason"]), ("usable", ""))

    def test_chrome_rejects_interactive_confirmation_at_or_after_deadline(
        self,
    ) -> None:
        for final_observation in (0.5, 0.501):
            with self.subTest(final_observation=final_observation):
                with tempfile.TemporaryDirectory() as temporary:
                    root = smoke.Path(temporary)
                    clock = 0.0
                    runtime_calls = 0
                    evidence = self._chrome_evidence(
                        signals=self._signals(ready_state="interactive")
                    )

                    def monotonic() -> float:
                        return clock

                    def sleep(_seconds: float) -> None:
                        nonlocal clock
                        clock = 0.49

                    def command(
                        _debugger: str,
                        _port: int,
                        method: str,
                        _payload: dict[str, object],
                        **_kwargs: object,
                    ) -> dict:
                        nonlocal clock, runtime_calls
                        if method == "Page.navigate":
                            return {}
                        runtime_calls += 1
                        if runtime_calls == 2:
                            clock = final_observation
                        return evidence

                    with ExitStack() as stack:
                        lifecycle = self._enter_chrome_lifecycle(stack, root)
                        stack.enter_context(
                            mock.patch.dict(
                                smoke.SITES["app.aikido.dev"],
                                {"deadline_ms": 500},
                            )
                        )
                        stack.enter_context(
                            mock.patch.object(
                                smoke.chromium,
                                "_wait_for_devtools_port",
                                return_value=9222,
                            )
                        )
                        stack.enter_context(
                            mock.patch.object(
                                smoke.chromium,
                                "_devtools_json",
                                return_value=[
                                    {
                                        "type": "page",
                                        "url": "about:blank",
                                        "webSocketDebuggerUrl": (
                                            "ws://127.0.0.1/devtools/page/1"
                                        ),
                                    }
                                ],
                            )
                        )
                        stack.enter_context(
                            mock.patch.object(
                                smoke.chromium,
                                "_devtools_command",
                                side_effect=command,
                            )
                        )
                        stack.enter_context(
                            mock.patch.object(
                                smoke.time,
                                "monotonic",
                                side_effect=monotonic,
                            )
                        )
                        stack.enter_context(
                            mock.patch.object(smoke.time, "sleep", side_effect=sleep)
                        )
                        result = smoke._run_chrome(
                            "app.aikido.dev", lifecycle.executable, 501, 20
                        )

                self.assertEqual(runtime_calls, 2)
                self.assertEqual(
                    (result["outcome"], result["reason"]),
                    (
                        "terminal_error",
                        "readiness_document_pending_semantic_ready",
                    ),
                )

    def test_chrome_rejects_complete_response_at_or_after_deadline(self) -> None:
        for final_observation in (0.5, 0.501):
            with self.subTest(final_observation=final_observation):
                with tempfile.TemporaryDirectory() as temporary:
                    root = smoke.Path(temporary)
                    clock = 0.0
                    runtime_calls = 0

                    def monotonic() -> float:
                        return clock

                    def command(
                        _debugger: str,
                        _port: int,
                        method: str,
                        _payload: dict[str, object],
                        **_kwargs: object,
                    ) -> dict:
                        nonlocal clock, runtime_calls
                        if method == "Page.navigate":
                            return {}
                        runtime_calls += 1
                        clock = final_observation
                        return self._chrome_evidence()

                    with ExitStack() as stack:
                        lifecycle = self._enter_chrome_lifecycle(stack, root)
                        stack.enter_context(
                            mock.patch.dict(
                                smoke.SITES["app.aikido.dev"],
                                {"deadline_ms": 500},
                            )
                        )
                        stack.enter_context(
                            mock.patch.object(
                                smoke.chromium,
                                "_wait_for_devtools_port",
                                return_value=9222,
                            )
                        )
                        stack.enter_context(
                            mock.patch.object(
                                smoke.chromium,
                                "_devtools_json",
                                return_value=[
                                    {
                                        "type": "page",
                                        "url": "about:blank",
                                        "webSocketDebuggerUrl": (
                                            "ws://127.0.0.1/devtools/page/1"
                                        ),
                                    }
                                ],
                            )
                        )
                        stack.enter_context(
                            mock.patch.object(
                                smoke.chromium,
                                "_devtools_command",
                                side_effect=command,
                            )
                        )
                        stack.enter_context(
                            mock.patch.object(smoke.time, "monotonic", monotonic)
                        )
                        result = smoke._run_chrome(
                            "app.aikido.dev", lifecycle.executable, 501, 20
                        )

                self.assertEqual(runtime_calls, 1)
                self.assertEqual(
                    (result["outcome"], result["reason"]),
                    ("terminal_error", "readiness_timeout"),
                )

    def test_chrome_navigation_deadline_starts_after_browser_setup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = smoke.Path(temporary)
            commands = mock.Mock(
                side_effect=[
                    {},
                    self._chrome_evidence(),
                ]
            )
            with ExitStack() as stack:
                lifecycle = self._enter_chrome_lifecycle(stack, root)
                stack.enter_context(
                    mock.patch.object(
                        smoke.chromium, "_wait_for_devtools_port", return_value=9222
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        smoke.chromium,
                        "_devtools_json",
                        return_value=[
                            {
                                "type": "page",
                                "url": "about:blank",
                                "webSocketDebuggerUrl": (
                                    "ws://127.0.0.1/devtools/page/1"
                                ),
                            }
                        ],
                    )
                )
                stack.enter_context(
                    mock.patch.object(smoke.chromium, "_devtools_command", commands)
                )
                monotonic = stack.enter_context(
                    mock.patch.object(
                        smoke.time,
                        "monotonic",
                        side_effect=(1.0, 101.0, 101.1, 101.2, 101.3, 102.0),
                    )
                )
                result = smoke._run_chrome(
                    "app.aikido.dev", lifecycle.executable, 501, 20
                )

        self.assertEqual(result["outcome"], "usable")
        self.assertEqual(result["elapsed_ms"], 1_000)
        self.assertEqual(monotonic.call_count, 6)

    def test_chrome_uses_compact_evidence_for_a_large_document(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = smoke.Path(temporary)
            commands = mock.Mock(
                side_effect=[
                    {},
                    self._chrome_evidence(document_bytes=70_000),
                ]
            )
            with ExitStack() as stack:
                lifecycle = self._enter_chrome_lifecycle(stack, root)
                stack.enter_context(
                    mock.patch.object(
                        smoke.chromium, "_wait_for_devtools_port", return_value=9222
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        smoke.chromium,
                        "_devtools_json",
                        return_value=[
                            {
                                "type": "page",
                                "url": "about:blank",
                                "webSocketDebuggerUrl": (
                                    "ws://127.0.0.1/devtools/page/1"
                                ),
                            }
                        ],
                    )
                )
                stack.enter_context(
                    mock.patch.object(smoke.chromium, "_devtools_command", commands)
                )
                result = smoke._run_chrome(
                    "app.aikido.dev", lifecycle.executable, 501, 20
                )

        self.assertEqual((result["outcome"], result["reason"]), ("usable", ""))
        self.assertEqual(commands.call_count, 2)
        runtime_call = commands.call_args_list[1]
        self.assertEqual(runtime_call.args[2], "Runtime.evaluate")
        expression = runtime_call.args[3]["expression"]
        self.assertIn("document_bytes", expression)
        self.assertNotEqual(expression.strip(), "document.documentElement.outerHTML")

    def test_chrome_compact_evidence_keeps_challenges_nonpassing(self) -> None:
        evidence = self._chrome_evidence(
            document_bytes=70_000,
            challenge_detected=True,
            signals=self._signals(
                title="StarrToy",
                main_text_length=80,
            ),
        )["result"]["value"]

        self.assertEqual(
            smoke._classify_browser_evidence("xpersonatoy.com", evidence),
            ("challenge_or_auth", "challenge_or_auth"),
        )

    def test_chrome_uses_the_same_visible_captcha_boolean_as_safari(self) -> None:
        expression = smoke._browser_evidence_expression("xpersonatoy.com")

        self.assertIn("signals.visible_challenge_marker === true", expression)
        self.assertIn("visibleChallengeWidget", expression)
        self.assertNotIn('"captcha"].some((marker) => lowered.includes(marker))', expression)
        self.assertIn("document_activation_id", expression)
        self.assertIn("crypto.getRandomValues", expression)
        self.assertIn("activationState.root !== root", expression)
        self.assertIn("addEventListener('pagehide'", expression)
        self.assertNotIn("performance.timeOrigin", expression)
        self.assertNotIn("location.href", expression)

    def test_shared_compact_evidence_missing_root_is_retryable(self) -> None:
        expression = smoke._browser_evidence_expression("app.aikido.dev")

        root_read = expression.index("const root = document.documentElement;")
        root_guard = expression.index(
            "const documentSource = root ? root.outerHTML : '';"
        )
        self.assertLess(root_read, root_guard)
        self.assertNotIn("document.documentElement.outerHTML", expression)

        evidence = self._browser_evidence(
            document_bytes=0,
            document_activation_id=None,
            signals=None,
        )
        outcome, reason = smoke._classify_browser_evidence(
            "app.aikido.dev", evidence
        )
        self.assertEqual(
            smoke._settle_observation(
                outcome,
                reason,
                evidence["signals"],
                observation_started_at=1.0,
                observation_completed_at=1.1,
                document_activation_id=None,
                interactive_confirmation=(0.5, (1, 2, 3, 4)),
                confirmation_deadline=2.0,
            ),
            ("terminal_error", "document_too_short", None, False),
        )

    def test_chrome_compact_evidence_has_a_fixed_private_envelope(self) -> None:
        positive = self._chrome_evidence()["result"]["value"]
        self.assertEqual(
            set(positive),
            {
                "challenge_detected",
                "denial_detected",
                "document_activation_id",
                "document_bytes",
                "signals",
            },
        )
        self.assertEqual(
            smoke._classify_browser_evidence("app.aikido.dev", positive),
            ("usable", ""),
        )
        self.assertEqual(
            smoke._classify_browser_evidence(
                "weather.com",
                self._chrome_evidence(
                    denial_detected=True,
                    signals=None,
                )["result"]["value"],
            ),
            ("regional_access_denied", "regional_access_denied"),
        )
        self.assertEqual(
            smoke._classify_browser_evidence(
                "app.aikido.dev",
                self._chrome_evidence(document_bytes=0)["result"]["value"],
            ),
            ("terminal_error", "document_too_short"),
        )
        malformed = (
            None,
            {},
            {
                **positive,
                "document": "private raw page content",
            },
            {**positive, "document_bytes": True},
            {**positive, "document_bytes": -1},
            {**positive, "denial_detected": "false"},
            {**positive, "challenge_detected": 0},
            {**positive, "document_activation_id": None},
            {**positive, "document_activation_id": True},
            {**positive, "document_activation_id": [1, 2, 3]},
            {**positive, "document_activation_id": [1, 2, 3, -1]},
            {**positive, "document_activation_id": [1, 2, 3, 1 << 32]},
            {**positive, "document_activation_id": [1, 2, 3, "4"]},
        )
        for evidence in malformed:
            with self.subTest(evidence=evidence):
                self.assertEqual(
                    smoke._classify_browser_evidence("app.aikido.dev", evidence),
                    ("terminal_error", "document_invalid"),
                )
        self.assertEqual(
            smoke._classify_browser_evidence(
                "app.aikido.dev",
                {**positive, "signals": None},
            ),
            ("terminal_error", "readiness_signals_invalid"),
        )

    def test_chrome_retries_one_bounded_devtools_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = smoke.Path(temporary)
            commands = mock.Mock(
                side_effect=[
                    {},
                    TimeoutError("timed out"),
                    self._chrome_evidence(),
                ]
            )
            with ExitStack() as stack:
                lifecycle = self._enter_chrome_lifecycle(stack, root)
                stack.enter_context(
                    mock.patch.object(
                        smoke.chromium, "_wait_for_devtools_port", return_value=9222
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        smoke.chromium,
                        "_devtools_json",
                        return_value=[
                            {
                                "type": "page",
                                "url": "about:blank",
                                "webSocketDebuggerUrl": (
                                    "ws://127.0.0.1/devtools/page/1"
                                ),
                            }
                        ],
                    )
                )
                stack.enter_context(
                    mock.patch.object(smoke.chromium, "_devtools_command", commands)
                )
                stack.enter_context(mock.patch.object(smoke.time, "sleep"))
                result = smoke._run_chrome(
                    "app.aikido.dev", lifecycle.executable, 501, 20
                )

        self.assertEqual((result["outcome"], result["reason"]), ("usable", ""))
        self.assertLessEqual(commands.call_args_list[1].kwargs["response_timeout"], 2.0)
        self.assertLessEqual(commands.call_args_list[2].kwargs["response_timeout"], 2.0)

    def test_chrome_deadline_limited_devtools_timeout_remains_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = smoke.Path(temporary)
            commands = mock.Mock(side_effect=[{}, TimeoutError("timed out")])
            with ExitStack() as stack:
                lifecycle = self._enter_chrome_lifecycle(stack, root)
                stack.enter_context(
                    mock.patch.object(
                        smoke.chromium, "_wait_for_devtools_port", return_value=9222
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        smoke.chromium,
                        "_devtools_json",
                        return_value=[
                            {
                                "type": "page",
                                "url": "about:blank",
                                "webSocketDebuggerUrl": (
                                    "ws://127.0.0.1/devtools/page/1"
                                ),
                            }
                        ],
                    )
                )
                stack.enter_context(
                    mock.patch.object(smoke.chromium, "_devtools_command", commands)
                )
                stack.enter_context(
                    mock.patch.object(
                        smoke.time,
                        "monotonic",
                        side_effect=(
                            0.0,
                            100.0,
                            129.9,
                            129.9,
                            129.95,
                            130.0,
                            130.0,
                        ),
                    )
                )
                sleep = stack.enter_context(mock.patch.object(smoke.time, "sleep"))
                result = smoke._run_chrome(
                    "app.aikido.dev", lifecycle.executable, 501, 20
                )

        self.assertEqual(
            (result["outcome"], result["reason"]),
            ("terminal_error", "browser_observation_failed"),
        )
        self.assertAlmostEqual(
            commands.call_args_list[1].kwargs["response_timeout"], 0.1
        )
        sleep.assert_called_once_with(mock.ANY)
        self.assertAlmostEqual(sleep.call_args.args[0], 0.05)

    def test_chrome_unexpected_devtools_error_remains_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = smoke.Path(temporary)
            commands = mock.Mock(side_effect=[{}, OSError("unexpected")])
            with ExitStack() as stack:
                lifecycle = self._enter_chrome_lifecycle(stack, root)
                stack.enter_context(
                    mock.patch.object(
                        smoke.chromium, "_wait_for_devtools_port", return_value=9222
                    )
                )
                stack.enter_context(
                    mock.patch.object(
                        smoke.chromium,
                        "_devtools_json",
                        return_value=[
                            {
                                "type": "page",
                                "url": "about:blank",
                                "webSocketDebuggerUrl": (
                                    "ws://127.0.0.1/devtools/page/1"
                                ),
                            }
                        ],
                    )
                )
                stack.enter_context(
                    mock.patch.object(smoke.chromium, "_devtools_command", commands)
                )
                result = smoke._run_chrome(
                    "app.aikido.dev", lifecycle.executable, 501, 20
                )

        self.assertEqual(
            (result["outcome"], result["reason"]),
            ("terminal_error", "browser_observation_failed"),
        )

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
        self.assertEqual(result["elapsed_ms"], 0)

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
        self.assertEqual(result["elapsed_ms"], 0)

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
        self.assertEqual(result["elapsed_ms"], 0)

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
        self.assertEqual(result["elapsed_ms"], 0)

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
        self.assertEqual(result["elapsed_ms"], 0)

    def test_safari_clean_session_navigates_without_originless_cookie_delete(
        self,
    ) -> None:
        calls: list[tuple[str, str]] = []
        session_payload: dict | None = None

        def webdriver(
            _base_url: str,
            method: str,
            path: str,
            payload: dict | None = None,
            **_kwargs: object,
        ) -> dict:
            nonlocal session_payload
            calls.append((method, path))
            if method == "POST" and path == "/session":
                session_payload = payload
                return {"value": {"sessionId": "session-id"}}
            if method == "POST" and path.endswith("/execute/sync"):
                return {"value": smoke.json.dumps(self._browser_evidence())}
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
        self.assertEqual(
            session_payload,
            {
                "capabilities": {
                    "alwaysMatch": {
                        "browserName": "safari",
                        "pageLoadStrategy": "none",
                    }
                }
            },
        )

    def test_safari_navigation_rejection_remains_terminal(self) -> None:
        def webdriver(
            _base_url: str,
            method: str,
            path: str,
            _payload: dict | None = None,
            **_kwargs: object,
        ) -> dict:
            if method == "POST" and path == "/session":
                return {"value": {"sessionId": "session-id"}}
            if method == "POST" and path.endswith("/url"):
                raise smoke.lifecycle.LifecycleError("private navigation diagnostic")
            return {}

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

        self.assertEqual(
            (result["outcome"], result["reason"]),
            ("terminal_error", "navigation_rejected"),
        )

    def test_safari_later_webdriver_failure_is_not_a_decode_failure(self) -> None:
        evidence_calls = 0

        def webdriver(
            _base_url: str,
            method: str,
            path: str,
            _payload: dict | None = None,
            **_kwargs: object,
        ) -> dict:
            nonlocal evidence_calls
            if method == "POST" and path == "/session":
                return {"value": {"sessionId": "session-id"}}
            if method == "POST" and path.endswith("/execute/sync"):
                evidence_calls += 1
                if evidence_calls > 1:
                    raise smoke.lifecycle.LifecycleError("private HTTP diagnostic")
                return {"value": smoke.json.dumps(self._browser_evidence())}
            return {}

        with (
            mock.patch.object(smoke, "_wait_for_safaridriver_ready"),
            mock.patch.object(smoke.lifecycle, "_assert_no_safari_process"),
            mock.patch.object(smoke.lifecycle, "_webdriver_request", webdriver),
            mock.patch.object(
                smoke.lifecycle, "_wait_for_safari_process", return_value=4321
            ),
            mock.patch.object(smoke.lifecycle, "_stop_owned_safari_process"),
            mock.patch.object(
                smoke,
                "_classify_browser_evidence",
                return_value=("terminal_error", "readiness_timeout"),
            ),
            mock.patch.object(smoke.time, "sleep"),
        ):
            result = smoke._run_safari(
                "app.aikido.dev", "http://127.0.0.1:12345", 501
            )

        self.assertEqual(result["reason"], "browser_observation_failed")

    def test_safari_retries_only_a_transient_observation_timeout(self) -> None:
        evidence_calls = 0

        def webdriver(
            _base_url: str,
            method: str,
            path: str,
            _payload: dict | None = None,
            **_kwargs: object,
        ) -> dict:
            nonlocal evidence_calls
            if method == "POST" and path == "/session":
                return {"value": {"sessionId": "session-id"}}
            if method == "POST" and path.endswith("/execute/sync"):
                evidence_calls += 1
                if evidence_calls == 1:
                    raise self._safari_observation_timeout()
                return {"value": smoke.json.dumps(self._browser_evidence())}
            return {}

        with (
            mock.patch.object(smoke, "_wait_for_safaridriver_ready"),
            mock.patch.object(smoke.lifecycle, "_assert_no_safari_process"),
            mock.patch.object(smoke.lifecycle, "_webdriver_request", webdriver),
            mock.patch.object(
                smoke.lifecycle, "_wait_for_safari_process", return_value=4321
            ),
            mock.patch.object(smoke.lifecycle, "_stop_owned_safari_process"),
            mock.patch.object(smoke.time, "sleep") as sleep,
        ):
            result = smoke._run_safari(
                "app.aikido.dev", "http://127.0.0.1:12345", 501
            )

        self.assertEqual((result["outcome"], result["reason"]), ("usable", ""))
        self.assertEqual(evidence_calls, 2)
        sleep.assert_called_once_with(mock.ANY)
        self.assertLessEqual(sleep.call_args.args[0], 0.25)

    def test_all_fixed_sites_have_positive_semantic_fixtures(self) -> None:
        document = "<html>" + "x" * 600
        fixtures = {
            "xpersonatoy.com": self._signals(
                title="StarrToy",
                main_text_length=80,
            ),
            "app.aikido.dev": self._signals(),
            "weather.com": self._signals(
                title="Weather",
                main_text_length=100,
            ),
            "capacitorjs.com": self._signals(
                title="Capacitor",
                main_text_length=100,
            ),
        }

        self.assertEqual(set(fixtures), set(smoke.SITES))
        for host, signals in fixtures.items():
            with self.subTest(host=host, ready_state="complete"):
                self.assertEqual(
                    smoke._classify_document_evidence(
                        host,
                        document,
                        {**signals, "ready_state": "complete"},
                    ),
                    ("usable", ""),
                )
            with self.subTest(host=host, ready_state="interactive"):
                self.assertEqual(
                    smoke._classify_document_evidence(
                        host,
                        document,
                        {**signals, "ready_state": "interactive"},
                    ),
                    (
                        "terminal_error",
                        "readiness_document_pending_semantic_ready",
                    ),
                )
            with self.subTest(host=host, ready_state="loading"):
                self.assertEqual(
                    smoke._classify_document_evidence(
                        host,
                        document,
                        {**signals, "ready_state": "loading"},
                    ),
                    (
                        "terminal_error",
                        "readiness_document_pending",
                    ),
                )

    def test_readiness_blockers_are_fixed_privacy_bounded_reasons(self) -> None:
        document = "<html>private document marker" + "x" * 600
        cases = (
            ({"https": False}, "readiness_context_invalid"),
            ({"host_matches": False}, "readiness_context_invalid"),
            (
                {"ready_state": "loading"},
                "readiness_document_pending",
            ),
            (
                {"dom_content_loaded": False},
                "readiness_document_pending",
            ),
            ({"visible_body": False}, "readiness_visibility_missing"),
            ({"next_hop_protocol": ""}, "readiness_transport_missing"),
            ({"title": "private title marker"}, "readiness_title_mismatch"),
            ({"app_text_length": 0}, "readiness_content_missing"),
            ({"host_matches": None}, "readiness_signals_invalid"),
            ({"host_matches": "true"}, "readiness_signals_invalid"),
            ({"dom_content_loaded": None}, "readiness_signals_invalid"),
            ({"dom_content_loaded": "true"}, "readiness_signals_invalid"),
        )

        for changes, expected_reason in cases:
            with self.subTest(expected_reason=expected_reason):
                outcome, reason = smoke._classify_document_evidence(
                    "app.aikido.dev",
                    document,
                    self._signals(**changes),
                )
                self.assertEqual(
                    (outcome, reason),
                    ("terminal_error", expected_reason),
                )
                self.assertIn(reason, smoke.TERMINAL_BROWSER_REASONS)
                self.assertNotIn("private", reason)

    def test_script_only_captcha_does_not_override_positive_readiness(
        self,
    ) -> None:
        document = "<html><script>captcha dormant script</script>" + "x" * 600
        positive = self._signals(
            title="StarrToy",
            main_text_length=80,
        )

        self.assertEqual(
            smoke._classify_document_evidence(
                "xpersonatoy.com", document, positive
            ),
            ("usable", ""),
        )
        self.assertEqual(
            smoke._classify_document_evidence(
                "xpersonatoy.com", "<html>cf-chl-" + "x" * 600, positive
            ),
            ("challenge_or_auth", "challenge_or_auth"),
        )

    def test_visible_challenge_widget_signal_remains_nonpassing(self) -> None:
        document = "<html>" + "x" * 600
        signals = self._signals(
            title="StarrToy",
            main_text_length=80,
            ready_state="interactive",
            # The page-side expression produces this same fixed boolean for a
            # visible captcha widget; it never crosses DOM or iframe content.
            visible_challenge_marker=True,
        )

        self.assertEqual(
            smoke._classify_document_evidence(
                "xpersonatoy.com",
                document,
                signals,
            ),
            ("challenge_or_auth", "challenge_or_auth"),
        )

    def test_interactive_document_passes_only_when_semantic_content_is_ready(
        self,
    ) -> None:
        document = "<html>" + "x" * 600
        interactive_weather = self._signals(
            title="Weather",
            main_text_length=100,
            ready_state="interactive",
        )

        self.assertEqual(
            smoke._classify_document_evidence(
                "weather.com", document, interactive_weather
            ),
            ("terminal_error", "readiness_document_pending_semantic_ready"),
        )
        self.assertEqual(
            smoke._classify_document_evidence(
                "weather.com",
                document,
                {**interactive_weather, "main_text_length": 0},
            ),
            ("terminal_error", "readiness_content_missing"),
        )
        self.assertEqual(
            smoke._classify_document_evidence(
                "weather.com",
                document,
                {**interactive_weather, "visible_challenge_marker": "false"},
            ),
            ("terminal_error", "readiness_signals_invalid"),
        )
        self.assertEqual(
            smoke._classify_document_evidence(
                "weather.com",
                document,
                {**interactive_weather, "ready_state": "loaded"},
            ),
            ("terminal_error", "readiness_signals_invalid"),
        )

    def test_interactive_settle_requires_a_stable_positive_sequence(self) -> None:
        signals = self._signals(ready_state="interactive")
        first = smoke._settle_observation(
            "terminal_error",
            "readiness_document_pending_semantic_ready",
            signals,
            observation_started_at=0.9,
            observation_completed_at=1.0,
            document_activation_id=self.DOCUMENT_ACTIVATION_ID,
            interactive_confirmation=None,
            confirmation_deadline=10.0,
        )
        self.assertEqual(
            first,
            (
                "terminal_error",
                "readiness_document_pending_semantic_ready",
                self._confirmation(1.0),
                False,
            ),
        )

        challenge = smoke._settle_observation(
            "challenge_or_auth",
            "challenge_or_auth",
            signals,
            observation_started_at=1.2,
            observation_completed_at=1.25,
            document_activation_id=self.DOCUMENT_ACTIVATION_ID,
            interactive_confirmation=first[2],
            confirmation_deadline=10.0,
        )
        self.assertEqual(
            challenge,
            ("challenge_or_auth", "challenge_or_auth", None, False),
        )

        restarted = smoke._settle_observation(
            "terminal_error",
            "readiness_document_pending_semantic_ready",
            signals,
            observation_started_at=1.9,
            observation_completed_at=2.0,
            document_activation_id=self.DOCUMENT_ACTIVATION_ID,
            interactive_confirmation=challenge[2],
            confirmation_deadline=10.0,
        )
        before_settle = smoke._settle_observation(
            "terminal_error",
            "readiness_document_pending_semantic_ready",
            signals,
            observation_started_at=2.49,
            observation_completed_at=2.49,
            document_activation_id=self.DOCUMENT_ACTIVATION_ID,
            interactive_confirmation=restarted[2],
            confirmation_deadline=10.0,
        )
        settled = smoke._settle_observation(
            "terminal_error",
            "readiness_document_pending_semantic_ready",
            signals,
            observation_started_at=2.5,
            observation_completed_at=2.5,
            document_activation_id=self.DOCUMENT_ACTIVATION_ID,
            interactive_confirmation=before_settle[2],
            confirmation_deadline=10.0,
        )
        self.assertFalse(restarted[3])
        self.assertFalse(before_settle[3])
        self.assertEqual(settled, ("usable", "", self._confirmation(2.0), True))

        loading = smoke._settle_observation(
            "terminal_error",
            "readiness_document_pending",
            self._signals(ready_state="loading"),
            observation_started_at=2.6,
            observation_completed_at=2.6,
            document_activation_id=self.DOCUMENT_ACTIVATION_ID,
            interactive_confirmation=self._confirmation(2.0),
            confirmation_deadline=10.0,
        )
        self.assertEqual(
            loading,
            (
                "terminal_error",
                "readiness_document_pending",
                None,
                False,
            ),
        )

    def test_interactive_host_and_dom_failures_restart_the_full_settle(self) -> None:
        positive = self._signals(ready_state="interactive")
        confirmation: smoke.InteractiveConfirmation | None = None

        def observe(signals: dict[str, object], observed_at: float):
            nonlocal confirmation
            outcome, reason = smoke._classify_browser_evidence(
                "app.aikido.dev",
                self._browser_evidence(signals=signals),
            )
            result = smoke._settle_observation(
                outcome,
                reason,
                signals,
                observation_started_at=observed_at,
                observation_completed_at=observed_at,
                document_activation_id=self.DOCUMENT_ACTIVATION_ID,
                interactive_confirmation=confirmation,
                confirmation_deadline=10.0,
            )
            confirmation = result[2]
            return result

        self.assertEqual(
            observe(positive, 1.0)[2:],
            (self._confirmation(1.0), False),
        )
        self.assertEqual(
            observe({**positive, "host_matches": False}, 1.4),
            ("terminal_error", "readiness_context_invalid", None, False),
        )
        self.assertEqual(
            observe(positive, 2.0)[2:],
            (self._confirmation(2.0), False),
        )
        self.assertEqual(
            observe({**positive, "dom_content_loaded": False}, 2.49),
            ("terminal_error", "readiness_document_pending", None, False),
        )
        self.assertEqual(
            observe(positive, 3.0)[2:],
            (self._confirmation(3.0), False),
        )
        self.assertEqual(observe(positive, 3.49)[3], False)
        self.assertEqual(
            observe(positive, 3.5),
            ("usable", "", self._confirmation(3.0), True),
        )

    def test_document_replacement_restarts_the_full_settle(self) -> None:
        signals = self._signals(ready_state="interactive")
        reason = "readiness_document_pending_semantic_ready"
        first_id = (1, 2, 3, 4)
        replacement_id = (5, 6, 7, 8)
        first = smoke._settle_observation(
            "terminal_error",
            reason,
            signals,
            observation_started_at=0.9,
            observation_completed_at=1.0,
            document_activation_id=first_id,
            interactive_confirmation=None,
            confirmation_deadline=10.0,
        )
        replacement = smoke._settle_observation(
            "terminal_error",
            reason,
            signals,
            observation_started_at=1.6,
            observation_completed_at=1.7,
            document_activation_id=replacement_id,
            interactive_confirmation=first[2],
            confirmation_deadline=10.0,
        )
        self.assertEqual(
            replacement,
            (
                "terminal_error",
                reason,
                self._confirmation(1.7, replacement_id),
                False,
            ),
        )
        before_settle = smoke._settle_observation(
            "terminal_error",
            reason,
            signals,
            observation_started_at=2.199,
            observation_completed_at=2.199,
            document_activation_id=replacement_id,
            interactive_confirmation=replacement[2],
            confirmation_deadline=10.0,
        )
        self.assertFalse(before_settle[3])
        self.assertEqual(
            smoke._settle_observation(
                "terminal_error",
                reason,
                signals,
                observation_started_at=2.2,
                observation_completed_at=2.2,
                document_activation_id=replacement_id,
                interactive_confirmation=before_settle[2],
                confirmation_deadline=10.0,
            ),
            (
                "usable",
                "",
                self._confirmation(1.7, replacement_id),
                True,
            ),
        )

    def test_interactive_confirmation_must_finish_strictly_before_deadline(
        self,
    ) -> None:
        signals = self._signals(ready_state="interactive")
        reason = "readiness_document_pending_semantic_ready"
        for completed_at in (10.0, 10.001):
            with self.subTest(completed_at=completed_at):
                self.assertEqual(
                    smoke._settle_observation(
                        "terminal_error",
                        reason,
                        signals,
                        observation_started_at=9.9,
                        observation_completed_at=completed_at,
                        document_activation_id=self.DOCUMENT_ACTIVATION_ID,
                        interactive_confirmation=self._confirmation(9.0),
                        confirmation_deadline=10.0,
                    ),
                    ("terminal_error", reason, None, True),
                )
        self.assertEqual(
            smoke._settle_observation(
                "terminal_error",
                reason,
                signals,
                observation_started_at=9.9,
                observation_completed_at=10.0,
                document_activation_id=self.DOCUMENT_ACTIVATION_ID,
                interactive_confirmation=None,
                confirmation_deadline=10.0,
            ),
            ("terminal_error", reason, None, True),
        )
        self.assertEqual(
            smoke._settle_observation(
                "terminal_error",
                reason,
                signals,
                observation_started_at=9.999,
                observation_completed_at=9.999,
                document_activation_id=self.DOCUMENT_ACTIVATION_ID,
                interactive_confirmation=self._confirmation(9.0),
                confirmation_deadline=10.0,
            ),
            ("usable", "", self._confirmation(9.0), True),
        )

    def test_transport_latency_cannot_age_an_interactive_candidate(self) -> None:
        signals = self._signals(ready_state="interactive")
        reason = "readiness_document_pending_semantic_ready"
        first = smoke._settle_observation(
            "terminal_error",
            reason,
            signals,
            observation_started_at=0.0,
            observation_completed_at=2.0,
            document_activation_id=self.DOCUMENT_ACTIVATION_ID,
            interactive_confirmation=None,
            confirmation_deadline=10.0,
        )
        self.assertEqual(first[2:], (self._confirmation(2.0), False))
        delayed_second = smoke._settle_observation(
            "terminal_error",
            reason,
            signals,
            observation_started_at=2.25,
            observation_completed_at=4.25,
            document_activation_id=self.DOCUMENT_ACTIVATION_ID,
            interactive_confirmation=first[2],
            confirmation_deadline=10.0,
        )
        self.assertEqual(
            delayed_second[2:],
            (self._confirmation(2.0), False),
        )
        self.assertEqual(
            smoke._settle_observation(
                "terminal_error",
                reason,
                signals,
                observation_started_at=4.5,
                observation_completed_at=6.5,
                document_activation_id=self.DOCUMENT_ACTIVATION_ID,
                interactive_confirmation=delayed_second[2],
                confirmation_deadline=10.0,
            ),
            ("usable", "", self._confirmation(2.0), True),
        )

        for started_at, expected_stop in ((2.499, False), (2.5, True)):
            with self.subTest(started_at=started_at):
                result = smoke._settle_observation(
                    "terminal_error",
                    reason,
                    signals,
                    observation_started_at=started_at,
                    observation_completed_at=2.6,
                    document_activation_id=self.DOCUMENT_ACTIVATION_ID,
                    interactive_confirmation=self._confirmation(2.0),
                    confirmation_deadline=10.0,
                )
                self.assertEqual(result[3], expected_stop)
        self.assertEqual(
            smoke._settle_observation(
                "terminal_error",
                reason,
                signals,
                observation_started_at=5.0,
                observation_completed_at=4.9,
                document_activation_id=self.DOCUMENT_ACTIVATION_ID,
                interactive_confirmation=self._confirmation(2.0),
                confirmation_deadline=10.0,
            ),
            ("terminal_error", "browser_observation_failed", None, True),
        )

    def test_safari_keeps_polling_until_a_challenge_resolves(self) -> None:
        evidence_calls = 0
        evidence = iter(
            (
                self._browser_evidence(
                    challenge_detected=True,
                    signals=self._signals(
                        title="Just a moment",
                        main_text_length=0,
                        body_text_length=0,
                    ),
                ),
                self._browser_evidence(
                    signals=self._signals(
                        title="StarrToy",
                        main_text_length=80,
                    ),
                ),
            )
        )

        def webdriver(
            _base_url: str,
            method: str,
            path: str,
            _payload: dict | None = None,
            **_kwargs: object,
        ) -> dict:
            nonlocal evidence_calls
            if method == "POST" and path == "/session":
                return {"value": {"sessionId": "session-id"}}
            if method == "POST" and path.endswith("/execute/sync"):
                evidence_calls += 1
                return {"value": smoke.json.dumps(next(evidence))}
            return {}

        with (
            mock.patch.object(smoke, "_wait_for_safaridriver_ready"),
            mock.patch.object(smoke.lifecycle, "_assert_no_safari_process"),
            mock.patch.object(smoke.lifecycle, "_webdriver_request", webdriver),
            mock.patch.object(
                smoke.lifecycle, "_wait_for_safari_process", return_value=4321
            ),
            mock.patch.object(smoke.lifecycle, "_stop_owned_safari_process"),
            mock.patch.object(smoke.time, "sleep") as sleep,
        ):
            result = smoke._run_safari(
                "xpersonatoy.com", "http://127.0.0.1:12345", 501
            )

        self.assertEqual(result["outcome"], "usable")
        self.assertEqual(result["reason"], "")
        self.assertEqual(evidence_calls, 2)
        sleep.assert_called_once()

    def test_safari_retries_rootless_compact_evidence(self) -> None:
        evidence_calls = 0
        rootless = self._browser_evidence(
            document_bytes=0,
            signals=self._signals(
                body_text_length=0,
                dom_content_loaded=False,
                main_text_length=0,
                ready_state="loading",
                title="",
                visible_body=False,
            ),
        )
        self.assertEqual(
            smoke._classify_browser_evidence("app.aikido.dev", rootless),
            ("terminal_error", "document_too_short"),
        )
        evidence = iter((rootless, self._browser_evidence()))

        def webdriver(
            _base_url: str,
            method: str,
            path: str,
            _payload: dict | None = None,
            **_kwargs: object,
        ) -> dict:
            nonlocal evidence_calls
            if method == "POST" and path == "/session":
                return {"value": {"sessionId": "session-id"}}
            if method == "POST" and path.endswith("/execute/sync"):
                evidence_calls += 1
                return {"value": smoke.json.dumps(next(evidence))}
            return {}

        with (
            mock.patch.object(smoke, "_wait_for_safaridriver_ready"),
            mock.patch.object(smoke.lifecycle, "_assert_no_safari_process"),
            mock.patch.object(smoke.lifecycle, "_webdriver_request", webdriver),
            mock.patch.object(
                smoke.lifecycle, "_wait_for_safari_process", return_value=4321
            ),
            mock.patch.object(smoke.lifecycle, "_stop_owned_safari_process"),
            mock.patch.object(smoke.time, "sleep") as sleep,
        ):
            result = smoke._run_safari(
                "app.aikido.dev", "http://127.0.0.1:12345", 501
            )

        self.assertEqual((result["outcome"], result["reason"]), ("usable", ""))
        self.assertEqual(evidence_calls, 2)
        sleep.assert_called_once()

    def test_safari_late_challenge_resets_interactive_settle(self) -> None:
        evidence_calls = 0
        clock = 0.0
        signals = self._signals(
            title="StarrToy",
            main_text_length=80,
            ready_state="interactive",
        )

        def monotonic() -> float:
            nonlocal clock
            clock += 0.1
            return clock

        def webdriver(
            _base_url: str,
            method: str,
            path: str,
            _payload: dict | None = None,
            **_kwargs: object,
        ) -> dict:
            nonlocal evidence_calls
            if method == "POST" and path == "/session":
                return {"value": {"sessionId": "session-id"}}
            if method == "POST" and path.endswith("/execute/sync"):
                evidence_calls += 1
                return {
                    "value": smoke.json.dumps(
                        self._browser_evidence(
                            challenge_detected=evidence_calls == 2,
                            signals=signals,
                        )
                    )
                }
            return {}

        with (
            mock.patch.object(smoke, "_wait_for_safaridriver_ready"),
            mock.patch.object(smoke.lifecycle, "_assert_no_safari_process"),
            mock.patch.object(smoke.lifecycle, "_webdriver_request", webdriver),
            mock.patch.object(
                smoke.lifecycle, "_wait_for_safari_process", return_value=4321
            ),
            mock.patch.object(smoke.lifecycle, "_stop_owned_safari_process"),
            mock.patch.object(smoke.time, "monotonic", monotonic),
            mock.patch.object(smoke.time, "sleep"),
        ):
            result = smoke._run_safari(
                "xpersonatoy.com", "http://127.0.0.1:12345", 501
            )

        self.assertEqual((result["outcome"], result["reason"]), ("usable", ""))
        self.assertGreaterEqual(evidence_calls, 4)

    def test_safari_response_latency_cannot_satisfy_interactive_settle(
        self,
    ) -> None:
        clock = 0.0
        evidence_calls = 0
        interactive = self._browser_evidence(
            signals=self._signals(ready_state="interactive")
        )
        complete = self._browser_evidence()

        def monotonic() -> float:
            return clock

        def sleep(_seconds: float) -> None:
            nonlocal clock
            clock = 2.25 if evidence_calls == 1 else 4.5

        def webdriver(
            _base_url: str,
            method: str,
            path: str,
            _payload: dict | None = None,
            **_kwargs: object,
        ) -> dict:
            nonlocal clock, evidence_calls
            if method == "POST" and path == "/session":
                return {"value": {"sessionId": "session-id"}}
            if method == "POST" and path.endswith("/execute/sync"):
                evidence_calls += 1
                if evidence_calls == 1:
                    clock = 2.0
                    evidence = interactive
                elif evidence_calls == 2:
                    clock = 4.25
                    evidence = interactive
                else:
                    clock = 4.6
                    evidence = complete
                return {"value": smoke.json.dumps(evidence)}
            return {}

        with (
            mock.patch.dict(
                smoke.SITES["app.aikido.dev"], {"deadline_ms": 10_000}
            ),
            mock.patch.object(smoke, "_wait_for_safaridriver_ready"),
            mock.patch.object(smoke.lifecycle, "_assert_no_safari_process"),
            mock.patch.object(smoke.lifecycle, "_webdriver_request", webdriver),
            mock.patch.object(
                smoke.lifecycle, "_wait_for_safari_process", return_value=4321
            ),
            mock.patch.object(smoke.lifecycle, "_stop_owned_safari_process"),
            mock.patch.object(smoke.time, "monotonic", monotonic),
            mock.patch.object(smoke.time, "sleep", side_effect=sleep),
        ):
            result = smoke._run_safari(
                "app.aikido.dev", "http://127.0.0.1:12345", 501
            )

        self.assertEqual(evidence_calls, 3)
        self.assertEqual((result["outcome"], result["reason"]), ("usable", ""))

    def test_safari_document_replacement_restarts_interactive_settle(
        self,
    ) -> None:
        clock = 0.0
        evidence_calls = 0
        first_id = [1, 2, 3, 4]
        replacement_id = [5, 6, 7, 8]
        signals = self._signals(ready_state="interactive")

        def monotonic() -> float:
            return clock

        def sleep(_seconds: float) -> None:
            nonlocal clock
            clock = 0.7 if evidence_calls == 1 else 1.3

        def webdriver(
            _base_url: str,
            method: str,
            path: str,
            _payload: dict | None = None,
            **_kwargs: object,
        ) -> dict:
            nonlocal clock, evidence_calls
            if method == "POST" and path == "/session":
                return {"value": {"sessionId": "session-id"}}
            if method == "POST" and path.endswith("/execute/sync"):
                evidence_calls += 1
                clock = {1: 0.1, 2: 0.8, 3: 1.31}[evidence_calls]
                return {
                    "value": smoke.json.dumps(
                        self._browser_evidence(
                            document_activation_id=(
                                first_id
                                if evidence_calls == 1
                                else replacement_id
                            ),
                            signals=signals,
                        )
                    )
                }
            return {}

        with (
            mock.patch.dict(
                smoke.SITES["app.aikido.dev"], {"deadline_ms": 10_000}
            ),
            mock.patch.object(smoke, "_wait_for_safaridriver_ready"),
            mock.patch.object(smoke.lifecycle, "_assert_no_safari_process"),
            mock.patch.object(smoke.lifecycle, "_webdriver_request", webdriver),
            mock.patch.object(
                smoke.lifecycle, "_wait_for_safari_process", return_value=4321
            ),
            mock.patch.object(smoke.lifecycle, "_stop_owned_safari_process"),
            mock.patch.object(smoke.time, "monotonic", monotonic),
            mock.patch.object(smoke.time, "sleep", side_effect=sleep),
        ):
            result = smoke._run_safari(
                "app.aikido.dev", "http://127.0.0.1:12345", 501
            )

        self.assertEqual(evidence_calls, 3)
        self.assertEqual((result["outcome"], result["reason"]), ("usable", ""))

    def test_safari_rejects_interactive_confirmation_at_or_after_deadline(
        self,
    ) -> None:
        for final_observation in (0.5, 0.501):
            with self.subTest(final_observation=final_observation):
                clock = 0.0
                evidence_calls = 0
                evidence = self._browser_evidence(
                    signals=self._signals(ready_state="interactive")
                )

                def monotonic() -> float:
                    return clock

                def sleep(_seconds: float) -> None:
                    nonlocal clock
                    clock = 0.49

                def webdriver(
                    _base_url: str,
                    method: str,
                    path: str,
                    _payload: dict | None = None,
                    **_kwargs: object,
                ) -> dict:
                    nonlocal clock, evidence_calls
                    if method == "POST" and path == "/session":
                        return {"value": {"sessionId": "session-id"}}
                    if method == "POST" and path.endswith("/execute/sync"):
                        evidence_calls += 1
                        if evidence_calls == 2:
                            clock = final_observation
                        return {"value": smoke.json.dumps(evidence)}
                    return {}

                with (
                    mock.patch.dict(
                        smoke.SITES["app.aikido.dev"], {"deadline_ms": 500}
                    ),
                    mock.patch.object(smoke, "_wait_for_safaridriver_ready"),
                    mock.patch.object(smoke.lifecycle, "_assert_no_safari_process"),
                    mock.patch.object(
                        smoke.lifecycle, "_webdriver_request", webdriver
                    ),
                    mock.patch.object(
                        smoke.lifecycle,
                        "_wait_for_safari_process",
                        return_value=4321,
                    ),
                    mock.patch.object(
                        smoke.lifecycle, "_stop_owned_safari_process"
                    ),
                    mock.patch.object(
                        smoke.time, "monotonic", side_effect=monotonic
                    ),
                    mock.patch.object(smoke.time, "sleep", side_effect=sleep),
                ):
                    result = smoke._run_safari(
                        "app.aikido.dev", "http://127.0.0.1:12345", 501
                    )

                self.assertEqual(evidence_calls, 2)
                self.assertEqual(
                    (result["outcome"], result["reason"]),
                    (
                        "terminal_error",
                        "readiness_document_pending_semantic_ready",
                    ),
                )

    def test_safari_rejects_complete_response_at_or_after_deadline(self) -> None:
        for final_observation in (0.5, 0.501):
            with self.subTest(final_observation=final_observation):
                clock = 0.0
                evidence_calls = 0

                def monotonic() -> float:
                    return clock

                def webdriver(
                    _base_url: str,
                    method: str,
                    path: str,
                    _payload: dict | None = None,
                    **_kwargs: object,
                ) -> dict:
                    nonlocal clock, evidence_calls
                    if method == "POST" and path == "/session":
                        return {"value": {"sessionId": "session-id"}}
                    if method == "POST" and path.endswith("/execute/sync"):
                        evidence_calls += 1
                        clock = final_observation
                        return {
                            "value": smoke.json.dumps(self._browser_evidence())
                        }
                    return {}

                with (
                    mock.patch.dict(
                        smoke.SITES["app.aikido.dev"], {"deadline_ms": 500}
                    ),
                    mock.patch.object(smoke, "_wait_for_safaridriver_ready"),
                    mock.patch.object(smoke.lifecycle, "_assert_no_safari_process"),
                    mock.patch.object(
                        smoke.lifecycle, "_webdriver_request", webdriver
                    ),
                    mock.patch.object(
                        smoke.lifecycle,
                        "_wait_for_safari_process",
                        return_value=4321,
                    ),
                    mock.patch.object(
                        smoke.lifecycle, "_stop_owned_safari_process"
                    ),
                    mock.patch.object(smoke.time, "monotonic", monotonic),
                ):
                    result = smoke._run_safari(
                        "app.aikido.dev", "http://127.0.0.1:12345", 501
                    )

                self.assertEqual(evidence_calls, 1)
                self.assertEqual(
                    (result["outcome"], result["reason"]),
                    ("terminal_error", "readiness_timeout"),
                )

    def test_safari_navigation_deadline_starts_after_session_setup(self) -> None:
        events: list[tuple[str, object]] = []
        clock_values = iter((1.0, 101.0, 101.1, 101.2, 101.3, 102.0))

        def monotonic() -> float:
            value = next(clock_values)
            events.append(("clock", value))
            return value

        def webdriver(
            _base_url: str,
            method: str,
            path: str,
            _payload: dict | None = None,
            **_kwargs: object,
        ) -> dict:
            events.append((method, path))
            if method == "POST" and path == "/session":
                return {"value": {"sessionId": "session-id"}}
            if method == "POST" and path.endswith("/execute/sync"):
                return {"value": smoke.json.dumps(self._browser_evidence())}
            return {}

        with (
            mock.patch.object(smoke, "_wait_for_safaridriver_ready"),
            mock.patch.object(smoke.lifecycle, "_assert_no_safari_process"),
            mock.patch.object(smoke.lifecycle, "_webdriver_request", webdriver),
            mock.patch.object(
                smoke.lifecycle, "_wait_for_safari_process", return_value=4321
            ),
            mock.patch.object(smoke.lifecycle, "_stop_owned_safari_process"),
            mock.patch.object(smoke.time, "monotonic", side_effect=monotonic),
        ):
            result = smoke._run_safari(
                "app.aikido.dev", "http://127.0.0.1:12345", 501
            )

        navigation = ("POST", "/session/session-id/url")
        navigation_index = events.index(navigation)
        self.assertEqual(events[navigation_index - 1], ("clock", 101.0))
        self.assertEqual(result["outcome"], "usable")
        self.assertEqual(result["elapsed_ms"], 1_000)

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

    def test_safari_evidence_requires_a_json_object_string(self) -> None:
        evidence = self._browser_evidence()
        self.assertEqual(
            smoke._decode_safari_evidence(smoke.json.dumps(evidence)),
            evidence,
        )
        for invalid in (None, evidence, "not-json", "[]"):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(
                    smoke.LiveSiteError,
                    "^Safari returned invalid compact evidence$",
                ):
                    smoke._decode_safari_evidence(invalid)

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

    def test_control_route_dormant_captcha_text_is_not_a_challenge(self) -> None:
        response = mock.Mock(
            returncode=0,
            stdout=(
                b"<script>captcha dormant third-party script</script>"
                + (b"x" * 600)
                + b"\n__SLIPSTREAM_STATUS__:200"
            ),
        )
        with mock.patch.object(smoke.subprocess, "run", return_value=response):
            self.assertEqual(smoke._control_route("xpersonatoy.com", "direct"), "usable")

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
