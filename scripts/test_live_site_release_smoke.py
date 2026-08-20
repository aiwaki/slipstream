from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest import mock

import live_site_release_smoke as smoke


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
        document = "<html><title>Aikido Security</title><div id='app'></div>" + "x" * 600
        skeleton = self._signals(app_text_length=0, visible_app=False)
        self.assertEqual(
            smoke._classify_document("app.aikido.dev", document, skeleton),
            "terminal_error",
        )
        self.assertEqual(
            smoke._classify_document(
                "app.aikido.dev", document, self._signals()
            ),
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

    def test_successful_sites_cannot_hide_cleanup_failure(self) -> None:
        browser_result = {
            "browser": "safari",
            "deadline_ms": 20_000,
            "elapsed_ms": 100,
            "outcome": "usable",
            "route": "slipstream_selected",
        }
        target = SimpleNamespace(install_command=("install",))
        system = mock.Mock()
        with (
            mock.patch.object(smoke, "_require_protected_ci"),
            mock.patch.object(smoke.pf, "PfctlRunner", return_value=mock.Mock()),
            mock.patch.object(smoke.lifecycle, "_preflight", return_value=("before", 501, 20)),
            mock.patch.object(smoke.lifecycle, "packaged_app_target", return_value=target),
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
            report, status = smoke.run_gate(
                mock.Mock(), mock.Mock(), "http://127.0.0.1:1"
            )

        self.assertEqual(status, 1)
        self.assertEqual(report["result"], "failed")


if __name__ == "__main__":
    unittest.main()
