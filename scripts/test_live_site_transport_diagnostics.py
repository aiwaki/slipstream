from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import unittest

import live_site_release_smoke as smoke


class LiveSiteTransportDiagnosticsTests(unittest.TestCase):
    def record(self, diagnostics: object, stage: str = "observed") -> dict:
        observation = {}
        smoke._record_safari_observation(observation, stage, 500, {
            "document_bytes": 142202,
            "signals": {"transport_diagnostics": diagnostics},
        })
        return observation["observations"]["final"]["transport_diagnostics"]

    def test_dom_bytes_and_received_body_sizes_are_independent(self):
        snapshot = self.record({
            "navigation": {"encoded_bytes": 73640, "decoded_bytes": 838287,
                           "response_end_ms": 2746},
            "node_count": 50, "resource_count": 57,
            "stylesheets_observed": 7, "stylesheets_attached": 6,
            "last_scanned_node": {"ordinal": 49, "kind": "script",
                                  "external": False, "in_body": True},
            "missing_nodes": [{"ordinal": 44, "kind": "stylesheet",
                               "sheet_attached": False, "timing": None}],
        })
        self.assertEqual(snapshot["navigation"]["decoded_bytes"], 838287)
        self.assertEqual(snapshot["stylesheets_attached"], 6)
        self.assertEqual(snapshot["last_scanned_node"]["kind"], "script")
        self.assertFalse(snapshot["missing_nodes"][0]["sheet_attached"])
        self.assertIsNone(snapshot["missing_nodes"][0]["timing"])

    def test_malformed_fields_and_private_strings_are_not_retained(self):
        row = {"ordinal": "private", "kind": "private", "in_body": 1,
               "external": "private", "same_origin": [], "sheet_attached": {},
               "timing": {"encoded_bytes": True, "decoded_bytes": -1,
                          "response_end_ms": float("inf"), "url": "private"},
               "url": "private", "error": "private"}
        diagnostic = {"navigation": row["timing"], "resource_count": True,
                      "node_count": "private", "nodes_truncated": 1,
                      "last_scanned_node": row, "missing_nodes": [row, None, "private"],
                      "private": "private"}
        snapshot = self.record(diagnostic)
        self.assertNotIn("private", json.dumps(snapshot))
        self.assertIsNone(snapshot["resource_count"])
        self.assertIsNone(snapshot["nodes_truncated"])
        self.assertIsNone(snapshot["last_scanned_node"]["kind"])
        self.assertIsNone(snapshot["last_scanned_node"]["in_body"])
        self.assertTrue(all(v is None for v in snapshot["navigation"].values()))
        self.assertEqual(len(snapshot["missing_nodes"]), 1)

    def test_payload_and_numeric_bounds_preserve_unknown_vs_zero(self):
        snapshot = self.record({
            "navigation": {"decoded_bytes": 10**30, "encoded_bytes": 0,
                           "response_end_ms": 10**30, "transfer_bytes": 1.5},
            "missing_nodes": [{"ordinal": n, "kind": "stylesheet"} for n in range(100)],
            "missing_nodes_truncated": False,
        })
        self.assertEqual(snapshot["navigation"]["decoded_bytes"], 16 * 1024 * 1024)
        self.assertEqual(snapshot["navigation"]["response_end_ms"], 60_000)
        self.assertEqual(snapshot["navigation"]["encoded_bytes"], 0)
        self.assertIsNone(snapshot["navigation"]["transfer_bytes"])
        self.assertEqual(len(snapshot["missing_nodes"]), 16)
        self.assertTrue(snapshot["missing_nodes_truncated"])
        for value in (None, [], "private", 1):
            self.assertIsNone(self.record(value))
        for value in (-1, 128, True, 1.5, "private"):
            self.assertIsNone(self.record({"last_scanned_node": {"ordinal": value}})["last_scanned_node"]["ordinal"])

    def test_timeout_keeps_last_completed_observation_separate(self):
        observation = {}
        smoke._record_safari_observation(observation, "observed", 100, {
            "document_bytes": 142202,
            "signals": {"transport_diagnostics": {"navigation": {"decoded_bytes": 838287}}},
        })
        smoke._record_safari_observation(observation, "pending", 200)
        smoke._record_safari_observation(observation, "timeout", 2000)
        progress = observation["observations"]
        self.assertEqual(progress["final"]["stage"], "timeout")
        self.assertIsNone(progress["final"]["transport_diagnostics"])
        self.assertEqual(progress["last_observed"]["elapsed_ms"], 100)
        self.assertEqual(progress["last_observed"]["transport_diagnostics"]["navigation"]["decoded_bytes"], 838287)

    def test_diagnostics_cannot_promote_or_demote_readiness(self):
        # Use the existing boundary helper so the diagnostic is exercised with
        # both a blocked document and one whose ordinary readiness is usable.
        from test_live_site_release_smoke import LiveSiteReleaseSmokeTests
        factory = LiveSiteReleaseSmokeTests()
        for signals in (factory._signals(), factory._signals(
            ready_state="loading", dom_content_loaded=False, body_text_length=15,
            main_text_length=0, app_text_length=0, visible_app=False,
        )):
            evidence = factory._browser_evidence(signals=signals)
            before = smoke._classify_browser_evidence("xpersonatoy.com", evidence)
            for diagnostic in (None, "private", {"navigation": {"decoded_bytes": 838287}}):
                signals["transport_diagnostics"] = diagnostic
                self.assertEqual(smoke._classify_browser_evidence("xpersonatoy.com", evidence), before)

    def test_javascript_collection_is_bounded_read_only_and_exception_isolated(self):
        node = shutil.which("node")
        self.assertIsNotNone(node, "Node.js is required for browser-observer contract tests")
        result = subprocess.run(
            [node, str(Path(__file__).with_name("live_site_transport_diagnostics_fixtures.mjs"))],
            input=json.dumps({"expression": smoke.TRANSPORT_DIAGNOSTICS_EXPRESSION}),
            text=True, capture_output=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["cases_passed"], 8)


if __name__ == "__main__":
    unittest.main()
