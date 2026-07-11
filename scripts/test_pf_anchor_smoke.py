from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout

import pf_anchor_smoke


class PfAnchorSmokeTests(unittest.TestCase):
    def test_redirect_rules_never_target_https(self) -> None:
        rules = pf_anchor_smoke.build_redirect_rules(
            target_port=18443,
            proxy_port=19443,
        )

        self.assertIn("port 18443", rules)
        self.assertIn("port 19443", rules)
        self.assertNotIn("port 443 ", rules)

    def test_redirect_rules_reject_tcp_443(self) -> None:
        with self.assertRaisesRegex(pf_anchor_smoke.SmokeError, "never intercept"):
            pf_anchor_smoke.build_redirect_rules(target_port=443, proxy_port=19443)

    def test_pfctl_guard_accepts_only_scoped_mutations(self) -> None:
        for command in (
            ("/sbin/pfctl", "-s", "info"),
            ("pfctl", "-sn"),
            ("pfctl", "-sr"),
            ("pfctl", "-E"),
            ("pfctl", "-X", "1234"),
            ("pfctl", "-a", pf_anchor_smoke.SLIPSTREAM_ANCHOR, "-f", "/tmp/rules"),
            ("pfctl", "-a", pf_anchor_smoke.SENTINEL_ANCHOR, "-F", "rules"),
            ("pfctl", "-a", pf_anchor_smoke.SENTINEL_ANCHOR, "-F", "nat"),
        ):
            pf_anchor_smoke.validate_pfctl_args(command)

    def test_pfctl_guard_rejects_global_or_external_mutations(self) -> None:
        commands = (
            ("pfctl", "-d"),
            ("pfctl", "-F", "states"),
            ("pfctl", "-a", pf_anchor_smoke.SLIPSTREAM_ANCHOR, "-F", "states"),
            ("pfctl", "-a", pf_anchor_smoke.SLIPSTREAM_ANCHOR, "-F", "all"),
            ("pfctl", "-a", pf_anchor_smoke.SLIPSTREAM_ANCHOR, "-F", "rules", "-e"),
            ("pfctl", "-f", "/etc/pf.conf"),
            ("pfctl", "-a", "com.vendor/external", "-F", "all"),
            ("rm", "-rf", "/"),
        )
        for command in commands:
            with self.subTest(command=command):
                with self.assertRaises(pf_anchor_smoke.SmokeError):
                    pf_anchor_smoke.validate_pfctl_args(command)

    def test_audit_log_redacts_pf_enable_token(self) -> None:
        command = ("/sbin/pfctl", "-X", "sensitive-token")

        rendered = pf_anchor_smoke.PfctlRunner.display(command)

        self.assertNotIn("sensitive-token", rendered)
        self.assertIn("<redacted-token>", rendered)

    def test_snapshot_comparison_detects_global_changes(self) -> None:
        before = pf_anchor_smoke.PfSnapshot(False, "nat", "filter")
        after = pf_anchor_smoke.PfSnapshot(False, "changed", "filter")

        with self.assertRaisesRegex(pf_anchor_smoke.SmokeError, "global NAT"):
            pf_anchor_smoke._assert_same_snapshot(before, after)

    def test_dry_run_is_non_privileged_and_explicit(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            result = pf_anchor_smoke.main(["--dry-run"])

        self.assertEqual(result, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["result"], "dry-run")
        self.assertFalse(report["intercepts_tcp_443"])
        self.assertIn("pfctl -d", report["forbidden_operations"])


if __name__ == "__main__":
    unittest.main()
