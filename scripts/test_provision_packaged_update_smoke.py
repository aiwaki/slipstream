import os
import json
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import provision_packaged_update_smoke as provision


class ProvisionTests(unittest.TestCase):
    def test_fault_requires_complete_three_path_baseline(self):
        good = {"status": "pass", "results": [
            {"path": name, "pass": True, "attempts": [{"url": url, "pass": True} for url in provision.URLS]}
            for name in ("proxy_ipv4", "proxy_ipv6", "transparent")
        ]}
        provision.require_traffic_baseline(subprocess.CompletedProcess([], 0, json.dumps(good), ""))
        for code, report in ((1, good), (0, {**good, "results": good["results"][:2]}),
                             (0, {**good, "status": "fail"}),
                             (0, {**good, "results": [*good["results"][:2],
                                  {"path": "transparent", "pass": False}]})):
            with self.subTest(code=code, report=report), self.assertRaises(RuntimeError):
                provision.require_traffic_baseline(
                    subprocess.CompletedProcess([], code, json.dumps(report), ""))

    def test_baseline_cannot_hide_an_already_failed_alternative(self):
        for attempts in ([], [{"url": provision.URLS[0], "pass": True}] * 2,
                         [{"url": u, "pass": i == 0} for i, u in enumerate(provision.URLS)]):
            report = {"status": "pass", "results": [
                {"path": p, "pass": True, "attempts": attempts}
                for p in ("proxy_ipv4", "proxy_ipv6", "transparent")]}
            with self.assertRaisesRegex(RuntimeError, "both independent"):
                provision.require_traffic_baseline(subprocess.CompletedProcess([], 0, json.dumps(report), ""))

    def test_partial_fault_startup_is_cleaned_in_reverse_order(self):
        from unittest.mock import Mock
        first, second = Mock(), Mock()
        second.start.side_effect = RuntimeError("second fixture start failed")
        events = []
        first.stop.side_effect = lambda: events.append("first")
        second.stop.side_effect = lambda: events.append("second")
        resolvers = []
        with patch.object(provision.lifecycle, 'StalledSystemResolver', side_effect=[first, second]) as factory:
            with self.assertRaisesRegex(RuntimeError, 'second fixture'):
                provision.start_payload_faults('traffic_failure', resolvers)
            self.assertEqual([c.kwargs['domain'] for c in factory.call_args_list],
                             ['media.discordapp.net', 'cdn.discordapp.com'])
        self.assertEqual(provision.stop_payload_faults(resolvers), [])
        self.assertEqual(events, ['second', 'first'])

    def test_one_host_fault_leaves_alternative_untouched(self):
        with patch.object(provision.lifecycle, 'StalledSystemResolver') as factory:
            resolvers = []
            provision.start_payload_faults('primary_unavailable', resolvers)
            factory.assert_called_once_with(domain='media.discordapp.net')
            factory.return_value.start.assert_called_once()
            provision.stop_payload_faults(resolvers)
            factory.return_value.stop.assert_called_once()

    def test_fault_cleanup_continues_after_one_restore_error(self):
        from unittest.mock import Mock
        first, second = Mock(), Mock()
        second.stop.side_effect = RuntimeError('restore failure')
        self.assertEqual(provision.stop_payload_faults([first, second]), ['restore failure'])
        first.stop.assert_called_once()

    def test_cleanup_never_signals_reused_pid(self):
        root = Path("/private/owned-case")
        identity = (os.getuid(), "old birth", str(root / "Slipstream.app/Contents/MacOS/slipstream"))
        changed = (os.getuid(), "new birth", identity[2])
        with patch.object(provision.subprocess, "run", return_value=subprocess.CompletedProcess(
            [], 0, "123\n", ""
        )), patch.object(provision.transaction, "snapshot", side_effect=[identity, changed, changed, changed]), \
                patch.object(provision.os, "kill") as kill:
            provision.stop_owned_trays(root, os.getuid())
            kill.assert_not_called()

    def test_cleanup_ignores_unrelated_trays(self):
        with patch.object(provision.subprocess, "run", return_value=subprocess.CompletedProcess(
            [], 0, "123\n", ""
        )), patch.object(provision.transaction, "snapshot", return_value=(
            os.getuid(), "birth", "/Applications/Slipstream.app/Contents/MacOS/slipstream"
        )), patch.object(provision.os, "kill") as kill:
            provision.stop_owned_trays(Path("/private/owned-case"), os.getuid())
            kill.assert_not_called()

    def test_cleanup_rejects_external_watchdog(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            root = home / "owned-case"
            root.mkdir()
            helper = home / "unrelated-helper"
            helper.write_text("unrelated")
            agent = home / "Library/LaunchAgents/dev.slipstream.update-watchdog.plist"
            agent.parent.mkdir(parents=True)
            agent.write_bytes(plistlib.dumps({"ProgramArguments": [str(helper)]}))
            with patch.object(provision.subprocess, "run") as run:
                with self.assertRaisesRegex(RuntimeError, "outside qualification"):
                    provision.cleanup_watchdog(root, home, os.getuid())
                run.assert_not_called()
                self.assertTrue(agent.exists())


if __name__ == "__main__":
    unittest.main()
