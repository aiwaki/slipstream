import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import provision_packaged_update_smoke as provision


class ProvisionTests(unittest.TestCase):
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
