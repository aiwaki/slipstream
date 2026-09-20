import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import packaged_update_transaction_smoke as gate


class TransactionGateTests(unittest.TestCase):
    def test_workstation_refused_before_any_process_call(self):
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}), patch.object(
            gate.subprocess, "run"
        ) as run:
            with self.assertRaisesRegex(RuntimeError, "refusing"):
                gate.guard()
            run.assert_not_called()

    def test_fault_signal_requires_exact_birth_uid_and_command(self):
        journal = {"successor_pid": 123, "successor_started": "Sun Sep 20 12:00:00 2026"}
        exe = Path("/private/test/Slipstream.app/Contents/MacOS/slipstream")
        expected = (os.getuid(), journal["successor_started"], str(exe))
        for wrong in (None, (0, expected[1], expected[2]),
                      (expected[0], "different birth", expected[2]),
                      (expected[0], expected[1], "/unrelated/program")):
            with self.subTest(wrong=wrong), patch.object(gate, "snapshot", return_value=wrong), \
                    patch.object(gate.os, "kill") as kill:
                with self.assertRaisesRegex(RuntimeError, "identity changed"):
                    gate.stop_successor(journal, exe)
                kill.assert_not_called()

    def observe(self, case, *, failure_nonce="a", changed_process=False):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app-update-transaction-v1.json"
            exe = Path(tmp) / "Slipstream.app/Contents/MacOS/slipstream"
            journal = {"phase": "successor_launched", "nonce": "a",
                       "successor_pid": 123, "successor_started": "Sun Sep 20 12:00:00 2026"}
            path.write_text(json.dumps(journal))

            def terminal(_):
                path.unlink()
                if case == "rollback":
                    (Path(tmp) / "app-update-transaction-failed-a.json").write_text(
                        json.dumps({"phase": "old_relaunched", "nonce": failure_nonce}))

            identity = (os.getuid(), journal["successor_started"], str(exe))
            with patch.object(gate.time, "sleep", side_effect=terminal), \
                    patch.object(gate, "stop_successor") as stop, \
                    patch.object(gate, "snapshot", return_value=None if changed_process else identity):
                result = gate.observe(path, exe, case)
                self.assertEqual(stop.call_count, int(case == "rollback"))
                return result

    def test_accept_requires_surviving_exact_successor(self):
        self.assertTrue(self.observe("accept")["transaction_removed"])
        with self.assertRaisesRegex(RuntimeError, "changed identity"):
            self.observe("accept", changed_process=True)

    def test_rollback_requires_fault_and_matching_terminal_record(self):
        self.assertTrue(self.observe("rollback")["stopped"])
        with self.assertRaisesRegex(RuntimeError, "exact transaction"):
            self.observe("rollback", failure_nonce="old-unrelated-transaction")

    def test_traffic_fault_requires_live_successor_and_advancing_heartbeat(self):
        for duration, advances, alive, accepted in (
            (60, True, True, True), (20, True, True, False),
            (60, False, True, False), (60, True, False, False),
        ):
            with self.subTest(duration=duration, advances=advances, alive=alive), \
                    tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "app-update-transaction-v1.json"
                exe = Path(tmp) / "Slipstream.app/Contents/MacOS/slipstream"
                journal = {"phase": "successor_launched", "nonce": "a",
                           "successor_pid": 123, "successor_started": "birth",
                           "successor_deadline_unix": 60}
                path.write_text(json.dumps(journal))
                clock = [0]
                def step(_):
                    if clock[0] == 0:
                        clock[0] = duration
                    else:
                        path.unlink()
                        (Path(tmp) / "app-update-transaction-failed-a.json").write_text(
                            json.dumps({"phase": "old_relaunched", "nonce": "a"}))
                identity = (os.getuid(), "birth", str(exe))
                with patch.object(gate.time, "monotonic", side_effect=lambda: clock[0]), \
                        patch.object(gate.time, "time", side_effect=lambda: clock[0]), \
                        patch.object(gate.time, "sleep", side_effect=step), \
                        patch.object(gate, "snapshot", return_value=identity if alive else None), \
                        patch.object(gate, "stop_successor") as stop:
                    check = lambda: 1 + int(advances and clock[0] > 0)
                    if accepted:
                        report = gate.observe(path, exe, "traffic_failure", traffic_health=check)
                        self.assertTrue(report["live_traffic_failure"])
                        self.assertFalse(report["stopped"])
                    else:
                        with self.assertRaisesRegex(RuntimeError, "expected injected"):
                            gate.observe(path, exe, "traffic_failure", traffic_health=check)
                    stop.assert_not_called()

    def test_restored_tray_must_be_distinct_and_owned(self):
        import subprocess
        exe = Path("/private/test/Slipstream.app/Contents/MacOS/slipstream")
        result = subprocess.CompletedProcess([], 0, "123\n", "")
        with patch.object(gate.subprocess, "run", return_value=result), patch.object(
            gate, "snapshot", return_value=(os.getuid(), "birth", str(exe))
        ):
            with self.assertRaisesRegex(RuntimeError, "distinct live"):
                gate.restored_app_pid(exe, 123)
            self.assertEqual(gate.restored_app_pid(exe, 122), 123)

    def test_missing_transaction_is_not_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(RuntimeError, "before any phase"):
                gate.observe(Path(tmp) / "absent.json", Path(tmp) / "app", "accept")


if __name__ == "__main__":
    unittest.main()
