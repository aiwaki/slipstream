import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import packaged_update_transaction_smoke as gate


class TransactionGateTests(unittest.TestCase):
    def test_legacy_root_mode_contract_rejects_every_other_difference(self):
        known = {".": {"expected": {"mode": "0o755", "kind": "directory"},
                       "actual": {"mode": "0o700", "kind": "directory"}}}
        gate.require_legacy_root_mode_defect(known)
        variants = [{}, {**known, "binary": {"expected": "original", "actual": "changed"}},
                    {**known, "nested": {"expected": "0o755", "actual": "0o700"}}]
        for mode in ("0o777", "0o750", "0o755"):
            variants.append({".": {"expected": known["."]["expected"],
                                   "actual": {"mode": mode, "kind": "directory"}}})
        for changed in variants:
            with self.assertRaisesRegex(RuntimeError, "beyond the known"):
                gate.require_legacy_root_mode_defect(changed)

    def test_bundle_diagnostics_identify_bytes_modes_links_and_missing_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "bundle"
            root.mkdir()
            binary = root / "binary"
            binary.write_bytes(b"old")
            binary.chmod(0o755)
            (root / "link").symlink_to("binary")
            before = gate.bundle_inventory(root)
            self.assertEqual(gate.inventory_changes(before, before), {})
            binary.write_bytes(b"new")
            binary.chmod(0o644)
            (root / "link").unlink()
            (root / "extra").write_bytes(b"extra")
            changes = gate.inventory_changes(before, gate.bundle_inventory(root))
            self.assertEqual(set(changes), {"binary", "link", "extra"})
            self.assertNotEqual(changes["binary"]["expected"]["sha256"],
                                changes["binary"]["actual"]["sha256"])
            self.assertEqual(changes["binary"]["actual"]["mode"], "0o644")
            self.assertIsNone(changes["link"]["actual"])
            self.assertIsNone(changes["extra"]["expected"])

    def test_watchdog_provenance_requires_journal_and_actual_previous_bytes(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            helper = Path(tmp) / "helper"
            helper.write_bytes(b"previous helper")
            digest = hashlib.sha256(helper.read_bytes()).hexdigest()
            journal = {"helper": str(helper), "watchdog_sha256": digest}
            self.assertEqual(gate.watchdog_payload_evidence(journal, helper, digest)["source"],
                             "previous-bundle")
            helper.write_bytes(b"different candidate helper")
            with self.assertRaisesRegex(RuntimeError, "bytes differ"):
                gate.watchdog_payload_evidence(journal, helper, digest)
            helper.unlink()
            other = Path(tmp) / "other"
            other.write_bytes(b"previous helper")
            helper.symlink_to(other)
            with self.assertRaisesRegex(RuntimeError, "unsafe"):
                gate.watchdog_payload_evidence(journal, helper, digest)
            with self.assertRaisesRegex(RuntimeError, "unexpected"):
                gate.watchdog_payload_evidence(dict(journal, helper=str(other)), helper, digest)
            with self.assertRaisesRegex(RuntimeError, "previous bundle"):
                gate.watchdog_payload_evidence(dict(journal, watchdog_sha256="0" * 64), helper, digest)

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

    def observe(self, case, *, failure_nonce="a", changed_process=False, expect_legacy_defect=False):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app-update-transaction-v1.json"
            exe = Path(tmp) / "Slipstream.app/Contents/MacOS/slipstream"
            journal = {"phase": "successor_launched", "nonce": "a",
                       "successor_pid": 123, "successor_started": "Sun Sep 20 12:00:00 2026"}
            helper = Path(tmp) / "helper"
            helper.write_bytes(b"previous helper")
            digest = gate.hashlib.sha256(helper.read_bytes()).hexdigest()
            journal.update(helper=str(helper), watchdog_sha256=digest)
            path.write_text(json.dumps(journal))

            def terminal(_):
                path.unlink()
                if case == "rollback":
                    (Path(tmp) / "app-update-transaction-failed-a.json").write_text(
                        json.dumps({"phase": "old_relaunched", "nonce": failure_nonce}))

            identity = (os.getuid(), journal["successor_started"], str(exe))
            with patch.object(gate.time, "sleep", side_effect=terminal), \
                    patch.object(gate, "stop_successor") as stop, \
                    patch.object(gate, "snapshot", side_effect=lambda _:
                                 None if changed_process or (expect_legacy_defect and not path.exists()) else identity):
                result = gate.observe(path, exe, case, expected_watchdog=(helper, digest),
                                      expect_legacy_defect=expect_legacy_defect)
                self.assertEqual(result["watchdog_payload"]["sha256"], digest)
                self.assertEqual(stop.call_count, int(case == "rollback"))
                return result

    def test_legacy_defect_requires_live_successor_and_exact_terminal_phase(self):
        self.observe("accept", expect_legacy_defect=True)
        self.observe("rollback", expect_legacy_defect=True)
        with self.assertRaisesRegex(RuntimeError, "never observed alive"):
            self.observe("accept", changed_process=True, expect_legacy_defect=True)
        with self.assertRaisesRegex(RuntimeError, "exact transaction"):
            self.observe("rollback", failure_nonce="other", expect_legacy_defect=True)

    def test_legacy_defect_requires_no_terminal_tray_not_just_missing_original_pid(self):
        exe = Path("/private/test/Slipstream.app/Contents/MacOS/slipstream")
        with patch.object(gate, "snapshot", return_value=None), \
                patch.object(gate, "matching_app_pids", return_value=[]), \
                patch.object(gate.time, "sleep"):
            gate.require_legacy_terminal_loss(exe, 123)
        for original, matches in [(None, [456]), ((501, "birth", str(exe)), [])]:
            with patch.object(gate, "snapshot", return_value=original), \
                    patch.object(gate, "matching_app_pids", return_value=matches), \
                    patch.object(gate.time, "monotonic", side_effect=[0, 6]):
                with self.assertRaisesRegex(RuntimeError, "not reproduced"):
                    gate.require_legacy_terminal_loss(exe, 123)
        with patch.object(gate, "snapshot", side_effect=RuntimeError("inspection failed")):
            with self.assertRaisesRegex(RuntimeError, "inspection failed"):
                gate.require_legacy_terminal_loss(exe, 123)

    def test_startup_failure_can_finish_before_first_observation(self):
        for wrong_target, pid in ((False, None), (True, None), (False, 123)):
            with self.subTest(wrong_target=wrong_target, pid=pid), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                exe = root / "Slipstream.app/Contents/MacOS/slipstream"
                helper = root / "helper"
                helper.write_bytes(b"candidate helper")
                digest = gate.hashlib.sha256(helper.read_bytes()).hexdigest()
                record = {"phase": "old_relaunched", "nonce": "a" * 32,
                          "target": str(root / ("wrong.app" if wrong_target else "Slipstream.app")),
                          "successor_pid": pid, "helper": str(helper), "watchdog_sha256": digest}
                (root / "app-update-transaction-failed-a.json").write_text(json.dumps(record))
                def observe():
                    return gate.observe(root / "absent.json", exe, "startup_failure",
                                        expected_watchdog=(helper, digest), watchdog_source="verified-candidate")
                if wrong_target or pid is not None:
                    with self.assertRaisesRegex(RuntimeError, "identity mismatch"):
                        observe()
                else:
                    report = observe()
                    self.assertEqual(report["watchdog_payload"]["source"], "verified-candidate")
                    self.assertIsNone(report["successor_pid"])

    def test_spawn_fault_changes_only_main_executable_archive_mode(self):
        for name in ("slipstream", "slipstream-update-watchdog"):
            member = gate.tarfile.TarInfo("Slipstream.app/Contents/MacOS/" + name)
            member.mode = 0o755
            result = gate.remove_successor_execute(member)
            self.assertEqual(result.mode, 0o644 if name == "slipstream" else 0o755)
        link = gate.tarfile.TarInfo("Slipstream.app/Contents/MacOS/slipstream")
        link.type = gate.tarfile.SYMTYPE
        with self.assertRaisesRegex(RuntimeError, "regular file"):
            gate.remove_successor_execute(link)

    def test_heartbeat_read_retries_only_bounded_atomic_replacement_race(self):
        unstable = gate.VerificationError("StatusV2 changed while read")
        with patch.object(gate, "verify_status_v2", side_effect=[unstable, {"heartbeat_seq": 4}]) as read, \
                patch.object(gate.time, "sleep"):
            self.assertEqual(gate.read_advancing_status(Path("status"), 123), {"heartbeat_seq": 4})
            self.assertEqual(read.call_count, 2)
            read.assert_called_with(status_path=Path("status"), expected_pid=123)
        for error, calls in ((unstable, 3), (gate.VerificationError("wrong daemon PID"), 1)):
            with patch.object(gate, "verify_status_v2", side_effect=error) as read, \
                    patch.object(gate.time, "sleep"):
                with self.assertRaises(gate.VerificationError):
                    gate.read_advancing_status(Path("status"), 123)
                self.assertEqual(read.call_count, calls)

    def test_accept_requires_surviving_exact_successor(self):
        self.assertTrue(self.observe("accept")["transaction_removed"])
        self.assertTrue(self.observe("primary_unavailable")["transaction_removed"])
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

    def test_instant_live_snapshot_does_not_prove_cleanup_survival(self):
        identity = (os.getuid(), "birth", "/owned/tray")
        with patch.object(gate, "snapshot", side_effect=[identity, None]), \
                patch.object(gate.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "survive watchdog cleanup"):
                gate.require_surviving_process(123, identity)

    def test_missing_transaction_is_not_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(RuntimeError, "before any phase"):
                gate.observe(Path(tmp) / "absent.json", Path(tmp) / "app", "accept")


if __name__ == "__main__":
    unittest.main()
