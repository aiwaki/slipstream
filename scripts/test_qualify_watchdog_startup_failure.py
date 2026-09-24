import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import qualify_watchdog_startup_failure as probe


class StartupFixtureTests(unittest.TestCase):
    def test_guard_precedes_execution(self):
        with mock.patch('sys.argv', ['probe', '--helper', '/missing']), \
             mock.patch.object(probe, 'guard', side_effect=RuntimeError('not disposable')), \
             mock.patch.object(probe.subprocess, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'not disposable'):
                probe.main()
            run.assert_not_called()

    def simulate(self, damage=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            source.write_bytes(b'fixture helper')
            def execute(argv, **kwargs):
                journal = Path(argv[-1])
                value = json.loads(journal.read_text())
                target, backup, stage = map(Path, (value['target'], value['backup'], value['stage']))
                target.rename(stage)
                backup.rename(target)
                probe.shutil.rmtree(stage)
                marker = target.parent / 'old-relaunched'
                marker.write_text('restored\n' * (2 if damage == 'duplicate' else 1))
                value['phase'] = 'old_relaunched'
                if damage == 'nonce':
                    value['nonce'] = '0' * 32
                journal.with_name(f"app-update-transaction-failed-{json.loads(journal.read_text())['nonce']}.json").write_text(json.dumps(value))
                journal.unlink()
                if damage == 'payload':
                    (target / 'Contents/MacOS/slipstream').write_text('wrong')
                return subprocess.CompletedProcess(argv, 0, '', '')
            with mock.patch.object(probe.subprocess, 'run', side_effect=execute):
                return probe.run_case(root, source, 'spawn_refused')

    def test_complete_evidence_passes(self):
        self.assertEqual(self.simulate()['status'], 'pass')

    def test_wrong_restored_bytes_duplicate_launch_and_nonce_are_rejected(self):
        for damage in ('payload', 'duplicate', 'nonce'):
            with self.subTest(damage=damage), self.assertRaises(RuntimeError):
                self.simulate(damage)
