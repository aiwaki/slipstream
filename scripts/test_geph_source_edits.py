import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import geph_vendor_source as source


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


class SourceEditTests(unittest.TestCase):
    def test_exact_edit_and_tampering(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'src').mkdir()
            path = root / 'src/session.rs'
            path.write_text('old\n')
            edit = dict(path='src/session.rs', before='old', after='new',
                        before_sha256=digest('old\n'), after_sha256=digest('new\n'))
            source.apply_source_edits(root, [edit])
            self.assertEqual(path.read_text(), 'new\n')
            with self.assertRaisesRegex(ValueError, 'input digest'):
                source.apply_source_edits(root, [edit])
            path.write_text('old\n')
            with self.assertRaisesRegex(ValueError, 'output digest'):
                source.apply_source_edits(root, [{**edit, 'after': 'wrong'}])
            self.assertEqual(path.read_text(), 'old\n')

    def test_ambiguous_match_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'src').mkdir()
            (root / 'src/session.rs').write_text('old old')
            with self.assertRaisesRegex(ValueError, 'exactly once'):
                source.apply_source_edits(root, [dict(path='src/session.rs',
                    before='old', after='new', before_sha256=digest('old old'),
                    after_sha256=digest('new new'))])

    def test_contract_rejects_path_escape(self):
        original = json.loads((Path(__file__).parents[1] / 'vendor/geph/SOURCE.json').read_text())
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'SOURCE.json'
            for target in ('../src/session.rs', '/tmp/session.rs', 'src/../session.rs'):
                original['source_edits'] = [dict(path=target, before='a', after='b',
                    before_sha256=digest('a'), after_sha256=digest('b'))]
                path.write_text(json.dumps(original))
                with self.assertRaisesRegex(ValueError, 'edit path'):
                    source.load_source_contract(path)

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'src').mkdir()
            (root / 'real').write_text('old')
            (root / 'src/session.rs').symlink_to(root / 'real')
            with self.assertRaisesRegex(ValueError, 'escapes'):
                source.apply_source_edits(root, [dict(path='src/session.rs')])
