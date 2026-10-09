import hashlib
import io
import tarfile
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
            for target in ('../src/session.rs', '/tmp/session.rs', 'src/../session.rs',
                           'Cargo.lock', 'build.rs', 'src/Cargo.toml', '.cargo/config.toml'):
                original['source_edits'] = [dict(path=target, before='a', after='b',
                    before_sha256=digest('a'), after_sha256=digest('b'))]
                path.write_text(json.dumps(original))
                with self.assertRaisesRegex(ValueError, 'edit path'):
                    source.load_source_contract(path)

    def test_hash_bound_root_manifest_edit_is_materializable(self):
        contract = json.loads((Path(__file__).parents[1] / 'vendor/geph/SOURCE.json').read_text())
        before = '[dependencies.sqlx]\nversion = "0.7.4"\n'
        after = '[dependencies.sqlx]\nversion = "=0.8.6"\ndefault-features = false\n'
        edit = dict(path='Cargo.toml', before=before, after=after,
                    before_sha256=digest(before), after_sha256=digest(after))
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            contract['source_edits'] = [edit]
            contract_path = root / 'SOURCE.json'
            contract_path.write_text(json.dumps(contract))
            loaded = source.load_source_contract(contract_path)
            manifest = root / 'Cargo.toml'
            manifest.write_text(before)
            source.apply_source_edits(root, loaded['source_edits'])
            self.assertEqual(manifest.read_text(), after)
            manifest.write_text(before + '# upstream changed\n')
            with self.assertRaisesRegex(ValueError, 'input digest'):
                source.apply_source_edits(root, loaded['source_edits'])

    def test_materialization_rejects_manifest_identity_changed_by_reviewed_edit(self):
        original = json.loads((Path(__file__).parents[1] / 'vendor/geph/SOURCE.json').read_text())
        version = original['crate']['version']
        before = f'[package]\nname = "geph5-client"\nversion = "{version}"\n'
        for after in (before.replace('geph5-client', 'other-client'),
                      before.replace(version, '99.0.0')):
            with self.subTest(after=after), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                archive = root / 'upstream.crate'
                with tarfile.open(archive, 'w:gz') as tar:
                    payload = before.encode()
                    info = tarfile.TarInfo(f'geph5-client-{version}/Cargo.toml')
                    info.size = len(payload)
                    tar.addfile(info, io.BytesIO(payload))
                contract = dict(original)
                contract['crate'] = dict(original['crate'], sha256=source.hash_file(archive))
                contract['lock_sha256'] = digest('version = 4\n')
                contract['source_edits'] = [dict(path='Cargo.toml', before=before, after=after,
                    before_sha256=digest(before), after_sha256=digest(after))]
                source_path = root / 'SOURCE.json'
                source_path.write_text(json.dumps(contract))
                (root / 'VERSION').write_text(version)
                (root / 'Cargo.lock').write_text('version = 4\n')
                with self.assertRaisesRegex(ValueError, 'manifest identity'):
                    source.materialize_source(source_path=source_path,
                        version_path=root / 'VERSION', cargo_lock_path=root / 'Cargo.lock',
                        crate_path=archive, output=root / 'materialized')

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / 'src').mkdir()
            (root / 'real').write_text('old')
            (root / 'src/session.rs').symlink_to(root / 'real')
            with self.assertRaisesRegex(ValueError, 'escapes'):
                source.apply_source_edits(root, [dict(path='src/session.rs')])
