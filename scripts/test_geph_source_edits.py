import copy
import hashlib
import io
import tarfile
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

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


class ReviewedRsaPolicyTransitionTests(unittest.TestCase):
    def setUp(self):
        root = Path(__file__).parents[1]
        self.current = json.loads(
            (root / 'security/geph-dependency-audit-policy.json').read_text())
        self.previous = copy.deepcopy(self.current)
        old_reasons = {
            'geph-rsa-0.8.2-marvin-public-key-only':
                'This graph enters through blind-rsa-signatures/Mizaru. The Geph client '
                'uses public-key blind, finalize, and verify operations; the vulnerable '
                'private-key decryption/signing operation is not present in the client '
                'flow. Replace with an upstream-fixed graph.',
            'geph-rsa-0.8.2-prime-validation-public-key-only':
                'The affected malformed private-key construction path is not used by '
                'the Geph client, which imports and applies only Mizaru public keys. '
                'Replace with an upstream-fixed blind-rsa-signatures graph.',
        }
        for exception in self.previous['exceptions']:
            if exception['id'] in old_reasons:
                exception.update(expires='2026-09-30', reason=old_reasons[exception['id']])
        self.binding = (
            'cb12b384c2ee25995a96bb000eddad115207dfed949ae1109c3de5169915c087',
            'd5a0e6f58cfdd7fea7db79c1322a486cc2d7ba47609c6d92c0edefe7a7e67b81',
            source.hash_file(root / 'vendor/geph/SOURCE.json'),
            source.hash_file(root / 'vendor/geph/Cargo.lock'),
        )

    def verify_policy(self, **overrides):
        args = dict(previous_policy=self.previous, current_policy=self.current,
                    previous_h2_present=False, current_h2_present=False,
                    verified_source_binding=self.binding)
        args.update(overrides)
        return source._verify_policy_transition(**args)

    def test_accepts_reviewed_pair_independent_of_json_object_order(self):
        for policy in (self.current, json.loads(json.dumps(self.current, indent=4),
                object_pairs_hook=lambda pairs: dict(reversed(pairs)))):
            with self.subTest(policy=policy):
                self.assertEqual(self.verify_policy(current_policy=policy),
                                 'renewed-reviewed-rsa-public-key-exceptions')

    def test_policy_only_callers_and_foreign_source_or_lock_are_rejected(self):
        bindings = [None]
        for index in range(4):
            changed = list(self.binding)
            changed[index] = '0' * 64
            bindings.append(tuple(changed))
        for binding in bindings:
            with self.subTest(binding=binding), self.assertRaisesRegex(
                    ValueError, 'additions or changes'):
                self.verify_policy(verified_source_binding=binding)
        with self.assertRaisesRegex(ValueError, 'additions or changes'):
            source._verify_policy_transition(previous_policy=self.previous,
                current_policy=self.current, previous_h2_present=False,
                current_h2_present=False)

    def test_other_policy_changes_and_partial_renewal_are_rejected(self):
        def rsa(policy):
            return next(e for e in policy['exceptions']
                        if e['id'] == 'geph-rsa-0.8.2-marvin-public-key-only')

        for side in ('previous_policy', 'current_policy'):
            original = self.previous if side == 'previous_policy' else self.current
            mutations = {
                'date': lambda p: rsa(p).update(expires='2026-10-23'),
                'reason': lambda p: rsa(p).update(reason='another review'),
                'advisory': lambda p: rsa(p).update(advisories=['CVE-2099-12345']),
                'package': lambda p: rsa(p).update(package='other-rsa'),
                'version': lambda p: rsa(p).update(version='0.8.3'),
                'scanner': lambda p: p['scanner'].update(version='2.3.9'),
                'scanner-checksum': lambda p: p['scanner']['assets'][
                    'linux-amd64'].update(sha256='0' * 64),
                'rules': lambda p: p['rules'].update(unreviewed='record'),
                'added-exception': lambda p: p['exceptions'].append(copy.deepcopy(rsa(p))),
                'removed-exception': lambda p: p['exceptions'].pop(0),
            }
            for label, mutate in mutations.items():
                policy = copy.deepcopy(original)
                mutate(policy)
                with self.subTest(side=side, mutation=label), self.assertRaisesRegex(
                        ValueError, 'additions or changes'):
                    self.verify_policy(**{side: policy})

        old_by_id = {e['id']: e for e in self.previous['exceptions']}
        for identifier in ('geph-rsa-0.8.2-marvin-public-key-only',
                           'geph-rsa-0.8.2-prime-validation-public-key-only'):
            partial = copy.deepcopy(self.current)
            partial['exceptions'] = [old_by_id[e['id']] if e['id'] == identifier else e
                                     for e in partial['exceptions']]
            with self.subTest(partial=identifier), self.assertRaisesRegex(
                    ValueError, 'additions or changes'):
                self.verify_policy(current_policy=partial)

    def test_unchanged_and_exact_h2_removal_keep_previous_behavior(self):
        self.assertEqual(self.verify_policy(current_policy=self.previous,
                                           verified_source_binding=None), 'unchanged')
        old = {'exceptions': [{'id': source.H2_TRANSITION_EXCEPTION_ID}],
               'rules': {'unreviewed': 'block'}}
        new = {'exceptions': [], 'rules': {'unreviewed': 'block'}}
        args = dict(previous_policy=old, current_policy=new,
                    previous_h2_present=True, current_h2_present=False)
        self.assertEqual(source._verify_policy_transition(**args),
                         'removed-temporary-h2-exception')
        new['rules']['unreviewed'] = 'record'
        with self.assertRaisesRegex(ValueError, 'only remove'):
            source._verify_policy_transition(**args)

    def verify_source(self, *, binding=None, fail_at=None):
        # Isolate the wiring: the existing contract/lock verifiers are mocked,
        # while policy admission and all transition ordering remain real.
        binding = self.binding if binding is None else binding
        previous = dict(schema_version=1, features=['aws_lambda'], targets=list(source.TARGETS),
                        crate={'name': source.CRATE_NAME}, release_revision=5,
                        lock_sha256=binding[1])
        current = {**previous, 'release_revision': 1, 'lock_sha256': binding[3]}
        summaries = [dict(version='0.3.9', release_tag='geph-vendor-0.3.9-r5',
                          lock_sha256=binding[1]),
                     dict(version='0.4.3', release_tag='geph-vendor-0.4.3-r1',
                          lock_sha256=binding[3])]
        with mock.patch.object(source, 'load_source_contract',
                               side_effect=[previous, current]), \
             mock.patch.object(source, 'hash_file', side_effect=[binding[0], binding[2]]), \
             mock.patch.object(source, 'verify_source_contract',
                               side_effect=summaries) as contracts, \
             mock.patch.object(source, '_cargo_lock_has_h2_0_4_15',
                               return_value=False) as locks, \
             mock.patch.object(source, '_load_geph_policy',
                               side_effect=[self.previous, self.current]), \
             mock.patch.object(source, '_verify_policy_transition',
                               wraps=source._verify_policy_transition) as admission:
            if fail_at:
                verifier = contracts if fail_at == 'contract' else locks
                verifier.side_effect = ValueError('fixture input verification failed')
            try:
                return source.verify_source_transition(
                    previous_source_path=Path('previous/SOURCE.json'),
                    previous_version_path=Path('previous/VERSION'),
                    previous_cargo_lock_path=Path('previous/Cargo.lock'),
                    previous_policy_path=Path('previous/policy.json'),
                    current_source_path=Path('current/SOURCE.json'),
                    current_version_path=Path('current/VERSION'),
                    current_cargo_lock_path=Path('current/Cargo.lock'),
                    current_policy_path=Path('current/policy.json'))
            finally:
                if fail_at:
                    admission.assert_not_called()
                else:
                    self.assertEqual(contracts.call_count, 2)
                    self.assertEqual(locks.call_count, 2)
                    self.assertEqual(admission.call_args.kwargs['verified_source_binding'],
                                     binding)

    def test_verified_source_transition_passes_actual_identities(self):
        result = self.verify_source()
        self.assertEqual(result['transition'], 'upgrade')
        self.assertEqual(result['policy_transition'],
                         'renewed-reviewed-rsa-public-key-exceptions')
        for index in range(4):
            changed = list(self.binding)
            changed[index] = '1' * 64
            with self.subTest(index=index), self.assertRaisesRegex(
                    ValueError, 'additions or changes'):
                self.verify_source(binding=tuple(changed))

    def test_failed_input_verification_never_reaches_policy_admission(self):
        for fail_at in ('contract', 'lock'):
            with self.subTest(fail_at=fail_at), self.assertRaisesRegex(
                    ValueError, 'fixture input verification failed'):
                self.verify_source(fail_at=fail_at)
