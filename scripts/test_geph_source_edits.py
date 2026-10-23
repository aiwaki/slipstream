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


# Exact 2026-10-15 policy, retained to test the historical source transition.
RSA_REVIEW_20261015_POLICY_JSON = r'''
{
  "exceptions": [
    {
      "advisories": [
        "GHSA-g59m-gf8j-gjf5"
      ],
      "ecosystem": "crates.io",
      "expires": "2026-09-30",
      "id": "geph-aws-sdk-lambda-1.35.0-region-validation",
      "package": "aws-sdk-lambda",
      "reason": "geph5-client pins this SDK for its broker transport. The advisory is defense-in-depth region validation; Slipstream supplies no user AWS credentials or region override. Track upstream and remove when Geph permits aws-sdk-lambda 1.104.0 or newer.",
      "version": "1.35.0"
    },
    {
      "advisories": [
        "GHSA-q83h-524g-xf6h",
        "RUSTSEC-2026-0258"
      ],
      "ecosystem": "crates.io",
      "expires": "2026-09-30",
      "id": "geph-h2-0.3.27-upstream-hyper-014",
      "package": "h2",
      "reason": "The low-severity empty-DATA-frame denial of service is reachable in geph5-client's exact aws-config 1.5.4 / Hyper 0.14 client, but requires a malicious HTTP/2 peer. Slipstream fixes the AWS Lambda function and region, does not accept a user endpoint override, uses WebPKI TLS authentication, applies a 10-second operation timeout, and consumes the response payload. No fixed h2 0.3 release exists; this is accepted residual availability risk until upstream Geph moves the AWS connector off Hyper 0.14 / h2 0.3.",
      "version": "0.3.27"
    },
    {
      "advisories": [
        "CVE-2023-49092"
      ],
      "ecosystem": "crates.io",
      "expires": "2026-10-22",
      "id": "geph-rsa-0.8.2-marvin-public-key-only",
      "package": "rsa",
      "reason": "Reviewed 2026-10-15 against Geph 0.4.3 SOURCE 843b3bf0a1f59bf7ddc0221500c59b97230ae3c9130949789385b70a7bcca3fe and Cargo.lock 5ee1bccd3f2f063898adc002d56b0df61ca068c581e7f32ca00cd564854dff5d. The client and its complete RSA reverse-dependency closure use public-key parsing, blind/finalize/verify only. No client config, RPC or cache DTO constructs or imports RsaPrivateKey, and no client call enters private-key signing/decryption required by Marvin. This is a bounded reachability exception, not removal of private APIs or a blanket cryptographic safety claim. Re-review on source, dependency or client-role changes; see docs/ROUTING_RESEARCH.md, RSA client review 2026-10-15.",
      "version": "0.8.2"
    },
    {
      "advisories": [
        "CVE-2026-21895"
      ],
      "ecosystem": "crates.io",
      "expires": "2026-10-22",
      "id": "geph-rsa-0.8.2-prime-validation-public-key-only",
      "package": "rsa",
      "reason": "Reviewed 2026-10-15 against the same Geph 0.4.3 SOURCE 843b3bf0a1f59bf7ddc0221500c59b97230ae3c9130949789385b70a7bcca3fe and Cargo.lock 5ee1bccd3f2f063898adc002d56b0df61ca068c581e7f32ca00cd564854dff5d. Untrusted broker key bytes are parsed as RsaPublicKey (modulus/exponent), not RsaPrivateKey. The malformed-prime from_components/precompute path is not called by the client, reverse dependencies, config, RPC or cache DTO. This exception covers only this advisory and exact client graph; see docs/ROUTING_RESEARCH.md, RSA client review 2026-10-15.",
      "version": "0.8.2"
    },
    {
      "advisories": [
        "CVE-2023-49092"
      ],
      "ecosystem": "crates.io",
      "expires": "2026-09-30",
      "id": "geph-rsa-0.9.10-unused-sqlx-mysql",
      "package": "rsa",
      "reason": "This package is pulled by sqlx-mysql default features, while geph5-client uses SQLite and does not execute the MySQL authentication path or RSA private-key operations. Remove when upstream disables unused SQLx defaults or updates SQLx.",
      "version": "0.9.10"
    },
    {
      "advisories": [
        "GHSA-82j2-j2ch-gfr8"
      ],
      "ecosystem": "crates.io",
      "expires": "2026-09-30",
      "id": "geph-rustls-webpki-0.101.7-no-crl-input",
      "package": "rustls-webpki",
      "reason": "The panic requires a crafted certificate revocation list. Geph configures WebPKI roots and does not load CRLs. Keep this exception short-lived and remove when upstream updates rustls-webpki.",
      "version": "0.101.7"
    },
    {
      "advisories": [
        "GHSA-965h-392x-2mh5"
      ],
      "ecosystem": "crates.io",
      "expires": "2026-09-30",
      "id": "geph-rustls-webpki-0.101.7-name-constraints-0098",
      "package": "rustls-webpki",
      "reason": "This is accepted residual TLS risk requiring a CA to issue a certificate that exploits incomplete name-constraint enforcement. It is not declared unreachable; remove as soon as upstream moves to a fixed rustls-webpki.",
      "version": "0.101.7"
    },
    {
      "advisories": [
        "GHSA-xgp8-3hg3-c2mh"
      ],
      "ecosystem": "crates.io",
      "expires": "2026-09-30",
      "id": "geph-rustls-webpki-0.101.7-name-constraints-0099",
      "package": "rustls-webpki",
      "reason": "This is accepted residual TLS risk requiring a CA to issue a certificate that exploits incomplete name-constraint enforcement. It is not declared unreachable; remove as soon as upstream moves to a fixed rustls-webpki.",
      "version": "0.101.7"
    },
    {
      "advisories": [
        "GHSA-7gcf-g7xr-8hxj"
      ],
      "ecosystem": "crates.io",
      "expires": "2026-09-30",
      "id": "geph-serde-with-1.14.0-key-value-map-unused",
      "package": "serde_with",
      "reason": "The advisory affects KeyValueMap serialization with empty entries. No KeyValueMap use exists in the reviewed geph5-client, stdcode, or Mizaru client path. Remove when upstream updates serde_with.",
      "version": "1.14.0"
    },
    {
      "advisories": [
        "GHSA-xmrp-424f-vfpx"
      ],
      "ecosystem": "crates.io",
      "expires": "2026-09-30",
      "id": "geph-sqlx-0.7.4-sqlite-only",
      "package": "sqlx",
      "reason": "The affected Postgres protocol path is not used; geph5-client persists state through SQLite. The advisory does not identify SQLite as exploitable. Remove when upstream updates SQLx and disables unused backend defaults.",
      "version": "0.7.4"
    }
  ],
  "rules": {
    "informational": "record",
    "unreviewed": "block"
  },
  "scanner": {
    "assets": {
      "darwin-arm64": {
        "name": "osv-scanner_darwin_arm64",
        "sha256": "a8cd6507b06239f463a7642430cfd2d154882f150f6e30cdc0653e28dfc34216"
      },
      "linux-amd64": {
        "name": "osv-scanner_linux_amd64",
        "sha256": "bc98e15319ed0d515e3f9235287ba53cdc5535d576d24fd573978ecfe9ab92dc"
      }
    },
    "repository": "google/osv-scanner",
    "version": "2.3.8"
  },
  "schema_version": 1
}
'''


class ReviewedRsaPolicyTransitionTests(unittest.TestCase):
    def setUp(self):
        self.current = json.loads(RSA_REVIEW_20261015_POLICY_JSON)
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
            '843b3bf0a1f59bf7ddc0221500c59b97230ae3c9130949789385b70a7bcca3fe',
            '5ee1bccd3f2f063898adc002d56b0df61ca068c581e7f32ca00cd564854dff5d',
        )
        self.versions = ('0.3.9', '0.4.3')
        self.revisions = (5, 1)
        self.transition = 'upgrade'
        self.assert_policy_digest(self.previous,
            '1fb2186a3ec212c509137c392a0beba24b61d39f423abf911a3a99d262a98e5f')
        self.assert_policy_digest(self.current,
            '53d6a5865d2106437b6106b65fd443a337b2d19fccb4a52a5a696e4f0a0d3ca0')

    def assert_policy_digest(self, policy, expected):
        canonical = json.dumps(policy, ensure_ascii=False, separators=(',', ':'),
                               sort_keys=True)
        self.assertEqual(digest(canonical), expected)

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
                'date': lambda p: rsa(p).update(expires='2026-10-31'),
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
                'other-exception-date': lambda p: p['exceptions'][0].update(
                    expires='2026-10-30'),
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
                        crate={'name': source.CRATE_NAME}, release_revision=self.revisions[0],
                        lock_sha256=binding[1])
        current = {**previous, 'release_revision': self.revisions[1],
                   'lock_sha256': binding[3]}
        summaries = [dict(version=version,
                          release_tag=f'geph-vendor-{version}-r{revision}',
                          lock_sha256=lock_hash)
                     for version, revision, lock_hash in zip(
                         self.versions, self.revisions, (binding[1], binding[3]))]
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
        self.assertEqual(result['transition'], self.transition)
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

    def test_reviewed_pair_rejects_h2_presence(self):
        for previous, current in ((True, False), (False, True), (True, True)):
            with self.subTest(previous=previous, current=current), self.assertRaises(ValueError):
                self.verify_policy(previous_h2_present=previous, current_h2_present=current)


class ReviewedRsaRevisionPolicyTransitionTests(ReviewedRsaPolicyTransitionTests):
    def setUp(self):
        root = Path(__file__).parents[1]
        self.previous = json.loads(RSA_REVIEW_20261015_POLICY_JSON)
        self.current = json.loads(
            (root / 'security/geph-dependency-audit-policy.json').read_text())
        self.binding = (
            '843b3bf0a1f59bf7ddc0221500c59b97230ae3c9130949789385b70a7bcca3fe',
            '5ee1bccd3f2f063898adc002d56b0df61ca068c581e7f32ca00cd564854dff5d',
            '387ddab282548377b2e35d0d2c6fdb5c81a23436de87fc631b6bbb41323f1a1e',
            '440c8b8156443144f6528ebc4be3613338ba84d3856f623f3aa4ce04512feffe',
        )
        self.versions = ('0.4.3', '0.4.3')
        self.revisions = (1, 2)
        self.transition = 'revision'

    def test_checked_out_inputs_match_exact_review(self):
        root = Path(__file__).parents[1]
        self.assertEqual(source.hash_file(root / 'vendor/geph/SOURCE.json'), self.binding[2])
        self.assertEqual(source.hash_file(root / 'vendor/geph/Cargo.lock'), self.binding[3])
        self.assert_policy_digest(self.previous,
            '53d6a5865d2106437b6106b65fd443a337b2d19fccb4a52a5a696e4f0a0d3ca0')
        self.assert_policy_digest(self.current,
            '467fa124869eb562ec6402af8802df28c7e096028179bea3aa40274d9be35ae7')

    def test_only_two_reviewed_reasons_and_expiries_change(self):
        previous = {e['id']: e for e in self.previous['exceptions']}
        current = {e['id']: e for e in self.current['exceptions']}
        reviewed_ids = {'geph-rsa-0.8.2-marvin-public-key-only',
                        'geph-rsa-0.8.2-prime-validation-public-key-only'}
        self.assertEqual(previous.keys(), current.keys())
        self.assertEqual(len(self.current['exceptions']), len(current))
        for identifier, old in previous.items():
            new = current[identifier]
            with self.subTest(identifier=identifier):
                if identifier in reviewed_ids:
                    self.assertEqual(new['expires'], '2026-10-30')
                    self.assertIn('Reviewed 2026-10-23', new['reason'])
                    self.assertIn(self.binding[2], new['reason'])
                    self.assertIn(self.binding[3], new['reason'])
                    self.assertNotEqual(new['reason'], old['reason'])
                    self.assertEqual({**new, 'reason': old['reason'],
                                      'expires': old['expires']}, old)
                else:
                    self.assertEqual(new, old)
        self.assertEqual({**self.current, 'exceptions': self.previous['exceptions']},
                         self.previous)

    def test_historical_and_revision_bindings_cannot_be_swapped_or_mixed(self):
        historical = ReviewedRsaPolicyTransitionTests()
        historical.setUp()
        for policies, wrong_binding in (
            ((self.previous, self.current), historical.binding),
            ((historical.previous, historical.current), self.binding),
            ((historical.previous, self.current), self.binding),
            ((self.previous, self.current), self.binding[2:] + self.binding[:2]),
            ((self.current, self.previous), self.binding),
        ):
            with self.subTest(binding=wrong_binding), self.assertRaisesRegex(
                    ValueError, 'additions or changes'):
                self.verify_policy(previous_policy=policies[0], current_policy=policies[1],
                                   verified_source_binding=wrong_binding)
