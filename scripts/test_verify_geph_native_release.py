"""Offline release-consumer integration over explicitly synthetic Mach-O proof.

The real source, bundle and link verifiers run; this is not a Geph build or a
cryptographic attestation verification. Verified-statement fixtures exercise
only the separate exact-subject/predicate binding step.
"""
import hashlib
import json
from pathlib import Path
import unittest
from unittest import mock

import geph_native_sqlite_bundle as bundle
import test_geph_native_sqlite_sbom as native_fixture
import test_verify_geph_release as legacy_fixture
import verify_geph_release as release_verifier


class NativeReleaseConsumerTests(unittest.TestCase):
    def setUp(self):
        case = native_fixture.NativeSqliteSbomTests()
        self.addCleanup(case.doCleanups)
        case.setUp()
        self.case = case
        self.legacy = legacy_fixture.VerifyGephReleaseTests()
        self.release, self.refs = self.legacy._fixture(case.root)
        self.refs['source'].write_bytes(case.source_bytes)
        self.refs['cargo_lock'].write_bytes(case.lock_bytes)
        (self.release / 'geph5-client.SOURCE.json').write_bytes(case.source_bytes)
        (self.release / 'geph5-client.Cargo.lock').write_bytes(case.lock_bytes)
        (self.release / 'geph5-client').write_bytes((case.root / 'geph-universal').read_bytes())
        (self.release / 'geph5-client.spdx.json').write_text(json.dumps(case.document()))
        self.bundle_path = self.release / release_verifier.NATIVE_EVIDENCE_NAME
        bundle.pack_bundle(
            receipt_path=case.receipt, artifacts_root=case.root, output_path=self.bundle_path,
            descriptor=case.source['native_sqlite'], source_sha256=case.source_sha,
            lock_sha256=case.source['lock_sha256'], published_binary=self.release / 'geph5-client',
        )
        self.output = case.root / 'verified-native'
        self.refresh_inventory()

    def refresh_inventory(self):
        digests = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in self.release.iterdir() if p.name != 'SHA256SUMS'}
        (self.release / 'SHA256SUMS').write_text(
            ''.join(f'{digest}  {name}\n' for name, digest in sorted(digests.items()))
        )
        self.refs['metadata_path'].write_text(json.dumps({
            'tag_name': self.refs['expected_tag'], 'draft': False, 'prerelease': True,
            'assets': [{'name': p.name, 'state': 'uploaded', 'size': p.stat().st_size,
                        'digest': 'sha256:' + hashlib.sha256(p.read_bytes()).hexdigest()}
                       for p in sorted(self.release.iterdir())],
        }))

    def verify(self, **kwargs):
        return release_verifier.verify_release_assets(
            release_dir=self.release, **(self.refs | {'native_output_root': self.output} | kwargs)
        )

    def attestations(self):
        provenance, spdx = self.legacy._attestation_fixture(self.case.root, self.release)
        value = json.loads(provenance.read_text())
        value[0]['verificationResult']['statement']['subject'].append({
            'name': self.bundle_path.name,
            'digest': {'sha256': hashlib.sha256(self.bundle_path.read_bytes()).hexdigest()},
        })
        provenance.write_text(json.dumps(value))
        return dict(release_dir=self.release, provenance_json=provenance, spdx_json=spdx,
                    source=self.refs['source'])

    def test_native_payload_is_checked_against_independent_download(self):
        result = self.verify()
        self.assertEqual(result['asset_count'], 9)
        proof = result['native_evidence']
        self.assertEqual(result['binary_sha256'], proof['final_binary_sha256'])
        self.assertTrue(Path(proof['receipt_path']).is_file())
        self.assertEqual(proof['bundle_sha256'], hashlib.sha256(self.bundle_path.read_bytes()).hexdigest())
        attested = release_verifier.verify_attestation_results(**self.attestations())
        self.assertEqual(attested['provenance_subject_count'], 9)

    def test_native_shape_requires_explicit_reviewed_source(self):
        kwargs = dict(metadata_path=self.refs['metadata_path'], expected_tag=self.refs['expected_tag'])
        with self.assertRaisesRegex(ValueError, 'asset set'):
            release_verifier.verify_release_metadata(**kwargs)
        self.assertEqual(release_verifier.verify_release_metadata(**kwargs, source=self.refs['source'])['asset_count'], 9)
        attest = self.attestations()
        attest.pop('source')
        with self.assertRaisesRegex(ValueError, 'asset set'):
            release_verifier.verify_attestation_results(**attest)

    def test_legacy_download_set_cannot_hide_native_source(self):
        self.bundle_path.unlink()
        self.refresh_inventory()
        with self.assertRaisesRegex(ValueError, 'asset set'):
            self.verify()
        provenance, spdx = self.legacy._attestation_fixture(self.case.root, self.release)
        with self.assertRaisesRegex(ValueError, 'reviewed source'):
            release_verifier.verify_attestation_results(
                release_dir=self.release, provenance_json=provenance, spdx_json=spdx)

    def test_missing_or_extra_native_asset_rejected(self):
        self.bundle_path.rename(self.bundle_path.with_suffix('.other'))
        self.refresh_inventory()
        with self.assertRaisesRegex(ValueError, 'asset set'):
            self.verify()

    def test_rehashed_downloaded_binary_does_not_reuse_proof(self):
        binary = self.release / 'geph5-client'
        binary.write_bytes(binary.read_bytes() + b'changed after proof')
        self.refresh_inventory()
        with self.assertRaises(ValueError):
            self.verify()

    def test_corrupt_bundle_even_with_coherent_api_and_checksum_rejected(self):
        self.bundle_path.write_bytes(b'not a native evidence tar')
        self.refresh_inventory()
        with self.assertRaises(ValueError):
            self.verify()

    def test_output_root_must_be_explicit_and_fresh(self):
        with self.assertRaisesRegex(ValueError, 'fresh evidence output root'):
            self.verify(native_output_root=None)
        self.output.mkdir()
        (self.output / 'keep').write_text('user data')
        with self.assertRaises((ValueError, FileExistsError)):
            self.verify()
        self.assertEqual((self.output / 'keep').read_text(), 'user data')

    def test_downloaded_source_cannot_select_its_own_contract(self):
        path = self.release / 'geph5-client.SOURCE.json'
        value = json.loads(path.read_text())
        value['release_revision'] += 1
        path.write_text(json.dumps(value))
        self.refresh_inventory()
        with self.assertRaisesRegex(ValueError, 'reviewed source'):
            self.verify()
        with self.assertRaisesRegex(ValueError, 'reviewed source'):
            release_verifier.verify_attestation_results(**self.attestations())

    def test_native_evidence_must_be_provenance_subject(self):
        attest = self.attestations()
        path = attest['provenance_json']
        value = json.loads(path.read_text())
        value[0]['verificationResult']['statement']['subject'].pop()
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, 'exact release asset set'):
            release_verifier.verify_attestation_results(**attest)

    def test_changed_bundle_between_inventory_and_unpack_rejected(self):
        real = bundle.unpack_bundle
        def changed(**kwargs):
            proof = real(**kwargs)
            # Simulate a second individually valid snapshot with different
            # inventory identity, without mocking the link/bundle verification.
            return proof | {'bundle_sha256': '0' * 64}
        with mock.patch.object(bundle, 'unpack_bundle', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'changed during asset verification'):
                self.verify()

    def test_spdx_snapshot_cannot_change_after_provenance_hashing(self):
        attest = self.attestations()
        sbom_path = self.release / 'geph5-client.spdx.json'
        modified = json.loads(sbom_path.read_text())
        modified['name'] = 'different snapshot after provenance hashing'
        spdx = json.loads(attest['spdx_json'].read_text())
        for entry in spdx:
            entry['verificationResult']['statement']['predicate'] = modified
        attest['spdx_json'].write_text(json.dumps(spdx))
        real = release_verifier._read_json_regular

        def change_after_subject_hashes(path, **kwargs):
            value = real(path, **kwargs)
            if path == attest['provenance_json']:
                sbom_path.write_text(json.dumps(modified))
            return value

        with mock.patch.object(release_verifier, '_read_json_regular', side_effect=change_after_subject_hashes):
            with self.assertRaisesRegex(ValueError, 'SPDX SBOM changed'):
                release_verifier.verify_attestation_results(**attest)

    def test_downloaded_source_snapshot_cannot_change_after_subject_hashing(self):
        # A legacy-size download with a native SOURCE must not become eligible
        # by replacing that SOURCE only for the later contract-shape read.
        self.bundle_path.unlink()
        self.refresh_inventory()
        provenance, spdx = self.legacy._attestation_fixture(self.case.root, self.release)
        source_path = self.release / 'geph5-client.SOURCE.json'
        modified = json.loads(source_path.read_text())
        modified.pop('native_sqlite')
        real = release_verifier._read_json_regular

        def replace_source_before_parse(path, **kwargs):
            if path == source_path:
                source_path.write_text(json.dumps(modified))
            return real(path, **kwargs)

        with mock.patch.object(release_verifier, '_read_json_regular', side_effect=replace_source_before_parse):
            with self.assertRaisesRegex(ValueError, 'source changed'):
                release_verifier.verify_attestation_results(
                    release_dir=self.release, provenance_json=provenance, spdx_json=spdx)


class NativeV2ConsumerCompatibilityTests(unittest.TestCase):
    """Synthetic H1 producer proof consumed with a different verifier identity."""

    def setUp(self):
        fixture = native_fixture.binary_fixture
        original = fixture.descriptor
        self.build = fixture.build
        self.producer_hash = hashlib.sha256(Path(self.build.__file__).read_bytes()).hexdigest()

        def pinned_descriptor():
            return original() | {'schema_version': 2, 'producer_helper_sha256': self.producer_hash}

        self.consumer = NativeReleaseConsumerTests()
        self.addCleanup(self.consumer.doCleanups)
        with mock.patch.object(fixture, 'descriptor', side_effect=pinned_descriptor):
            self.consumer.setUp()

    def test_new_verifier_accepts_pinned_producer_through_assets_bundle_and_spdx(self):
        other = self.consumer.case.root / 'new-verifier-identity.py'
        other.write_bytes(Path(self.build.__file__).read_bytes() + b'\n# newer verifier identity\n')
        self.assertNotEqual(hashlib.sha256(other.read_bytes()).hexdigest(), self.producer_hash)
        with mock.patch.object(self.build, '__file__', str(other)):
            result = self.consumer.verify()
            self.assertEqual(result['asset_count'], 9)
            document = json.loads((self.consumer.release / 'geph5-client.spdx.json').read_text())
            self.assertEqual(self.consumer.case.verify(document)['package_count'], 3)
        attested = release_verifier.verify_attestation_results(**self.consumer.attestations())
        self.assertEqual(attested['provenance_subject_count'], 9)

    def test_rehashed_downloaded_source_cannot_select_another_producer(self):
        source = self.consumer.release / 'geph5-client.SOURCE.json'
        value = json.loads(source.read_text())
        value['native_sqlite']['producer_helper_sha256'] = 'f' * 64
        source.write_text(json.dumps(value))
        self.consumer.refresh_inventory()
        with self.assertRaisesRegex(ValueError, 'reviewed'):
            self.consumer.verify()


if __name__ == '__main__':
    unittest.main()
