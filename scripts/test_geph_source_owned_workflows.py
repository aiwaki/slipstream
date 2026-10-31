"""Source-owned Geph evidence must survive each actual producer/consumer boundary."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


def workflow(name):
    return (ROOT / '.github/workflows' / name).read_text()


def step(text, name):
    return text.split('name: ' + name + '\n', 1)[1].split('\n      - ', 1)[0]


class GephSourceOwnedWorkflowTests(unittest.TestCase):
    def test_producer_trigger_and_payload_cover_the_review(self):
        text = workflow('build-geph.yml')
        paths = text.split('\njobs:', 1)[0]
        for path in ('scripts/geph_source_owned_*.py', 'scripts/geph_native_sqlite*.py',
                     'scripts/geph_rsa_fixture.py', 'scripts/fixtures/geph-rsa-auth/**',
                     'security/geph-source-owned-review/**'):
            self.assertIn('      - "' + path + '"\n', paths)
        audit = step(text, 'Build and audit the vendored dependency inventory')
        self.assertIn('--source-owned-evidence security/geph-source-owned-review', audit)
        self.assertIn('geph_source_owned_bundle.py pack', audit)
        self.assertIn('--output out/geph5-client-source-review-evidence.tar', audit)
        self.assertLess(text.index('geph_source_owned_bundle.py pack'),
                        text.index('shasum -a 256 geph5-client*'))

    def test_historical_reuse_unpacks_against_immutable_policy(self):
        text = step(workflow('build-geph.yml'), 'Decide whether review or build is required')
        self.assertIn('--pattern geph5-client-source-review-evidence.tar', text)
        self.assertIn('geph_source_owned_bundle.py unpack', text)
        self.assertIn('--policy "$historical_policy"', text)
        self.assertIn('--source-owned-evidence "$source_review"', text)
        self.assertIn('--source-commit "$vendor_commit"', text)
        self.assertNotIn('--for-publication', text)

    def test_exact_audit_artifact_includes_source_review_archive(self):
        text = workflow('dependency-audit.yml')
        audit = step(text, 'Enforce the Geph dependency policy')
        self.assertIn('--source-owned-evidence security/geph-source-owned-review', audit)
        self.assertIn('--output dist-geph-audit/geph5-client-source-review-evidence.tar', audit)
        self.assertIn('name: geph-vendor-dependency-audit-${{ github.sha }}', text)
        self.assertIn('path: dist-geph-audit/', text)

    def test_binary_consumer_uses_reviewed_source_and_historical_evidence(self):
        text = step(workflow('ci.yml'), 'Fetch and verify the recorded Geph build')
        self.assertIn('--pattern geph5-client-source-review-evidence.tar', text)
        self.assertIn('--source-owned-policy "$historical_policy"', text)
        self.assertIn('--source-owned-output-root "$source_review"', text)
        self.assertIn('--source-owned-evidence "$source_review"', text)
        for command in ('verify-metadata', 'verify-attestations'):
            body = text.split('scripts/verify_geph_release.py ' + command + ' \\\n', 1)[1]
            lines = body.splitlines()
            end = next(i for i, line in enumerate(lines) if not line.rstrip().endswith('\\'))
            body = '\n'.join(lines[:end + 1])
            self.assertIn('--source vendor/geph/SOURCE.json', body)
        self.assertIn('--source-digest "$tag_commit"', text)
        self.assertIn('--deny-self-hosted-runners', text)

    def test_all_full_geph_audit_calls_have_explicit_source_review_inputs(self):
        import re
        found = {"scan": 0, "verify": 0, "admit-release": 0, "generate": 0}
        for name in ('build-geph.yml', 'dependency-audit.yml', 'ci.yml', 'build-app.yml'):
            text = workflow(name)
            pattern = r'python3 scripts/(dependency_audit|make_geph_vendor_sbom)\.py (scan|verify|admit-release|generate) \\\n(?:[^\n]*\\\n)*[^\n]*'
            for match in re.finditer(pattern, text):
                script, command = match.group(1, 2)
                call = match.group(0)
                begin = text.rfind('        run: |\n', 0, match.start())
                context = text[begin:match.start()]
                if script == 'make_geph_vendor_sbom':
                    if command == 'generate':
                        found[command] += 1
                        self.assertIn('--source-root ', call, name)
                    continue
                if command == 'admit-release':
                    found[command] += 1
                    self.assertIn('"${geph_args[@]}"', call, name)
                    self.assertIn('--geph-source vendor/geph/SOURCE.json', context, name)
                    self.assertIn('--geph-source-owned-evidence "$source_review"', context, name)
                    self.assertIn('geph_source_owned_bundle.py unpack', context, name)
                elif '--vendored-transitive-dependencies full' in call:
                    found[command] += 1
                    self.assertIn('"${review_args[@]}"', call, name)
                    self.assertIn('--source vendor/geph/SOURCE.json', context, name)
                    self.assertIn('--source-owned-evidence ', context, name)
                    if command == 'scan':
                        self.assertIn('--evidence-dir ', call, name)
                else:
                    self.assertNotIn('--source-owned-evidence', call, name)
        self.assertEqual(found, {"scan": 2, "verify": 4, "admit-release": 2, "generate": 2})

    def test_final_publication_rechecks_source_review_with_both_audits(self):
        text = workflow('build-app.yml')
        self.assertIn('artifact-ids: ${{ steps.runs.outputs.geph_audit_artifact_id }}', text)
        body = step(text, 'Publish only the verified exact release draft')
        self.assertIn('geph_source_owned_bundle.py unpack', body)
        self.assertIn('--geph-source vendor/geph/SOURCE.json', body)
        self.assertIn('--geph-source-owned-evidence "$source_review"', body)
        self.assertIn('--geph-policy security/geph-dependency-audit-policy.json', body)
        self.assertLess(body.index('admit-release'), body.index('gh api --method PATCH'))
        self.assertIn("if: steps.ver.outputs.resume_release_id == ''", body)


class WorkflowCliBindingTests(unittest.TestCase):
    """Run the checked-in shell arguments through real CLI parsers, without tools."""

    def run_bootstrap_source_check(self, change=None):
        import hashlib
        import json
        import os
        import shlex
        import subprocess
        import sys
        import tempfile
        import textwrap
        import test_geph_vendor_source as source_fixture

        fixture = source_fixture.GephVendorSourceTests()
        with tempfile.TemporaryDirectory(prefix='geph bootstrap cli ') as temporary:
            root = Path(temporary)
            lock = fixture._transition_lock(('geph5-client', '0.4.3'))
            previous = fixture._transition_contract(root / 'previous snapshot',
                version='0.4.3', revision=4, lock=lock)
            current = fixture._transition_contract(root / 'vendor/geph',
                version='0.4.3', revision=4, lock=lock)
            security = root / 'security'
            security.mkdir()
            policy = fixture._transition_policy(security / 'geph-dependency-audit-policy.json',
                h2_exception=False)
            (previous / 'dependency-audit-policy.json').write_bytes(policy.read_bytes())
            if change == 'both-invalid-lock':
                for directory in (previous, current):
                    (directory / 'Cargo.lock').write_text('not the contracted lock')
            elif change == 'SOURCE.json':
                source = json.loads((current / change).read_text())
                (current / 'Cargo.lock').write_bytes(lock + b'\n# changed graph snapshot\n')
                source['lock_sha256'] = hashlib.sha256((current / 'Cargo.lock').read_bytes()).hexdigest()
                (current / change).write_text(json.dumps(source))
            elif change in ('VERSION', 'Cargo.lock'):
                (current / change).write_text('invalid changed bytes')
            elif change == 'policy-only':
                policy.write_text(policy.read_text() + '\n')
            elif change in ('revision', 'revision-policy-change'):
                source = json.loads((current / 'SOURCE.json').read_text())
                source['release_revision'] = 5
                (current / 'SOURCE.json').write_text(json.dumps(source))
                if change == 'revision-policy-change':
                    data = json.loads(policy.read_text())
                    data['rules']['unreviewed'] = 'allow'
                    policy.write_text(json.dumps(data))
            (root / 'scripts').symlink_to(ROOT / 'scripts', target_is_directory=True)
            body = step(workflow('ci.yml'), 'Verify reviewed Geph source transition')
            body = textwrap.dedent(body.split('        run: |\n', 1)[1])
            # Exercise the actual callsite after its unchanged immutable Git export.
            body = body.split('> "$previous/dependency-audit-policy.json"\n', 1)[1]
            return subprocess.run(['/bin/bash', '-c',
                'set -euo pipefail\nprevious=' + shlex.quote(str(previous)) + '\n' + body],
                cwd=root, env={**os.environ,
                    'PATH': str(Path(sys.executable).parent) + os.pathsep + os.environ['PATH']},
                capture_output=True, text=True, timeout=5)

    def test_unchanged_bootstrap_contract_is_verified_without_a_revision_transition(self):
        import json
        result = self.run_bootstrap_source_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value['release_tag'], 'geph-vendor-0.4.3-r4')
        self.assertNotIn('transition', value)

    def test_unchanged_bootstrap_still_validates_actual_lock_bytes(self):
        result = self.run_bootstrap_source_check('both-invalid-lock')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Cargo.lock does not match the source contract', result.stderr)

    def test_any_changed_bootstrap_input_keeps_strict_transition_checks(self):
        for change, message in (
            ('SOURCE.json', 'release revision is reused or decreases'),
            ('VERSION', 'Geph version file is invalid'),
            ('Cargo.lock', 'Cargo.lock does not match the source contract'),
            ('policy-only', 'release revision is reused or decreases'),
        ):
            with self.subTest(change=change):
                result = self.run_bootstrap_source_check(change)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(message, result.stderr)

    def test_changed_bootstrap_preserves_valid_revision_and_policy_guards(self):
        import json
        result = self.run_bootstrap_source_check('revision')
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value['transition'], 'revision')
        self.assertEqual(value['policy_transition'], 'unchanged')
        self.assertEqual(value['current_release_tag'], 'geph-vendor-0.4.3-r5')
        result = self.run_bootstrap_source_check('revision-policy-change')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('dependency audit policy additions or changes are forbidden', result.stderr)

    def test_producer_publishes_physical_root_before_sbom_consumes_it(self):
        import json
        import os
        import subprocess
        import sys
        import textwrap
        import test_geph_source_owned_sbom as sbom_fixture

        fixture = sbom_fixture.SourceOwnedGephSbomTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        alias = fixture.fixture.root / 'source parent alias'
        alias.symlink_to(fixture.root.parent, target_is_directory=True)
        lexical_root = alias / fixture.root.name
        # The validator must continue rejecting a lexical path through a symlink.
        with self.assertRaisesRegex(ValueError, 'physical and without symlinks'):
            fixture.collect(source_root=lexical_root)

        body = step(workflow('build-geph.yml'), 'Materialize the reviewed Geph source')
        body = textwrap.dedent(body.split('        run: |\n', 1)[1])
        shell = body[body.index('source_root='):]
        output = fixture.fixture.root / 'github output'
        result = subprocess.run(['/bin/bash', '-c', 'set -euo pipefail\n' + shell],
            env={**os.environ, 'source_json': json.dumps({'root': str(lexical_root)}),
                 'GITHUB_OUTPUT': str(output),
                 'PATH': str(Path(sys.executable).parent) + os.pathsep + os.environ['PATH']},
            capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = output.read_text().splitlines()
        self.assertEqual(len(lines), 1)
        key, value = lines[0].split('=', 1)
        self.assertEqual(key, 'root')
        published_root = Path(value)
        components = fixture.collect(source_root=published_root)
        self.assertEqual(published_root, fixture.root)
        self.assertEqual({item.name for item in components}, {'direct-registry', 'local-transitive'})

    def run_parser(self, name, step_name, script, command, *, prefix=False):
        import json
        import os
        import shlex
        import subprocess
        import sys
        import tempfile
        import textwrap
        body = step(workflow(name), step_name).split('        run: |\n', 1)[1]
        body = textwrap.dedent(body)
        marker = 'python3 scripts/' + script + ' ' + command + ' \\\n'
        start = body.index(marker)
        lines = body[start:].splitlines()
        end = next(i for i, line in enumerate(lines) if not line.rstrip().endswith('\\'))
        setup = body[:start].split('for attempt in 1 2 3 4; do', 1)[0] if prefix else ''
        shell = setup + '\n'.join(lines[:end + 1])
        with tempfile.TemporaryDirectory(prefix='source review cli ') as temporary:
            root = Path(temporary)
            (root / 'vendor/geph').mkdir(parents=True)
            (root / 'vendor/geph/SOURCE.json').write_text('{"embedded_packages":{}}')
            tools = root / 'bin'
            tools.mkdir()
            (tools / 'git').write_text('#!/bin/sh\nprintf "123\\n"\n')
            (tools / 'git').chmod(0o755)
            (tools / 'python3').write_text(
                f'#!{sys.executable}\nimport os,sys,json\nfrom pathlib import Path\n'
                f'sys.path.insert(0, {str(ROOT / "scripts")!r})\n'
                'if sys.argv[1] == "-c": os.execv(sys.executable, [sys.executable,*sys.argv[1:]])\n'
                'name=Path(sys.argv[1]).name\n'
                'if name == "dependency_audit.py" and sys.argv[2] in ("scan", "verify", "admit-release"):\n'
                ' import dependency_audit; args=dependency_audit.parse_args(sys.argv[2:])\n'
                'elif name == "make_geph_vendor_sbom.py":\n'
                ' import make_geph_vendor_sbom; sys.argv=sys.argv[1:]; args=make_geph_vendor_sbom.parse_args()\n'
                'else: raise SystemExit(0)\n'
                'print(json.dumps(vars(args),default=str))\n'
            )
            (tools / 'python3').chmod(0o755)
            shell = shell.replace('${{ github.repository }}', 'aiwaki/slipstream')
            shell = shell.replace('${{ steps.source.outputs.root }}', str(root / 'materialized'))
            shell = 'set -euo pipefail\nsource_date_epoch=123\nsource_root=' + shlex.quote(str(root / 'materialized')) + '\n' + shell
            result = subprocess.run(['/bin/bash', '-c', shell], cwd=root,
                env={**os.environ, 'PATH': str(tools) + os.pathsep + os.environ['PATH'],
                     'RUNNER_TEMP': str(root), 'GITHUB_SHA': 'a' * 40,
                     'SOURCE_COMMIT': 'a' * 40, 'SLIPSTREAM_TAURI_TARGET': 'aarch64-apple-darwin'},
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout.splitlines()[-1])

    def test_both_generators_bind_materialized_source_root(self):
        for name, title in (
            ('build-geph.yml', 'Build and audit the vendored dependency inventory'),
            ('dependency-audit.yml', 'Materialize the reviewed Geph source graph'),
        ):
            with self.subTest(workflow=name):
                value = self.run_parser(name, title, 'make_geph_vendor_sbom.py', 'generate')
                self.assertIsNotNone(value['source_root'])
                self.assertTrue(value['source_root'].endswith('/materialized'))

    def test_both_publisher_gates_parse_exact_source_review_arguments(self):
        for title in ('Verify current application and full Geph dependency admission',
                      'Publish only the verified exact release draft'):
            with self.subTest(step=title):
                value = self.run_parser('build-app.yml', title,
                    'dependency_audit.py', 'admit-release', prefix=True)
                self.assertEqual(value['geph_source'], 'vendor/geph/SOURCE.json')
                self.assertTrue(value['geph_source_owned_evidence'].endswith('/evidence'))

    def test_both_source_owned_scans_keep_a_fresh_evidence_snapshot(self):
        for name, title in (
            ('build-geph.yml', 'Build and audit the vendored dependency inventory'),
            ('dependency-audit.yml', 'Enforce the Geph dependency policy'),
        ):
            with self.subTest(workflow=name):
                value = self.run_parser(name, title, 'dependency_audit.py', 'scan', prefix=True)
                self.assertIsNotNone(value['evidence_dir'])
                self.assertEqual(value['source'], 'vendor/geph/SOURCE.json')
                self.assertEqual(value['source_owned_evidence'], 'security/geph-source-owned-review')


if __name__ == '__main__':
    unittest.main()
