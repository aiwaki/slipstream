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
