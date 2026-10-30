"""Native candidate authentication uses its attested historical audit policy."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

import dependency_audit
import native_root_update as driver
import release_candidate
import test_release_audit_admission as fixtures


class NativeCandidatePolicyTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ReleaseAuditAdmissionTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.path, _ = self.fixture.candidate("integrity")
        self.manifest = json.loads(self.path.read_text())
        self.source = self.manifest["source"]["commit"]
        self.pinned = dict(source_commit=self.source, run_id=42, run_attempt=1,
                           candidate_manifest_sha256=driver.digest(self.path))
        self.events, self.policy_paths = [], []
        self.policy_mode = "ok"
        self.attestation_ok = True
        self.metadata = dict(head_sha=self.source, head_branch="main", event="push",
                             conclusion="success", path=".github/workflows/ci.yml")
        self.native = driver.Native.__new__(driver.Native)
        self.native.args = SimpleNamespace(repository=fixtures.REPOSITORY, gh="fixture-gh")
        self.native.candidate = SimpleNamespace(
            MANIFEST_NAME=release_candidate.MANIFEST_NAME, validate_manifest=self.validate)
        self.native.run = self.github_run

    def github_run(self, argv, **kwargs):
        self.assertEqual(argv[0], "fixture-gh")
        self.assertTrue(kwargs["github"])
        if argv[1:3] == ["attestation", "verify"]:
            self.events.append("attestation")
            self.assertEqual(argv[3], self.path)
            self.assertIn("--deny-self-hosted-runners", argv)
            self.assertEqual(argv[argv.index("--source-digest") + 1], self.source)
            self.assertEqual(argv[argv.index("--source-ref") + 1], "refs/heads/main")
            if not self.attestation_ok:
                raise driver.Refused("attestation rejected")
            return SimpleNamespace(returncode=0, stdout=b"")
        if argv[1:3] == ["api", f"repos/{fixtures.REPOSITORY}/actions/runs/42/attempts/1"]:
            self.events.append("main-ci")
            return SimpleNamespace(returncode=0, stdout=json.dumps(self.metadata).encode())
        self.assertEqual(argv[1:], ["api", "-H", "Accept: application/vnd.github.raw+json",
            f"repos/{fixtures.REPOSITORY}/contents/security/dependency-audit-policy.json?ref={self.source}"])
        self.events.append("policy")
        if self.policy_mode == "missing":
            raise driver.Refused("historical policy unavailable")
        body = self.fixture.policy_path.read_bytes()
        if self.policy_mode == "empty": body = b""
        if self.policy_mode == "invalid": body = b"{"
        if self.policy_mode == "wrong": body = dependency_audit.DEFAULT_POLICY.read_bytes()
        return SimpleNamespace(returncode=0, stdout=body)

    def validate(self, **kwargs):
        path = kwargs.get("historical_audit_policy")
        if path is not None:
            self.policy_paths.append(path)
            self.assertNotEqual(path.parent, self.fixture.release)
            if self.policy_mode == "ok":
                self.assertEqual(path.read_bytes(), self.fixture.policy_path.read_bytes())
        return release_candidate.validate_manifest(**kwargs)

    def verify(self):
        return self.native.verified_manifest(self.pinned, self.fixture.release)

    def test_attested_old_candidate_survives_later_current_policy_change(self):
        original = {path.name: path.read_bytes() for path in self.fixture.release.iterdir()}
        self.assertNotEqual(self.fixture.policy_path.read_bytes(), dependency_audit.DEFAULT_POLICY.read_bytes())
        self.assertEqual(self.verify(), self.manifest)
        self.assertEqual(self.events, ["attestation", "main-ci", "policy"])
        self.assertEqual(len(self.policy_paths), 1)
        self.assertFalse(self.policy_paths[0].exists())
        self.assertEqual({path.name: path.read_bytes() for path in self.fixture.release.iterdir()}, original)

    def test_no_policy_fetch_before_attestation(self):
        self.attestation_ok = False
        with self.assertRaisesRegex(driver.Refused, "attestation rejected"):
            self.verify()
        self.assertEqual(self.events, ["attestation"])

    def test_no_policy_fetch_before_successful_exact_main_ci(self):
        for field, bad in (("head_sha", "b" * 40), ("head_branch", "topic"),
                           ("event", "pull_request"), ("conclusion", "failure"),
                           ("path", ".github/workflows/other.yml")):
            with self.subTest(field=field):
                original = self.metadata[field]
                self.metadata[field] = bad
                self.events.clear()
                with self.assertRaisesRegex(driver.Refused, "successful exact main CI"):
                    self.verify()
                self.assertEqual(self.events, ["attestation", "main-ci"])
                self.metadata[field] = original

    def test_source_pin_mismatch_stops_before_github(self):
        self.pinned["source_commit"] = "b" * 40
        with self.assertRaisesRegex(driver.Refused, "candidate source mismatch"):
            self.verify()
        self.assertEqual(self.events, [])

    def test_unavailable_malformed_or_wrong_policy_fails_closed(self):
        for mode in ("missing", "empty", "invalid", "wrong"):
            with self.subTest(mode=mode):
                self.policy_mode = mode
                with self.assertRaises((ValueError, driver.Refused)):
                    self.verify()
                self.assertTrue(all(not path.exists() for path in self.policy_paths))

    def test_tampered_candidate_file_still_fails_after_authentication(self):
        self.fixture.sbom_path.write_bytes(self.fixture.sbom_path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "candidate artifact hashes"):
            self.verify()
        self.assertEqual(self.events, ["attestation", "main-ci", "policy"])
        self.assertFalse(self.policy_paths[0].exists())

    def test_concurrent_verifications_use_independent_policy_files(self):
        successor = NativeCandidatePolicyTests()
        self.addCleanup(successor.doCleanups)
        # Construct distinct synthetic source identities before starting the
        # concurrent calls. Production module globals are never changed there.
        with mock.patch.object(fixtures, "SOURCE", "d" * 40):
            successor.setUp()
        self.assertNotEqual(self.source, successor.source)
        with ThreadPoolExecutor(max_workers=2) as executor:
            old = executor.submit(self.verify)
            new = executor.submit(successor.verify)
            self.assertEqual(old.result(), self.manifest)
            self.assertEqual(new.result(), successor.manifest)
        paths = self.policy_paths + successor.policy_paths
        self.assertEqual(len(set(paths)), 2)
        self.assertTrue(all(not path.exists() for path in paths))
