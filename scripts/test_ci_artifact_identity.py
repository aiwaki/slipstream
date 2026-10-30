"""Exercise the real signer/assembler heredocs without builds or network calls."""

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/ci.yml"
STEPS = {
    "signer": "Verify exact-run signing input and artifact digest",
    "assembly": "Bind downloaded artifacts to this exact run and source",
}


def embedded_verifier(kind):
    lines = WORKFLOW.read_text().splitlines()
    step = lines.index(f"      - name: {STEPS[kind]}")
    start = next(i for i in range(step, len(lines)) if lines[i].endswith("<<'PY'")) + 1
    end = lines.index("          PY", start)
    return compile("\n" * start + textwrap.dedent("\n".join(lines[start:end])),
                   str(WORKFLOW), "exec")


class CIArtifactIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.input_dir = root / "input"
        self.input_dir.mkdir()
        self.archive = self.input_dir / "Slipstream.app.tar.gz"
        self.archive.write_bytes(b"tiny fixture: never executed")
        self.manifest_path = self.input_dir / "signing-input.json"
        self.proof_path = root / "signing-proof.json"
        self.signature = root / "Slipstream.app.tar.gz.sig"
        self.signature.write_bytes(b"fixture signature")
        self.artifacts_path = root / "artifacts.json"
        self.environment = {
            "GITHUB_REPOSITORY": "example/slipstream",
            "GITHUB_REPOSITORY_ID": "1234",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "5678",
            "GITHUB_RUN_ATTEMPT": "2",
            "GITHUB_REF": "refs/heads/main",
            "ARTIFACT_NAME": "updater-signing-input-" + "a" * 40,
            "EXPECTED_ARTIFACT_ID": "102",
            "EXPECTED_ARTIFACT_DIGEST": "b" * 64,
            "SIGNING_INPUT_ARTIFACT_ID": "102",
            "SIGNING_INPUT_ARTIFACT_DIGEST": "b" * 64,
            "SIGNATURE_ARTIFACT_ID": "202",
            "SIGNATURE_ARTIFACT_DIGEST": "c" * 64,
            "PACKAGED_BUILD_ARTIFACT_ID": "302",
            "PACKAGED_BUILD_ARTIFACT_DIGEST": "d" * 64,
        }
        identity = {
            "repository": self.environment["GITHUB_REPOSITORY"],
            "source_commit": self.environment["GITHUB_SHA"],
            "workflow_run_id": 5678,
            "workflow_run_attempt": 2,
            "version": (ROOT / "VERSION").read_text().strip(),
        }
        archive_sha = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.manifest = {
            **identity,
            "schema_version": 1,
            "target": "aarch64-apple-darwin",
            "archive": {"name": self.archive.name, "sha256": archive_sha,
                        "size": self.archive.stat().st_size},
        }
        self.proof = {
            **identity,
            "archive_sha256": archive_sha,
            "signature_sha256": hashlib.sha256(self.signature.read_bytes()).hexdigest(),
            "signing_input_artifact_digest": "b" * 64,
        }
        self.artifacts = [self.artifact("updater-signing-input", 102, "b"),
                          self.artifact("updater-signature", 202, "c"),
                          self.artifact("packaged-app-build", 302, "d")]

    def artifact(self, prefix, identifier, digest):
        return {
            "id": identifier,
            "name": prefix + "-" + "a" * 40,
            "digest": "sha256:" + digest * 64,
            "expired": False,
            "workflow_run": {"id": 5678, "repository_id": 1234,
                             "head_repository_id": 1234, "head_branch": "main",
                             "head_sha": "a" * 40},
        }

    def execute(self, kind):
        self.manifest_path.write_text(json.dumps(self.manifest))
        self.proof_path.write_text(json.dumps(self.proof))
        self.artifacts_path.write_text(json.dumps({"artifacts": self.artifacts}))
        args = [self.manifest_path, self.archive]
        if kind == "assembly":
            args = [self.manifest_path, self.archive, self.proof_path, self.signature]
        args.append(self.artifacts_path)
        namespace = {"__name__": "__main__"}
        # The assembly reads VERSION only; its working directory remains this checkout.
        with mock.patch.dict(os.environ, self.environment, clear=True), \
                mock.patch.object(sys, "argv", ["embedded-verifier", *map(str, args)]):
            exec(embedded_verifier(kind), namespace)

    def add_prior_attempt_artifacts(self):
        prior = copy.deepcopy(self.artifacts)
        for artifact in prior:
            artifact["id"] -= 1
            artifact["digest"] = "sha256:" + "e" * 64
        self.artifacts = prior + self.artifacts

    def test_signer_accepts_current_id_among_same_name_attempts(self):
        self.add_prior_attempt_artifacts()
        self.execute("signer")

    def test_assembler_accepts_current_id_among_same_name_attempts(self):
        self.add_prior_attempt_artifacts()
        self.execute("assembly")

    def test_current_single_artifact_set_is_accepted(self):
        for kind in STEPS:
            with self.subTest(kind=kind):
                self.execute(kind)

    def test_selected_artifact_identity_errors_are_refused(self):
        original = copy.deepcopy(self.artifacts)
        mutations = {
            "wrong_id": lambda a: a.update(id=999),
            "boolean_id": lambda a: a.update(id=True),
            "wrong_name": lambda a: a.update(name="other"),
            "wrong_digest": lambda a: a.update(digest="sha256:" + "f" * 64),
            "expired": lambda a: a.update(expired=True),
            "missing_expiry": lambda a: a.pop("expired"),
            "wrong_run": lambda a: a["workflow_run"].update(id=999),
            "wrong_source": lambda a: a["workflow_run"].update(head_sha="f" * 40),
            "wrong_repository": lambda a: a["workflow_run"].update(repository_id=999),
            "foreign_head_repository": lambda a: a["workflow_run"].update(head_repository_id=999),
            "wrong_branch": lambda a: a["workflow_run"].update(head_branch="other"),
            "missing_workflow_run": lambda a: a.pop("workflow_run"),
        }
        for kind in STEPS:
            for index in (range(3) if kind == "assembly" else (0,)):
                for label, mutate in mutations.items():
                    with self.subTest(kind=kind, artifact=index, mutation=label):
                        self.artifacts = copy.deepcopy(original)
                        mutate(self.artifacts[index])
                        with self.assertRaises(SystemExit):
                            self.execute(kind)
        self.artifacts = original

    def test_duplicate_exact_id_is_refused(self):
        self.artifacts.append(copy.deepcopy(self.artifacts[0]))
        for kind in STEPS:
            with self.subTest(kind=kind), self.assertRaises(SystemExit):
                self.execute(kind)

    def test_missing_or_stale_trusted_id_is_refused(self):
        self.add_prior_attempt_artifacts()
        for kind, key in (("signer", "EXPECTED_ARTIFACT_ID"),
                          ("assembly", "SIGNING_INPUT_ARTIFACT_ID")):
            for value in ("", "not-an-id", "0", "101", "999"):
                with self.subTest(kind=kind, value=value):
                    with mock.patch.dict(self.environment, {key: value}):
                        with self.assertRaises(SystemExit):
                            self.execute(kind)

    def test_old_document_attempt_is_refused(self):
        for kind in STEPS:
            with self.subTest(kind=kind):
                self.manifest["workflow_run_attempt"] = 1
                with self.assertRaises(SystemExit):
                    self.execute(kind)
        self.manifest["workflow_run_attempt"] = 2

    def test_signature_and_packaged_build_id_must_match(self):
        for key in ("SIGNATURE_ARTIFACT_ID", "PACKAGED_BUILD_ARTIFACT_ID"):
            with self.subTest(key=key):
                with mock.patch.dict(self.environment, {key: "999"}):
                    with self.assertRaises(SystemExit):
                        self.execute("assembly")


class CIArtifactDownloadWiringTests(unittest.TestCase):
    def setUp(self):
        parts = re.split(r"(?m)^  ([a-z][a-z0-9-]*):\n",
                         WORKFLOW.read_text().split("\njobs:\n", 1)[1])
        self.jobs = dict(zip(parts[1::2], parts[2::2]))

    def consumers(self):
        for job, body in self.jobs.items():
            steps = re.split(r"(?m)^      - ", body)[1:]
            downloads = [step for step in steps if "uses: actions/download-artifact@" in step]
            if downloads:
                guards = [step for step in steps if step.startswith(
                    "name: Require trusted artifact IDs before download\n")]
                self.assertEqual(len(guards), 1, job)
                guard = guards[0]
                self.assertLess(steps.index(guard), min(steps.index(s) for s in downloads))
                bindings = dict(re.findall(
                    r"          ([A-Z_]+): \$\{\{ (needs\.[a-z-]+\.outputs\.[a-z-]+) \}\}", guard))
                script = textwrap.dedent(guard.split("        run: |\n", 1)[1])
                yield job, body, downloads, bindings, script

    def test_download_ids_bind_exact_producer_upload_outputs(self):
        count = 0
        consumers = list(self.consumers())
        self.assertEqual(len(consumers), 6)
        for job, body, downloads, bindings, _ in consumers:
            for step in downloads:
                with self.subTest(job=job, download=count):
                    count += 1
                    self.assertNotRegex(step, r"(?m)^          (name|pattern):")
                    self.assertIn("          digest-mismatch: error\n", step)
                    match = re.search(r"artifact-ids: \$\{\{ (needs\.([a-z-]+)\.outputs\.([a-z-]+)) \}\}", step)
                    self.assertIsNotNone(match)
                    ref, producer, output = match.groups()
                    self.assertIn(ref, bindings.values())
                    self.assertRegex(body, r"(?m)^    needs: \[[^\n]*\b" + re.escape(producer) + r"\b")
                    producer_body = self.jobs[producer]
                    upload = re.search(re.escape(output) + r": \$\{\{ steps\.([a-z-]+)\.outputs\.artifact-id \}\}", producer_body)
                    self.assertIsNotNone(upload)
                    self.assertRegex(producer_body, r"id: " + re.escape(upload.group(1)) + r"\n        uses: actions/upload-artifact@")
                    self.assertNotIn("overwrite: true", producer_body)
        self.assertEqual(count, 10)

    def test_actual_predownload_guards_reject_invalid_required_ids(self):
        bad_ids = ("", "not-an-id", "0", "-1", "1,2", "1x", " 1", "1\n2")
        for job, _, _, bindings, script in self.consumers():
            contexts = [("push", "refs/heads/main")]
            dual = job in ("packaged-browser-qualification", "packaged-app-lifecycle-heavy")
            if dual:
                contexts.append(("pull_request", "refs/pull/1/merge"))
            for event, ref in contexts:
                selected = (["CANDIDATE_ARTIFACT_ID" if event == "push" else "PACKAGED_BUILD_ARTIFACT_ID"]
                            if dual else list(bindings))
                environment = {key: "1234" for key in bindings}
                environment.update(GITHUB_EVENT_NAME=event, GITHUB_REF=ref)
                with self.subTest(job=job, event=event, valid=True):
                    result = subprocess.run(["/bin/bash", "-c", script], env=environment,
                                            capture_output=True, timeout=3)
                    self.assertEqual(result.returncode, 0, result.stderr)
                for key in selected:
                    for value in bad_ids:
                        with self.subTest(job=job, event=event, key=key, value=value):
                            result = subprocess.run(["/bin/bash", "-c", script],
                                                    env={**environment, key: value},
                                                    capture_output=True, timeout=3)
                            self.assertNotEqual(result.returncode, 0)
                if dual:
                    other = next(key for key in bindings if key not in selected)
                    with self.subTest(job=job, event=event, irrelevant_id_missing=True):
                        result = subprocess.run(["/bin/bash", "-c", script],
                                                env={**environment, other: ""},
                                                capture_output=True, timeout=3)
                        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
