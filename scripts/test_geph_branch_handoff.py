"""Execute the actual Geph bump shell against disposable local Git remotes."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/build-geph.yml"
REMOTE_REF = "refs/heads/automation/geph-0.4.3"


class GephBranchHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.remote = self.root / "remote.git"
        self.checkout = self.root / "checkout"
        self.checkout.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.templates = self.root / "empty-templates"
        self.templates.mkdir()
        self.trace = self.root / "trace"
        self.real_git = shutil.which("git")
        self.assertIsNotNone(self.real_git)
        routing_variables = {
            "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR",
            "BASH_ENV", "ENV",
        }
        self.env = {
            key: value for key, value in os.environ.items()
            if key not in routing_variables and not key.startswith("GIT_CONFIG")
        }
        # Confine Git configuration, hooks and transport without changing HOME.
        self.env.update(
            GIT_CONFIG_GLOBAL=os.devnull,
            GIT_TEMPLATE_DIR=str(self.templates),
            GIT_CONFIG_SYSTEM=os.devnull, GIT_CONFIG_NOSYSTEM="1",
            GIT_TERMINAL_PROMPT="0", GIT_ALLOW_PROTOCOL="file",
            GIT_CONFIG_COUNT="2", GIT_CONFIG_KEY_0="commit.gpgsign",
            GIT_CONFIG_VALUE_0="false", GIT_CONFIG_KEY_1="core.hooksPath",
            GIT_CONFIG_VALUE_1=os.devnull,
            REAL_GIT=self.real_git, TEST_REMOTE=str(self.remote),
            TEST_REF=REMOTE_REF, TEST_TRACE=str(self.trace),
            PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}",
        )
        self.git("init", "--bare", str(self.remote))
        self.git("init")
        self.git("checkout", "-b", "main")
        self.git("config", "user.name", "Fixture Human")
        self.git("config", "user.email", "fixture@example.invalid")
        for relative in ("vendor/geph/VERSION", "vendor/geph/SOURCE.json",
                         "vendor/geph/Cargo.lock",
                         "security/geph-dependency-audit-policy.json"):
            file = self.checkout / relative
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text("baseline\n")
        self.git("add", ".")
        self.git("commit", "-m", "fixture baseline")
        self.baseline = self.git("rev-parse", "HEAD")
        self.git("remote", "add", "origin", str(self.remote))
        self.git("push", "origin", "HEAD:refs/heads/main")
        (self.checkout / "reviewed-human-fix").write_text("preserve this fix\n")
        self.git("add", "reviewed-human-fix")
        self.git("commit", "-m", "human source qualification")
        self.human = self.git("rev-parse", "HEAD")
        # Make the commit available to the remote without creating the target ref.
        self.git("push", "origin", "HEAD:refs/heads/prepared-human-commit")
        self.git("reset", "--hard", self.baseline)
        self.env["TEST_HUMAN_OID"] = self.human
        self.script("git", '''#!/bin/bash
set -euo pipefail
if [ "${1:-}" = ls-remote ]; then
  if [ "${TEST_LOOKUP_FAIL:-}" = 1 ]; then exit 72; fi
  "$REAL_GIT" "$@"
  if [ "${TEST_CREATE_RACE:-}" = 1 ]; then
    "$REAL_GIT" --git-dir="$TEST_REMOTE" update-ref "$TEST_REF" "$TEST_HUMAN_OID"
  fi
else
  exec "$REAL_GIT" "$@"
fi
''')
        self.script("curl", '#!/bin/sh\necho curl >> "$TEST_TRACE"\n')
        self.script("python3", '''#!/bin/sh
set -eu
echo "python3 $*" >> "$TEST_TRACE"
if [ "${2:-}" = prepare ]; then
  printf 'candidate source contract\n' > vendor/geph/SOURCE.json
fi
''')
        self.script("gh", '''#!/bin/sh
set -eu
echo "gh $*" >> "$TEST_TRACE"
case "${1:-} ${2:-}" in
  "pr view") [ "${TEST_PR_EXISTS:-}" = 1 ] ;;
  "api --method")
    if [ "${TEST_PR_LOOKUP_FAIL:-}" = 1 ]; then exit 71; fi
    if [ "${TEST_PR_EXISTS:-}" = 1 ]; then echo 123; fi ;;
  "pr create") [ "${TEST_PR_CREATE_FAIL:-}" != 1 ] ;;
  "pr edit") echo 'unexpected PR description edit' >&2; exit 73 ;;
  *) exit 74 ;;
esac
''')

    def script(self, name: str, source: str) -> None:
        file = self.bin / name
        file.write_text(source)
        file.chmod(0o755)

    def git(self, *args: str) -> str:
        result = subprocess.run([self.real_git, *args], cwd=self.checkout,
                                env=self.env, text=True, capture_output=True,
                                timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def bump(self, **extra: str) -> subprocess.CompletedProcess[str]:
        section = WORKFLOW.read_text().split(
            "      - name: Open the reviewed-source update PR\n", 1)[1].split(
            "\n  build:", 1)[0]
        shell = section.split("        run: |\n", 1)[1]
        shell = "\n".join(line[10:] if line.startswith(" " * 10) else line
                          for line in shell.splitlines())
        replacements = {
            "${{ needs.resolve.outputs.version }}": "0.4.3",
            "${{ needs.resolve.outputs.crate_url }}": "https://fixture.invalid/geph.crate",
            "${{ needs.resolve.outputs.crate_sha256 }}": "a" * 64,
            "${{ github.repository }}": "fixture/slipstream",
            "${{ github.repository_owner }}": "fixture",
        }
        for token, value in replacements.items():
            shell = shell.replace(token, value)
        self.assertNotIn("${{", shell)
        return subprocess.run(["/bin/bash", "-c", shell], cwd=self.checkout,
                              env=dict(self.env, **extra), text=True,
                              capture_output=True, timeout=20)

    def remote_head(self) -> str:
        result = subprocess.run([self.real_git, "--git-dir", str(self.remote),
                                 "rev-parse", "--verify", REMOTE_REF],
                                env=self.env, capture_output=True, text=True,
                                timeout=10)
        return result.stdout.strip() if result.returncode == 0 else ""

    def trace_text(self) -> str:
        return self.trace.read_text() if self.trace.exists() else ""

    def test_absent_branch_created_from_candidate_and_pr_opened(self) -> None:
        result = self.bump()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.remote_head(), self.git("rev-parse", "HEAD"))
        self.assertNotEqual(self.remote_head(), self.baseline)
        self.assertIn("gh pr create", self.trace_text())
        self.assertNotIn("gh pr edit", self.trace_text())

    def test_existing_human_branch_preserved_before_materialization(self) -> None:
        self.git("push", "origin", f"{self.human}:{REMOTE_REF}")
        result = self.bump(TEST_PR_EXISTS="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.remote_head(), self.human)
        self.assertEqual(self.git("rev-parse", "HEAD"), self.baseline)
        self.assertIn("gh api --method GET repos/fixture/slipstream/pulls", self.trace_text())
        self.assertIn("head=fixture:automation/geph-0.4.3", self.trace_text())
        self.assertIn('select(.head.repo.full_name == "fixture/slipstream" and '
                      '.head.ref == "automation/geph-0.4.3")', self.trace_text())
        self.assertNotIn("gh pr create", self.trace_text())
        self.assertNotIn("gh pr edit", self.trace_text())
        self.assertNotIn("curl", self.trace_text())
        self.assertNotIn("python3", self.trace_text())

    def test_remote_lookup_failure_aborts_before_materialization(self) -> None:
        result = self.bump(TEST_LOOKUP_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.remote_head(), "")
        self.assertEqual(self.git("rev-parse", "HEAD"), self.baseline)
        self.assertEqual(self.trace_text(), "")

    def test_concurrent_branch_creation_never_overwrites_human_commit(self) -> None:
        result = self.bump(TEST_CREATE_RACE="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.remote_head(), self.human)
        self.assertNotEqual(self.git("rev-parse", "HEAD"), self.human)
        self.assertNotIn("gh pr", self.trace_text())
        self.assertIn("stale info", result.stderr)

    def test_existing_pr_description_not_rewritten_after_branch_creation(self) -> None:
        result = self.bump(TEST_PR_EXISTS="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotEqual(self.remote_head(), "")
        self.assertIn("gh pr view", self.trace_text())
        self.assertNotIn("gh pr edit", self.trace_text())
        self.assertNotIn("gh pr create", self.trace_text())

    def test_failed_pr_creation_replays_without_regenerating_candidate(self) -> None:
        first = self.bump(TEST_PR_CREATE_FAIL="1")
        self.assertNotEqual(first.returncode, 0)
        candidate = self.remote_head()
        self.assertNotEqual(candidate, "")
        self.trace.unlink()
        self.git("checkout", "main")
        replay = self.bump()
        self.assertEqual(replay.returncode, 0, replay.stderr)
        self.assertEqual(self.remote_head(), candidate)
        self.assertEqual(self.git("rev-parse", "HEAD"), self.baseline)
        trace = self.trace_text()
        self.assertIn("gh pr create", trace)
        self.assertIn("existing source candidate", trace)
        self.assertNotIn("gh pr edit", trace)
        self.assertNotIn("curl", trace)
        self.assertNotIn("python3", trace)

    def test_existing_branch_pr_lookup_failure_aborts_without_mutations(self) -> None:
        self.git("push", "origin", f"{self.human}:{REMOTE_REF}")
        result = self.bump(TEST_PR_LOOKUP_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.remote_head(), self.human)
        self.assertEqual(self.git("rev-parse", "HEAD"), self.baseline)
        trace = self.trace_text()
        self.assertIn("gh api --method GET", trace)
        self.assertNotIn("gh pr create", trace)
        self.assertNotIn("gh pr edit", trace)
        self.assertNotIn("curl", trace)
        self.assertNotIn("python3", trace)


class AmbientGitEnvironmentTests(unittest.TestCase):
    def test_ambient_git_routing_and_config_cannot_escape_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            outside = Path(temporary) / "must-remain-absent"
            template = Path(temporary) / "external-template"
            template.mkdir()
            (template / "template-marker").write_text("must not be inherited\n")
            shell_env = Path(temporary) / "shell-env"
            shell_env.write_text('echo "unexpected ambient shell init" >&2; exit 87\n')
            poisoned = {key: str(outside) for key in (
                "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
                "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR",
                "GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM")}
            poisoned.update(GIT_CONFIG_COUNT="3", GIT_CONFIG_KEY_2="core.worktree",
                            GIT_CONFIG_VALUE_2=str(outside),
                            GIT_TEMPLATE_DIR=str(template),
                            BASH_ENV=str(shell_env), ENV=str(shell_env))
            original_home = os.environ.get("HOME")
            with mock.patch.dict(os.environ, poisoned):
                case = GephBranchHandoffTests(
                    "test_absent_branch_created_from_candidate_and_pr_opened")
                try:
                    case.setUp()
                    self.assertFalse((case.checkout / ".git/template-marker").exists())
                    self.assertFalse((case.remote / "template-marker").exists())
                    self.assertEqual(case.env.get("HOME"), original_home)
                    case.test_absent_branch_created_from_candidate_and_pr_opened()
                finally:
                    case.doCleanups()
            self.assertFalse(outside.exists())


if __name__ == "__main__":
    unittest.main()
