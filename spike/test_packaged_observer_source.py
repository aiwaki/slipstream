"""Real temporary Git histories; no installed applications or network."""
from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from verify_packaged_observer_source import verify_source


@pytest.fixture
def history(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*args):
        return subprocess.run(["git", "-C", str(repo), *args], check=True,
                              capture_output=True, timeout=10).stdout.decode().strip()

    def write(path, text="initial\n"):
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        return target

    def commit():
        git("add", ".")
        git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
            "-c", "commit.gpgsign=false", "commit", "-m", "fixture")
        return git("rev-parse", "HEAD")

    git("init", "-b", "main")
    write("scripts/packaged_update_observer.py")
    write("app-tauri/src-tauri/src/updater_transaction.rs")
    base = commit()
    env = {"GITHUB_SHA": base, "GITHUB_REF": "refs/heads/main",
           "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REPOSITORY": "aiwaki/slipstream",
           "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2"}
    return repo, git, write, commit, base, env


def test_exact_candidate_and_observer_descendant_keep_distinct_provenance(history):
    repo, git, write, commit, base, env = history
    exact = verify_source(repo, base, env)
    assert exact["changes"] == []
    write("scripts/packaged_update_observer.py", "fixed observer\n")
    write("spike/test_packaged_observer_source.py")
    env["GITHUB_SHA"] = commit()
    proof = verify_source(repo, base, env)
    assert proof["candidate_new_source_sha"] == base
    assert proof["harness_source_sha"] == env["GITHUB_SHA"] != base
    assert proof["harness_tree_sha"] == git("rev-parse", "HEAD^{tree}")
    assert proof["harness_run_id"] == "123" and proof["harness_run_attempt"] == "2"
    assert {change["status"] for change in proof["changes"]} == {"A", "M"}
    assert proof["candidate_inputs_unchanged"]
    assert proof["diff_sha256"] != exact["diff_sha256"]


@pytest.mark.parametrize("path", [
    "app-tauri/src-tauri/src/updater_transaction.rs", "VERSION", "spike/requirements.txt",
    "scripts/materialize_pair.py", "scripts/build_packaged_update_trigger.py",
    ".github/workflows/native-root-update-qualification.yml", "scripts/qualify_candidate.py",
])
def test_product_dependencies_materializer_trigger_and_root_gate_changes_refuse(history, path):
    repo, _, write, commit, base, env = history
    write(path, "changed\n")
    env["GITHUB_SHA"] = commit()
    with pytest.raises(ValueError, match="runtime/build input changed"):
        verify_source(repo, base, env)


@pytest.mark.parametrize("kind", ["delete", "rename", "executable", "symlink"])
def test_allowed_paths_cannot_be_removed_replaced_or_change_mode(history, kind):
    repo, _, _, commit, base, env = history
    source = repo / "scripts/packaged_update_observer.py"
    if kind == "delete":
        source.unlink()
    elif kind == "rename":
        source.rename(repo / "scripts/packaged_update_preack.py")
    elif kind == "executable":
        source.chmod(0o755)
    else:
        source.unlink()
        source.symlink_to("untrusted.py")
    env["GITHUB_SHA"] = commit()
    with pytest.raises(ValueError, match="removal/rename|mode changed"):
        verify_source(repo, base, env)


@pytest.mark.parametrize("key,value", [
    ("GITHUB_SHA", "f" * 40), ("GITHUB_SHA", "abc"), ("GITHUB_REF", "refs/heads/feature"),
    ("GITHUB_EVENT_NAME", "pull_request"), ("GITHUB_REPOSITORY", "other/slipstream"),
    ("GITHUB_RUN_ID", ""), ("GITHUB_RUN_ATTEMPT", "0"),
])
def test_workflow_identity_is_mandatory(history, key, value):
    repo, _, _, _, base, env = history
    env[key] = value
    with pytest.raises(ValueError):
        verify_source(repo, base, env)


@pytest.mark.parametrize("staged", [False, True])
def test_dirty_allowed_bytes_refuse_even_after_preflight(history, staged):
    repo, git, write, _, base, env = history
    verify_source(repo, base, env)
    write("scripts/packaged_update_observer.py", "uncommitted\n")
    if staged:
        git("add", ".")
    with pytest.raises(ValueError, match="dirty"):
        verify_source(repo, base, env)


def test_candidate_must_be_ancestor_not_a_sibling(history):
    repo, git, write, commit, base, env = history
    write("scripts/packaged_update_observer.py", "sibling\n")
    sibling = commit()
    git("checkout", "--detach", base)
    write("scripts/packaged_update_preack.py")
    env["GITHUB_SHA"] = commit()
    with pytest.raises(subprocess.CalledProcessError):
        verify_source(repo, sibling, env)


def test_missing_candidate_object_refuses(history):
    repo, _, _, _, _, env = history
    with pytest.raises(subprocess.CalledProcessError):
        verify_source(repo, "f" * 40, env)
