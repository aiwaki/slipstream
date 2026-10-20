#!/usr/bin/env python3
"""Bind an audited observer revision to unchanged signed candidate inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


ALLOWED = frozenset({
    "scripts/verify_packaged_observer_source.py",
    "scripts/packaged_update_observer.py",
    "scripts/packaged_update_preack.py",
    "scripts/qualify_packaged_update_commit.py",
    "spike/test_packaged_observer_source.py",
    "spike/test_packaged_update_observer.py",
    "spike/test_packaged_update_preack.py",
    "spike/test_packaged_update_commit.py",
    "spike/test_preack_workflow_wiring.py",
    ".github/workflows/packaged-update-commit-qualification.yml",
    "docs/CURRENT_STATE.md", "docs/RELEASES.md", "docs/DECISIONS.md",
})
# These files also authenticate candidates and install/clean up applications.
# A path allowance alone is insufficient: only this reviewed observer wiring
# delta may be reused. Future changes need an explicit reviewed pin update.
PINNED_SHA256 = {
    "scripts/qualify_packaged_update_commit.py":
        "98847f0553e373332b1802c2acee0a43bdd6c7313bdb6cd6224e494f890514b3",
    ".github/workflows/packaged-update-commit-qualification.yml":
        "c06565887ff3d2aa003a81c59c86c29de15f8e4134729bfd3f5181d2b4fbc16f",
}


def verify_source(repo, candidate_source, env=None):
    env = os.environ if env is None else env

    def require(ok, reason):
        if not ok:
            raise ValueError(reason)

    def git(*args):
        return subprocess.run(["git", "-C", str(repo), *args], check=True,
                              capture_output=True, timeout=15).stdout

    harness = env.get("GITHUB_SHA", "")
    require(all(re.fullmatch(r"[0-9a-f]{40}", value) for value in
                (candidate_source, harness)), "full candidate and harness SHA required")
    require(env.get("GITHUB_REF") == "refs/heads/main"
            and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and env.get("GITHUB_REPOSITORY") == "aiwaki/slipstream",
            "observer qualification requires the repository main workflow")
    require(all(re.fullmatch(r"[1-9][0-9]*", env.get(name, "")) for name in
                ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")), "positive harness run and attempt required")
    require(git("rev-parse", "HEAD").decode().strip() == harness,
            "harness checkout differs from workflow SHA")
    require(not git("status", "--porcelain=v1", "--untracked-files=no", "-z"),
            "harness tracked checkout is dirty")
    # The bounded workflow checkout must contain the complete ancestry to NEW.
    # A missing/shallow object fails; it never substitutes an unproven base.
    git("merge-base", "--is-ancestor", candidate_source, harness)
    raw = git("diff", "--raw", "--no-abbrev", "--no-renames", "-z",
              candidate_source, harness, "--")
    require(len(raw) <= 32768, "observer diff exceeds the bounded source allowance")
    parts = raw.split(b"\0")
    require(parts[-1] == b"" and (len(parts) - 1) % 2 == 0, "malformed source diff")
    changes = []
    for index in range(0, len(parts) - 1, 2):
        old_mode, new_mode, old_blob, new_blob, status = parts[index].decode("ascii").lstrip(":").split()
        path = parts[index + 1].decode("utf-8")
        require(path in ALLOWED, "candidate runtime/build input changed: " + path)
        require(status in {"A", "M"}, "observer source removal/rename is not allowed")
        require(new_mode == "100644" and (status == "A" or old_mode == new_mode),
                "observer source mode changed or is not a regular data file")
        if path in PINNED_SHA256:
            require(hashlib.sha256(git("cat-file", "blob", new_blob)).hexdigest() == PINNED_SHA256[path],
                    "candidate handling differs from reviewed observer wiring: " + path)
        changes.append({"path": path, "status": status, "old_blob": old_blob,
                        "new_blob": new_blob, "mode": new_mode})
    return {"schema_version": 1, "candidate_new_source_sha": candidate_source,
            "harness_source_sha": harness,
            "harness_run_id": env["GITHUB_RUN_ID"],
            "harness_run_attempt": env["GITHUB_RUN_ATTEMPT"],
            "harness_tree_sha": git("rev-parse", "HEAD^{tree}").decode().strip(),
            "diff_sha256": hashlib.sha256(raw).hexdigest(), "changes": changes,
            "candidate_inputs_unchanged": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--candidate-source", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    proof = verify_source(args.repo, args.candidate_source)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(proof, stream, indent=2, sort_keys=True)
        stream.write("\n")


if __name__ == "__main__":
    main()
