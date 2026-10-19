#!/usr/bin/env python3
"""Authenticate downloaded exact-main candidates before ordinary ditto extraction."""
import argparse
import json
import os
from pathlib import Path
import re
from types import SimpleNamespace

from native_root_update import Native, guard, modules, require


def pins_from_environment(env):
    pins = {"schema_version": 1}
    for side in ("old", "new"):
        prefix = side.upper() + "_"
        source, manifest = env[prefix + "SOURCE_SHA"], env[prefix + "MANIFEST_SHA"]
        require(re.fullmatch(r"[0-9a-f]{40}", source), "full source SHA required")
        require(re.fullmatch(r"[0-9a-f]{64}", manifest), "full manifest SHA256 required")
        run, attempt = env[prefix + "RUN_ID"], env[prefix + "RUN_ATTEMPT"]
        require(re.fullmatch(r"[1-9][0-9]*", run) and re.fullmatch(r"[1-9][0-9]*", attempt), "positive run/attempt required")
        pins[side] = {"source_commit": source, "candidate_manifest_sha256": manifest,
                      "run_id": int(run), "run_attempt": int(attempt)}
    require(pins["old"]["source_commit"] != pins["new"]["source_commit"], "two distinct source builds required")
    require(pins["old"]["run_id"] != pins["new"]["run_id"], "two distinct CI runs required")
    return pins


def materialize(backend, pins, root):
    results = []
    for side in ("old", "new"):
        directory, destination = root / (side + "-candidate"), root / (side + "-app")
        manifest = backend.verified_manifest(pins[side], directory)
        destination.mkdir()  # Never merge an extraction with an existing tree.
        backend.run(["/usr/bin/ditto", "-x", "-k", directory / "Slipstream-macos-arm64.zip", destination], timeout=60)
        app = destination / "Slipstream.app"
        require(backend.candidate.deterministic_tree_sha256(app) == manifest["app_tree_sha256"], "extracted app differs from authenticated candidate")
        results.append({"side": side, "candidate_id": manifest["candidate_id"], "app_tree_sha256": manifest["app_tree_sha256"]})
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--gh", required=True)
    args = parser.parse_args()
    uid = guard()
    root, repo = args.root.resolve(strict=True), args.repo.resolve(strict=True)
    require(root.parent == Path(os.environ["RUNNER_TEMP"]).resolve(), "candidate root must be directly under RUNNER_TEMP")
    result = {"materialized": False}
    try:
        pins = pins_from_environment(os.environ)
        with (root / "pair.json").open("x") as stream:
            json.dump(pins, stream, indent=2)
        tproxy, candidate = modules(repo)
        backend = Native(SimpleNamespace(repo=repo, repository=os.environ["GITHUB_REPOSITORY"], gh=args.gh), uid, tproxy, candidate)
        result["candidates"] = materialize(backend, pins, root)
        result["materialized"] = True
    except Exception as error:
        result["error"] = str(error)
        raise
    finally:
        with (root / "materialization.json").open("x") as stream:
            json.dump(result, stream, indent=2)


if __name__ == "__main__":
    main()
