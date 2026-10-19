#!/usr/bin/env python3
"""Build a disposable-CI trigger around authenticated OLD updater source.

This creates a separate binary, never changes an app bundle, and never runs an
installer. Only the binary's explicit --prepare operation starts a transaction.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from types import SimpleNamespace

from native_root_update import Native, digest, document, guard, modules, require


BIN = "slipstream-packaged-update-trigger"
MODULES = ("app_update", "install_attestation", "updater_transaction", "daemon_update")


def pins(value):
    require(set(value) == {"schema_version", "old", "new"} and value["schema_version"] == 1,
            "invalid pair schema")
    for side in ("old", "new"):
        item = value[side]
        require(set(item) == {"source_commit", "candidate_manifest_sha256", "run_id", "run_attempt"},
                "invalid candidate pin schema")
        for field, length in (("source_commit", 40), ("candidate_manifest_sha256", 64)):
            require(isinstance(item[field], str) and re.fullmatch("[0-9a-f]{" + str(length) + "}", item[field]),
                    "full candidate digest required")
        require(all(type(item[k]) is int and item[k] > 0 for k in ("run_id", "run_attempt")),
                "positive exact run/attempt required")
    require(value["old"]["source_commit"] != value["new"]["source_commit"]
            and value["old"]["run_id"] != value["new"]["run_id"], "distinct candidate builds required")
    return value


def crate_manifest(source, old):
    """Keep OLD's locked dependency graph, but no product binary/lib/build.rs."""
    sections = re.split(r"(?m)^(?=\[)", source)
    kept = [part for part in sections if not part.startswith(("[lib]", "[[bin]]"))]
    text = "".join(kept)
    require(text.count("[package]\n") == 1, "package section missing")
    require(not re.search(r"(?m)^\s*(?:build|autobins)\s*=", text), "unexpected package build override")
    text = text.replace("[package]\n", "[package]\nbuild = false\nautobins = false\n", 1)
    core = 'slipstream-core = { path = "../../crates/slipstream-core" }'
    require(text.count(core) == 1, "OLD core dependency shape changed")
    text = text.replace(core, "slipstream-core = { path = " + json.dumps(str(old / "crates/slipstream-core")) + " }")
    return text + '\n[[bin]]\nname = "' + BIN + '"\npath = "bridge.rs"\n'


def bridge_source(old, trigger, plan, public_key):
    lines = []
    for name in MODULES[:-1]:
        lines += ["#[allow(dead_code)]", "#[path = " + json.dumps(str(old / "app-tauri/src-tauri/src" / (name + ".rs"))) + "]",
                  "mod " + name + ";"]
    lines += ["const OLD_PUBLIC_KEY: &str = " + json.dumps(public_key) + ";",
              "const PINNED_PLAN: &str = include_str!(" + json.dumps(str(plan)) + ");",
              "#[path = " + json.dumps(str(trigger)) + "]", "mod trigger;",
              "fn main() { trigger::main(); }", ""]
    return "\n".join(lines)


def git(old, *args):
    return subprocess.run(["git", "-C", str(old), *args], check=True, capture_output=True, timeout=30).stdout


def verified_source(old, manifest):
    require(git(old, "rev-parse", "HEAD").decode().strip() == manifest["source"]["commit"], "OLD checkout SHA mismatch")
    require(git(old, "rev-parse", "HEAD^{tree}").decode().strip() == manifest["source"]["tree"], "OLD checkout tree mismatch")
    require(not git(old, "status", "--porcelain", "--untracked-files=no"), "OLD tracked checkout is dirty")
    paths = ["app-tauri/src-tauri/src/" + name + ".rs" for name in MODULES]
    paths += ["app-tauri/src-tauri/" + name for name in ("Cargo.toml", "Cargo.lock", "tauri.conf.json")]
    paths += git(old, "ls-files", "crates/slipstream-core", "contracts", "app-tauri/src-tauri/tests").decode().splitlines()
    hashes = {}
    for relative in sorted(set(paths)):
        expected = hashlib.sha256(git(old, "show", "HEAD:" + relative)).hexdigest()
        require(digest(old / relative) == expected, "OLD source bytes changed: " + relative)
        hashes[relative] = expected
    return hashes


def exclusive(path, content):
    with path.open("x", encoding="utf-8") as stream:
        os.chmod(path, 0o600)
        stream.write(content)


def write_crate(output, old, trigger, plan, public_key):
    output.mkdir(mode=0o700)  # A previous run must never be reused implicitly.
    exclusive(output / "pinned-plan.json", json.dumps(plan, indent=2) + "\n")
    exclusive(output / "Cargo.toml", crate_manifest((old / "app-tauri/src-tauri/Cargo.toml").read_text(), old))
    exclusive(output / "Cargo.lock", (old / "app-tauri/src-tauri/Cargo.lock").read_text())
    exclusive(output / "bridge.rs", bridge_source(old, trigger, output / "pinned-plan.json", public_key))


def build(args):
    uid = guard()
    repo, old = args.repo.resolve(strict=True), args.old_source.resolve(strict=True)
    temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    output = args.output_dir.absolute()
    require(output.parent.resolve(strict=True) == temp and not output.exists() and not output.is_symlink(),
            "new output directory directly under RUNNER_TEMP required")
    output = temp / output.name
    pair_path = args.pair_manifest.resolve(strict=True)
    pair = pins(document(pair_path))
    pair_hash = digest(pair_path)
    tproxy, candidate = modules(repo)
    backend = Native(SimpleNamespace(repo=repo, repository=os.environ["GITHUB_REPOSITORY"], gh=args.gh), uid, tproxy, candidate)
    artifacts, manifests = {}, {}
    for side in ("old", "new"):
        directory = getattr(args, side + "_candidate_dir").resolve(strict=True)
        app = getattr(args, side + "_app").resolve(strict=True)
        artifacts[side] = backend.artifact(side, pair[side], app, directory)
        manifests[side] = {"path": str(directory / candidate.MANIFEST_NAME),
                           "sha256": pair[side]["candidate_manifest_sha256"]}
    require(artifacts["old"]["version"] != artifacts["new"]["version"], "distinct candidate versions required")
    for key in ("app_executable_sha256", "daemon_sha256"):
        require(artifacts["old"][key] != artifacts["new"][key], "candidate " + key + " is unchanged")
    old_manifest = document(Path(manifests["old"]["path"]))
    source_hashes = verified_source(old, old_manifest)
    config = document(old / "app-tauri/src-tauri/tauri.conf.json")
    public_key = config["plugins"]["updater"]["pubkey"]
    require(isinstance(public_key, str) and public_key, "OLD updater key missing")
    trigger = repo / "scripts/packaged_update_trigger.rs"
    trigger_hash = digest(trigger)
    new_dir = args.new_candidate_dir.resolve(strict=True)
    plan = {"schema_version": 1, "uid": uid, "runner_temp": str(temp), "output_dir": str(output),
            "pair": {"path": str(pair_path), "sha256": pair_hash}, "manifests": manifests,
            "archive_path": str(new_dir / "Slipstream.app.tar.gz"),
            "signature": {"path": str(new_dir / "Slipstream.app.tar.gz.sig"),
                          "sha256": digest(new_dir / "Slipstream.app.tar.gz.sig")},
            "expected": artifacts}
    write_crate(output, old, trigger, plan, public_key)
    generated = {name: digest(output / name) for name in ("Cargo.toml", "Cargo.lock", "bridge.rs", "pinned-plan.json")}
    env = dict(os.environ)
    for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"):
        env.pop(name, None)
    env.update(CARGO_BUILD_JOBS="2", CARGO_TARGET_DIR=str(output / "target"))
    base = ["cargo", "--locked", "--manifest-path", str(output / "Cargo.toml"), "--bin", BIN]
    # The crate and tests exist only on the disposable runner. No installer,
    # daemon, launchctl, app, or --prepare invocation belongs to this builder.
    with (output / "build.log").open("x") as log:
        for command in ([base[0], "build", *base[1:]], [base[0], "test", *base[1:], "trigger::tests::"]):
            subprocess.run(command, cwd=output, env=env, stdout=log, stderr=subprocess.STDOUT,
                           check=True, timeout=1200)
    require(verified_source(old, old_manifest) == source_hashes, "OLD source changed during build")
    require(digest(trigger) == trigger_hash, "trigger source changed during build")
    require(all(digest(output / name) == value for name, value in generated.items()), "generated inputs changed during build")
    require(digest(pair_path) == pair_hash and all(digest(Path(p["path"])) == p["sha256"] for p in manifests.values()),
            "authenticated pair changed during build")
    receipt = {"schema_version": 1, "built": True, "pair": pair, "pair_sha256": pair_hash,
               "old_source_sha256": source_hashes, "trigger_sha256": trigger_hash, "generated_sha256": generated,
               "binary": str(output / "target/debug" / BIN), "binary_sha256": digest(output / "target/debug" / BIN),
               "qualification_scope": "production prepare -> packaged OLD watchdog -> real successor ACK",
               "not_qualified": ["release discovery", "old tray exit", "administrator dialog", "transaction outcome"]}
    exclusive(output / "build-receipt.json", json.dumps(receipt, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "old-source", "pair-manifest", "old-candidate-dir", "new-candidate-dir", "old-app", "new-app", "output-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--gh", required=True)
    build(parser.parse_args())


if __name__ == "__main__":
    main()
