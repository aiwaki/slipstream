#!/usr/bin/env python3
"""Normal signed CI .29 tray -> published .30 on an isolated hosted macOS runner.

This exercises real background discovery, AXPress and the app's own privileged
preparation. It never invokes a prepare hook, changes the candidate or supplies
an administrator password. Unknown outcomes are retained for runner disposal.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from build_packaged_update_trigger import pins
from native_root_update import Native, Refused, digest, document, guard, modules, require
from packaged_update_observer import exact_equal, same_process
from public_update_menu_smoke import PublicMenu, VERSION
from public_update_observer import PublicObserver, PublicPreAckObserver
from qualify_packaged_update_commit import cleanup_committed, install_old, prerequisite


NEW_SOURCE = "86dd9393f671120f9ad6adb887ebb0e29d56467b"
PAIR = {"schema_version": 1,
    "old": {"source_commit": "4c6209e3a0ceb1c099ec9f7ff63b2782aa410c37", "run_id": 39412657264, "run_attempt": 1,
            "candidate_manifest_sha256": "9dbac35693cddbf8d1c86eaead4586c18d665402ab1e76b7a38a2991fcbc7238"},
    "new": {"source_commit": NEW_SOURCE, "run_id": 39414812044, "run_attempt": 1,
            "candidate_manifest_sha256": "63215717ad7fa005ecf44fc1355160acb0af2cad7d759be191a043b5a1c01954"}}
REUSED = ("native_root_update.py", "packaged_update_observer.py", "packaged_update_preack.py",
          "qualify_packaged_update_commit.py", "build_packaged_update_trigger.py", "verify_packaged_observer_source.py")


def source_binding(backend):
    qualified = backend.args.repo
    harness = Path(__file__).resolve().parents[1]
    def git(root, *args):
        return backend.run(["/usr/bin/git", "-C", root, *args]).stdout
    require(git(qualified, "rev-parse", "HEAD").decode().strip() == NEW_SOURCE
            and not git(qualified, "status", "--porcelain", "--untracked-files=no"), "qualified product source changed")
    harness_sha = git(harness, "rev-parse", "HEAD").decode().strip()
    require(re.fullmatch(r"[a-f0-9]{40}", harness_sha) and harness_sha == os.environ.get("GITHUB_SHA")
            and not git(harness, "status", "--porcelain", "--untracked-files=no"), "harness source changed")
    hashes = {}
    for name in REUSED:
        relative = "scripts/" + name
        expected = hashlib.sha256(git(qualified, "show", NEW_SOURCE + ":" + relative)).hexdigest()
        require(digest(qualified / relative) == expected and digest(harness / relative) == expected,
                "shared qualification helper differs from qualified source: " + name)
        hashes[relative] = expected
    public = ("public_update_ax.py", "public_update_ui_preflight.py", "public_update_menu_smoke.py",
              "public_update_observer.py", "public_update_pair_smoke.py", "public_update_visibility.py")
    for name in public:
        relative = "scripts/" + name
        expected = hashlib.sha256(git(harness, "show", harness_sha + ":" + relative)).hexdigest()
        require(digest(harness / relative) == expected, "public harness bytes changed")
        hashes[relative] = expected
    return {"harness_source": harness_sha, "qualified_product_source": NEW_SOURCE, "sha256": hashes}


def public_binding(backend):
    args = backend.args
    require(args.repository == "aiwaki/slipstream", "fixed public repository required")
    # Canonical publication verifier binds all release IDs/asset hashes/URLs/tag.
    command = [sys.executable, args.repo / "scripts/verify_published_release.py",
        "--release-metadata", args.public_release_metadata, "--tag-ref", args.public_tag_ref,
        "--release-dir", args.public_dir, "--repository", args.repository, "--version", VERSION,
        "--tag", "v" + VERSION, "--channel", "preview", "--release-name", "Slipstream " + VERSION,
        "--source-commit", NEW_SOURCE, "--target", "aarch64-apple-darwin", "--release-id", "418378834", "--state", "published"]
    verified = json.loads(backend.run(command, timeout=90).stdout)
    manifest = document(args.new_candidate_dir / "release-candidate-manifest.json")
    names = ["release-candidate-manifest.json"] + [item["name"] for item in manifest["artifacts"]]
    require(len(names) == 7 and len(set(names)) == 7
            and all(Path(name).name == name for name in names), "candidate inventory changed")
    for name in names:
        require(digest(args.new_candidate_dir / name) == digest(args.public_dir / name),
                "NEW candidate is not the published payload: " + name)
    appcast = document(args.public_dir / "latest.json")
    platform = appcast.get("platforms", {}).get("darwin-aarch64", {})
    base = f"https://github.com/{args.repository}/releases/download/v{VERSION}/"
    require(appcast.get("version") == VERSION and platform.get("url") == base + "Slipstream.app.tar.gz"
            and platform.get("signature") == (args.public_dir / "Slipstream.app.tar.gz.sig").read_text().strip(),
            "public appcast endpoint/signature mismatch")
    return {"release": verified, "public_release_metadata_sha256": digest(args.public_release_metadata),
            "public_tag_ref_sha256": digest(args.public_tag_ref), "appcast_sha256": digest(args.public_dir / "latest.json"),
            "endpoint": base + "latest.json", "archive_url": platform["url"],
            "archive_sha256": backend.expected["new"]["archive_sha256"],
            "old_origin": "authenticated CI candidate, not a public .29 release",
            "endpoint_network_capture": False}


def cleanup_before_click(backend):
    require(not backend.click_attempted and backend.identity is None, "pending public action prevents cleanup")
    if backend.old_launch_attempted:
        require(hasattr(backend, "original_process") and backend.initiator is not None,
                "OLD launch outcome unknown; runner disposal required")
        child = backend.original_process
        if child.poll() is None:
            require(same_process(backend.initiator, backend.process_snapshot(child.pid))
                    and digest(backend.target / "Contents/MacOS/slipstream") == backend.expected["old"]["app_executable_sha256"],
                    "pre-click cleanup OLD identity changed")
            child.terminate()  # Owned fixture cleanup, never the qualified OLD update exit.
            child.wait(timeout=10)
        require(backend.process_snapshot(child.pid) is None, "OLD process remains/reused before cleanup")
    Native.teardown(backend)


def drive(backend):
    from public_update_visibility import PublicUpdateVisibility
    install_old(backend)
    backend.menu = PublicMenu(backend)
    backend.visibility = PublicUpdateVisibility()
    backend.visibility.start()
    backend.visibility.set_phase("discovery")
    backend.menu.launch()
    backend.menu.discover()
    backend.visibility.set_phase("interaction")
    backend.menu.press()
    qualified = backend.qualify_app()
    backend.transaction_observed = True
    backend.menu.finish_click()
    backend.visibility.set_phase("terminal")
    require(backend.original_exited, "original normal app exit was not observed")
    return {**qualified, "public_update_transaction_qualified": True, "normal_old_update_exit_qualified": True,
            "public_discovery_qualified": True, "production_authorization_completed": True,
            "administrator_dialog_interaction_qualified": False, "normal_quit_qualified": False,
            "notification_delivery_qualified": False, "public_pair_qualified": False}


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repo", "pair-manifest", "old-candidate-dir", "new-candidate-dir", "old-app", "new-app",
                 "root-gate-dir", "public-dir", "public-release-metadata", "public-tag-ref", "output-dir"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--root-gate-run-id", type=int, required=True)
    parser.add_argument("--root-gate-attempt", type=int, required=True)
    parser.add_argument("--gh", required=True)
    parser.add_argument("--repository", default="aiwaki/slipstream")
    parser.add_argument("--mode", choices=("commit", "kill-successor-before-ack"), default="commit")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    uid = guard()
    os.umask(0o077)
    temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    for name in ("repo", "pair_manifest", "old_candidate_dir", "new_candidate_dir", "old_app", "new_app",
                 "root_gate_dir", "public_dir", "public_release_metadata", "public_tag_ref"):
        setattr(args, name, getattr(args, name).resolve(strict=True))
    args.output_dir = args.output_dir.absolute()
    require(args.output_dir.parent == temp and not os.path.lexists(args.output_dir), "new direct RUNNER_TEMP output required")
    require((args.root_gate_run_id, args.root_gate_attempt) == (39417619778, 1), "fixed root prerequisite required")
    args.output_dir.mkdir(mode=0o700)
    args.output = args.output_dir / "public-update-result.json"
    tproxy, candidate = modules(args.repo)
    backend = (PublicObserver if args.mode == "commit" else PublicPreAckObserver)(args, uid, tproxy, candidate)
    backend.old_launch_attempted = backend.click_attempted = backend.transaction_observed = False
    backend.visibility = None
    result = {"schema_version": 2, "status": "failed", "mode": args.mode,
              "public_pair_qualified": False, "public_update_transaction_qualified": False,
              "transaction_observed": False, "cleanup_errors": [],
              "not_qualified": ["visible administrator dialog interaction", "notification delivery/removal",
                                "normal Quit", "browser routing", "other updater fault windows"]}
    with args.output.open("x") as stream:
        try:
            pair = pins(document(args.pair_manifest))
            require(exact_equal(pair, PAIR), "public qualification pair differs from pinned .29 -> .30")
            result["source_binding"] = source_binding(backend)
            for side in ("old", "new"):
                backend.expected[side] = backend.artifact(side, pair[side], getattr(args, side + "_app"),
                                                           getattr(args, side + "_candidate_dir"))
            result["public_release"] = public_binding(backend)
            metadata = json.loads(backend.run([args.gh, "api",
                f"repos/{args.repository}/actions/runs/{args.root_gate_run_id}/attempts/{args.root_gate_attempt}"], github=True).stdout)
            result["root_prerequisite"] = prerequisite(metadata, args.root_gate_dir, pair, backend.expected,
                                                       args.root_gate_run_id, args.root_gate_attempt)
            require(exact_equal(result["source_binding"], source_binding(backend)), "source changed before installation")
            result.update(drive(backend), status="passed")
        except Exception as error:
            result.update(error_type=type(error).__name__, reason=str(error)[:512], status="failed")
        finally:
            if backend.visibility is not None:
                try:
                    result["visibility"] = backend.visibility.close()
                    backend.visibility.assert_passed()
                except Exception as error:
                    result.update(status="failed", visibility_error=str(error)[:512])
            try:
                if backend.transaction_observed:
                    cleanup_committed(backend) if args.mode == "commit" else backend.cleanup_rollback()
                elif backend.click_attempted:
                    backend.retain_public_diagnostic()
                    raise Refused("public action outcome incomplete; pending privilege/transaction retained for runner disposal")
                else:
                    cleanup_before_click(backend)
            except Exception as error:
                result["cleanup_errors"].append(str(error)[:512])
                result["status"] = "failed"
            if hasattr(backend, "menu"):
                backend.menu.close()
            result.update(events=backend.events, identity=backend.identity, transaction_observed=backend.transaction_observed)
            json.dump(result, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
    return 0 if result["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
